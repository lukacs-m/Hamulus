// Service worker: keeps blocklists fresh, answers "analyse this email" requests from content scripts.
import { FEEDS, normaliseUrl } from "./lib/feeds.js";
import { analyse } from "./lib/analyzer.js";
import { registrableDomain } from "./lib/domains.js";
import { iconPaths, scoreTitle } from "./lib/icons.js";

let brands = null;
let blocklist = null; // { urls: Set, domains: Set, meta: {...} }

// ---------- feed sync ----------
chrome.runtime.onInstalled.addListener(() => { scheduleAll(); syncAll(); });
chrome.runtime.onStartup.addListener(() => { scheduleAll(); });
chrome.alarms.onAlarm.addListener((a) => { if (a.name.startsWith("feed:")) syncFeed(a.name.slice(5)); });

function scheduleAll() {
  for (const f of FEEDS) chrome.alarms.create(`feed:${f.id}`, { periodInMinutes: f.refreshMinutes, delayInMinutes: 1 });
}

async function syncAll() { for (const f of FEEDS) await syncFeed(f.id); }

async function syncFeed(id) {
  const feed = FEEDS.find((f) => f.id === id);
  if (!feed) return;
  try {
    const { feedHeaders = {} } = await chrome.storage.local.get("feedHeaders");
    const res = await fetch(feed.url, { headers: feedHeaders[id] || {}, cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const entries = feed.parse(await res.text());
    const cleaned = feed.kind === "url" ? entries.map(normaliseUrl) : entries.map((d) => d.toLowerCase());
    await chrome.storage.local.set({
      [`feed:${id}`]: { kind: feed.kind, entries: cleaned, updatedAt: Date.now(), count: cleaned.length, error: null },
    });
    blocklist = null; // force rebuild
  } catch (e) {
    const prev = (await chrome.storage.local.get(`feed:${id}`))[`feed:${id}`] || { kind: feed.kind, entries: [] };
    await chrome.storage.local.set({ [`feed:${id}`]: { ...prev, error: String(e.message || e), lastAttempt: Date.now() } });
  }
}

async function loadBlocklist() {
  if (blocklist) return blocklist;
  const urls = new Set(), domains = new Set(), meta = {};
  const stored = await chrome.storage.local.get(FEEDS.map((f) => `feed:${f.id}`));
  for (const f of FEEDS) {
    const data = stored[`feed:${f.id}`];
    meta[f.id] = { name: f.name, count: data?.count || 0, updatedAt: data?.updatedAt || null, error: data?.error || null };
    if (!data) continue;
    for (const e of data.entries) {
      if (f.kind === "url") {
        urls.add(e);
        try { domains.add(registrableDomain(new URL(e).hostname)); } catch {}
      } else domains.add(e);
    }
  }
  // Feeds also list full URLs on shared hosts (drive.google.com, t.co...). Never treat those as blocklisted domains.
  for (const shared of ["google.com", "microsoft.com", "dropbox.com", "amazonaws.com", "github.com", "t.co", "bit.ly", "sharepoint.com", "cloudfront.net", "wixsite.com", "weebly.com", "blogspot.com", "sites.google.com", "docs.google.com"]) domains.delete(shared);
  blocklist = { urls, domains, meta };
  return blocklist;
}

async function loadBrands() {
  if (brands) return brands;
  brands = await (await fetch(chrome.runtime.getURL("data/brands.json"))).json();
  return brands;
}

// DMARC check over DNS-over-HTTPS. Only the sender's DOMAIN is sent — never email content.
async function dmarcPolicy(domain) {
  if (!domain) return "unknown";
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`, { headers: { accept: "application/dns-json" } });
    const j = await r.json();
    const txt = (j.Answer || []).map((a) => a.data).find((d) => /v=DMARC1/i.test(d));
    if (!txt) return "none";
    const m = txt.match(/p=(none|quarantine|reject)/i);
    return m ? m[1].toLowerCase() : "none";
  } catch { return "unknown"; }
}

// ---------- messaging ----------
let latestScan = 0;

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "ANALYSE") {
      const scan = ++latestScan;
      const [bl, br] = await Promise.all([loadBlocklist(), loadBrands()]);
      const senderDomain = (String(msg.email.sender?.email || "").match(/@([^>\s]+)/) || [])[1];
      const dmarc = msg.settingsDmarc === false ? "unknown" : await dmarcPolicy(senderDomain ? registrableDomain(senderDomain) : null);
      const result = analyse({ ...msg.email, dmarc }, { blocklist: bl, brands: br });
      sendResponse(result);
      if (scan !== latestScan) return;
      await chrome.storage.session?.set?.({ lastResult: { ...result, subject: msg.email.subject, sender: msg.email.sender } });
      await Promise.all([
        chrome.action.setIcon({ path: iconPaths(result.level) }),
        chrome.action.setTitle({ title: scoreTitle(result) }),
      ]).catch((e) => console.warn("toolbar update failed", e));
    } else if (msg.type === "FEED_STATUS") {
      sendResponse((await loadBlocklist()).meta);
    } else if (msg.type === "SYNC_NOW") {
      await syncAll();
      sendResponse((await loadBlocklist()).meta);
    }
  })().catch((e) => sendResponse({ error: String(e) }));
  return true; // async response
});
