import { FEEDS, normaliseUrl, cleanEntries } from "./lib/feeds.js";
import { analyse } from "./lib/analyzer.js";
import { canonicalHost, registrableDomain, isIpHost } from "./lib/domains.js";
import { iconPaths, scoreTitle } from "./lib/icons.js";
import { validateEmail, callerKind } from "./lib/messages.js";
import { fetchText } from "./lib/network.js";

let brands = null;
let blocklist = null;
let syncing = null;
let latestScan = 0;
let latestOwner = "";
let publishing = Promise.resolve();
let settingsEpoch = 0;
const dnsCache = new Map();
const dnsRequests = new Map();

chrome.runtime.onInstalled.addListener(() => { scheduleAll(); syncAll().catch(() => console.warn("Feed synchronization failed")); });
chrome.runtime.onStartup.addListener(scheduleAll);
chrome.alarms.onAlarm.addListener(a => {
  if (a.name.startsWith("feed:")) syncFeed(a.name.slice(5)).catch(() => console.warn("Feed synchronization failed"));
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (Object.keys(changes).some(key => key.startsWith("feed:"))) blocklist = null;
  if (changes.dnsEnabled) {
    settingsEpoch++;
    dnsCache.clear();
    if (changes.dnsEnabled.newValue !== true) for (const request of dnsRequests.values()) request.controller.abort();
  }
});
function scheduleAll() {
  for (const feed of FEEDS) chrome.alarms.create(`feed:${feed.id}`, { periodInMinutes: feed.refreshMinutes, delayInMinutes: 1 });
}
function syncAll() {
  if (!syncing) syncing = Promise.all(FEEDS.map(feed => syncFeed(feed.id))).finally(() => { syncing = null; });
  return syncing;
}
async function syncFeed(id) {
  const feed = FEEDS.find(f => f.id === id);
  if (!feed) return;
  try {
    const { feedHeaders = {} } = await chrome.storage.local.get("feedHeaders");
    const body = await fetchText(feed.url, { headers: feedHeaders[id] || {} });
    const entries = cleanEntries(feed, feed.parse(body));
    await chrome.storage.local.set({ [`feed:${id}`]: { kind: feed.kind, entries, updatedAt: Date.now(), count: entries.length, error: null } });
  } catch (error) {
    const key = `feed:${id}`;
    const previous = (await chrome.storage.local.get(key))[key] || { kind: feed.kind, entries: [] };
    await chrome.storage.local.set({ [key]: { ...previous, error: String(error.message || error).slice(0, 200), lastAttempt: Date.now() } });
  } finally { blocklist = null; }
}
function loadBlocklist() {
  if (blocklist) return blocklist;
  blocklist = (async () => {
    let stored = {};
    try { stored = await chrome.storage.local.get(FEEDS.map(f => `feed:${f.id}`)); }
    catch { blocklist = null; }
    const urls = new Set(), domains = new Set(), meta = {};
    for (const feed of FEEDS) {
      const data = stored[`feed:${feed.id}`];
      let entries = [];
      let error = data?.error || null;
      try { if (data) entries = cleanEntries(feed, data.entries); }
      catch { error = "Stored feed data is unavailable or exceeds supported limits."; }
      meta[feed.id] = { name: feed.name, count: entries.length, updatedAt: data?.updatedAt || null, error };
      for (const entry of entries) {
        if (feed.kind === "url") {
          urls.add(normaliseUrl(entry));
          domains.add(registrableDomain(new URL(entry).hostname));
        } else domains.add(canonicalHost(entry));
      }
    }
    // Exact URL feeds on shared services must not blacklist their whole provider.
    for (const shared of ["google.com", "microsoft.com", "dropbox.com", "amazonaws.com", "github.com", "t.co", "bit.ly", "sharepoint.com", "cloudfront.net", "wixsite.com", "weebly.com", "blogspot.com", "sites.google.com", "docs.google.com"]) domains.delete(shared);
    return { urls, domains, meta };
  })();
  return blocklist;
}
function feedStatus(meta) {
  return Object.fromEntries(FEEDS.map(feed => {
    const data = meta[feed.id];
    const stale = !Number.isFinite(data.updatedAt) || Date.now() - data.updatedAt > feed.refreshMinutes * 120000;
    const state = !data.count ? "unavailable" : data.error ? "refresh failed" : stale ? "stale" : "current";
    return [feed.id, { ...data, state }];
  }));
}
function loadBrands() {
  if (!brands) brands = fetchText(chrome.runtime.getURL("data/brands.json"), { maxBytes: 200000, timeout: 5000 })
    .then(JSON.parse).catch(() => { brands = null; return null; });
  return brands;
}
async function dnsEnabled() {
  const epoch = settingsEpoch;
  try { return (await chrome.storage.local.get("dnsEnabled")).dnsEnabled === true && epoch === settingsEpoch; }
  catch { return false; }
}
async function dmarcPolicy(domain) {
  if (!domain || isIpHost(domain) || !/^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/.test(domain) || domain.length > 253) return "unknown";
  const cached = dnsCache.get(domain);
  if (cached?.expires > Date.now()) return cached.value;
  if (dnsRequests.has(domain)) return dnsRequests.get(domain).promise;
  if (dnsRequests.size >= 4) return "unknown";
  const controller = new AbortController();
  const epoch = settingsEpoch;
  const promise = (async () => {
    try {
      const body = await fetchText(`https://cloudflare-dns.com/dns-query?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`, {
        headers: { accept: "application/dns-json" }, timeout: 5000, maxBytes: 32000, signal: controller.signal,
      });
      const json = JSON.parse(body);
      if (![0, 3].includes(json.Status)) return "unknown";
      const record = (Array.isArray(json.Answer) ? json.Answer : []).find(a => a.type === 16 && typeof a.data === "string" && /v=DMARC1/i.test(a.data));
      const value = record ? (/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)(?=\s*(?:;|"|$))/i.exec(record.data.replace(/"/g, ""))?.[1].toLowerCase() || "unknown") : "none";
      if (epoch === settingsEpoch) {
        if (dnsCache.size >= 128) dnsCache.delete(dnsCache.keys().next().value);
        dnsCache.set(domain, { value, expires: Date.now() + 3600000 });
      }
      return value;
    } catch { return "unknown"; }
    finally { dnsRequests.delete(domain); }
  })();
  dnsRequests.set(domain, { controller, promise });
  return promise;
}
function publish(scan, result) {
  publishing = publishing.then(async () => {
    if (scan !== latestScan) return;
    const outcomes = await Promise.allSettled([
      chrome.storage.session.set({ lastResult: result }),
      chrome.action.setIcon({ path: iconPaths(Hamulus.iconLevel(result)) }),
      chrome.action.setTitle({ title: scoreTitle(result) }),
    ]);
    for (const outcome of outcomes) if (outcome.status === "rejected") console.warn("could not publish latest result", outcome.reason);
  }).catch(error => console.warn("could not publish latest result", error));
}
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const kind = callerKind(sender, chrome.runtime);
  if (!msg || typeof msg !== "object" || !kind ||
      (msg.type === "ANALYSE" ? kind !== "mail" : kind !== "popup") ||
      !["ANALYSE", "FEED_STATUS", "SYNC_NOW", "GET_SETTINGS", "SET_DNS"].includes(msg.type)) {
    sendResponse({ error: "Unsupported request or caller." });
    return false;
  }
  let email = null;
  try { if (msg.type === "ANALYSE") email = validateEmail(msg.email); } catch {}
  let scan = null;
  if (msg.type === "ANALYSE" && (!email?.coverage.unavailable || email.messageId === latestOwner)) {
    latestOwner = email?.messageId || "";
    scan = ++latestScan;
  }
  (async () => {
    if (msg.type === "ANALYSE") {
      if (!email) throw new Error("Invalid email summary.");
      if (email.coverage.unavailable) throw new Error("Message body is unavailable.");
      publish(scan, { status: "scanning", subject: email.subject, sender: email.sender, analysedAt: Date.now() });
      const [bl, br] = await Promise.all([loadBlocklist(), loadBrands()]);
      const enabled = await dnsEnabled();
      const bodyUnread = email.coverage.bodyUnavailable;
      const domain = canonicalHost((email.sender.email.match(/@([^>\s]+)/) || [])[1]);
      const dmarc = enabled && !bodyUnread ? await dmarcPolicy(registrableDomain(domain)) : "unknown";
      const result = analyse({ ...email, dmarc }, { blocklist: bl, brands: br || {} });
      const feeds = feedStatus(bl.meta);
      const unavailable = Object.values(feeds).filter(feed => feed.state !== "current");
      const notes = [...result.coverage.notes];
      if (unavailable.length) notes.push(`Blocklist coverage is incomplete: ${unavailable.map(f => `${f.name} (${f.state})`).join(", ")}. Cached entries, when available, were still checked.`);
      if (!br) notes.push("The local brand catalogue is unavailable.");
      if (email.coverage.truncated) notes.push("Message limits were reached. Some content or evidence was omitted; this assessment is incomplete.");
      if (!email.sender.email) notes.push("Sender address could not be extracted; sender checks were not performed.");
      if (bodyUnread) notes.push("The message body could not be read. Only header and attachment details were assessed; the message content is unassessed.");
      notes.push(!enabled ? "Sender-domain DNS lookup is disabled. No sender-domain metadata was sent by this scan."
        : bodyUnread ? "Sender-domain DNS lookup was skipped because the message body could not be read. No sender-domain metadata was sent by this scan."
        : `Optional sender-domain DNS lookup: ${dmarc}. This does not authenticate this email.`);
      result.coverage = { incomplete: result.coverage.incomplete || !!unavailable.length || !br || email.coverage.truncated || !email.sender.email || bodyUnread, notes, feeds, dns: !enabled ? "disabled" : bodyUnread ? "skipped" : dmarc };
      Object.assign(result, { status: "complete", subject: email.subject, sender: email.sender });
      sendResponse(result);
      publish(scan, result);
    } else if (msg.type === "GET_SETTINGS") sendResponse({ dnsEnabled: await dnsEnabled() });
    else if (msg.type === "SET_DNS") {
      if (typeof msg.enabled !== "boolean") throw new Error("Invalid DNS preference.");
      await chrome.storage.local.set({ dnsEnabled: msg.enabled });
      sendResponse({ dnsEnabled: await dnsEnabled() });
    } else {
      if (msg.type === "SYNC_NOW") await syncAll();
      sendResponse(feedStatus((await loadBlocklist()).meta));
    }
  })().catch(() => {
    const result = { status: "error", error: "The scan could not be completed. Retry from the email banner.", subject: email?.subject || "", sender: email?.sender || {}, analysedAt: Date.now() };
    sendResponse(result);
    if (scan != null) publish(scan, result);
  });
  return true;
});
