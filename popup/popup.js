import { iconPaths } from "../lib/icons.js";
const el = id => document.getElementById(id);
const request = message => new Promise((resolve, reject) => {
  chrome.runtime.sendMessage(message, result => {
    if (chrome.runtime.lastError || !result || result.error) reject(new Error(result?.error || "Extension unavailable. Try again."));
    else resolve(result);
  });
});
function ago(ts) {
  if (!ts) return "never refreshed";
  const minutes = Math.max(0, Math.round((Date.now() - ts) / 60000));
  return minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} h ago`;
}
function renderFeeds(meta) {
  el("feeds").textContent = "";
  for (const feed of Object.values(meta)) {
    const row = Hamulus.append(el("feeds"), "tr", "");
    Hamulus.append(row, "td", feed.name);
    Hamulus.append(row, "td", `${feed.state} · ${feed.count.toLocaleString()} entries · ${ago(feed.updatedAt)}${feed.error ? ` · ${feed.error}` : ""}`, `n ${feed.state !== "current" ? "err" : ""}`);
  }
}
function renderResult(result) {
  el("icon").src = chrome.runtime.getURL(iconPaths(Hamulus.iconLevel(result))[128]);
  el("last").className = `last ${Hamulus.iconLevel(result)}`;
  el("heading").textContent = Hamulus.heading(result) + (result?.score == null ? "" : ` (${result.score}/100)`);
  el("subject").textContent = result ? Hamulus.text(result.subject || "(no subject)") : "";
  el("sender").textContent = Hamulus.text(result?.sender?.email || "");
  el("time").textContent = result?.analysedAt ? new Date(result.analysedAt).toLocaleString() : "";
  el("details").hidden = !result || result.status === "scanning";
  if (result) Hamulus.details(el("evidence"), result);
}
el("warning").textContent = Hamulus.warning;
let resultRevision = 0;
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.lastResult) { resultRevision++; renderResult(changes.lastResult.newValue); }
  if (area === "local" && changes.dnsEnabled) el("dns").checked = changes.dnsEnabled.newValue === true;
});
const initialRevision = resultRevision;
chrome.storage.session.get("lastResult").then(({ lastResult }) => {
  if (initialRevision === resultRevision) renderResult(lastResult);
}).catch(() => renderResult({ status: "error", error: "Latest scan could not be loaded." }));
request({ type: "FEED_STATUS" }).then(renderFeeds).catch(error => { el("feed-status").textContent = error.message; });
request({ type: "GET_SETTINGS" }).then(settings => {
  el("dns").checked = settings.dnsEnabled === true;
  el("dns").disabled = false;
}).catch(() => { el("settings-status").textContent = "Preference unavailable. DNS lookups remain disabled unless a saved opt-in can be read."; });
el("dns").addEventListener("change", async () => {
  const enabled = el("dns").checked;
  el("dns").disabled = true;
  try {
    const settings = await request({ type: "SET_DNS", enabled });
    el("dns").checked = settings.dnsEnabled;
    el("settings-status").textContent = settings.dnsEnabled ? "Saved. Future scans may perform a DNS lookup." : "Saved. Future scans will not send DNS lookups.";
  } catch (error) { el("dns").checked = !enabled; el("settings-status").textContent = error.message; }
  finally { el("dns").disabled = false; }
});
el("sync").addEventListener("click", async () => {
  el("sync").disabled = true;
  el("sync").textContent = "Refreshing…";
  try { renderFeeds(await request({ type: "SYNC_NOW" })); el("feed-status").textContent = "Refresh finished. Check coverage above."; }
  catch (error) { el("feed-status").textContent = error.message; }
  finally { el("sync").disabled = false; el("sync").textContent = "Refresh blocklists now"; }
});
