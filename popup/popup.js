import { iconPaths, scoreTitle } from "../lib/icons.js";

function ago(ts) {
  if (!ts) return "never";
  const m = Math.round((Date.now() - ts) / 60000);
  return m < 60 ? `${m} min ago` : `${Math.round(m / 60)} h ago`;
}
function render(meta) {
  const t = document.getElementById("feeds");
  t.textContent = "";
  for (const [id, f] of Object.entries(meta)) {
    const tr = document.createElement("tr");
    const name = document.createElement("td"); name.textContent = f.name;
    const n = document.createElement("td"); n.className = "n";
    n.textContent = f.error ? `error: ${f.error}` : `${f.count.toLocaleString()} · ${ago(f.updatedAt)}`;
    if (f.error) n.classList.add("err");
    tr.append(name, n); t.append(tr);
  }
}
chrome.runtime.sendMessage({ type: "FEED_STATUS" }, render);
chrome.storage.session?.get?.("lastResult").then(({ lastResult }) => {
  if (!lastResult) return;
  const icon = document.getElementById("icon");
  icon.src = chrome.runtime.getURL(iconPaths(lastResult.level)[32]);
  icon.alt = scoreTitle(lastResult);
  const box = document.getElementById("last");
  box.hidden = false; box.classList.add(lastResult.level);
  document.getElementById("score").textContent = lastResult.score;
  document.getElementById("subject").textContent = lastResult.subject || "(no subject)";
  document.getElementById("sender").textContent = lastResult.sender?.email || "";
});
document.getElementById("sync").addEventListener("click", () => {
  document.getElementById("sync").textContent = "Refreshing…";
  chrome.runtime.sendMessage({ type: "SYNC_NOW" }, (meta) => { render(meta); document.getElementById("sync").textContent = "Refresh blocklists now"; });
});
