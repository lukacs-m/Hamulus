// Client-agnostic scanner. Each mail client ships a tiny adapter that only supplies DOM selectors.
// Loaded before the adapter (see manifest "js" order). No modules in content scripts, hence the global.
window.__emailShield = (() => {
  const SEEN = new WeakSet();

  let current = null;

  function init(adapter) {
    current = adapter;
    const observer = new MutationObserver(() => scan(adapter));
    observer.observe(document.body, { childList: true, subtree: true });
    // Bodies rendered inside iframes (Proton) don't trigger the parent observer: poll as a backup.
    setInterval(() => scan(adapter), 1500);
    scan(adapter);
  }

  // ad.body: selector string, or function(msg) -> element (used when the body lives in an iframe).
  const bodyOf = (msg, ad) => (typeof ad.body === "function" ? ad.body(msg) : msg.querySelector(ad.body));

  function scan(ad) {
    for (const msg of document.querySelectorAll(ad.message)) {
      let body;
      try { body = bodyOf(msg, ad); } catch { body = null; }
      if (!body || SEEN.has(msg) || body.childElementCount === 0) continue;
      SEEN.add(msg);
      const email = summarise(msg, body, ad);
      chrome.runtime.sendMessage({ type: "ANALYSE", email }, (result) => {
        if (chrome.runtime.lastError || !result || result.error) return;
        paintBanner((ad.mount && ad.mount(msg)) || body, result);
      });
    }
  }

  // Run window.__emailShield.probe() in DevTools to see which selectors match on the current page.
  function probe() {
    const ad = current;
    const msgs = [...document.querySelectorAll(ad.message)];
    console.log("[Hamulus] messages:", msgs.length);
    for (const msg of msgs) {
      let body = null; try { body = bodyOf(msg, ad); } catch (e) { console.warn("body error", e); }
      console.log({ body, sender: ad.sender(msg), subject: ad.subject(msg), attachments: ad.attachments(msg), replyTo: ad.replyTo?.(msg) });
    }
  }

  function summarise(msg, body, ad) {
    const links = [];
    for (const a of body.querySelectorAll("a[href]")) {
      links.push({ href: a.getAttribute("href") || "", text: (a.textContent || "").trim().slice(0, 200), hidden: isHidden(a) });
    }
    const images = [];
    for (const img of body.querySelectorAll("img")) {
      images.push({
        src: img.getAttribute("src") || "",
        width: Number(img.getAttribute("width")) || img.width || 0,
        height: Number(img.getAttribute("height")) || img.height || 0,
        hidden: isHidden(img),
      });
    }
    let hiddenTextChars = 0;
    for (const el of body.querySelectorAll("*")) {
      if (el.children.length === 0 && el.textContent && isHidden(el)) hiddenTextChars += el.textContent.trim().length;
    }
    return {
      sender: ad.sender(msg),
      replyTo: ad.replyTo ? ad.replyTo(msg) : null,
      subject: ad.subject(msg),
      text: (body.innerText || "").slice(0, 20000),
      links,
      images,
      forms: body.querySelectorAll("form, input, select, textarea").length,
      attachments: ad.attachments(msg),
      hiddenTextChars,
    };
  }

  function isHidden(el) {
    const cs = (el.ownerDocument.defaultView || window).getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity) === 0) return true;
    if (parseFloat(cs.fontSize) === 0) return true;
    const r = el.getBoundingClientRect();
    if (r.width <= 1 && r.height <= 1 && el.tagName !== "IMG") return true;
    const color = cs.color, bg = cs.backgroundColor;
    if (color && bg && color === bg && bg !== "rgba(0, 0, 0, 0)") return true;
    return false;
  }

  // Banner in a closed shadow root, textContent only: email HTML/CSS can't touch it.
  function paintBanner(anchor, result) {
    const host = document.createElement("div");
    host.setAttribute("data-email-shield", "");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; display: block; margin: 0 0 12px; font: 14px/1.4 -apple-system, "Segoe UI", Roboto, sans-serif; }
      .bar { display: flex; align-items: center; gap: 14px; padding: 10px 14px; border-radius: 8px; cursor: pointer; border: 1px solid; user-select: none; }
      .safe    { background: #eef7ee; border-color: #8fc98f; color: #1d4d1d; }
      .caution { background: #fff6e0; border-color: #e6b64a; color: #5a3c00; }
      .danger  { background: #fdeaea; border-color: #e46b6b; color: #6d1212; }
      .score { font-size: 26px; font-weight: 700; min-width: 52px; text-align: center; }
      .label { font-weight: 600; }
      .sub { opacity: .8; font-size: 13px; }
      .toggle { margin-left: auto; font-size: 12px; opacity: .7; }
      ul { margin: 6px 0 0; padding: 0 0 0 18px; }
      li { margin: 6px 0; }
      li b { display: block; }
      li span { opacity: .85; font-size: 13px; }
      .sev { display: inline-block; font-size: 11px; padding: 1px 6px; border-radius: 4px; margin-right: 6px; color: #fff; }
      .sev.critical { background: #b71c1c; } .sev.high { background: #d84315; } .sev.medium { background: #b8860b; } .sev.low { background: #607d8b; }
    `;
    root.append(style);

    const bar = document.createElement("div");
    bar.className = `bar ${result.level}`;
    const score = document.createElement("div"); score.className = "score"; score.textContent = String(result.score);
    const txt = document.createElement("div");
    const label = document.createElement("div"); label.className = "label";
    label.textContent = { safe: "Looks legitimate", caution: "Be careful with this email", danger: "Likely phishing — do not click or reply" }[result.level];
    const sub = document.createElement("div"); sub.className = "sub";
    sub.textContent = result.findings.length ? `${result.findings.length} issue${result.findings.length > 1 ? "s" : ""} found — click for details` : "No issues found";
    txt.append(label, sub);
    const toggle = document.createElement("div"); toggle.className = "toggle"; toggle.textContent = "Hamulus";
    bar.append(score, txt, toggle);

    const details = document.createElement("div");
    details.hidden = true;
    const ul = document.createElement("ul");
    for (const f of result.findings) {
      const li = document.createElement("li");
      const b = document.createElement("b");
      const sev = document.createElement("span"); sev.className = `sev ${f.severity}`; sev.textContent = f.severity;
      b.append(sev, document.createTextNode(f.title));
      const span = document.createElement("span"); span.textContent = f.detail;
      li.append(b, span);
      ul.append(li);
    }
    details.append(ul);
    bar.addEventListener("click", () => { details.hidden = !details.hidden; });
    root.append(bar, details);
    anchor.parentElement.insertBefore(host, anchor);
  }

  // Helper: first matching element among comma-separated fallback selectors.
  const q = (root, sel) => root.querySelector(sel) || document.querySelector(sel);
  const emailFrom = (s) => { const m = String(s || "").match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/); return m ? m[0].toLowerCase() : ""; };

  return { init, probe, q, emailFrom };
})();
