// Client adapters supply selectors; summaries and banners stay local to each message.
window.__emailShield = (() => {
  const states = new WeakMap();
  const hosts = new WeakSet();
  const identities = new WeakMap();
  const { limits } = Hamulus;
  const pageToken = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  let current;
  let debounce;
  let sequence = 0;
  const bodyOf = (msg, ad) => typeof ad.body === "function" ? ad.body(msg) : msg.querySelector(ad.body);
  const idOf = (msg, ad) => {
    const stable = ad.id?.(msg);
    if (stable) return String(stable).slice(0, 100);
    if (!identities.has(msg)) identities.set(msg, `${pageToken}:${++sequence}`);
    return identities.get(msg);
  };
  // Attachments and headers live outside the body, so they never show that the body itself was rendered.
  const bodyRead = email => !!(email.text.trim() || email.links.length || email.images.length || email.forms || email.hiddenTextChars);
  function read(msg, ad) {
    let body = null, email;
    try { body = bodyOf(msg, ad) || null; email = summarise(msg, body, ad); } catch {}
    if (!email) return { body };
    if (bodyRead(email)) return { body, email };
    if (!email.attachments.length) return { body };
    email.coverage.bodyUnavailable = true;
    return { body, email };
  }

  function init(adapter) {
    current = adapter;
    new MutationObserver(records => {
      if (records.every(r => hosts.has(r.target) || (r.type === "childList" && [...r.addedNodes, ...r.removedNodes].every(n => hosts.has(n))))) return;
      clearTimeout(debounce);
      debounce = setTimeout(() => scan(adapter), 100);
    }).observe(document.body, { childList: true, subtree: true, attributes: true, characterData: true });
    // Iframe mutations do not reach the parent observer.
    setInterval(() => scan(adapter), 1500);
    scan(adapter);
  }

  function scan(ad) {
    for (const msg of document.querySelectorAll(ad.message)) {
      const { body, email } = read(msg, ad);
      const fingerprint = email ? JSON.stringify(email) : "unavailable";
      const previous = states.get(msg);
      if (previous?.fingerprint === fingerprint && previous.body === body && previous.host?.isConnected) continue;
      if (previous) { clearTimeout(previous.timer); previous.host?.remove(); }
      const state = { body, fingerprint };
      states.set(msg, state);
      const anchor = (ad.mount && ad.mount(msg)) || body || msg.firstElementChild;
      if (!anchor) continue;
      const retry = () => { if (states.get(msg) === state) { states.delete(msg); state.host?.remove(); scan(ad); } };
      const paint = result => {
        state.host?.remove();
        state.host = paintBanner(anchor, result, retry);
      };
      if (!email) {
        paint({ status: "error", error: "Message body is unavailable. It will be checked again when it loads." });
        try {
          chrome.runtime.sendMessage({ type: "ANALYSE", email: { messageId: idOf(msg, ad), subject: String(ad.subject(msg) || "").slice(0, 300), coverage: { unavailable: true } } }, () => { void chrome.runtime.lastError; });
        } catch {}
        continue;
      }
      paint({ status: "scanning" });
      let answered = false;
      const finish = result => {
        if (answered || states.get(msg) !== state || !msg.isConnected) return;
        answered = true;
        clearTimeout(state.timer);
        const next = read(msg, ad);
        const nextFingerprint = next.email ? JSON.stringify(next.email) : "unavailable";
        if (next.body !== body || (body && !body.isConnected) || nextFingerprint !== fingerprint) { scan(ad); return; }
        paint(result);
      };
      state.timer = setTimeout(() => finish({ status: "error", error: "The scan timed out. Retry to check this message." }), 15000);
      try {
        chrome.runtime.sendMessage({ type: "ANALYSE", email }, result => {
          const failed = chrome.runtime.lastError || !result || result.error;
          finish(failed ? { status: "error", error: "The scan could not be completed. Retry to check this message." } : result);
        });
      } catch { finish({ status: "error", error: "The extension is unavailable. Reload this page or retry." }); }
    }
  }

  function summarise(msg, body, ad) {
    let truncated = false;
    const clip = (value, max) => {
      const text = String(value || "");
      if (text.length > max) truncated = true;
      return text.slice(0, max);
    };
    const url = value => {
      const text = String(value || "");
      if (text.length <= limits.url) return text;
      truncated = true;
      return ""; // A sliced URL could point to a different destination.
    };
    const boxes = new WeakMap();
    const reasons = new WeakMap();
    const styleOf = el => (el.ownerDocument.defaultView || window).getComputedStyle(el);
    // display, opacity, clipping and collapsed boxes suppress a whole subtree; font size and colour
    // are inherited but any descendant can override them, so they belong to the element that owns the text.
    function boxState(el) {
      if (!el) return { reason: "", background: "" };
      if (boxes.has(el)) return boxes.get(el);
      const parent = el === body ? { reason: "", background: "" } : boxState(el.parentElement);
      const cs = styleOf(el);
      const rect = el.getBoundingClientRect();
      const state = {
        reason: parent.reason || (cs.display === "none" ? "display: none" :
          Number.parseFloat(cs.opacity) === 0 ? "zero opacity" :
          cs.clipPath !== "none" || cs.clip !== "auto" ? "clipped content" :
          rect.width <= 1 && rect.height <= 1 && el.tagName !== "IMG" ? "very small content area" : ""),
        background: cs.backgroundColor === "rgba(0, 0, 0, 0)" ? parent.background : cs.backgroundColor,
      };
      boxes.set(el, state);
      return state;
    }
    function hiddenReason(el) {
      if (!el) return "";
      if (reasons.has(el)) return reasons.get(el);
      const box = boxState(el);
      const cs = styleOf(el);
      const reason = box.reason || (cs.visibility === "hidden" || cs.visibility === "collapse" ? "hidden visibility" :
        Number.parseFloat(cs.fontSize) === 0 ? "zero font size" :
        cs.color === "rgba(0, 0, 0, 0)" ? "transparent text" :
        cs.color === box.background ? "text matches background" : "");
      reasons.set(el, reason);
      return reason;
    }
    const links = [], images = [], excerpts = [];
    let chars = 0, hiddenTruncated = false, text = "", forms = 0, nodes = 0;
    const walker = body && body.ownerDocument.createTreeWalker(body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: node => node.nodeType === 1 && (hosts.has(node) || ["SCRIPT", "STYLE", "NOSCRIPT"].includes(node.tagName)) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
    });
    let node;
    while (walker && (node = walker.nextNode())) {
      if (++nodes > limits.nodes) { truncated = true; hiddenTruncated = true; break; }
      if (node.nodeType === 3) {
        const value = node.textContent.trim();
        if (!value) continue;
        const reason = hiddenReason(node.parentElement);
        if (reason) {
          chars = Math.min(10000000, chars + value.length);
          if (excerpts.length < limits.excerpts) excerpts.push({ reason, text: value.slice(0, limits.excerpt) });
          else hiddenTruncated = true;
          if (value.length > limits.excerpt) hiddenTruncated = true;
        } else if (text.length < limits.text) text = clip(text + " " + value, limits.text);
        else truncated = true;
        continue;
      }
      if (node.matches("a[href]")) {
        if (links.length >= limits.links) { truncated = true; continue; }
        const rawHref = url(node.getAttribute("href"));
        let href = "";
        try { if (rawHref) href = url(new URL(rawHref, node.baseURI).href); } catch {}
        links.push({ rawHref, href, text: clip(node.textContent.trim(), 200), hidden: !!hiddenReason(node) });
      }
      if (node.tagName === "IMG") {
        if (images.length >= limits.images) { truncated = true; continue; }
        const size = dimension => Math.min(10000000, Math.max(0, Math.round(Number(node.getAttribute(dimension)) || node[dimension] || 0)));
        images.push({ src: url(node.getAttribute("src")), width: size("width"), height: size("height"), hidden: !!hiddenReason(node) });
      }
      if (node.matches("form,input,select,textarea")) forms++;
    }
    const sender = ad.sender(msg) || {};
    const attachments = ad.attachments(msg) || [];
    if (attachments.length > limits.attachments) truncated = true;
    const replyTo = String(ad.replyTo?.(msg) || "");
    const result = {
      messageId: idOf(msg, ad),
      sender: { name: clip(sender.name, 200), email: sender.email?.length > 320 ? (truncated = true, "") : String(sender.email || "") },
      subject: clip(ad.subject(msg), 300), replyTo: replyTo.length > 320 ? (truncated = true, "") : replyTo,
      text, links, images, forms, attachments: attachments.slice(0, limits.attachments).map(name => clip(name, 200)),
      hiddenTextChars: chars, hiddenText: { chars, excerpts, truncated: hiddenTruncated },
    };
    result.coverage = { truncated, missingSender: !result.sender.email };
    return result;
  }

  function paintBanner(anchor, result, retry) {
    const doc = anchor.ownerDocument;
    const host = doc.createElement("div");
    hosts.add(host);
    host.setAttribute("data-email-shield", "");
    const root = host.attachShadow({ mode: "closed" });
    const style = doc.createElement("style");
    style.textContent = `
      :host { all: initial; display: block; margin: 0 0 12px; font: 14px/1.45 -apple-system, "Segoe UI", sans-serif; color: #222; }
      .box { border: 1px solid #aaa; border-radius: 8px; background: #f5f5f5; padding: 12px; }
      .safe { background: #eef7ee; border-color: #8fc98f; } .caution { background: #fff6e0; border-color: #e6b64a; } .danger { background: #fdeaea; border-color: #e46b6b; }
      h2 { font-size: 16px; margin: 0; } p { margin: 8px 0; } summary, button { cursor: pointer; }
      summary:focus-visible, button:focus-visible { outline: 3px solid #1766b3; outline-offset: 3px; }
      .warning { font-size: 13px; } .evidence { border-top: 1px solid #bbb; margin-top: 10px; }
      p, li, h2, h3 { overflow-wrap: anywhere; unicode-bidi: plaintext; } button { padding: 6px 12px; }
    `;
    root.append(style);
    const box = Hamulus.append(root, "div", "", `box ${Hamulus.iconLevel(result)}`);
    const score = Hamulus.scoreLabel(result);
    const heading = Hamulus.append(box, "h2", `Hamulus - ${Hamulus.heading(result)}${score ? ` (${score})` : ""}`);
    heading.setAttribute("role", "status");
    Hamulus.append(box, "p", Hamulus.warning, "warning");
    if (result.error) {
      Hamulus.append(box, "p", result.error);
      Hamulus.append(box, "button", "Retry scan").addEventListener("click", retry);
    }
    if (result.status !== "scanning") {
      const details = Hamulus.append(box, "details", "");
      Hamulus.append(details, "summary", "Assessment details and evidence");
      Hamulus.details(Hamulus.append(details, "div", ""), result);
    }
    anchor.parentElement?.insertBefore(host, anchor);
    return host;
  }
  function probe() {
    if (!current) return;
    for (const msg of document.querySelectorAll(current.message)) {
      let body;
      try { body = bodyOf(msg, current) || null; console.log({ body, summary: summarise(msg, body, current) }); }
      catch (error) { console.warn("Hamulus extraction unavailable", error); }
    }
  }
  const q = (root, sel) => root.querySelector(sel);
  // Subjects can legitimately live in a conversation header outside the message node; senders never may.
  const qConversation = (root, sel) => root.querySelector(sel) || document.querySelector(sel);
  const emailFrom = s => String(s || "").match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/)?.[0].toLowerCase() || "";
  return { init, probe, q, qConversation, emailFrom };
})();
