// Gmail adapter — selectors only. Gmail strips scripts and proxies images before we ever see the DOM.
const { init, q, emailFrom } = window.__emailShield;
init({
  message: "div[data-message-id]",
  body: ".a3s",
  sender: (msg) => { const el = q(msg, ".gD"); return { name: el?.getAttribute("name") || "", email: el?.getAttribute("email") || "" }; },
  subject: () => (document.querySelector("h2.hP")?.textContent || "").trim(),
  attachments: (msg) => [...msg.querySelectorAll("span.aV3")].map((e) => e.textContent.trim()),
});
