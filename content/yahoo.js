// Yahoo Mail adapter. Yahoo's web app tags most nodes with data-test-id attributes, which are far
// more stable than class names. Each selector lists fallbacks; verify with DevTools if a banner stops
// appearing after a Yahoo redesign (search the message pane for data-test-id).
const { init, q, emailFrom } = window.__emailShield;
init({
  message: '[data-test-id="message-view"], [data-test-id="message-view-container"], div.message-view',
  body: '[data-test-id="message-view-body"], [data-test-id="message-body"], .msg-body',
  sender: (msg) => {
    const el = q(msg, '[data-test-id="message-from"] [title*="@"], [data-test-id="message-from"] span[title], [data-test-id="email-pill"]');
    const raw = el?.getAttribute("title") || el?.textContent || "";
    const name = (q(msg, '[data-test-id="message-from"]')?.textContent || "").replace(raw, "").trim();
    return { name, email: emailFrom(raw) };
  },
  replyTo: (msg) => {
    const el = q(msg, '[data-test-id="message-reply-to"] [title*="@"]');
    return el ? emailFrom(el.getAttribute("title")) : null;
  },
  subject: (msg) => (q(msg, '[data-test-id="message-subject"], [data-test-id="message-group-view-subject"], h1[data-test-id]')?.textContent || "").trim(),
  attachments: (msg) => [...msg.querySelectorAll('[data-test-id="attachment-name"], [data-test-id*="attachment"] [title]')]
    .map((e) => (e.getAttribute("title") || e.textContent).trim()).filter(Boolean),
});
