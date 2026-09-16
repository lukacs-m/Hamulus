// Proton Mail adapter.
// Proton renders each message body in a same-origin sandboxed <iframe> (title "Email content"),
// so the body is read through iframe.contentDocument and the banner is mounted ABOVE the iframe.
// Proton's own sanitiser (DOMPurify) has already run on that document; remote images are proxied/blocked
// per user settings, and nothing in it can script.
const { init, q, emailFrom } = window.__emailShield;

const iframeOf = (msg) => msg.querySelector('iframe[title="Email content"], iframe[data-testid="content-iframe"], .message-content iframe');

init({
  message: '[data-testid="message-view"], article[data-shortcut-target="message-container"], .message-container',
  body: (msg) => {
    const f = iframeOf(msg);
    const doc = f?.contentDocument;              // null while loading or if Proton drops allow-same-origin
    return doc?.body && doc.body.childElementCount ? doc.body : null;
  },
  mount: (msg) => iframeOf(msg)?.parentElement?.querySelector("[data-email-shield]") ? null : iframeOf(msg),
  sender: (msg) => {
    const el = q(msg, '[data-testid="recipients:sender"] [title*="@"], [data-testid="message-header-from"] [title*="@"], .message-recipient-item-label [title*="@"], [data-testid*="sender"] [title*="@"]');
    const name = (q(msg, '[data-testid="recipients:sender"], [data-testid="message-header-from"]')?.textContent || "").trim();
    return { name, email: emailFrom(el?.getAttribute("title") || el?.textContent || name) };
  },
  subject: (msg) => (q(msg, '[data-testid="conversation-header:subject"], [data-testid="message-header:subject"], h1.message-conversation-summary-header')?.textContent || "").trim(),
  attachments: (msg) => [...msg.querySelectorAll('[data-testid^="attachment-item"] [title], .message-attachmentList [title], [data-testid*="attachment"] [title]')]
    .map((e) => (e.getAttribute("title") || "").trim()).filter(Boolean),
});
