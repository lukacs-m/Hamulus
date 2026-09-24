// Outlook on the web adapter — outlook.live.com (personal), outlook.office.com / outlook.office365.com (M365).
// Outlook's class names are hashed; aria-labels are localised (EN "Message body" / FR "Corps du message").
// The id prefix "UniqueMessageBody" and data-app-section attributes are the most stable hooks.
const { init, q, qConversation, emailFrom } = window.__emailShield;

init({
  message: 'div[data-app-section="ItemContainer"], div[aria-label="Email message"], div[aria-label="Message électronique"], div.wide-content-host',
  body: 'div[id^="UniqueMessageBody"], div[aria-label="Message body"], div[aria-label="Corps du message"], div.allowTextSelection',
  sender: (msg) => {
    // Header persona button carries the address in title / aria-label.
    const el = q(msg, 'div[data-app-section="ItemHeader"] [title*="@"], [data-testid="SenderPersona"] [title*="@"], span[aria-label*="@"], [title*="@"]');
    const raw = el?.getAttribute("title") || el?.getAttribute("aria-label") || el?.textContent || "";
    const name = (el?.textContent || "").replace(/<.*>/, "").trim();
    return { name, email: emailFrom(raw) };
  },
  subject: (msg) => (qConversation(msg, 'div[role="heading"][aria-level="2"], [data-testid="SubjectHeader"], span[title][class*="Subject"]')?.textContent || "").trim(),
  attachments: (msg) => [...msg.querySelectorAll('div[data-app-section="AttachmentWell"] [title], [aria-label*="attachment" i] [title], [aria-label*="pièce jointe" i] [title]')]
    .map((e) => (e.getAttribute("title") || "").trim()).filter((n) => /\.\w{2,5}$/.test(n)),
});
