import "./shared.js";
const { limits } = Hamulus;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
function string(value, max, fallback = "") {
  if (value == null) return fallback;
  if (typeof value !== "string" || value.length > max) throw new Error("Email summary exceeds supported text limits.");
  return value;
}
function count(value, max = 10000000) {
  if (value == null) return 0;
  if (!Number.isSafeInteger(value) || value < 0 || value > max) throw new Error("Invalid email summary count.");
  return value;
}
function boolean(value) {
  if (value == null) return false;
  if (typeof value !== "boolean") throw new Error("Invalid email summary flag.");
  return value;
}
function array(value, max, map) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > max) throw new Error("Email summary exceeds supported item limits.");
  return value.map(map);
}
function record(value) {
  if (!object(value)) throw new Error("Invalid email summary object.");
  return value;
}
export function validateEmail(input) {
  const e = record(input);
  const sender = e.sender == null ? {} : record(e.sender);
  const hidden = e.hiddenText == null ? {} : record(e.hiddenText);
  const coverage = e.coverage == null ? {} : record(e.coverage);
  return {
    sender: { name: string(sender.name, 200), email: string(sender.email, 320) },
    messageId: string(e.messageId, 100), subject: string(e.subject, 300), replyTo: string(e.replyTo, 320), text: string(e.text, limits.text),
    links: array(e.links, limits.links, link => {
      record(link);
      return { href: string(link.href, limits.url), rawHref: string(link.rawHref, limits.url), text: string(link.text, 200), hidden: boolean(link.hidden) };
    }),
    images: array(e.images, limits.images, img => {
      record(img);
      return { src: string(img.src, limits.url), width: count(img.width), height: count(img.height), hidden: boolean(img.hidden) };
    }),
    forms: count(e.forms), attachments: array(e.attachments, limits.attachments, name => string(name, 200)),
    hiddenTextChars: count(e.hiddenTextChars),
    hiddenText: { chars: count(hidden.chars ?? e.hiddenTextChars), truncated: boolean(hidden.truncated), excerpts: array(hidden.excerpts, limits.excerpts, excerpt => {
      record(excerpt);
      return { text: string(excerpt.text, limits.excerpt), reason: string(excerpt.reason, 160) };
    }) },
    coverage: { truncated: boolean(coverage.truncated), missingSender: boolean(coverage.missingSender), unavailable: boolean(coverage.unavailable), bodyUnavailable: boolean(coverage.bodyUnavailable) },
  };
}
export function callerKind(sender, runtime) {
  if (!sender || sender.id !== runtime.id) return null;
  try {
    const url = new URL(sender.url);
    if (url.href === runtime.getURL("popup/popup.html")) return "popup";
    if (!Number.isInteger(sender.tab?.id) || sender.frameId !== 0 || url.protocol !== "https:") return null;
    const hosts = ["mail.google.com", "mail.yahoo.com", "outlook.live.com", "outlook.office.com", "outlook.office365.com", "outlook.cloud.microsoft", "mail.proton.me"];
    if (hosts.includes(url.hostname) || url.hostname.endsWith(".mail.yahoo.com")) return "mail";
  } catch {}
  return null;
}
