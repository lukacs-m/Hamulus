// Pure analysis engine. Input is a STRUCTURED summary of the email (never raw HTML),
// output is a score 0-100 plus a list of findings with human explanations.
// Nothing here fetches, renders or executes anything from the email.

import { canonicalHost, registrableDomain, isIpHost, levenshtein, foldHomoglyphs, SHORTENERS, FREEMAIL } from "./domains.js";
import { normaliseUrl } from "./feeds.js";
import "./shared.js";

const URGENCY = [
  /verify (your )?(account|identity)/i, /account (has been|will be) (suspended|locked|closed)/i,
  /within (24|48) hours/i, /immediate(ly)? action/i, /unusual (sign-?in|activity)/i, /confirm your (payment|details)/i,
  /votre compte (sera|a été) (suspendu|bloqué|désactivé)/i, /sous (24|48) ?h/i, /action (urgente|immédiate)/i,
  /v[ée]rifi(ez|er) (votre|vos) (identit|compte|coordonn)/i, /colis (en attente|bloqué)/i, /frais de (douane|livraison) (impayé|non réglé)/i,
  /amende (impayée|à régler)/i, /remboursement (en attente|disponible)/i,
];
const CREDENTIAL_LURE = [/password/i, /mot de passe/i, /identifiant/i, /log ?in/i, /connexion sécurisée/i, /code (de )?(vérification|sécurité)/i];
const RISKY_ATTACHMENTS = /\.(html?|hta|js|jse|vbs|wsf|lnk|iso|img|exe|scr|bat|cmd|ps1|jar|xlsm|docm|one|svg)$/i;

export function analyse(email, ctx) {
  const findings = [];
  const linkEvidence = [];
  let activeLink = null;
  let incomplete = false;
  const counted = new Set();
  const add = (id, severity, points, title, detail, key = "") => {
    const discrepancy = `${id}|${key}`;
    const text = detail.slice(0, 700);
    if (!counted.has(discrepancy)) {
      counted.add(discrepancy);
      findings.push({ id, severity, points, title, detail: text });
    }
    if (activeLink) activeLink.reasons.push(`${title}: ${text}`);
  };

  const senderDomain = domainOf(email.sender?.email);
  const senderReg = senderDomain ? registrableDomain(senderDomain) : null;

  // ---------- Sender ----------
  if (senderReg) {
    const brand = brandMentioned(email.sender?.name || "", ctx.brands) || (!FREEMAIL.has(senderReg) && brandMentioned(email.subject || "", ctx.brands));
    if (brand && (FREEMAIL.has(senderReg) || !brandOwns(brand, senderDomain))) {
      if (FREEMAIL.has(senderReg)) {
        add("SENDER_FREEMAIL_BRAND", "critical", 45, `"${brand.label}" writing from a free webmail address`,
          `The sender presents as ${brand.label} but the address ends in ${senderReg}. A consumer mailbox does not establish affiliation with that company.`);
      } else {
        add("SENDER_BRAND_MISMATCH", "high", 30, `Sender claims to be ${brand.label} but domain is ${senderReg}`,
          `Known ${brand.label} domains include ${brand.domains.slice(0, 3).join(", ")}. This sender uses ${senderReg}; the catalogue is incomplete and this is not proof of impersonation.`);
      }
    }
    const look = lookalike(senderDomain, ctx.brands);
    if (look) add("SENDER_LOOKALIKE", "high", 30, `Sender domain imitates ${look.brand.label}`, `${senderDomain} looks like ${look.official} but is not it (${look.reason}).`);
    if (/xn--/.test(senderDomain)) add("SENDER_PUNYCODE", "high", 25, "Sender domain uses internationalised characters", `${senderDomain} contains punycode, which can be legitimate but can also disguise look-alike letters.`);
    if ((ctx.blocklist.domains.has(senderReg) || ctx.blocklist.domains.has(senderDomain))) add("SENDER_BLOCKLISTED", "critical", 60, "Sender domain is on a phishing blocklist", `${senderReg} appears in a locally stored phishing/malware feed. Check coverage details for freshness.`);
  }
  const replyReg = domainOf(email.replyTo) ? registrableDomain(domainOf(email.replyTo)) : null;
  if (replyReg && senderReg && replyReg !== senderReg) {
    add("REPLY_TO_MISMATCH", "high", 25, "Replies go to a different domain", `From: ${senderReg} but Reply-To: ${replyReg}. Your answer would reach someone else.`);
  }
  if (email.dmarc === "none" && senderReg && !FREEMAIL.has(senderReg)) {
    add("NO_DMARC", "low", 8, "No enforcing DMARC policy observed", `${senderReg} has no enforcing DMARC policy in this lookup. DNS policy does not authenticate this particular email.`);
  }

  // ---------- Links ----------
  for (const link of email.links || []) {
    activeLink = { text: link.text || "", href: link.href || link.rawHref || "", hostname: "", reasons: [] };
    linkEvidence.push(activeLink);
    let url;
    try { url = new URL(link.href); } catch {
      incomplete = true;
      add("LINK_UNRESOLVED", "info", 0, "Link destination could not be resolved", "The document did not provide a usable absolute destination. This link was not checked against blocklists.");
      continue;
    }
    activeLink.hostname = canonicalHost(url.hostname);
    const scheme = url.protocol.replace(":", "");
    if (scheme === "javascript" || scheme === "data" || scheme === "vbscript") {
      add("LINK_ACTIVE_SCHEME", "critical", 40, `Link uses ${scheme}: scheme`, "A link that runs code or embeds a payload instead of opening a page. Treat this as a warning sign; the link was not executed.", link.href);
      continue;
    }
    if (!["http", "https", "mailto", "tel"].includes(scheme)) {
      incomplete = true;
      add("LINK_UNSUPPORTED", "info", 0, "Unsupported link type", `The ${scheme}: destination was not checked against web blocklists.`);
      continue;
    }
    if (scheme !== "http" && scheme !== "https") continue;

    const host = canonicalHost(url.hostname);
    const reg = registrableDomain(host);
    const norm = normaliseUrl(link.href);

    if (ctx.blocklist.urls.has(norm) || ctx.blocklist.domains.has(reg) || ctx.blocklist.domains.has(host)) {
      add("LINK_BLOCKLISTED", "critical", 60, "Link is on a locally stored phishing / malware blocklist", `${host} matched a stored feed entry. Check coverage details for freshness; lists can be wrong. Do not open it if unsure.`, host);
    }
    if (isIpHost(host)) add("LINK_IP_HOST", "high", 20, "Link points to a raw IP address", `${link.href} has no domain name at all — this makes the destination harder to recognize.`, host);
    if (/xn--/.test(host)) add("LINK_PUNYCODE", "high", 25, "Link domain uses look-alike international characters", `${host} is punycode; the visible name may be spoofing a real one.`, host);
    if (SHORTENERS.has(reg)) add("LINK_SHORTENER", "medium", 10, "Link is a URL shortener", `${reg} hides the real destination. Its final destination is unknown because redirects are not followed.`, reg);
    if (scheme === "http") add("LINK_PLAIN_HTTP", "low", 5, "Link is not encrypted (http://)", `${host} — a modern company site would use https.`, host);
    if (/@/.test(url.username + url.password) || link.href.replace(/^https?:\/\//, "").split("/")[0].includes("@")) {
      add("LINK_USERINFO", "high", 25, "Link hides its real host behind an @", `Everything before the @ in ${link.href} is decoration; the browser goes to ${host}.`, link.href);
    }
    const look = lookalike(host, ctx.brands);
    if (look) add("LINK_LOOKALIKE", "high", 30, `Link domain imitates ${look.brand.label}`, `${host} resembles ${look.official} but is a different site (${look.reason}).`, host);

    // Visible text says one domain, href goes to another.
    const textHost = hostInText(link.text);
    if (textHost && registrableDomain(textHost) !== reg) {
      add("LINK_TEXT_MISMATCH", "high", 25, "Link text and destination disagree", `The link shows "${textHost}" but actually opens ${host}.`, `${textHost}>${host}`);
    }
    // Brand named in the anchor text but href elsewhere
    const brandInText = brandMentioned(link.text || "", ctx.brands);
    if (brandInText && !brandOwns(brandInText, host) && !SHORTENERS.has(reg)) {
      add("LINK_BRAND_MISMATCH", "high", 20, `"${brandInText.label}" link goes to ${reg}`, `Text mentions ${brandInText.label} but the destination is not a ${brandInText.label} domain.`, `${brandInText.label}>${reg}`);
    }
    if (link.hidden) add("LINK_HIDDEN", "medium", 10, "Hidden link in the message", `A link to ${host} is invisible to you but present in the HTML.`, host);
  }

  activeLink = null;

  // ---------- Images / tracking ----------
  let pixels = 0;
  for (const img of email.images || []) {
    const tiny = (img.width <= 2 && img.height <= 2) || (img.width === 0 && img.height === 0);
    if ((tiny || img.hidden) && /^https?:/i.test(img.src || "")) pixels++;
  }
  if (pixels) add("TRACKING_PIXEL", "low", 5, `${pixels} tracking pixel${pixels > 1 ? "s" : ""}`, "A small or hidden remote image can signal an open if the mail client loads it. Common in marketing; proxies and image blocking affect what the sender can observe.");

  // ---------- Content ----------
  if ((email.forms || 0) > 0) add("FORM_IN_EMAIL", "high", 25, "The email contains an input form", "An embedded form can request information directly inside the message. Do not enter information if unsure.");
  if ((email.hiddenTextChars || 0) > 40) add("HIDDEN_TEXT", "medium", 12, "Hidden text inside the message", `${email.hiddenTextChars} characters are invisible to you (zero-size, transparent or display:none). Hidden text can be legitimate preview or accessibility content, but can also be used to influence filters.`);

  const text = `${email.subject || ""}\n${email.text || ""}`;
  const urg = URGENCY.filter((r) => r.test(text)).length;
  if (urg) add("URGENCY", urg > 1 ? "medium" : "low", Math.min(20, 8 * urg), "Pressure / urgency language", "Threats of suspension, deadlines or 'immediate action' are the standard lever of phishing.");
  const lure = CREDENTIAL_LURE.filter((r) => r.test(text)).length;
  if (lure && (email.links || []).length) add("CREDENTIAL_LURE", "medium", 10, "Asks for credentials or codes", "Combined with a link, this is the classic 'log in here' trap.");

  for (const name of email.attachments || []) {
    if (RISKY_ATTACHMENTS.test(name)) add("RISKY_ATTACHMENT", "high", 30, `Dangerous attachment type: ${name}`, "HTML, ISO, script and macro files are the main way malware arrives by mail. Do not open.", name);
  }
  if ((email.links || []).length === 0 && (email.attachments || []).length === 0 && !urg) {
    // nothing to click, nothing to open: mostly harmless
  }

  // ---------- Score ----------
  const deduct = findings.reduce((s, f) => s + f.points, 0);
  const critical = findings.some((f) => f.severity === "critical");
  let score = Math.max(0, 100 - deduct);
  if (critical) score = Math.min(score, 15);
  const level = score >= 80 ? "safe" : score >= 50 ? "caution" : "danger";
  findings.sort((a, b) => b.points - a.points);
  return {
    score, level, findings: findings.slice(0, Hamulus.limits.findings),
    findingsOmitted: Math.max(0, findings.length - Hamulus.limits.findings),
    linkEvidence: linkEvidence.filter(link => link.reasons.length),
    hiddenText: email.hiddenText || { chars: email.hiddenTextChars || 0, excerpts: [], truncated: !!email.hiddenTextChars },
    coverage: { incomplete, notes: incomplete ? ["Some link destinations could not be checked."] : [] },
    analysedAt: Date.now(),
  };
}

// ---------- helpers ----------
function domainOf(addr) {
  const m = String(addr || "").match(/@([^>\s]+)/);
  return m ? canonicalHost(m[1]) : null;
}

function brandMentioned(str, brands) {
  const s = String(str).toLowerCase();
  for (const [key, b] of Object.entries(brands)) {
    if (s.includes(key) || s.includes(b.label.toLowerCase())) return b;
  }
  return null;
}

function brandOwns(brand, host) {
  const reg = registrableDomain(host);
  return brand.domains.some((d) => reg === registrableDomain(d) || host === d || host.endsWith("." + d));
}

// Detects hosts that imitate a brand: typo-squats, homoglyphs, brand-in-subdomain, brand-with-suffix.
function lookalike(host, brands) {
  const reg = registrableDomain(host);
  const label = reg.split(".")[0];
  for (const [key, brand] of Object.entries(brands)) {
    if (brandOwns(brand, host)) return null; // it IS the brand
    if (host.split(".").slice(0, -2).some((sub) => sub.includes(key))) {
      return { brand, official: brand.domains[0], reason: "brand name placed in a sub-domain of an unrelated site" };
    }
    if (label === key) return { brand, official: brand.domains[0], reason: "same name, different extension" };
    if (label.includes(key) && label !== key) return { brand, official: brand.domains[0], reason: `brand name padded with extra words ("${label}")` };
    if (key.length >= 5 && foldHomoglyphs(label).includes(foldHomoglyphs(key)) && !label.includes(key)) return { brand, official: brand.domains[0], reason: "look-alike characters (e.g. rn→m, 0→o, 1→l)" };
    if (key.length >= 5) {
      if (levenshtein(label, key) <= (key.length > 7 ? 2 : 1)) return { brand, official: brand.domains[0], reason: "one or two characters changed (typo-squat)" };
      if (foldHomoglyphs(label) === foldHomoglyphs(key) && label !== key) return { brand, official: brand.domains[0], reason: "look-alike characters (e.g. rn→m, 0→o, 1→l)" };
    }
  }
  return null;
}

function hostInText(text) {
  const m = String(text || "").match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/?#]|$|\s)/i);
  return m ? canonicalHost(m[1]) : null;
}
