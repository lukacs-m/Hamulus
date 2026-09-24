// Registrable-domain helpers (small embedded suffix list; swap for the full Public Suffix List in production).

const MULTI_LEVEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp",
  "com.br", "com.mx", "com.ar", "co.za", "com.tr", "co.in", "gouv.fr", "asso.fr", "com.cn",
  "com.hk", "com.sg", "com.tw", "co.kr", "com.pl", "com.ua", "com.ru",
]);

export function canonicalHost(hostname) {
  try {
    const url = new URL(`http://${String(hostname || "").trim()}`);
    if (url.username || url.password || url.port || url.pathname !== "/" || url.search || url.hash) return "";
    return url.hostname.toLowerCase().replace(/\.$/, "");
  } catch { return ""; }
}

export function registrableDomain(hostname) {
  const h = canonicalHost(hostname);
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join(".");
  if (MULTI_LEVEL_SUFFIXES.has(last2) && parts.length >= 3) return parts.slice(-3).join(".");
  return last2;
}

export function isIpHost(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[?[0-9a-f:]+\]?$/i.test(hostname) && hostname.includes(":");
}

export function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

// Fold common homoglyph substitutions so "paypa1.com" / "rnicrosoft.com" collapse onto the brand.
export function foldHomoglyphs(s) {
  return s
    .replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l")
    .replace(/3/g, "e").replace(/5/g, "s").replace(/7/g, "t").replace(/\$/g, "s").replace(/@/g, "a")
    .replace(/[-_.]/g, "");
}

export const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
  "t.ly", "shorturl.at", "tiny.cc", "lnkd.in", "s.id", "rebrand.ly", "urlz.fr", "vu.fr",
]);

export const FREEMAIL = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.fr", "yahoo.com", "yahoo.fr", "live.com",
  "live.fr", "icloud.com", "aol.com", "protonmail.com", "proton.me", "orange.fr", "free.fr",
  "laposte.net", "sfr.fr", "wanadoo.fr", "gmx.com", "gmx.fr", "mail.com", "yandex.com",
]);
