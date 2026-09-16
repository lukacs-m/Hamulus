// Threat-feed registry. Everything is downloaded in the background and matched LOCALLY.
// No email content ever leaves the browser.
//
// kind: "url"    -> exact full-URL entries (normalised)
//       "domain" -> registrable-domain / hostname entries
// Check each feed's licence before shipping commercially (OpenPhish community feed is non-commercial).

export const FEEDS = [
  {
    id: "urlhaus",
    name: "URLhaus (abuse.ch) — malware URLs",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
    kind: "url",
    refreshMinutes: 60,
    // abuse.ch may require a free Auth-Key header: put it in chrome.storage.local "feedHeaders.urlhaus".
    parse: plainLines,
  },
  {
    id: "openphish",
    name: "OpenPhish community feed",
    url: "https://openphish.com/feed.txt",
    kind: "url",
    refreshMinutes: 360,
    parse: plainLines,
  },
  {
    id: "phishing-database-domains",
    name: "Phishing.Database — active domains",
    url: "https://phish.co.za/latest/phishing-domains-ACTIVE.txt",
    kind: "domain",
    refreshMinutes: 180,
    parse: plainLines,
  },
  {
    id: "destroylist",
    name: "PhishDestroy destroylist (hosts format)",
    url: "https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/hosts.txt",
    kind: "domain",
    refreshMinutes: 120,
    parse: hostsFile,
  },
  {
    id: "phishing-filter",
    name: "malware-filter phishing-filter (curated, popular sites excluded)",
    url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
    kind: "domain",
    refreshMinutes: 360,
    parse: plainLines,
  },
];

function plainLines(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    out.push(line);
  }
  return out;
}

function hostsFile(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    const host = parts.length > 1 ? parts[1] : parts[0];
    if (host && host !== "localhost") out.push(host.toLowerCase());
  }
  return out;
}

// Normalise URL for exact matching: lowercase host, strip fragment, trailing slash, "www."
export function normaliseUrl(u) {
  try {
    const url = new URL(u);
    url.hash = "";
    const host = url.hostname.toLowerCase().replace(/^www\./, "");
    const s = `${url.protocol}//${host}${url.port ? ":" + url.port : ""}${url.pathname}${url.search}`;
    return s.replace(/\/$/, "");
  } catch {
    return String(u).trim().toLowerCase();
  }
}
