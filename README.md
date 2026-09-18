# Hamulus - phishing score for every email you open

Chrome / Edge / Brave extension (Manifest V3). Adapters for **Gmail, Yahoo Mail, Outlook on the web
(personal + Microsoft 365) and Proton Mail**. `content/shared.js` does all the work; each client is a
~15-line adapter that only supplies DOM selectors (`content/gmail.js`, `yahoo.js`, `outlook.js`, `proton.js`).

### Verifying / fixing selectors
Webmail DOMs are undocumented and change. If no banner appears on a client, open DevTools on an opened
message and run `window.__emailShield.probe()` — it prints how many messages matched and what body /
sender / subject / attachments the adapter extracted, so you can see which selector to update.
Gmail selectors are the most battle-tested; Yahoo relies on `data-test-id`, Outlook on
`id^="UniqueMessageBody"` / `data-app-section`, Proton on `data-testid` plus its body iframe.

## Load it
1. `chrome://extensions` → Developer mode → *Load unpacked* → pick this folder.
2. Open Gmail, open any email: a banner with a 0–100 score appears above the message. Click it for the explanations.
3. The popup (toolbar icon) shows blocklist freshness and lets you force a refresh.

The toolbar and popup use the supplied hook-and-envelope icon. Before the first scan it is neutral;
the most recently scanned email changes the hook to green (80–100), amber (50–79), or red (0–49).
The toolbar tooltip includes the score. It follows the last email the extension was asked to scan, across
all tabs — not whichever analysis happens to finish first, and not a rating of the active page. Every
message still gets its own banner with its own score.

Run the tests with `npm test` (Node's built-in runner, no dependencies to install).

## Security design (why the email can't hurt you through the extension)
- **Nothing from the email is executed or fetched.** The content script only reads the DOM that Gmail has
  already sanitised (scripts stripped, images proxied). It converts it to a plain structured object
  (`links[]`, `images[]`, text, counts) — raw HTML never crosses the message boundary and is never
  injected anywhere.
- **Links are never opened, previewed or resolved.** Matching is done against locally stored feeds.
- **Local matching, no telemetry.** Feeds are downloaded on a schedule (`chrome.alarms`) and kept in
  `chrome.storage.local`. The only outbound request that depends on an email is an optional DNS-over-HTTPS
  lookup of `_dmarc.<sender-domain>` — the sender's domain only, never subject/body/links.
- **The banner lives in a closed shadow root and is built with `textContent`**, so the email's CSS/HTML
  can't restyle, hide or spoof it.
- **Strict CSP** (`script-src 'self'`, `connect-src` limited to the feed hosts).

## Scoring
`lib/analyzer.js` — start at 100, subtract per finding; any *critical* finding caps the score at 15.
- 80–100 green "Looks legitimate" · 50–79 amber "Be careful" · <50 red "Likely phishing".

| Check | Weight |
|---|---|
| Link / sender domain on an active blocklist | 60 (critical) |
| `javascript:` / `data:` link | 40 (critical) |
| Brand impersonation from free webmail (gmail/outlook…) | 45 (critical) |
| Look-alike domain (typo-squat, homoglyph, brand in subdomain, brand + suffix) | 30 |
| Sender display name claims a brand, domain isn't the brand's | 30 |
| Dangerous attachment (.html .iso .js .lnk .xlsm …) | 30 |
| Link text shows domain A, href goes to domain B | 25 |
| Form inside the email · Reply-To ≠ From · punycode · `user@host` trick · raw IP | 20–25 |
| Hidden text, hidden links, URL shorteners, credential lures | 10–12 |
| Urgency language (EN + FR) | 8 per hit, max 20 |
| No DMARC record · plain http · tracking pixel | 5–8 |

Tune weights in one place: the `add(...)` calls in `analyse()`.

## Feeds (`lib/feeds.js`)
| Feed | Type | Refresh | Notes |
|---|---|---|---|
| URLhaus (abuse.ch) | full URLs, malware | 1 h | may need a free `Auth-Key` header → `chrome.storage.local.feedHeaders.urlhaus` |
| OpenPhish community | full URLs, phishing | 6 h | **non-commercial licence** |
| Phishing.Database (phish.co.za) | domains | 3 h | |
| PhishDestroy destroylist | domains (hosts file) | 2 h | also has a free `/v1/check?domain=` API if you want an online second opinion |
| malware-filter phishing-filter | domains | 6 h | curated, top-1M popular sites already excluded → low false positives |

Add PhishTank (`https://data.phishtank.com/data/<api-key>/online-valid.json`, hourly) once you have a key,
or Google Safe Browsing / Web Risk for hash-prefix lookups (privacy-preserving, huge coverage).

## "Real company domains"
There is no universal registry. `data/brands.json` is a hand-curated seed (banks, carriers, French public
services, big tech). Grow it, and/or add an allow-list from the Tranco top-1M list so popular legitimate
domains never trigger look-alike heuristics.

## Known limitations of this v0.1
- Selectors for all four clients are undocumented and change occasionally; use `probe()` (above) to fix them.
- Proton renders the body in a sandboxed same-origin iframe; the adapter reads `iframe.contentDocument`.
  If Proton ever drops `allow-same-origin`, switch the Proton entry to `all_frames: true` + `match_about_blank`
  and pass the body summary to the parent frame via `chrome.runtime` messaging.
- Outlook's aria-labels are localised; EN and FR are covered, add your locale to `outlook.js` if needed.
- Reply-To is not visible in Gmail's DOM without "Show details"; hook it there if you need it.
- Registrable-domain logic uses a short embedded suffix list; swap in the full Public Suffix List.
- Large feeds (>200k lines) are stored as arrays in `chrome.storage.local`; move to IndexedDB + a Bloom
  filter if memory becomes an issue.
