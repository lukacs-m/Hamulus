# Hamulus - phishing score for every email you open

Chrome / Edge / Brave extension (Manifest V3). Adapters for **Gmail, Yahoo Mail, Outlook on the web
(personal + Microsoft 365) and Proton Mail**. `content/shared.js` does all the work; each client is a
small adapter that only supplies DOM selectors (`content/gmail.js`, `yahoo.js`, `outlook.js`, `proton.js`).

### Verifying / fixing selectors
Webmail DOMs are undocumented and change. If no banner appears on a client, open DevTools on an opened
message and run `window.__emailShield.probe()` — it prints how many messages matched and what body /
sender / subject / attachments the adapter extracted, so you can see which selector to update.
The adapters have synthetic browser-fixture coverage, not live-account certification. Yahoo relies on `data-test-id`, Outlook on
`id^="UniqueMessageBody"` / `data-app-section`, Proton on `data-testid` plus its body iframe.

## Load it
1. `chrome://extensions` → Developer mode → *Load unpacked* → pick this folder.
2. Open Gmail, open any email: a banner with a heuristic 0–100 score appears above the message. Expand its keyboard-accessible details for explanations and evidence.
3. The popup shows the latest requested scan, blocklist freshness, refresh control and the optional DNS preference.

The toolbar and popup use the supplied hook-and-envelope icon. Before the first scan it is neutral;
a complete assessment of the latest requested email changes the hook to green (80–100), amber (50–79), or red (0–49).
The toolbar tooltip includes the score. It follows the last email the extension was asked to scan, across
all tabs. It is not a rating of the active page, and an older completion cannot replace a newer request. Every
message still gets its own banner. Changed or reused bodies are rescanned; stale callbacks are ignored. Scanning, failed and incomplete assessments use a neutral icon. A failed scan has a Retry button.

Run the tests with `npm test` (Node's built-in runner, no dependencies to install). Pull requests
re-run them together with a JavaScript syntax check; see `.github/workflows/tests.yml`.

## Safety, evidence and privacy
Hamulus can produce **false positives and false negatives**. A high score is not authentication or proof
that an email is safe. If unsure, do not click links, open attachments, reply or enter information.
Open the official website or app directly using a trusted bookmark or an address you know.
This warning is shown in both the email banner and popup.

- Email content is read from the mail client DOM and summarized into bounded strings, arrays and counts.
  The extension does not execute email HTML, fetch email links or remote images, follow redirects, or
  open destinations. The mail client may itself load images or other content independently.
- Relative URLs are resolved locally against the actual document base, including accessible body iframes.
  This is URL parsing, not a network request. Unresolvable and unsupported destinations reduce coverage.
- Flagged-link evidence shows displayed text, the resolved URL, its hostname and the detected mechanisms.
  Redirect destinations remain unknown. Hidden-text evidence includes bounded excerpts, character counts,
  hiding reasons and truncation notices. Legitimate preheaders and accessibility content may be hidden.
- Evidence is rendered as inert text, with visible markers for bidirectional control characters and wrapping
  for long URLs. The closed shadow root limits accidental style interference; it is **not** an authenticity
  boundary. The surrounding page can hide/remove the host or imitate a banner. The extension popup is the
  trusted surface for checking the latest result.
- Feed matching is local with no telemetry. Feed providers receive scheduled download requests.
  Failed, oversized or unusable refreshes retain the last known good entries. Stale, missing or failed feeds
  are disclosed as incomplete coverage. The worker validates message callers and bounds summaries, feed
  reads and network timeouts. Cosmetic toolbar or popup-storage failures do not suppress email results.
- **Sender-domain DNS is off by default.** Only an explicit saved opt-in in the popup enables a lookup of
  `_dmarc.<sender-domain>` via Cloudflare DNS. It sends no subject, body or links, but the resolver and
  potentially the domain owner can observe the lookup. A domain policy does not authenticate this email.
  Missing, malformed or unreadable settings disable lookups; message flags cannot opt in. Requests have
  time/size/concurrency limits and an in-memory cache. Opting out aborts active requests and clears that cache;
  it cannot retract requests already sent. The setting is stored locally on this device.
- CSP restricts extension scripts to packaged code and network connections to the listed feed/DNS hosts.

## Scoring
`lib/analyzer.js` — start at 100, subtract per finding; any *critical* finding caps the score at 15.
- 80–100 green "No strong warning signs detected" · 50–79 amber "Be careful with this email" · <50 red "Strong warning signs detected". Incomplete coverage never receives a green status.

| Check | Weight |
|---|---|
| Link / sender domain on an active blocklist | 60 (critical) |
| `javascript:` / `data:` link | 40 (critical) |
| Brand display name from consumer webmail (gmail/outlook…) | 45 (critical) |
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

## "Real company domains"
There is no universal registry. `data/brands.json` is a hand-curated seed (banks, carriers, French public
services, big tech). It is incomplete and domain matching is heuristic. Consumer mailboxes do not establish provider affiliation,
while ordinary provider links remain recognized. Each anchor is checked even when another link shares its host.

## Known limitations of this v0.1
- Selectors for all four clients are undocumented and change occasionally; use `probe()` (above) to fix them.
- Proton renders the body in a sandboxed same-origin iframe; the adapter reads `iframe.contentDocument`.
  An inaccessible/loading body is reported as unavailable; no access restrictions are bypassed.
- Outlook's aria-labels are localised; EN and FR are covered, add your locale to `outlook.js` if needed.
- Reply-To is not visible in Gmail's DOM without "Show details"; hook it there if you need it.
- Registrable-domain logic uses a short embedded suffix list, not the full Public Suffix List. This can
  misclassify uncommon suffixes. DNS root dots are canonicalized both in cached feeds and scanned URLs.
- Summaries inspect up to 5,000 DOM nodes, 100 links, 200 images, 50 attachments and 20,000 visible-text
  characters. URLs are limited to 2,048 characters; overlong URLs are omitted rather than sliced into a
  different destination. Hidden evidence shows up to 20 excerpts of 240 characters. Findings are capped
  at 200. Reached extraction limits are disclosed; unsupported content can still escape heuristic detection.
- Each feed read is limited to 4 MB / 100,000 entries and 10 seconds; a larger feed remains unavailable
  or falls back to prior data. DNS reads are limited to 32 KB / 5 seconds / four concurrent domains, with
  up to 128 cached results for one hour. These are coverage limits, not guarantees of detection.

## Browser verification
`npm test` covers analysis, input/caller boundaries, feed handling, DNS consent and toolbar races.
The independent browser fixtures need Playwright and Chromium installed outside the extension:

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs CHROMIUM_PATH=/absolute/path/to/chromium node tests-browser/run.mjs
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs CHROMIUM_PATH=/absolute/path/to/chromium node tests-browser/extension.mjs
```

Set `SCREENSHOT_DIR` to an output directory to save UI captures. The first suite uses synthetic mail DOMs
for all four adapters. The second loads the real extension in a temporary browser profile, uses synthetic
Gmail content and mocks feed/DNS responses after worker startup. Initial installation can trigger public
feed downloads; no real mailbox is opened. It tests the popup, packaged catalogue/CSP, consent and refresh
failure behavior. These tests do not establish compatibility with current live account DOMs, every locale,
or every Chrome/Edge/Brave version. Validate those before release.
