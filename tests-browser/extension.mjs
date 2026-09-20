import assert from "node:assert/strict";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FEEDS } from "../lib/feeds.js";
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("../", import.meta.url));
const profile = await mkdtemp(join(tmpdir(), "hamulus-smoke-"));
const output = process.env.SCREENSHOT_DIR;
if (output) await mkdir(output, { recursive: true });
let context;
try {
  context = await chromium.launchPersistentContext(profile, { headless: true, executablePath: process.env.CHROMIUM_PATH, args: [`--disable-extensions-except=${root}`, `--load-extension=${root}`] });
  let worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  const id = new URL(worker.url()).host;
  await worker.evaluate(async feeds => {
    self.requests = [];
    const nativeFetch = self.fetch;
    self.fetch = async (url, options) => {
      self.requests.push(String(url));
      if (String(url).startsWith("chrome-extension:")) return nativeFetch(url, options);
      if (String(url).includes("dns-query")) return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: "v=DMARC1; p=reject" }] }));
      return new Response("<html>Feed temporarily unavailable</html>");
    };
    await chrome.storage.local.clear();
    await chrome.storage.local.set(Object.fromEntries(feeds.map(feed => [`feed:${feed.id}`, { entries: [feed.kind === "url" ? "https://bad.test/" : "bad.test"], updatedAt: Date.now() }])));
    await chrome.storage.session.clear();
  }, FEEDS.map(({ id, kind }) => ({ id, kind })));
  const page = await context.newPage();
  await page.route("https://mail.google.com/**", route => route.fulfill({ contentType: "text/html", body: `<html><head><title>Mail fixture</title></head><body><h2 class=hP>Fixture subject</h2><div data-message-id=fixture><span class=gD name=Alex email=alex@example.test>Alex</span><div class=a3s>Hello from a synthetic message.</div></div></body></html>` }));
  await page.goto("https://mail.google.com/mail/u/0/");
  await page.waitForSelector("[data-email-shield]");
  await page.waitForTimeout(300);
  let result = await worker.evaluate(async () => (await chrome.storage.session.get("lastResult")).lastResult);
  assert.equal(result.status, "complete");
  assert.equal(result.coverage.dns, "disabled");
  assert.equal(result.subject, "Fixture subject");
  assert.equal((await worker.evaluate(() => requests.filter(url => url.includes("dns-query")))).length, 0);
  const brandLoad = await worker.evaluate(async () => { const response = await fetch(chrome.runtime.getURL("data/brands.json")); return { status: response.status, count: Object.keys(await response.json()).length }; });
  assert.equal(brandLoad.status, 200);
  assert.ok(brandLoad.count > 0);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${id}/popup/popup.html`);
  await popup.waitForFunction(() => !document.getElementById("dns").disabled);
  assert.equal(await popup.locator("#dns").isChecked(), false);
  assert.equal(await popup.locator("#icon").getAttribute("alt"), "");
  assert.match(await popup.locator("#warning").textContent(), /false positives and false negatives/);
  const visualCases = [
    ["safe", { status: "complete", score: 100, level: "safe", findings: [], coverage: { notes: [] } }],
    ["caution", { status: "complete", score: 60, level: "caution", findings: [{ title: "Link text and destination disagree", detail: "Displayed text names paypal.com; destination is other.test." }], linkEvidence: [{ text: "PayPal\u202E <img src=x>", href: "https://other.test/" + "long/".repeat(30), hostname: "other.test", reasons: ["Brand text differs from destination"] }], coverage: { notes: [] } }],
    ["danger", { status: "complete", score: 15, level: "danger", findings: [{ title: "Link is on a phishing blocklist", detail: "bad.test matched a locally stored feed." }], coverage: { notes: [] } }],
    ["incomplete", { status: "complete", score: 100, level: "safe", findings: [], coverage: { incomplete: true, notes: ["Blocklist coverage is incomplete. Cached entries were still checked."] } }],
    ["error", { status: "error", error: "The scan could not be completed. Retry from the email banner." }],
    ["scanning", { status: "scanning" }],
  ];
  for (const [name, state] of visualCases) {
    await worker.evaluate(async state => chrome.storage.session.set({ lastResult: { ...state, subject: "Fixture subject", sender: { email: "alex@example.test" }, analysedAt: Date.now() } }), state);
    await popup.waitForFunction(expected => document.getElementById("icon").getAttribute("src").includes(expected), ["incomplete", "error", "scanning"].includes(name) ? "neutral-128" : `${name}-128`);
    if (name === "caution") {
      await popup.locator("summary").click();
      assert.equal(await popup.locator("#evidence a, #evidence img").count(), 0);
      assert.match(await popup.locator("#evidence").textContent(), /\[U\+202E\]/);
    }
    assert.equal(await popup.evaluate(() => document.body.scrollWidth <= 392), true);
    if (output) await popup.screenshot({ path: `${output}/popup-${name}.png`, fullPage: true });
  }
  await popup.locator("#dns").check();
  await popup.waitForFunction(() => document.getElementById("settings-status").textContent.includes("Saved"));
  await page.locator(".a3s").evaluate(el => { el.textContent = "Changed fixture to trigger an opted-in scan."; });
  await page.waitForTimeout(500);
  result = await worker.evaluate(async () => (await chrome.storage.session.get("lastResult")).lastResult);
  assert.equal(result.coverage.dns, "reject");
  assert.equal((await worker.evaluate(() => requests.filter(url => url.includes("dns-query")))).length, 1);
  await popup.locator("#dns").uncheck();
  await popup.waitForFunction(() => document.getElementById("settings-status").textContent.includes("will not send"));
  await page.locator(".a3s").evaluate(el => el.remove());
  await page.waitForTimeout(300);
  assert.equal((await worker.evaluate(async () => (await chrome.storage.session.get("lastResult")).lastResult)).status, "error");
  await popup.locator("#sync").click();
  await popup.waitForFunction(() => document.getElementById("feed-status").textContent.includes("Refresh finished"));
  assert.match(await popup.locator("#feeds").textContent(), /refresh failed/);
  console.log("PASS installed extension: content script, packaged catalogue/CSP, popup six states, DNS opt-in/out, feed failure recovery");
} finally {
  await context?.close();
  await rm(profile, { recursive: true, force: true });
}
