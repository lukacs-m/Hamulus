import assert from "node:assert/strict";
import { readFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { analyse } from "../lib/analyzer.js";
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("../", import.meta.url));
const screenshotDir = process.env.SCREENSHOT_DIR;
if (screenshotDir) await mkdir(screenshotDir, { recursive: true });
const brands = JSON.parse(await readFile(new URL("../data/brands.json", import.meta.url)));
const ctx = { brands, blocklist: { urls: new Set(), domains: new Set(["bad.test"]) } };
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH });
const failures = [];
async function check(name, fn) {
  try { await fn(); console.log(`PASS ${name}`); } catch (error) { failures.push(name); console.error(`FAIL ${name}`, error); }
}
async function fixture(html, adapter) {
  const page = await browser.newPage();
  await page.route("**/*", route => route.abort());
  await page.setContent(html);
  await page.evaluate(() => {
    window.calls = []; window.roots = [];
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(options) { const root = attach.call(this, options); window.roots.push(root); return root; };
    window.chrome = { runtime: { sendMessage: (message, callback) => window.calls.push({ message, callback }) } };
  });
  await page.addScriptTag({ path: `${root}lib/shared.js` });
  await page.addScriptTag({ path: `${root}content/shared.js` });
  if (adapter) await page.addScriptTag({ path: `${root}content/${adapter}.js` });
  else await page.evaluate(() => window.__emailShield.init({ message: "article", body: ".body", sender: msg => ({ name: msg.dataset.name || "Alex", email: msg.dataset.email || "alex@example.test" }), subject: msg => msg.dataset.subject || "Fixture", attachments: () => [] }));
  return page;
}
const summary = (page, index = 0) => page.evaluate(index => calls[index].message.email, index);
const banner = page => page.evaluate(() => roots.filter(r => r.host.isConnected).map(r => r.textContent).join("\n"));
async function answer(page, index = 0, override) {
  const email = await summary(page, index);
  const result = override || { ...analyse(email, ctx), status: "complete", sender: email.sender, subject: email.subject };
  await page.evaluate(({ index, result }) => calls[index].callback(result), { index, result });
  return result;
}
try {
  await check("relative links, equivalent URL forms, hidden ancestors and inert evidence", async () => {
    const page = await fixture(`<base href="https://bad.test/folder/message"><article><div class="body"><a href="../pay">https://paypal.com</a><a href="//bad.test/root">second</a><a href="?q=1">query</a><a href="#part">fragment</a><div style="display:none">parent text <span>hidden child</span><a href="/hidden">hidden link</a></div><p>&lt;img src=x onerror=alert(1)&gt;\u202E</p></div></article>`);
    const email = await summary(page);
    assert.deepEqual(email.links.map(l => l.href), ["https://bad.test/pay", "https://bad.test/root", "https://bad.test/folder/message?q=1", "https://bad.test/folder/message#part", "https://bad.test/hidden"]);
    assert.equal(email.hiddenTextChars, "parent texthidden childhidden link".length);
    assert.ok(email.links.at(-1).hidden);
    await answer(page);
    const text = await banner(page);
    assert.match(text, /false positives and false negatives/);
    assert.match(text, /Actual destination URL: https:\/\/bad.test\/pay/);
    assert.match(text, /display: none/);
    assert.equal(await page.evaluate(() => roots.at(-1).querySelectorAll("a, img, iframe, script").length), 0);
    await page.evaluate(() => roots.at(-1).querySelector("summary").focus());
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => roots.at(-1).querySelector("details").open), true);
    if (screenshotDir) await page.screenshot({ path: `${screenshotDir}/banner-evidence.png`, fullPage: true });
    await page.close();
  });
  await check("reused bodies discard stale responses and replace green banners immediately", async () => {
    const page = await fixture(`<article><div class="body">First message</div></article>`);
    await page.locator(".body").evaluate(el => { el.textContent = "New message"; });
    await page.waitForFunction(() => calls.length === 2);
    await answer(page, 1, { status: "complete", score: 15, level: "danger", findings: [], coverage: {} });
    await answer(page, 0, { status: "complete", score: 100, level: "safe", findings: [], coverage: {} });
    assert.match(await banner(page), /Strong warning signs/);
    await page.locator(".body").evaluate(el => { el.innerHTML = "<p>Third message</p>"; });
    await page.waitForFunction(() => calls.length === 3);
    assert.match(await banner(page), /Scanning email/);
    assert.doesNotMatch(await banner(page), /100\/100/);
    await answer(page, 2);
    assert.equal(await page.locator("[data-email-shield]").count(), 1);
    await page.close();
  });
  await check("failed scans retry and concurrent messages retain separate banners", async () => {
    const page = await fixture(`<article><div class="body">First</div></article><article><div class="body">Second</div></article>`);
    await answer(page, 0, { status: "error", error: "unavailable" });
    await answer(page, 1);
    await page.evaluate(() => roots.find(r => r.host.isConnected && r.querySelector("button")).querySelector("button").click());
    await page.waitForFunction(() => calls.length === 3);
    await answer(page, 2);
    assert.equal(await page.locator("[data-email-shield]").count(), 2);
    assert.doesNotMatch(await banner(page), /Scan unavailable/);
    await page.close();
  });
  await check("bounded large summaries report omitted content and visible bidi markers", async () => {
    const page = await fixture(`<article><div class="body"><div style="display:none">${"x".repeat(1000)}</div>${Array.from({ length: 110 }, () => "<a href=\"https://other.test\">PayPal\u202E</a>").join("")}</div></article>`);
    const email = await summary(page);
    assert.equal(email.links.length, 100);
    assert.equal(email.coverage.truncated, true);
    assert.equal(email.hiddenText.excerpts[0].text.length, 240);
    assert.equal(email.hiddenText.truncated, true);
    const result = await answer(page);
    assert.ok(result.linkEvidence.length <= 100);
    assert.match(await banner(page), /\[U\+202E\]/);
    assert.match(await banner(page), /excerpts are truncated/);
    await page.close();
  });
  await check("all four adapters extract sender and text-only bodies; Proton rescans iframe replacement", async () => {
    const cases = {
      gmail: `<h2 class=hP>Subject</h2><div data-message-id=1><span class=gD name=Alex email=alex@example.test></span><div class=a3s>Text only</div></div>`,
      yahoo: `<div data-test-id=message-view><div data-test-id=message-from><span title=alex@example.test>Alex</span></div><div data-test-id=message-subject>Subject</div><div data-test-id=message-body>Text only</div></div>`,
      outlook: `<div data-app-section=ItemContainer><div data-app-section=ItemHeader><span title=alex@example.test>Alex</span></div><div role=heading aria-level=2>Subject</div><div id=UniqueMessageBody1>Text only</div></div>`,
      proton: `<div data-testid=message-view><div data-testid="recipients:sender"><span title=alex@example.test>Alex</span></div><div data-testid="message-header:subject">Subject</div><iframe title="Email content" srcdoc="<base href=https://bad.test/parent/><a href=../pay>Pay</a>"></iframe></div>`,
    };
    for (const [adapter, html] of Object.entries(cases)) {
      const page = await fixture(html, adapter);
      await page.waitForFunction(() => calls.length > 0);
      const email = await summary(page);
      assert.equal(email.sender.email, "alex@example.test", adapter);
      assert.equal(email.subject, "Subject", adapter);
      if (adapter === "proton") assert.equal(email.links[0].href, "https://bad.test/pay");
      await answer(page);
      if (adapter === "proton") {
        await page.locator("iframe").evaluate(el => { el.srcdoc = "<p>Replacement message</p>"; });
        await page.waitForFunction(() => calls.length === 2);
        await answer(page, 1);
        assert.equal(await page.locator("[data-email-shield]").count(), 1);
      }
      assert.equal(await page.locator("[data-email-shield]").count(), 1, adapter);
      await page.close();
    }
  });
  await check("missing and inaccessible bodies clear previous results", async () => {
    const page = await fixture(`<article><p>Header</p><div class="body">First</div></article>`);
    await answer(page);
    await page.locator(".body").evaluate(el => el.remove());
    await page.waitForFunction(() => roots.some(r => r.host.isConnected && r.textContent.includes("Message body is unavailable")));
    assert.doesNotMatch(await banner(page), /100\/100/);
    assert.equal((await summary(page, 1)).coverage.unavailable, true);
    await page.locator("article").evaluate(el => { const body = document.createElement("div"); body.className = "body"; body.textContent = "Returned"; el.append(body); });
    await page.waitForFunction(() => calls.length === 3);
    await answer(page, 2);
    await page.close();
  });
} finally { await browser.close(); }
if (failures.length) process.exitCode = 1;
