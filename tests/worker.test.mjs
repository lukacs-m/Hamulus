import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { FEEDS } from "../lib/feeds.js";
import { scoreTitle } from "../lib/icons.js";
const brands = await readFile(new URL("../data/brands.json", import.meta.url), "utf8");
let sequence = 0;
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
async function harness({ dns, entries, updatedAt = Date.now(), localGet, network, session = {}, sessionGet } = {}) {
  let listener, changed;
  const stored = Object.fromEntries(FEEDS.map(feed => [`feed:${feed.id}`, { entries: entries || [feed.kind === "url" ? "https://bad.test/" : "bad.test"], updatedAt }]));
  if (dns !== undefined) stored.dnsEnabled = dns;
  const calls = [], results = [], icons = [];
  const mail = { id: "test", url: "https://mail.google.com/mail/", tab: { id: 1 }, frameId: 0, documentId: "doc-1" };
  const popup = { id: "test", url: "chrome-extension://test/popup/popup.html" };
  globalThis.chrome = {
    runtime: { id: "test", getURL: path => `chrome-extension://test/${path}`, onMessage: { addListener: fn => { listener = fn; } }, onInstalled: { addListener() {} }, onStartup: { addListener() {} } },
    alarms: { onAlarm: { addListener() {} }, create() {} },
    storage: { onChanged: { addListener: fn => { changed = fn; } }, local: {
      get: async key => { if (localGet) await localGet(key, stored); return stored; },
      set: async values => { Object.assign(stored, values); changed(Object.fromEntries(Object.entries(values).map(([k,v]) => [k, { newValue: v }])), "local"); },
    }, session: {
      get: async () => { if (sessionGet) await sessionGet(); return session; },
      set: async value => { Object.assign(session, value); results.push(value.lastResult); },
    } },
    action: { setIcon: async ({ path }) => { icons.push(path[32]); }, setTitle: async () => {} },
  };
  globalThis.fetch = async (url, options) => {
    calls.push(String(url));
    if (String(url).startsWith("chrome-extension:")) return new Response(brands);
    return network ? network(url, options) : new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: "v=DMARC1; p=reject" }] }));
  };
  await import(`../background.js?case=${sequence++}`);
  return {
    stored, calls, results, icons, session, mail,
    send: (message, sender = popup) => new Promise(resolve => listener(message, sender, resolve)),
    scan: (email = {}, sender = mail) => new Promise(resolve => listener({ type: "ANALYSE", settingsDmarc: true, email: { sender: { email: "person@sender.test" }, ...email } }, sender, resolve)),
  };
}
test("DNS is off for missing, false, malformed or unreadable saved settings despite caller opt-in", async () => {
  for (const dns of [undefined, false, "true", {}]) {
    const h = await harness({ dns });
    const result = await h.scan();
    assert.equal(result.coverage.dns, "disabled");
    assert.equal(h.calls.filter(url => url.includes("dns-query")).length, 0);
    await tick();
  }
  const h = await harness({ dns: true, localGet: key => { if (key === "dnsEnabled") throw new Error("storage unavailable"); } });
  assert.equal((await h.scan()).coverage.dns, "disabled");
});
test("saved opt-in enables bounded cached lookup; opt-out cancels active work and clears cache", async () => {
  let abortSeen = false;
  const h = await harness({ network: (url, { signal }) => {
    if (String(url).includes("pending.test")) return new Promise((_, reject) => signal.addEventListener("abort", () => { abortSeen = true; reject(new Error("aborted")); }));
    return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: "v=DMARC1; p=reject" }] }));
  } });
  assert.equal((await h.send({ type: "SET_DNS", enabled: true })).dnsEnabled, true);
  assert.equal((await h.scan()).coverage.dns, "reject");
  assert.equal((await h.scan()).coverage.dns, "reject");
  assert.equal(h.calls.filter(url => url.includes("dns-query")).length, 1);
  const pending = h.scan({ sender: { email: "a@pending.test" } });
  await tick();
  await h.send({ type: "SET_DNS", enabled: false });
  await pending;
  assert.ok(abortSeen);
  assert.equal((await h.scan()).coverage.dns, "disabled");
  await h.send({ type: "SET_DNS", enabled: true });
  await h.scan();
  assert.equal(h.calls.filter(url => url.includes("sender.test")).length, 2);
});
test("consent is checked after slow dependencies before any sender-domain request", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = await harness({ dns: true, localGet: key => Array.isArray(key) ? gate : undefined });
  const pending = h.scan();
  await h.send({ type: "SET_DNS", enabled: false });
  release();
  assert.equal((await pending).coverage.dns, "disabled");
  assert.equal(h.calls.filter(url => url.includes("dns-query")).length, 0);
});
test("cached feeds normalize root dots, preserve shared-host exclusions and retain last good data on refresh failure", async () => {
  const h = await harness({ network: () => new Response("<html>Service unavailable</html>") });
  await chrome.storage.local.set({ "feed:urlhaus": { entries: ["https://docs.google.com./bad"], updatedAt: Date.now() } });
  const bad = await h.scan({ links: [{ href: "https://docs.google.com/bad" }] });
  assert.ok(bad.findings.some(f => f.id === "LINK_BLOCKLISTED"));
  const good = await h.scan({ links: [{ href: "https://docs.google.com/good" }] });
  assert.ok(!good.findings.some(f => f.id === "LINK_BLOCKLISTED"));
  const meta = await h.send({ type: "SYNC_NOW" });
  assert.equal(meta.urlhaus.state, "refresh failed");
  assert.deepEqual(h.stored["feed:urlhaus"].entries, ["https://docs.google.com./bad"]);
  assert.equal((await h.scan()).coverage.incomplete, true);
});
test("unavailable and stale coverage is explicit; bad messages cannot leave an old green result", async () => {
  const h = await harness({ entries: [], updatedAt: 1 });
  assert.equal((await h.scan()).coverage.incomplete, true);
  const invalid = await h.scan({ links: Array(101).fill({}) });
  assert.equal(invalid.status, "error");
  await tick();
  assert.equal(h.results.at(-1).status, "error");
  assert.ok((await h.scan({}, { id: "foreign", url: "https://mail.google.com" })).error);
  assert.ok((await h.send({ type: "SET_DNS", enabled: "true" })).error);
  const stale = await harness({ updatedAt: 1 });
  assert.equal(Object.values((await stale.scan()).coverage.feeds)[0].state, "stale");
});

test("an unavailable replacement body clears shared success without running DNS or analysis", async () => {
  const h = await harness({ dns: true });
  const result = await h.scan({ coverage: { unavailable: true } });
  assert.equal(result.status, "error");
  await tick();
  assert.equal(h.results.at(-1).status, "error");
  assert.equal(h.calls.filter(url => url.includes("dns-query")).length, 0);
});

test("DMARC policy parsing distinguishes p from sp and handles quoted TXT chunks", async () => {
  const h = await harness({ dns: true, network: () => new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: "\"v=DMARC1; sp=none; \"\"p=reject;\"" }] })) });
  assert.equal((await h.scan()).coverage.dns, "reject");
});

test("enabled DNS requests are capped across concurrent sender domains", async () => {
  const releases = [];
  const h = await harness({ dns: true, network: () => new Promise(resolve => releases.push(() => resolve(new Response(JSON.stringify({ Status: 0, Answer: [] }))))) });
  const scans = Array.from({ length: 8 }, (_, index) => h.scan({ sender: { email: `person@sender${index}.test` } }));
  await tick();
  assert.equal(h.calls.filter(url => url.includes("dns-query")).length, 4);
  releases.forEach(release => release());
  const results = await Promise.all(scans);
  assert.equal(results.filter(result => result.coverage.dns === "unknown").length, 4);
});

test("an unreadable sibling cannot supersede a result it never published", async () => {
  const h = await harness();
  const [good, sibling] = await Promise.all([
    h.scan({ messageId: "page:1", links: [{ href: "https://bad.test/pay", text: "bad.test" }] }),
    h.scan({ messageId: "page:2", coverage: { unavailable: true } }),
  ]);
  assert.equal(good.level, "danger");
  assert.equal(sibling.status, "error");
  await tick(); await tick();
  assert.equal(h.results.at(-1).level, "danger");

  assert.equal((await h.scan({ messageId: "othertab:1", text: "Hello" })).status, "complete");
  await tick(); await tick();
  assert.equal((await h.scan({ messageId: "page:1", coverage: { unavailable: true } })).status, "error");
  await tick(); await tick();
  assert.equal(h.results.at(-1).status, "complete");

  assert.equal((await h.scan({ messageId: "othertab:1", coverage: { unavailable: true } })).status, "error");
  await tick(); await tick();
  assert.equal(h.results.at(-1).status, "error");
});

test("an unread body is assessed as incomplete metadata, never green and never with DNS", async () => {
  const h = await harness({ dns: true });
  const result = await h.scan({ messageId: "page:1", attachments: ["invoice.pdf"], coverage: { bodyUnavailable: true } });
  assert.equal(result.status, "complete");
  assert.equal(result.coverage.incomplete, true);
  assert.equal(result.coverage.dns, "skipped");
  assert.equal(h.calls.filter(url => url.includes("dns-query")).length, 0);
  assert.equal(globalThis.Hamulus.iconLevel(result), "neutral");
  assert.match(globalThis.Hamulus.heading(result), /Incomplete assessment/);
  assert.ok(result.coverage.notes.some(note => /body could not be read/.test(note)));

  const risky = await h.scan({ messageId: "page:1", attachments: ["invoice.pdf.html"], coverage: { bodyUnavailable: true } });
  assert.ok(risky.findings.some(f => f.id === "RISKY_ATTACHMENT"));
  assert.equal(risky.coverage.incomplete, true);
});

test("the owning message still clears shared success after a worker restart", async () => {
  const first = await harness();
  await first.scan({ messageId: "m1", text: "Hello" });
  await tick(); await tick();
  assert.equal(first.session.lastResult.status, "complete");

  const restarted = await harness({ session: first.session });
  assert.equal((await restarted.scan({ messageId: "m1", coverage: { unavailable: true } })).status, "error");
  await tick(); await tick();
  assert.equal(restarted.session.lastResult.status, "error");
  assert.equal(restarted.icons.at(-1), "icons/neutral-32.png");
});

test("after a restart only the owning tab, document or message may erase the shared result", async () => {
  const first = await harness();
  await first.scan({ messageId: "m1", text: "Hello" });
  await tick(); await tick();

  const sibling = await harness({ session: first.session });
  assert.equal((await sibling.scan({ messageId: "m2", coverage: { unavailable: true } })).status, "error");
  await tick(); await tick();
  assert.equal(sibling.session.lastResult.status, "complete");

  const otherTab = await harness({ session: first.session });
  await otherTab.scan({ messageId: "m1", coverage: { unavailable: true } }, { ...otherTab.mail, tab: { id: 2 }, documentId: "doc-9" });
  await tick(); await tick();
  assert.equal(otherTab.session.lastResult.status, "complete");

  const reloaded = await harness({ session: first.session });
  await reloaded.scan({ messageId: "fresh-page:1", coverage: { unavailable: true } }, { ...reloaded.mail, documentId: "doc-2" });
  await tick(); await tick();
  assert.equal(reloaded.session.lastResult.status, "error");
});

test("unreadable state with no recoverable owner clears rather than keeping a stale result", async () => {
  const orphaned = { lastResult: { status: "complete", score: 100, level: "safe", coverage: {} } };
  const h = await harness({ session: orphaned });
  await h.scan({ messageId: "m1", coverage: { unavailable: true } });
  await tick(); await tick();
  assert.equal(h.session.lastResult.status, "error");
});

test("competing first requests keep their order while ownership is still being restored", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const seeded = { lastResult: { status: "complete", score: 100, level: "safe", coverage: {} }, lastOwner: { tab: 1, document: "doc-1", message: "m1" } };
  const h = await harness({ session: seeded, sessionGet: () => gate });
  const readable = h.scan({ messageId: "m2", text: "Hello" });
  const stranger = h.scan({ messageId: "m3", coverage: { unavailable: true } });
  release();
  const [good, bad] = await Promise.all([readable, stranger]);
  assert.equal(good.status, "complete");
  assert.equal(bad.status, "error");
  await tick(); await tick(); await tick();
  assert.equal(h.session.lastResult.status, "complete");
  assert.equal(h.session.lastOwner.message, "m2");
});

test("a message whose body was never read is never given a numeric score", async () => {
  const h = await harness();
  const harmless = await h.scan({ messageId: "m1", attachments: ["invoice.pdf"], coverage: { bodyUnavailable: true } });
  assert.equal(harmless.coverage.bodyUnavailable, true);
  assert.equal(globalThis.Hamulus.scoreLabel(harmless), null);
  assert.match(scoreTitle(harmless), /Not scored/);
  assert.doesNotMatch(scoreTitle(harmless), /100\/100/);

  const risky = await h.scan({ messageId: "m1", attachments: ["invoice.pdf.html"], coverage: { bodyUnavailable: true } });
  assert.ok(risky.findings.some(f => f.id === "RISKY_ATTACHMENT"));
  assert.equal(globalThis.Hamulus.scoreLabel(risky), null);
  assert.match(globalThis.Hamulus.heading(risky), /Incomplete assessment - be careful with this email/);

  const readable = await h.scan({ messageId: "m1", text: "Now the body is here" });
  assert.equal(readable.coverage.bodyUnavailable, false);
  assert.equal(globalThis.Hamulus.scoreLabel(readable), `${readable.score}/100`);
  assert.match(scoreTitle(readable), new RegExp(`${readable.score}/100`));
});

test("an invalidation supersedes scans requested before it but not ones requested after", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = await harness({ localGet: key => Array.isArray(key) ? gate : undefined });
  const inflight = h.scan({ messageId: "m1", text: "Hello" });
  await tick();
  await h.scan({ messageId: "m1", coverage: { unavailable: true } });
  await tick(); await tick();
  assert.equal(h.session.lastResult.status, "error");
  release();
  await inflight;
  await tick(); await tick();
  assert.equal(h.session.lastResult.status, "error");

  const later = await harness();
  const pending = later.scan({ messageId: "m1", text: "Hello" });
  await later.scan({ messageId: "m1", coverage: { unavailable: true } });
  await tick();
  assert.equal((await later.scan({ messageId: "m1", text: "Body is back" })).status, "complete");
  await pending;
  await tick(); await tick();
  assert.equal(later.session.lastResult.status, "complete");
});
