import assert from "node:assert/strict";
import test from "node:test";
import { validateEmail, callerKind } from "../lib/messages.js";
import { FEEDS, cleanEntries } from "../lib/feeds.js";
import { fetchText } from "../lib/network.js";

const runtime = { id: "test", getURL: path => `chrome-extension://test/${path}` };
const mail = { id: "test", url: "https://mail.google.com/mail/", tab: { id: 1 }, frameId: 0 };
test("worker caller validation requires our extension and a supported top-level mail page", () => {
  assert.equal(callerKind(mail, runtime), "mail");
  assert.equal(callerKind({ id: "test", url: runtime.getURL("popup/popup.html") }, runtime), "popup");
  for (const change of [{ id: "other" }, { frameId: 1 }, { tab: undefined }, { url: "https://mail.google.com.evil.test/" }, { url: "http://mail.google.com/" }, { url: "https://mail.yahoo.com.evil.test/" }]) assert.equal(callerKind({ ...mail, ...change }, runtime), null);
});
test("summary validation rejects malformed or oversized input and strips untrusted options", () => {
  for (const input of [null, [], { links: Array(101).fill({}) }, { text: "x".repeat(20001) }, { sender: [] }, { links: [{ href: "x".repeat(2049) }] }, { forms: -1 }, { images: [{ width: 1.1 }] }, { coverage: { truncated: "no" } }]) assert.throws(() => validateEmail(input));
  const valid = validateEmail({ links: [{ href: "javascript:alert(1)", hidden: true }], dmarc: "reject", settingsDmarc: true });
  assert.equal(valid.links[0].href, "javascript:alert(1)");
  assert.equal(valid.dmarc, undefined);
});
test("feed ingestion canonicalizes root dots, rejects empty/error documents and bounds entries", () => {
  const domain = FEEDS.find(f => f.kind === "domain"), url = FEEDS.find(f => f.kind === "url");
  assert.deepEqual(cleanEntries(domain, ["BAD.example.", "bad.example。", "<html>", "a b", "https://bad.example/path"]), ["bad.example"]);
  assert.deepEqual(cleanEntries(url, ["https://docs.google.com./bad", "https://docs.google.com。/bad"]), ["https://docs.google.com/bad"]);
  for (const entries of [[], ["<html>Bad gateway</html>"], Array(100001).fill("bad.test")]) assert.throws(() => cleanEntries(domain, entries));
});
test("network reads reject HTTP errors and oversized bodies; use no credentials or redirects", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async (_, options) => {
      assert.equal(options.credentials, "omit"); assert.equal(options.redirect, "error");
      return new Response("abcdef");
    };
    await assert.rejects(fetchText("https://feed.test", { maxBytes: 5 }), /size/);
    globalThis.fetch = async () => new Response("x", { status: 503 });
    await assert.rejects(fetchText("https://feed.test"), /HTTP 503/);
    globalThis.fetch = (_, { signal }) => new Promise((_, reject) => signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
    await assert.rejects(fetchText("https://feed.test", { timeout: 10 }), /aborted/);
  } finally { globalThis.fetch = original; }
});
