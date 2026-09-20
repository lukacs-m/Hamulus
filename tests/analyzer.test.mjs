import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { analyse } from "../lib/analyzer.js";
import { normaliseUrl } from "../lib/feeds.js";

const brands = JSON.parse(await readFile(new URL("../data/brands.json", import.meta.url)));
const context = (domains = [], urls = []) => ({ brands, blocklist: { domains: new Set(domains), urls: new Set(urls) } });
const ids = (email, ctx = context()) => analyse(email, ctx).findings.map(f => f.id);

test("every anchor is checked even after a benign link to the same host", () => {
  const bad = { href: "https://other.example/second", text: "https://paypal.com", hidden: true };
  const first = { href: "https://other.example/first", text: "First" };
  for (const links of [[first, bad], [bad, first]]) {
    const found = ids({ links });
    assert.ok(found.includes("LINK_TEXT_MISMATCH"));
    assert.ok(found.includes("LINK_HIDDEN"));
  }
});

test("consumer mailboxes cannot establish provider-brand affiliation", () => {
  for (const [name, domain] of [["Google", "gmail.com"], ["Google", "googlemail.com"], ["Microsoft", "outlook.com"], ["Microsoft", "hotmail.com"]]) {
    assert.ok(ids({ sender: { name, email: `fraud@${domain}` } }).includes("SENDER_FREEMAIL_BRAND"), domain);
  }
  assert.deepEqual(ids({ sender: { name: "Google", email: "info@google.com" } }), []);
  assert.deepEqual(ids({ sender: { name: "Alex", email: "alex@gmail.com" } }), []);
  assert.ok(!ids({ links: [{ href: "https://gmail.com/", text: "Google" }] }).includes("LINK_BRAND_MISMATCH"));
});

test("DNS root-dot spellings match hostname and exact-URL blocklists", () => {
  for (const dot of [".", "。"] ) {
    assert.ok(ids({ links: [{ href: `https://evil.bad.example${dot}/pay` }] }, context(["evil.bad.example"])).includes("LINK_BLOCKLISTED"));
    assert.equal(normaliseUrl(`https://docs.google.com${dot}/bad`), normaliseUrl("https://docs.google.com/bad"));
  }
});
