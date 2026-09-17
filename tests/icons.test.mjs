import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

let onMessage;
let stored = {};
let action = {};
globalThis.chrome = {
  runtime: {
    onInstalled: { addListener() {} },
    onStartup: { addListener() {} },
    onMessage: { addListener(listener) { onMessage = listener; } },
    getURL: (path) => new URL(`../${path}`, import.meta.url).href,
  },
  alarms: { onAlarm: { addListener() {} } },
  storage: {
    local: { get: async () => ({}) },
    session: { set: async (value) => { stored = value; } },
  },
  action: {
    setIcon: async ({ path }) => { action.path = path; },
    setTitle: async ({ title }) => { action.title = title; },
  },
};
globalThis.fetch = async (url) => ({ json: async () => JSON.parse(await readFile(new URL(url), "utf8")) });
await import("../background.js");

test("analysis updates the toolbar and popup result across score boundaries", async () => {
  const urgency = "verify your account within 24 hours";
  const httpLink = { href: "http://example.com/", text: "example.com" };
  const cases = [
    { score: 100, level: "safe", email: {} },
    { score: 80, level: "safe", email: { text: `${urgency} immediate action` } },
    { score: 79, level: "caution", email: { text: urgency, links: [httpLink] } },
    { score: 50, level: "caution", email: { attachments: ["file.exe"], links: [{ href: "https://192.0.2.1/" }] } },
    { score: 49, level: "danger", email: { attachments: ["file.exe"], text: urgency, links: [httpLink] } },
    { score: 15, level: "danger", email: { links: [{ href: "javascript:alert(1)" }] } },
    { score: 100, level: "safe", email: {} },
  ];
  for (const { score, level, email } of cases) {
    const result = await new Promise((resolve) => {
      assert.equal(onMessage({ type: "ANALYSE", settingsDmarc: false, email }, {}, resolve), true);
    });
    assert.equal(result.error, undefined);
    assert.equal(result.score, score);
    assert.equal(result.level, level);
    assert.equal(stored.lastResult.score, score);
    assert.match(action.title, new RegExp(`Hamulus - Latest email: ${score}/100`));
    for (const [size, path] of Object.entries(action.path)) {
      assert.equal(path, `icons/${level}-${size}.png`);
      const png = await readFile(new URL(`../${path}`, import.meta.url));
      assert.equal(png.subarray(1, 4).toString(), "PNG");
      assert.equal(png.readUInt32BE(16), Number(size));
      assert.equal(png.readUInt32BE(20), Number(size));
    }
  }
});

test("installation uses Hamulus branding and neutral PNG icons", async () => {
  const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url)));
  assert.equal(manifest.name, "Hamulus");
  assert.equal(manifest.action.default_title, "Hamulus");
  assert.deepEqual(manifest.action.default_icon, manifest.icons);
  for (const [size, path] of Object.entries(manifest.icons)) {
    const png = await readFile(new URL(`../${path}`, import.meta.url));
    assert.equal(png.readUInt32BE(16), Number(size));
    assert.equal(png.readUInt32BE(20), Number(size));
  }
});
