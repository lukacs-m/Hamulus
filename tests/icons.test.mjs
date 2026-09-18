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

const settled = () => new Promise((resolve) => setTimeout(resolve, 0));

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
    await settled();
    assert.equal(result.error, undefined);
    assert.equal(result.score, score);
    assert.equal(result.level, level);
    assert.equal(stored.lastResult.score, score);
    assert.match(action.title, new RegExp(`Hamulus - Last scanned email: ${score}/100`));
    for (const [size, path] of Object.entries(action.path)) {
      assert.equal(path, `icons/${level}-${size}.png`);
      const png = await readFile(new URL(`../${path}`, import.meta.url));
      assert.equal(png.subarray(1, 4).toString(), "PNG");
      assert.equal(png.readUInt32BE(16), Number(size));
      assert.equal(png.readUInt32BE(20), Number(size));
    }
  }
});

test("a failed toolbar update still returns the analysis to the banner, and is reported", async () => {
  const setIcon = globalThis.chrome.action.setIcon;
  const warn = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  globalThis.chrome.action.setIcon = async () => { throw new Error("icon decode failed"); };
  try {
    const result = await new Promise((resolve) => {
      onMessage({ type: "ANALYSE", settingsDmarc: false, email: { links: [{ href: "javascript:alert(1)" }] } }, {}, resolve);
    });
    await settled();
    assert.equal(result.error, undefined);
    assert.equal(result.score, 15);
    assert.equal(result.level, "danger");
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /could not publish latest result.*icon decode failed/);
  } finally {
    globalThis.chrome.action.setIcon = setIcon;
    console.warn = warn;
  }
});

test("the last requested scan owns the toolbar even when an earlier one finishes after it", async () => {
  const realFetch = globalThis.fetch;
  const release = {};
  const gates = {
    first: new Promise((resolve) => { release.first = resolve; }),
    second: new Promise((resolve) => { release.second = resolve; }),
  };
  globalThis.fetch = async (url) => {
    const name = new URL(url).searchParams.get("name");
    if (!name) return realFetch(url);
    await gates[name.includes("second") ? "second" : "first"];
    return { json: async () => ({ Answer: [] }) };
  };
  const send = (email) => new Promise((resolve) => onMessage({ type: "ANALYSE", email }, {}, resolve));
  try {
    const first = send({ sender: { email: "alerts@first.example" } });
    const second = send({ sender: { email: "alerts@second.example" }, links: [{ href: "javascript:alert(1)" }] });
    release.second();
    const newest = await second;
    release.first();
    const oldest = await first;
    await settled();
    assert.equal(newest.level, "danger");
    assert.equal(oldest.level, "safe");
    assert.equal(stored.lastResult.score, newest.score);
    assert.equal(stored.lastResult.sender.email, "alerts@second.example");
    assert.match(action.title, new RegExp(`Hamulus - Last scanned email: ${newest.score}/100`));
    assert.equal(action.path[32], `icons/${newest.level}-32.png`);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a failed lastResult write still updates the toolbar and answers the message once", async () => {
  const set = globalThis.chrome.storage.session.set;
  const warn = console.warn;
  const warnings = [];
  const responses = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  globalThis.chrome.storage.session.set = async () => { throw new Error("session storage unavailable"); };
  try {
    const email = { text: "verify your account within 24 hours", links: [{ href: "http://example.com/", text: "example.com" }] };
    onMessage({ type: "ANALYSE", settingsDmarc: false, email }, {}, (response) => responses.push(response));
    await settled();
    assert.deepEqual(responses.map((r) => r.score), [79]);
    assert.match(action.title, /Hamulus - Last scanned email: 79\/100/);
    assert.equal(action.path[32], "icons/caution-32.png");
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /could not publish latest result.*session storage unavailable/);
  } finally {
    globalThis.chrome.storage.session.set = set;
    console.warn = warn;
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
