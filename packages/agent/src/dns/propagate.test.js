"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  normalizePropagationConfig,
  pollTxtUntil,
  waitForTxtPresent,
  waitForTxtAbsent,
  zoneCandidatesForHostname,
} = require("./propagate.js");
const { findLongestManagedZone, resolveChallengeZone } = require("./zone.js");
const { withFileLock } = require("./lockfile.js");

test("zoneCandidatesForHostname walks longest-first excluding the TLD-only form", () => {
  assert.deepEqual(zoneCandidatesForHostname("www.example.com"), [
    "www.example.com",
    "example.com",
  ]);
});

test("normalizePropagationConfig applies defaults and rejects bad shapes", () => {
  const defaults = normalizePropagationConfig(null);
  assert.equal(defaults.timeoutMs, 120000);
  assert.equal(defaults.checkAuthoritative, true);
  assert.throws(() => normalizePropagationConfig("nope"), /must be an object/);
  assert.throws(() => normalizePropagationConfig({ timeoutMs: 0 }), /timeoutMs/);
});

test("pollTxtUntil succeeds once the predicate matches", async () => {
  let calls = 0;
  const result = await pollTxtUntil({
    recordName: "_acme-challenge.example.com",
    servers: ["203.0.113.1"],
    predicate: (values) => values.includes("token"),
    timeoutMs: 1000,
    intervalMs: 1,
    sleep: async () => {},
    resolveTxt: async () => {
      calls += 1;
      return calls >= 2 ? ["token"] : [];
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.attempts, 2);
});

test("waitForTxtPresent / waitForTxtAbsent use injected resolvers", async () => {
  const present = await waitForTxtPresent(
    {
      recordName: "_acme-challenge.example.com",
      txtValue: "abc",
      config: normalizePropagationConfig({
        timeoutMs: 500,
        intervalMs: 1,
        checkAuthoritative: false,
        resolvers: ["203.0.113.9"],
      }),
    },
    {
      resolveTxt: async () => ["abc"],
      sleep: async () => {},
    },
  );
  assert.equal(present.ok, true);
  assert.equal(present.phase, "propagation");

  const absent = await waitForTxtAbsent(
    {
      recordName: "_acme-challenge.example.com",
      txtValue: "abc",
      config: normalizePropagationConfig({
        timeoutMs: 500,
        intervalMs: 1,
        checkAuthoritative: false,
        resolvers: ["203.0.113.9"],
      }),
    },
    {
      resolveTxt: async () => [],
      sleep: async () => {},
    },
  );
  assert.equal(absent.ok, true);
  assert.equal(absent.phase, "cleanup-verify");
});

test("findLongestManagedZone prefers the longest matching managed suffix", async () => {
  const managed = new Set(["example.com", "internal.example.com"]);
  const zone = await findLongestManagedZone("a.internal.example.com", (candidate) =>
    managed.has(candidate),
  );
  assert.equal(zone, "internal.example.com");
});

test("resolveChallengeZone uses mappedZone first", async () => {
  const zone = await resolveChallengeZone({
    domain: "www.example.com",
    mappedZone: "example.com",
  });
  assert.equal(zone, "example.com");
});

test("resolveChallengeZone falls back to NS discovery", async () => {
  const zone = await resolveChallengeZone({
    domain: "www.example.com",
    mappedZone: null,
    dnsDeps: {
      resolveNs: async (name) => {
        if (name === "example.com") {
          return ["ns1.example.com"];
        }
        throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      },
    },
  });
  assert.equal(zone, "example.com");
});

test("withFileLock serializes concurrent tasks on the same key", async () => {
  const lockDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-lock-"));
  const order = [];
  const task = async (label, delayMs) => {
    await withFileLock(
      "provider:example.com:_acme-challenge",
      async () => {
        order.push(`start-${label}`);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        order.push(`end-${label}`);
        return label;
      },
      { lockDir, pollMs: 5, waitTimeoutMs: 5000 },
    );
  };

  await Promise.all([task("a", 30), task("b", 5)]);
  // Whichever acquired first must fully finish before the other starts.
  const first = order[0].endsWith("-a") ? "a" : "b";
  const second = first === "a" ? "b" : "a";
  assert.deepEqual(order, [
    `start-${first}`,
    `end-${first}`,
    `start-${second}`,
    `end-${second}`,
  ]);
});
