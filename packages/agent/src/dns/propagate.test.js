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
  assert.equal(defaults.verificationMode, "all");
  assert.equal(defaults.quorumCount, null);
  assert.throws(() => normalizePropagationConfig("nope"), /must be an object/);
  assert.throws(() => normalizePropagationConfig({ timeoutMs: 0 }), /timeoutMs/);
  assert.throws(
    () => normalizePropagationConfig({ verificationMode: "maybe" }),
    /verificationMode/,
  );
  assert.throws(
    () => normalizePropagationConfig({ verificationMode: "quorum" }),
    /quorumCount/,
  );
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
  assert.equal(result.verificationMode, "all");
  assert.equal(result.serverResults.length, 1);
  assert.equal(result.serverResults[0].server, "203.0.113.1");
  assert.equal(result.serverResults[0].matched, true);
});

test("waitForTxtPresent requires ALL polled servers to confirm by default", async () => {
  const resolveCalls = [];
  const present = await waitForTxtPresent(
    {
      recordName: "_acme-challenge.example.com",
      txtValue: "abc",
      config: normalizePropagationConfig({
        timeoutMs: 50,
        intervalMs: 1,
        checkAuthoritative: true,
        resolvers: [],
      }),
    },
    {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1", "203.0.113.2"],
      resolveTxt: async (_name, servers) => {
        resolveCalls.push(servers);
        // Only the first authoritative server has the value; the second lags.
        if (servers[0] === "203.0.113.1") {
          return ["abc"];
        }
        return [];
      },
      sleep: async () => {},
    },
  );

  assert.equal(present.ok, false);
  assert.ok(resolveCalls.some((servers) => servers.length === 1));
  assert.ok(present.serverResults);
  assert.equal(present.serverResults.length, 2);
  const byServer = Object.fromEntries(
    present.serverResults.map((entry) => [entry.server, entry]),
  );
  assert.equal(byServer["203.0.113.1"].matched, true);
  assert.deepEqual(byServer["203.0.113.1"].values, ["abc"]);
  assert.equal(byServer["203.0.113.2"].matched, false);
  assert.deepEqual(byServer["203.0.113.2"].values, []);
});

test("waitForTxtPresent succeeds only after every server independently matches", async () => {
  let polls = 0;
  const present = await waitForTxtPresent(
    {
      recordName: "_acme-challenge.example.com",
      txtValue: "abc",
      config: normalizePropagationConfig({
        timeoutMs: 500,
        intervalMs: 1,
        checkAuthoritative: true,
      }),
    },
    {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1", "203.0.113.2"],
      resolveTxt: async (_name, servers) => {
        polls += 1;
        const attemptNumber = Math.ceil(polls / 2);
        // First attempt: .2 still lags. Later attempts: both confirm.
        if (attemptNumber === 1 && servers[0] === "203.0.113.2") {
          return [];
        }
        return ["abc"];
      },
      sleep: async () => {},
    },
  );

  assert.equal(present.ok, true);
  assert.equal(present.verificationMode, "all");
  assert.ok(present.attempts >= 2);
  assert.equal(present.serverResults.length, 2);
  assert.ok(present.serverResults.every((entry) => entry.matched === true));
  assert.ok(present.serverResults.every((entry) => entry.values.includes("abc")));
});

test("waitForTxtPresent quorum mode accepts a configurable minimum confirmation count", async () => {
  const present = await waitForTxtPresent(
    {
      recordName: "_acme-challenge.example.com",
      txtValue: "abc",
      config: normalizePropagationConfig({
        timeoutMs: 500,
        intervalMs: 1,
        checkAuthoritative: true,
        verificationMode: "quorum",
        quorumCount: 1,
      }),
    },
    {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1", "203.0.113.2"],
      resolveTxt: async (_name, servers) => {
        return servers[0] === "203.0.113.1" ? ["abc"] : [];
      },
      sleep: async () => {},
    },
  );

  assert.equal(present.ok, true);
  assert.equal(present.verificationMode, "quorum");
  assert.equal(present.quorumCount, 1);
  const matched = present.serverResults.filter((entry) => entry.matched);
  assert.equal(matched.length, 1);
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
  assert.equal(present.serverResults[0].server, "203.0.113.9");

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
