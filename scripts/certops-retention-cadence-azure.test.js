"use strict";
// Offline ownership/chronology regressions; no Azure/native commands are run.
const test = require("node:test");
const assert = require("node:assert/strict");
const a = require("./certops-retention-cadence-azure");
const c = require("./certops-retention-cadence-contract");
const crypto = require("node:crypto");
const { fixture } = require("./test-support/retention-cadence-artifact.cjs");
test("original owner is bound to actual prepare job, not queued approval time", () => {
  const f = fixture();
  const owner = a.verifyPrepareRun(f.run, f.jobs);
  assert.equal(a.verifyOriginalReceipt(f.original), f.original);
  assert.throws(() => a.verifyCreation("2026-10-14T12:01:00.000Z", owner));
  for (const field of ["head_sha", "path", "head_branch", "event"]) {
    const changed = structuredClone(f.run);
    changed[field] = "foreign";
    assert.throws(() => a.verifyPrepareRun(changed, f.jobs));
  }
  const fork = structuredClone(f.run);
  fork.head_repository.full_name = "foreign/core";
  assert.throws(() => a.verifyPrepareRun(fork, f.jobs));
});
test("handoff preserves original nonce, process, source and four-hour authority", () => {
  const f = fixture();
  assert.equal(a.verifyHandoffReceipt(f.handoff, f.original), f.handoff);
  for (const field of [
    "processId",
    "observerConfigSha256",
    "immediateLedgerFileId",
  ]) {
    const changed = structuredClone(f.handoff);
    changed.observed[field] = field === "processId" ? 999 : "0".repeat(64);
    assert.throws(() => a.verifyHandoffReceipt(changed, f.original));
  }
  const late = structuredClone(f.handoff);
  late.handedOffAt = f.original.preparedLease.expiresAt;
  assert.throws(() => a.verifyHandoffReceipt(late, f.original));
  const extra = structuredClone(f.original);
  extra.azure.foreign = true;
  assert.throws(() => a.verifyOriginalReceipt(extra));
});
test("cleanup accepts only chronological tagged ownership and bounded deadlines", () => {
  const f = fixture(),
    l = f.composite.preparedLease,
    owner = a.verifyPrepareRun(f.run, f.jobs);
  const group = {
    name: a.groupName(owner),
    id: f.original.azure.groupId,
    tags: {
      purpose: "certops-adcs-qualification",
      candidateSha: l.candidateSha,
      createdAt: l.createdAt,
      expiresAt: l.expiresAt,
      cadencePrepareKind: c.KIND,
      cadencePrepareNonce: l.nonce,
      cadencePrepareRunId: l.runId,
      cadencePrepareRunAttempt: l.runAttempt,
    },
  };
  const owned = a.verifyCleanupOwnership(group, null, null, owner, l.nonce);
  assert.equal(
    a.cleanupDecision(f.run, owned, Date.parse(l.createdAt) + 1),
    "preserve",
  );
  assert.equal(
    a.cleanupDecision(
      { ...f.run, conclusion: "cancelled" },
      owned,
      Date.parse(l.createdAt) + 1,
    ),
    "failed-owner",
  );
  assert.equal(
    a.cleanupDecision(f.run, owned, Date.parse(l.expiresAt)),
    "expired",
  );
  for (const key of ["candidateSha", "cadencePrepareNonce", "expiresAt"]) {
    const changed = structuredClone(group);
    changed.tags[key] = "foreign";
    assert.throws(() =>
      a.verifyCleanupOwnership(changed, null, null, owner, l.nonce),
    );
  }
  const extended = {
    ...group,
    tags: { ...group.tags, ...a.leaseTags(f.composite.lease) },
  };
  assert.equal(
    a.verifyCleanupOwnership(extended, null, null, owner, l.nonce).deadline,
    Date.parse(l.hardExpiresAt),
  );
  const moved = structuredClone(extended);
  moved.tags.expiresAt = "2026-10-16T00:00:00.000Z";
  assert.throws(() =>
    a.verifyCleanupOwnership(moved, null, null, owner, l.nonce),
  );
});

test("changing native producer executes once while a stable multi-chunk snapshot is assembled", () => {
  const lease = fixture().composite.preparedLease;
  for (const corrupt of [false, true]) {
    const bytes = Buffer.from(
      JSON.stringify({
        scope: "controlled-transport-only",
        data: "x".repeat(3500),
      }),
    );
    const hash = crypto.createHash("sha256").update(bytes).digest("hex");
    let produced = 0,
      removed = 0,
      chunks = 0;
    const execute = (_lease, script) => {
      if (script.includes("CERTOPS_OBSERVATION_CREATE")) {
        produced++;
        assert.ok(script.includes("CONTROLLED_CHANGING_NATIVE_PRODUCER"));
        assert.equal(produced, 1);
        return { length: bytes.length, sha256: hash, fileIdentity: "123:456" };
      }
      assert.equal(
        script.includes("CONTROLLED_CHANGING_NATIVE_PRODUCER"),
        false,
      );
      if (script.includes("CERTOPS_OBSERVATION_CLEANUP")) {
        removed++;
        assert.match(script, /123:456/);
        assert.match(script, /Remove-Item -LiteralPath/);
        assert.doesNotMatch(script, /-Recurse/);
        return { removed: true };
      }
      const match = /ToBase64String\(\$b,([0-9]+),/.exec(script);
      assert.ok(match);
      const offset = Number(match[1]);
      chunks++;
      return {
        length: bytes.length,
        sha256: corrupt && offset > 0 ? "f".repeat(64) : hash,
        chunk: bytes
          .subarray(offset, Math.min(bytes.length, offset + 1024))
          .toString("base64"),
      };
    };
    const action = () =>
      a.readOwnedObservation(lease, "# CONTROLLED_CHANGING_NATIVE_PRODUCER", {
        execute,
        requestNonce: "9".repeat(64),
      });
    if (corrupt) assert.throws(action);
    else assert.deepEqual(action(), JSON.parse(bytes));
    assert.equal(produced, 1);
    assert.equal(removed, 1);
    assert.ok(chunks >= 2);
  }
});
test("malformed snapshot receipt cannot authorize cleanup or enter generated commands", () => {
  const lease = fixture().composite.preparedLease;
  for (const patch of [
    { length: "1; Invoke-UntrustedCommand" },
    { length: -1 },
    { length: 65537 },
    { fileIdentity: "123:456; evil" },
    { sha256: "not a digest" },
    { extra: "private" },
  ]) {
    let calls = 0;
    assert.throws(() =>
      a.readOwnedObservation(lease, "# controlled producer", {
        requestNonce: "9".repeat(64),
        execute: () => {
          calls++;
          return {
            length: 100,
            sha256: "a".repeat(64),
            fileIdentity: "123:456",
            ...patch,
          };
        },
      }),
    );
    assert.equal(
      calls,
      1,
      "Unvalidated receipt must preserve unknown snapshot instead of cleanup",
    );
  }
});

test("one attempted cleanup and two pending inspections leave bounded upload headroom", () => {
  assert.equal(
    a.canInspectCampaign({
      attempts: 0,
      inspected: 0,
      remainingMs: 15 * 60000,
    }),
    true,
  );
  for (const value of [
    { attempts: 1, inspected: 0, remainingMs: 22 * 60000 },
    { attempts: 0, inspected: 2, remainingMs: 22 * 60000 },
    { attempts: 0, inspected: 0, remainingMs: 15 * 60000 - 1 },
  ])
    assert.equal(a.canInspectCampaign(value), false);
});
