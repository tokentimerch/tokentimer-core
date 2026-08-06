"use strict";

/**
 * Tests for packages/agent/src/windows-retention/index.js.
 *
 * All tests operate purely on plain data and a temp ledger directory; the
 * sweep functions take injected gatherContext/performCleanup/now
 * callbacks, so no real http.sys, certificate store, or TLS handshake is
 * touched. This module's contract IS the pure eligibility function plus
 * the ledger persistence; wiring gatherContext to real windows-iis/
 * windows-cert-store facts is separate follow-up work.
 */

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  MIN_RETENTION_HOURS,
  MAX_RETENTION_HOURS,
  CLOCK_SKEW_GRACE_SECONDS,
  DEFERRAL_REASONS,
  validateRetentionHours,
  computeCleanupDeadline,
  validateLedgerRow,
  createLedgerRow,
  readLedgerRow,
  writeLedgerRow,
  listLedgerThumbprints,
  closeJournalReference,
  evaluateEligibility,
  sweepLedger,
} = require("./index.js");

const OLD_THUMBPRINT = "AA".repeat(20);
const NEW_THUMBPRINT = "BB".repeat(20);
const CONTAINER_ID = "tokentimer-job-1-abcd1234";

const tempDirs = [];
function makeLedgerDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-retention-test-"));
  tempDirs.push(dir);
  return path.join(dir, "ledger");
}
afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

function baseRowInput(overrides = {}) {
  return {
    oldThumbprint: OLD_THUMBPRINT,
    replacementThumbprint: NEW_THUMBPRINT,
    cngKeyContainerId: CONTAINER_ID,
    verifiedCutoverAt: "2026-01-01T00:00:00.000Z",
    oldNotAfter: "2030-01-01T00:00:00.000Z",
    ownershipProvenance: "tokentimer_installed",
    ...overrides,
  };
}

function fullContext(overrides = {}) {
  return {
    retentionHours: 168,
    bindingStillReferencesOldThumbprint: false,
    keyContainerSharedWithSurvivor: false,
    replacementPassesHandshakeNow: true,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// validateRetentionHours
// ---------------------------------------------------------------------------

describe("validateRetentionHours", () => {
  it("accepts the documented boundary values", () => {
    assert.equal(validateRetentionHours(MIN_RETENTION_HOURS), 24);
    assert.equal(validateRetentionHours(168), 168);
    assert.equal(validateRetentionHours(MAX_RETENTION_HOURS), 720);
  });

  it("rejects zero (collapses to unconditional immediate deletion)", () => {
    assert.throws(() => validateRetentionHours(0), /INVALID_RETENTION_HOURS|must be an integer/);
  });

  it("rejects values just outside the range", () => {
    assert.throws(() => validateRetentionHours(23));
    assert.throws(() => validateRetentionHours(721));
  });

  it("rejects non-integers", () => {
    assert.throws(() => validateRetentionHours(168.5));
    assert.throws(() => validateRetentionHours("168"));
  });
});

// ---------------------------------------------------------------------------
// computeCleanupDeadline: earlier-of-two-clocks
// ---------------------------------------------------------------------------

describe("computeCleanupDeadline", () => {
  it("uses the retention-window deadline when it is earlier than notAfter+grace", () => {
    const deadline = computeCleanupDeadline({
      verifiedCutoverAt: "2026-01-01T00:00:00.000Z",
      oldNotAfter: "2030-01-01T00:00:00.000Z",
      retentionHours: 168,
    });
    assert.equal(deadline.toISOString(), "2026-01-08T00:00:00.000Z");
  });

  it("uses the notAfter+grace deadline when the certificate expires before the retention window ends", () => {
    const deadline = computeCleanupDeadline({
      verifiedCutoverAt: "2026-01-01T00:00:00.000Z",
      oldNotAfter: "2026-01-02T00:00:00.000Z",
      retentionHours: 168,
    });
    assert.equal(deadline.toISOString(), "2026-01-02T00:05:00.000Z");
    assert.equal(CLOCK_SKEW_GRACE_SECONDS, 300);
  });

  it("rejects an unparseable date", () => {
    assert.throws(
      () => computeCleanupDeadline({ verifiedCutoverAt: "not-a-date", oldNotAfter: "2030-01-01T00:00:00.000Z", retentionHours: 168 }),
      /verifiedCutoverAt/,
    );
  });

  it("rejects an out-of-range retentionHours", () => {
    assert.throws(() =>
      computeCleanupDeadline({
        verifiedCutoverAt: "2026-01-01T00:00:00.000Z",
        oldNotAfter: "2030-01-01T00:00:00.000Z",
        retentionHours: 0,
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// validateLedgerRow
// ---------------------------------------------------------------------------

describe("validateLedgerRow", () => {
  it("accepts a well-formed row and normalizes thumbprints to uppercase", () => {
    const row = validateLedgerRow({
      ...baseRowInput({ oldThumbprint: OLD_THUMBPRINT.toLowerCase() }),
      jobOrRollbackJournalRefs: [{ ref: "job-1", active: true }],
      lifecycleState: "pending_retention",
      deferralReason: null,
    });
    assert.equal(row.oldThumbprint, OLD_THUMBPRINT.toUpperCase());
    assert.equal(row.jobOrRollbackJournalRefs.length, 1);
  });

  it("rejects a malformed oldThumbprint", () => {
    assert.throws(
      () =>
        validateLedgerRow({
          ...baseRowInput({ oldThumbprint: "not-a-thumbprint" }),
          jobOrRollbackJournalRefs: [],
          lifecycleState: "pending_retention",
          deferralReason: null,
        }),
      /oldThumbprint/,
    );
  });

  it("rejects an invalid ownershipProvenance", () => {
    assert.throws(
      () =>
        validateLedgerRow({
          ...baseRowInput({ ownershipProvenance: "stolen" }),
          jobOrRollbackJournalRefs: [],
          lifecycleState: "pending_retention",
          deferralReason: null,
        }),
      /ownershipProvenance/,
    );
  });

  it("rejects an invalid lifecycleState", () => {
    assert.throws(
      () =>
        validateLedgerRow({
          ...baseRowInput(),
          jobOrRollbackJournalRefs: [],
          lifecycleState: "bogus",
          deferralReason: null,
        }),
      /lifecycleState/,
    );
  });

  it("rejects a deferralReason outside the six named reasons", () => {
    assert.throws(
      () =>
        validateLedgerRow({
          ...baseRowInput(),
          jobOrRollbackJournalRefs: [],
          lifecycleState: "deferred",
          deferralReason: "made_up_reason",
        }),
      /deferralReason/,
    );
  });

  it("rejects a malformed journal reference entry", () => {
    assert.throws(
      () =>
        validateLedgerRow({
          ...baseRowInput(),
          jobOrRollbackJournalRefs: [{ ref: "job-1" }],
          lifecycleState: "pending_retention",
          deferralReason: null,
        }),
      /active/,
    );
  });
});

// ---------------------------------------------------------------------------
// createLedgerRow / readLedgerRow / writeLedgerRow / listLedgerThumbprints
// ---------------------------------------------------------------------------

describe("createLedgerRow", () => {
  it("persists a new row in pending_retention state", () => {
    const ledgerDir = makeLedgerDir();
    const row = createLedgerRow(baseRowInput({ ledgerDir }));
    assert.equal(row.lifecycleState, "pending_retention");
    assert.equal(row.deferralReason, null);

    const reread = readLedgerRow(ledgerDir, OLD_THUMBPRINT);
    assert.deepEqual(reread, row);
  });

  it("refuses to create a second row for the same thumbprint", () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));
    assert.throws(
      () => createLedgerRow(baseRowInput({ ledgerDir })),
      /ROW_ALREADY_EXISTS|already exists/,
    );
  });

  it("creates the ledger directory if it does not exist", () => {
    const ledgerDir = makeLedgerDir();
    assert.equal(fs.existsSync(ledgerDir), false);
    createLedgerRow(baseRowInput({ ledgerDir }));
    assert.equal(fs.existsSync(ledgerDir), true);
  });
});

describe("writeLedgerRow", () => {
  it("overwrites an existing row atomically with a full replacement", () => {
    const ledgerDir = makeLedgerDir();
    const row = createLedgerRow(baseRowInput({ ledgerDir }));
    const updated = writeLedgerRow(ledgerDir, {
      ...row,
      lifecycleState: "deferred",
      deferralReason: "deadline_not_reached",
    });
    assert.equal(updated.lifecycleState, "deferred");
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT).lifecycleState, "deferred");
  });

  it("rejects an invalid row shape before writing anything", () => {
    const ledgerDir = makeLedgerDir();
    assert.throws(
      () => writeLedgerRow(ledgerDir, { ...baseRowInput(), jobOrRollbackJournalRefs: [], lifecycleState: "bogus" }),
      /lifecycleState/,
    );
    assert.equal(fs.existsSync(ledgerDir), false);
  });
});

describe("readLedgerRow", () => {
  it("returns null for a nonexistent row", () => {
    const ledgerDir = makeLedgerDir();
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT), null);
  });

  it("returns null when the ledger directory itself does not exist", () => {
    const ledgerDir = makeLedgerDir();
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT), null);
  });

  it("throws loudly on a corrupted (non-JSON) row file", () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));
    const rowPath = path.join(ledgerDir, `${OLD_THUMBPRINT}.json`);
    fs.writeFileSync(rowPath, "not json{{{", "utf8");
    assert.throws(() => readLedgerRow(ledgerDir, OLD_THUMBPRINT), /not valid JSON/);
  });
});

describe("listLedgerThumbprints", () => {
  it("lists thumbprints for every persisted row", () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));
    createLedgerRow(baseRowInput({ ledgerDir, oldThumbprint: "CC".repeat(20) }));
    const thumbprints = listLedgerThumbprints(ledgerDir).sort();
    assert.deepEqual(thumbprints, [OLD_THUMBPRINT, "CC".repeat(20)].sort());
  });

  it("returns an empty array when the ledger directory does not exist", () => {
    const ledgerDir = makeLedgerDir();
    assert.deepEqual(listLedgerThumbprints(ledgerDir), []);
  });
});

describe("closeJournalReference", () => {
  it("marks a matching reference inactive without touching others", () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(
      baseRowInput({
        ledgerDir,
        jobOrRollbackJournalRefs: [
          { ref: "rollback-1", active: true },
          { ref: "rollback-2", active: true },
        ],
      }),
    );

    const updated = closeJournalReference(ledgerDir, OLD_THUMBPRINT, "rollback-1");
    const refs = Object.fromEntries(updated.jobOrRollbackJournalRefs.map((r) => [r.ref, r.active]));
    assert.equal(refs["rollback-1"], false);
    assert.equal(refs["rollback-2"], true);
  });

  it("returns null when no row exists", () => {
    const ledgerDir = makeLedgerDir();
    assert.equal(closeJournalReference(ledgerDir, OLD_THUMBPRINT, "rollback-1"), null);
  });

  it("is a no-op when the ref is not found", () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir, jobOrRollbackJournalRefs: [{ ref: "rollback-1", active: true }] }));
    const updated = closeJournalReference(ledgerDir, OLD_THUMBPRINT, "does-not-exist");
    assert.equal(updated.jobOrRollbackJournalRefs[0].active, true);
  });
});

// ---------------------------------------------------------------------------
// evaluateEligibility: the six-condition check, each condition isolated
// ---------------------------------------------------------------------------

describe("evaluateEligibility", () => {
  const eligibleRow = validateLedgerRow({
    ...baseRowInput(),
    jobOrRollbackJournalRefs: [],
    lifecycleState: "pending_retention",
    deferralReason: null,
  });
  const afterDeadline = () => new Date("2026-01-09T00:00:00.000Z"); // cutover + 8 days

  it("is eligible when every condition holds and the deadline has passed", () => {
    const result = evaluateEligibility(eligibleRow, fullContext({ now: afterDeadline }));
    assert.deepEqual(result, { eligible: true });
  });

  it("defers with ownership_unrecorded when the row is preexisting", () => {
    const row = { ...eligibleRow, ownershipProvenance: "preexisting" };
    const result = evaluateEligibility(row, fullContext({ now: afterDeadline }));
    assert.deepEqual(result, { eligible: false, reason: "ownership_unrecorded" });
  });

  it("defers with binding_still_present", () => {
    const result = evaluateEligibility(
      eligibleRow,
      fullContext({ bindingStillReferencesOldThumbprint: true, now: afterDeadline }),
    );
    assert.deepEqual(result, { eligible: false, reason: "binding_still_present" });
  });

  it("defers with active_reference_present when an active journal ref exists", () => {
    const row = { ...eligibleRow, jobOrRollbackJournalRefs: [{ ref: "rollback-1", active: true }] };
    const result = evaluateEligibility(row, fullContext({ now: afterDeadline }));
    assert.deepEqual(result, { eligible: false, reason: "active_reference_present" });
  });

  it("does NOT block on a closed (inactive) journal ref", () => {
    const row = { ...eligibleRow, jobOrRollbackJournalRefs: [{ ref: "rollback-1", active: false }] };
    const result = evaluateEligibility(row, fullContext({ now: afterDeadline }));
    assert.deepEqual(result, { eligible: true });
  });

  it("defers with shared_key_container", () => {
    const result = evaluateEligibility(
      eligibleRow,
      fullContext({ keyContainerSharedWithSurvivor: true, now: afterDeadline }),
    );
    assert.deepEqual(result, { eligible: false, reason: "shared_key_container" });
  });

  it("defers with replacement_handshake_failed", () => {
    const result = evaluateEligibility(
      eligibleRow,
      fullContext({ replacementPassesHandshakeNow: false, now: afterDeadline }),
    );
    assert.deepEqual(result, { eligible: false, reason: "replacement_handshake_failed" });
  });

  it("defers with deadline_not_reached before the cleanup deadline", () => {
    const result = evaluateEligibility(
      eligibleRow,
      fullContext({ now: () => new Date("2026-01-02T00:00:00.000Z") }),
    );
    assert.deepEqual(result, { eligible: false, reason: "deadline_not_reached" });
  });

  it("checks conditions in the documented precedence order (ownership before binding, etc.)", () => {
    const row = { ...eligibleRow, ownershipProvenance: "preexisting" };
    const result = evaluateEligibility(
      row,
      fullContext({ bindingStillReferencesOldThumbprint: true, now: afterDeadline }),
    );
    assert.equal(result.reason, "ownership_unrecorded");
  });

  it("rejects a non-boolean context field", () => {
    assert.throws(
      () => evaluateEligibility(eligibleRow, fullContext({ bindingStillReferencesOldThumbprint: "yes" })),
      /bindingStillReferencesOldThumbprint/,
    );
  });

  it("every returned deferral reason is one of the six named DEFERRAL_REASONS", () => {
    assert.equal(DEFERRAL_REASONS.length, 6);
    const scenarios = [
      fullContext({ now: afterDeadline }),
      fullContext({ bindingStillReferencesOldThumbprint: true, now: afterDeadline }),
      fullContext({ keyContainerSharedWithSurvivor: true, now: afterDeadline }),
      fullContext({ replacementPassesHandshakeNow: false, now: afterDeadline }),
      fullContext({ now: () => new Date("2026-01-02T00:00:00.000Z") }),
    ];
    for (const ctx of scenarios.slice(1)) {
      const result = evaluateEligibility(eligibleRow, ctx);
      assert.equal(DEFERRAL_REASONS.includes(result.reason), true);
    }
  });
});

// ---------------------------------------------------------------------------
// sweepLedger: orchestration, metrics, restart-safety
// ---------------------------------------------------------------------------

describe("sweepLedger", () => {
  it("removes an eligible row and calls performCleanup exactly once", async () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));
    const cleanupCalls = [];

    const summary = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext: async () => ({
        bindingStillReferencesOldThumbprint: false,
        keyContainerSharedWithSurvivor: false,
        replacementPassesHandshakeNow: true,
      }),
      performCleanup: async (row) => {
        cleanupCalls.push(row.oldThumbprint);
      },
      now: () => new Date("2026-01-09T00:00:00.000Z"),
    });

    assert.deepEqual(summary.removed, [OLD_THUMBPRINT]);
    assert.equal(cleanupCalls.length, 1);
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT).lifecycleState, "removed");
  });

  it("defers a row and records the reason in both the row and the metric", async () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));

    const summary = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext: async () => ({
        bindingStillReferencesOldThumbprint: true,
        keyContainerSharedWithSurvivor: false,
        replacementPassesHandshakeNow: true,
      }),
      performCleanup: async () => {
        throw new Error("must not be called");
      },
      now: () => new Date("2026-01-09T00:00:00.000Z"),
    });

    assert.deepEqual(summary.removed, []);
    assert.equal(summary.deferred.length, 1);
    assert.equal(summary.deferred[0].reason, "binding_still_present");
    assert.equal(summary.deferredCountByReason.binding_still_present, 1);
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT).lifecycleState, "deferred");
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT).deferralReason, "binding_still_present");
  });

  it("never throws when performCleanup fails; retries the row as eligible on a later sweep", async () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));
    let attempts = 0;

    const gatherContext = async () => ({
      bindingStillReferencesOldThumbprint: false,
      keyContainerSharedWithSurvivor: false,
      replacementPassesHandshakeNow: true,
    });
    const now = () => new Date("2026-01-09T00:00:00.000Z");

    const firstSweep = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext,
      performCleanup: async () => {
        attempts += 1;
        throw new Error("transient failure");
      },
      now,
    });
    assert.deepEqual(firstSweep.removed, []);
    assert.equal(readLedgerRow(ledgerDir, OLD_THUMBPRINT).lifecycleState, "eligible");

    const secondSweep = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext,
      performCleanup: async () => {
        attempts += 1;
      },
      now,
    });
    assert.deepEqual(secondSweep.removed, [OLD_THUMBPRINT]);
    assert.equal(attempts, 2);
  });

  it("skips rows already in removed state (idempotent across sweeps)", async () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));
    const now = () => new Date("2026-01-09T00:00:00.000Z");
    const gatherContext = async () => ({
      bindingStillReferencesOldThumbprint: false,
      keyContainerSharedWithSurvivor: false,
      replacementPassesHandshakeNow: true,
    });

    await sweepLedger({ ledgerDir, retentionHours: 168, gatherContext, performCleanup: async () => {}, now });

    let gatherContextCallCount = 0;
    const summary = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext: async (row) => {
        gatherContextCallCount += 1;
        return gatherContext(row);
      },
      performCleanup: async () => {
        throw new Error("must not be called for an already-removed row");
      },
      now,
    });

    assert.equal(gatherContextCallCount, 0);
    assert.deepEqual(summary.removed, []);
    assert.deepEqual(summary.deferred, []);
  });

  it("is restart-safe: a fresh sweep call (simulating a new process) reaches the same decision from the persisted row alone", async () => {
    const ledgerDir = makeLedgerDir();
    createLedgerRow(baseRowInput({ ledgerDir }));

    // Simulated crash: nothing in memory survives between these two calls
    // except the ledger directory on disk.
    const summary = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext: async () => ({
        bindingStillReferencesOldThumbprint: false,
        keyContainerSharedWithSurvivor: false,
        replacementPassesHandshakeNow: true,
      }),
      performCleanup: async () => {},
      now: () => new Date("2026-01-09T00:00:00.000Z"),
    });

    assert.deepEqual(summary.removed, [OLD_THUMBPRINT]);
  });

  it("processes multiple independent rows in one sweep, isolating one row's failure from another's success", async () => {
    const ledgerDir = makeLedgerDir();
    const secondThumbprint = "CC".repeat(20);
    createLedgerRow(baseRowInput({ ledgerDir }));
    createLedgerRow(baseRowInput({ ledgerDir, oldThumbprint: secondThumbprint }));

    const summary = await sweepLedger({
      ledgerDir,
      retentionHours: 168,
      gatherContext: async (row) => ({
        bindingStillReferencesOldThumbprint: row.oldThumbprint === secondThumbprint,
        keyContainerSharedWithSurvivor: false,
        replacementPassesHandshakeNow: true,
      }),
      performCleanup: async () => {},
      now: () => new Date("2026-01-09T00:00:00.000Z"),
    });

    assert.deepEqual(summary.removed, [OLD_THUMBPRINT]);
    assert.equal(summary.deferred.length, 1);
    assert.equal(summary.deferred[0].oldThumbprint, secondThumbprint);
  });
});


