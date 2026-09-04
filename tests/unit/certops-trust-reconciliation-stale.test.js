"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  _test: { reconciliationStaleReasonForInstallation, RECONCILIATION_STALE_MESSAGE_BY_CODE },
} = require("../../apps/api/services/certops/trustAnchors");

function installation(overrides = {}) {
  return {
    transitionState: "pending_install",
    nextReconcileAt: null,
    lastError: null,
    ...overrides,
  };
}

describe("reconciliationStaleReasonForInstallation", () => {
  const knownCodes = [
    "reconciliation_stale_no_job",
    "reconciliation_stale_job_pending_approval",
    "reconciliation_stale_job_approved",
    "reconciliation_stale_job_pending",
    "reconciliation_stale_job_claimed",
    "reconciliation_stale_job_running",
  ];

  for (const code of knownCodes) {
    it(`maps ${code} to its operator-facing message`, () => {
      const reason = reconciliationStaleReasonForInstallation(
        installation({ lastError: code }),
      );
      assert.deepEqual(reason, {
        code,
        message: RECONCILIATION_STALE_MESSAGE_BY_CODE[code],
      });
    });
  }

  it("falls back to a generic message for an unmapped-but-prefixed code", () => {
    const reason = reconciliationStaleReasonForInstallation(
      installation({ lastError: "reconciliation_stale_job_dry_run_complete" }),
    );
    assert.equal(reason.code, "reconciliation_stale_job_dry_run_complete");
    assert.match(reason.message, /Manual retry is required/);
  });

  it("returns null when next_reconcile_at is still set, even with a known stale code", () => {
    // Defends against the "still scheduled" case being misclassified, even
    // though the sweep itself guarantees this can't currently co-occur.
    const reason = reconciliationStaleReasonForInstallation(
      installation({
        lastError: "reconciliation_stale_job_pending",
        nextReconcileAt: new Date().toISOString(),
      }),
    );
    assert.equal(reason, null);
  });

  it("returns null for a row that is not a live pending transition", () => {
    for (const transitionState of ["installed", "removed"]) {
      const reason = reconciliationStaleReasonForInstallation(
        installation({
          transitionState,
          lastError: "reconciliation_stale_job_pending",
        }),
      );
      assert.equal(reason, null);
    }
  });

  it("returns null for a genuine unrelated error", () => {
    const reason = reconciliationStaleReasonForInstallation(
      installation({ lastError: "agent unreachable" }),
    );
    assert.equal(reason, null);
  });

  it("returns null when last_error is null or empty", () => {
    assert.equal(
      reconciliationStaleReasonForInstallation(installation({ lastError: null })),
      null,
    );
    assert.equal(
      reconciliationStaleReasonForInstallation(installation({ lastError: "" })),
      null,
    );
  });
});
