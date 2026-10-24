const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  OnboardingValidationError,
  assertFlow,
  validateSessionWrite,
} = require("../../apps/api/services/onboarding/sessionSchema");

function rejects(body, code) {
  assert.throws(
    () => validateSessionWrite(body),
    (e) => e instanceof OnboardingValidationError && e.code === code,
  );
}

describe("onboarding session schema", () => {
  it("requires a non-negative integer expectedRevision", () => {
    rejects({}, "INVALID_REVISION");
    rejects({ expectedRevision: -1 }, "INVALID_REVISION");
    rejects({ expectedRevision: "1" }, "INVALID_REVISION");
    assert.equal(validateSessionWrite({ expectedRevision: 0 }).expectedRevision, 0);
  });

  it("accepts intent, progress and operation references", () => {
    const { patch } = validateSessionWrite({
      expectedRevision: 3,
      status: "in_progress",
      plannerVersion: 2,
      intent: { goal: "monitor_https", assetTypes: ["ssl_cert"] },
      progress: { position: "assets", parked: [] },
      operation_refs: { monitorUrl: "https://example.com", tokenIds: [4, 5] },
    });
    assert.equal(patch.plannerVersion, 2);
    assert.deepEqual(patch.operation_refs.tokenIds, [4, 5]);
  });

  it("rejects secret-like keys at any depth", () => {
    for (const key of ["password", "client_secret", "apiKey", "bootstrapToken", "private_key"]) {
      rejects(
        { expectedRevision: 1, operation_refs: { nested: { [key]: "x" } } },
        "SECRET_REJECTED",
      );
    }
  });

  it("rejects values that look like credentials", () => {
    const values = [
      "ttboot_0123456789abcdef_" + "a".repeat(64),
      "ttagent_abc",
      "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      "glpat-abcdefghij",
      "hvs.CAESIabc",
      "AKIAABCDEFGHIJKLMNOP",
      "-----BEGIN RSA PRIVATE KEY-----",
    ];
    for (const value of values) {
      rejects({ expectedRevision: 1, progress: { note: value } }, "SECRET_REJECTED");
    }
  });

  it("enforces shape and size limits", () => {
    rejects({ expectedRevision: 1, intent: [] }, "INVALID_SECTION");
    rejects({ expectedRevision: 1, intent: { "bad key": 1 } }, "INVALID_KEY");
    rejects({ expectedRevision: 1, intent: { a: "x".repeat(513) } }, "VALUE_TOO_LONG");
    rejects(
      { expectedRevision: 1, intent: { a: Array.from({ length: 101 }, () => 1) } },
      "TOO_MANY_ITEMS",
    );
    rejects({ expectedRevision: 1, status: "bogus" }, "INVALID_STATUS");
    rejects({ expectedRevision: 1, plannerVersion: 0 }, "INVALID_PLANNER_VERSION");
    let deep = { v: 1 };
    for (let i = 0; i < 8; i++) deep = { n: deep };
    rejects({ expectedRevision: 1, intent: deep }, "TOO_DEEP");
  });

  it("keeps the chosen existing agent in CertOps progress", () => {
    const certops = {
      objective: "observe",
      infrastructure: "linux",
      chosenAgentId: "4f0d2c1e-7a53-4a49-9d0b-2f1c8b6a9e11",
      chosenAgentConfirmed: "4f0d2c1e-7a53-4a49-9d0b-2f1c8b6a9e11",
    };
    const { patch } = validateSessionWrite({
      expectedRevision: 2,
      progress: { certops },
    });
    assert.deepEqual(patch.progress.certops, certops);
    // A write without the field (older client) stays valid.
    const older = validateSessionWrite({
      expectedRevision: 2,
      progress: { certops: { objective: "observe", infrastructure: "linux" } },
    });
    assert.equal(older.patch.progress.certops.chosenAgentId, undefined);
  });

  it("still applies the credential and size rules to the chosen agent", () => {
    rejects(
      { expectedRevision: 1, progress: { certops: { chosenAgentId: "ttagent_abc" } } },
      "SECRET_REJECTED",
    );
    rejects(
      { expectedRevision: 1, progress: { certops: { chosenAgentId: "a".repeat(513) } } },
      "VALUE_TOO_LONG",
    );
  });

  it("keeps the chosen existing Vault distribution in CertOps progress", () => {
    const certops = {
      objective: "vault",
      infrastructure: "linux",
      chosenDistributionId: "4f0d2c1e-7a53-4a49-9d0b-2f1c8b6a9e11",
      chosenDistributionConfirmed: "4f0d2c1e-7a53-4a49-9d0b-2f1c8b6a9e11",
    };
    const { patch } = validateSessionWrite({
      expectedRevision: 2,
      progress: { certops },
    });
    assert.deepEqual(patch.progress.certops, certops);
  });

  it("only accepts known flows", () => {
    assert.equal(assertFlow("mega"), "mega");
    assert.equal(assertFlow("certops"), "certops");
    assert.throws(() => assertFlow("other"), { code: "INVALID_FLOW" });
  });
});
