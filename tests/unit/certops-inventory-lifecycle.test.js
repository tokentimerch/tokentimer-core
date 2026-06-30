"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  RETIRE_STATUSES,
  isRetiredCertificateStatus,
} = require("../../apps/api/services/certops/inventory");

describe("CertOps inventory lifecycle helpers", () => {
  it("exports retire statuses as a Set", () => {
    assert.ok(RETIRE_STATUSES instanceof Set);
    assert.deepEqual(Array.from(RETIRE_STATUSES).sort(), [
      "decommissioned",
      "revoked",
    ]);
  });

  it("recognizes retired certificate statuses after trim", () => {
    assert.equal(isRetiredCertificateStatus("revoked"), true);
    assert.equal(isRetiredCertificateStatus(" decommissioned "), true);
    assert.equal(isRetiredCertificateStatus("REVOKED"), true);
    assert.equal(isRetiredCertificateStatus("active"), false);
    assert.equal(isRetiredCertificateStatus(null), false);
  });
});
