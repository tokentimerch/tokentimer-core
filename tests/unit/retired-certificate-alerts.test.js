"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  RETIRED_CERT_LIFECYCLE_STATUSES,
  isRetiredCertLifecycleStatus,
  isRetiredCertificateSuppressedAlertKey,
  shouldSkipRetiredCertificateAlert,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/src/shared/retiredCertificateAlerts.js",
  ),
);

describe("retired certificate alert policy", () => {
  it("treats revoked and decommissioned as retired", () => {
    assert.deepEqual([...RETIRED_CERT_LIFECYCLE_STATUSES].sort(), [
      "decommissioned",
      "revoked",
    ]);
    assert.equal(isRetiredCertLifecycleStatus("revoked"), true);
    assert.equal(isRetiredCertLifecycleStatus(" decommissioned "), true);
    assert.equal(isRetiredCertLifecycleStatus("REVOKED"), true);
    assert.equal(isRetiredCertLifecycleStatus("active"), false);
    assert.equal(isRetiredCertLifecycleStatus(null), false);
  });

  it("skips expiry alerts for retired certificates", () => {
    assert.equal(shouldSkipRetiredCertificateAlert("revoked"), true);
    assert.equal(shouldSkipRetiredCertificateAlert("decommissioned"), true);
  });

  it("never skips non-CertOps tokens or live certificates", () => {
    assert.equal(shouldSkipRetiredCertificateAlert(null), false);
    assert.equal(shouldSkipRetiredCertificateAlert("expiring"), false);
  });

  it("only suppresses expiry and renewal-failure queue keys", () => {
    assert.equal(
      isRetiredCertificateSuppressedAlertKey("token_expiry:12:poswin:30"),
      true,
    );
    assert.equal(
      isRetiredCertificateSuppressedAlertKey("cert_renewal_failed:abc"),
      true,
    );
    assert.equal(
      isRetiredCertificateSuppressedAlertKey("endpoint_health:mon-1:down"),
      false,
    );
    assert.equal(
      isRetiredCertificateSuppressedAlertKey("agent_health:agent-1:down"),
      false,
    );
  });
});
