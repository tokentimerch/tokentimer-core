"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  RETIRED_CERT_LIFECYCLE_STATUSES,
  RETIRED_CERT_UNSENT_ALERT_STATUSES,
  isRetiredCertLifecycleStatus,
  isRetiredCertificateSuppressedAlertKey,
  parseCertRenewalFailedJobId,
  shouldSkipRetiredCertificateAlert,
  shouldDiscardRetiredCertificateAlert,
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

  it("lists every unsent queue status the schema supports", () => {
    assert.deepEqual([...RETIRED_CERT_UNSENT_ALERT_STATUSES].sort(), [
      "blocked",
      "failed",
      "limit_exceeded",
      "partial",
      "pending",
    ]);
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

  it("parses the job id from a renewal-failure alert key", () => {
    assert.equal(
      parseCertRenewalFailedJobId(
        "cert_renewal_failed:11111111-1111-4111-8111-111111111111",
      ),
      "11111111-1111-4111-8111-111111111111",
    );
    assert.equal(parseCertRenewalFailedJobId("token_expiry:12:poswin:30"), null);
  });

  it("discards expiry alerts from the token lifecycle, not a sibling certificate", () => {
    assert.equal(
      shouldDiscardRetiredCertificateAlert({
        alertKey: "token_expiry:12:poswin:30",
        tokenLifecycleStatus: "revoked",
        jobCertificateStatus: "active",
      }),
      true,
    );
    assert.equal(
      shouldDiscardRetiredCertificateAlert({
        alertKey: "token_expiry:12:poswin:30",
        tokenLifecycleStatus: null,
        jobCertificateStatus: "revoked",
      }),
      false,
    );
  });

  it("discards renewal-failure alerts from the job certificate even when the token is still live", () => {
    assert.equal(
      shouldDiscardRetiredCertificateAlert({
        alertKey: "cert_renewal_failed:job-a",
        tokenLifecycleStatus: null,
        jobCertificateStatus: "decommissioned",
      }),
      true,
    );
    assert.equal(
      shouldDiscardRetiredCertificateAlert({
        alertKey: "cert_renewal_failed:job-b",
        tokenLifecycleStatus: null,
        jobCertificateStatus: "active",
      }),
      false,
    );
  });

  it("never discards endpoint or agent-health alerts from this policy", () => {
    assert.equal(
      shouldDiscardRetiredCertificateAlert({
        alertKey: "endpoint_health:mon-1:down",
        tokenLifecycleStatus: "revoked",
        jobCertificateStatus: "revoked",
      }),
      false,
    );
    assert.equal(
      shouldDiscardRetiredCertificateAlert({
        alertKey: "agent_health:agent-1:down",
        tokenLifecycleStatus: "revoked",
        jobCertificateStatus: "revoked",
      }),
      false,
    );
  });
});
