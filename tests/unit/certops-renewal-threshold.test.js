"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const { resolveCertificateRenewalThresholdDays, renewalThresholdDaysSql } = require("../../apps/api/services/certops/renewalThreshold.js");

it("waits until at least halfway through certificates shorter than ten days", () => {
  const issued = Date.parse("2026-01-01T00:00:00Z");
  const row = (hours) => ({ not_before: new Date(issued), not_after: new Date(issued + hours * 3600000) });
  assert.equal(resolveCertificateRenewalThresholdDays(row(1), {}), 1 / 48);
  assert.equal(resolveCertificateRenewalThresholdDays(row(24), {}), 0.5);
  assert.equal(resolveCertificateRenewalThresholdDays({ ...row(24), profile_renew_before_days: 1 }, {}), 1);
  assert.equal(resolveCertificateRenewalThresholdDays(row(24), { CERTOPS_RENEWAL_THRESHOLD_DAYS: "4" }), 4);
  assert.equal(resolveCertificateRenewalThresholdDays(row(47), {}), 47 / 48);
  assert.equal(resolveCertificateRenewalThresholdDays({ ...row(24), effective_renew_before_days: "0.5" }, {}), 0.5);
  assert.equal(resolveCertificateRenewalThresholdDays(row(0), {}), 30);
  assert.equal(resolveCertificateRenewalThresholdDays(row(160), {}), 3);
  assert.equal(resolveCertificateRenewalThresholdDays(row(48), {}), 1);
  assert.equal(resolveCertificateRenewalThresholdDays(row(240), {}), 7);
  assert.equal(resolveCertificateRenewalThresholdDays({ ...row(160), profile_renew_before_days: 5 }, {}), 5);
  assert.equal(resolveCertificateRenewalThresholdDays(row(160), { CERTOPS_RENEWAL_THRESHOLD_DAYS: "4" }), 4);
  assert.match(renewalThresholdDaysSql("$2", true), /< 10\s+THEN FLOOR/);
});
