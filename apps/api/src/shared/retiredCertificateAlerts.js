"use strict";

/**
 * Expiry and renewal-failure alerts for CertOps-retired certificates.
 *
 * Retiring a certificate keeps the token row (ADR-0007) so inventory and
 * evidence survive. The token's expiry is then meaningless, so the alert
 * pipeline skips revoked and decommissioned certificates the same way
 * Control Center already excludes them from asset health.
 *
 * Keep in sync with apps/worker/src/shared/retiredCertificateAlerts.js.
 */

const RETIRED_CERT_LIFECYCLE_STATUSES = Object.freeze([
  "revoked",
  "decommissioned",
]);

const RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES = Object.freeze([
  "token_expiry:",
  "cert_renewal_failed:",
]);

function isRetiredCertLifecycleStatus(status) {
  return RETIRED_CERT_LIFECYCLE_STATUSES.includes(
    String(status || "").trim().toLowerCase(),
  );
}

function isRetiredCertificateSuppressedAlertKey(alertKey) {
  const key = String(alertKey || "");
  return RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES.some((prefix) =>
    key.startsWith(prefix),
  );
}

function shouldSkipRetiredCertificateAlert(certLifecycleStatus) {
  return isRetiredCertLifecycleStatus(certLifecycleStatus);
}

module.exports = {
  RETIRED_CERT_LIFECYCLE_STATUSES,
  RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES,
  isRetiredCertLifecycleStatus,
  isRetiredCertificateSuppressedAlertKey,
  shouldSkipRetiredCertificateAlert,
};
