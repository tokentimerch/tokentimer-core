/**
 * Expiry and renewal-failure alerts for CertOps-retired certificates.
 *
 * Keep in sync with apps/api/src/shared/retiredCertificateAlerts.js.
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

export {
  RETIRED_CERT_LIFECYCLE_STATUSES,
  RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES,
  isRetiredCertLifecycleStatus,
  isRetiredCertificateSuppressedAlertKey,
  shouldSkipRetiredCertificateAlert,
};
