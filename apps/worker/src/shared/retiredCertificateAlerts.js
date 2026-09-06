/**
 * Expiry and renewal-failure alerts for CertOps-retired certificates.
 *
 * Keep in sync with apps/api/src/shared/retiredCertificateAlerts.js.
 */

const RETIRED_CERT_LIFECYCLE_STATUSES = Object.freeze([
  "revoked",
  "decommissioned",
]);

const TOKEN_EXPIRY_ALERT_PREFIX = "token_expiry:";
const CERT_RENEWAL_FAILED_ALERT_PREFIX = "cert_renewal_failed:";

const RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES = Object.freeze([
  TOKEN_EXPIRY_ALERT_PREFIX,
  CERT_RENEWAL_FAILED_ALERT_PREFIX,
]);

const RETIRED_CERT_UNSENT_ALERT_STATUSES = Object.freeze([
  "pending",
  "failed",
  "partial",
  "blocked",
  "limit_exceeded",
]);

function isRetiredCertLifecycleStatus(status) {
  return RETIRED_CERT_LIFECYCLE_STATUSES.includes(
    String(status || "").trim().toLowerCase(),
  );
}

function isTokenExpiryAlertKey(alertKey) {
  return String(alertKey || "").startsWith(TOKEN_EXPIRY_ALERT_PREFIX);
}

function isRenewalFailureAlertKey(alertKey) {
  return String(alertKey || "").startsWith(CERT_RENEWAL_FAILED_ALERT_PREFIX);
}

function isRetiredCertificateSuppressedAlertKey(alertKey) {
  return isTokenExpiryAlertKey(alertKey) || isRenewalFailureAlertKey(alertKey);
}

function parseCertRenewalFailedJobId(alertKey) {
  const key = String(alertKey || "");
  if (!key.startsWith(CERT_RENEWAL_FAILED_ALERT_PREFIX)) return null;
  const jobId = key.slice(CERT_RENEWAL_FAILED_ALERT_PREFIX.length).trim();
  return jobId || null;
}

function shouldSkipRetiredCertificateAlert(certLifecycleStatus) {
  return isRetiredCertLifecycleStatus(certLifecycleStatus);
}

function shouldDiscardRetiredCertificateAlert({
  alertKey,
  tokenLifecycleStatus,
  jobCertificateStatus,
} = {}) {
  if (isTokenExpiryAlertKey(alertKey)) {
    return isRetiredCertLifecycleStatus(tokenLifecycleStatus);
  }
  if (isRenewalFailureAlertKey(alertKey)) {
    return isRetiredCertLifecycleStatus(jobCertificateStatus);
  }
  return false;
}

export {
  RETIRED_CERT_LIFECYCLE_STATUSES,
  RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES,
  RETIRED_CERT_UNSENT_ALERT_STATUSES,
  TOKEN_EXPIRY_ALERT_PREFIX,
  CERT_RENEWAL_FAILED_ALERT_PREFIX,
  isRetiredCertLifecycleStatus,
  isTokenExpiryAlertKey,
  isRenewalFailureAlertKey,
  isRetiredCertificateSuppressedAlertKey,
  parseCertRenewalFailedJobId,
  shouldSkipRetiredCertificateAlert,
  shouldDiscardRetiredCertificateAlert,
};
