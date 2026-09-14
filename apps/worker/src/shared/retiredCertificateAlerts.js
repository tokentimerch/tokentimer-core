import alertEligibility from "@tokentimer/alert-eligibility";

const {
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
} = alertEligibility;

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
