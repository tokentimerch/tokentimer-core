"use strict";

const DEFAULT_ALERT_THRESHOLDS = Object.freeze([30, 14, 7, 1, 0]);
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

const DAY_MS = 86400000;

function calendarDay(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "string") {
    const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(value);
    if (match) {
      return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
    }
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  // PostgreSQL DATE values represent calendar dates and pg materializes them at
  // local midnight. Preserve that date instead of shifting it through UTC.
  return Date.UTC(date.getFullYear(), date.getMonth(), date.getDate());
}

function utcDay(value) {
  if (value === null || value === undefined || value === "") return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
  );
}

function formatUtcDay(value) {
  const day = utcDay(value);
  if (day === null) return null;
  return new Date(day).toISOString().slice(0, 10);
}

function formatCalendarDay(value) {
  const day = calendarDay(value);
  if (day === null) return null;
  return new Date(day).toISOString().slice(0, 10);
}

function computeDaysLeft(expiration, referenceDate = new Date()) {
  const expirationDay = calendarDay(expiration);
  const referenceDay = utcDay(referenceDate);
  if (expirationDay === null || referenceDay === null) return null;
  return Math.round((expirationDay - referenceDay) / DAY_MS);
}

function findThresholdWindow(daysUntil, thresholds) {
  if (daysUntil === null || daysUntil === undefined) return null;
  if (!Array.isArray(thresholds) || thresholds.length === 0) return null;

  const thresholdsAsc = [...new Set(thresholds)].sort((a, b) => a - b);
  if (daysUntil < 0) {
    const thresholdReached = thresholdsAsc
      .filter((threshold) => threshold < 0)
      .find((threshold) => daysUntil <= threshold);
    if (thresholdReached === undefined) return null;
    return { thresholdReached, negativeWindow: true };
  }

  const thresholdReached = thresholdsAsc.find(
    (threshold) => daysUntil <= threshold,
  );
  if (thresholdReached === undefined) return null;
  return { thresholdReached, negativeWindow: false };
}

function thresholdDateUtc(expiration, threshold) {
  const expirationDay = calendarDay(expiration);
  if (expirationDay === null || !Number.isFinite(threshold)) return null;
  return expirationDay - threshold * DAY_MS;
}

function isStaleImportThreshold(
  importedAt,
  expiration,
  thresholdReached,
  _negativeWindow,
) {
  const importedDay = utcDay(importedAt);
  const thresholdDay = thresholdDateUtc(expiration, thresholdReached);
  if (importedDay === null || thresholdDay === null) return false;
  return importedDay > thresholdDay;
}

function resolveContactGroup({
  contactGroups,
  contactGroupId,
  defaultContactGroupId,
}) {
  try {
    const groups = Array.isArray(contactGroups) ? contactGroups : [];
    const pickId =
      contactGroupId && String(contactGroupId).trim().length > 0
        ? String(contactGroupId)
        : defaultContactGroupId
          ? String(defaultContactGroupId)
          : null;
    if (!pickId) return null;

    let resolvedGroup =
      groups.find((group) => String(group.id) === pickId) || null;
    if (!resolvedGroup && contactGroupId && defaultContactGroupId) {
      resolvedGroup =
        groups.find(
          (group) => String(group.id) === String(defaultContactGroupId),
        ) || null;
    }
    return resolvedGroup;
  } catch (_) {
    return null;
  }
}

function hasEmailContacts(contactGroup) {
  return Boolean(
    contactGroup &&
      Array.isArray(contactGroup.email_contact_ids) &&
      contactGroup.email_contact_ids.length > 0,
  );
}

function hasWhatsAppContacts(contactGroup) {
  return Boolean(
    contactGroup &&
      Array.isArray(contactGroup.whatsapp_contact_ids) &&
      contactGroup.whatsapp_contact_ids.length > 0,
  );
}

function hasWebhookNames(contactGroup) {
  return Boolean(
    contactGroup &&
      (contactGroup.webhook_name ||
        (Array.isArray(contactGroup.webhook_names) &&
          contactGroup.webhook_names.length > 0)),
  );
}

function getWebhookNames(contactGroup) {
  if (!contactGroup) return [];
  if (Array.isArray(contactGroup.webhook_names)) {
    return contactGroup.webhook_names
      .filter(Boolean)
      .map((name) => String(name).trim());
  }
  if (contactGroup.webhook_name) {
    return [String(contactGroup.webhook_name).trim()];
  }
  return [];
}

function isRetiredCertLifecycleStatus(status) {
  return RETIRED_CERT_LIFECYCLE_STATUSES.includes(
    String(status || "").trim().toLowerCase(),
  );
}

function isTokenExpiryAlertKey(alertKey) {
  return String(alertKey || "").startsWith(TOKEN_EXPIRY_ALERT_PREFIX);
}

function isRenewalFailureAlertKey(alertKey) {
  return String(alertKey || "").startsWith(
    CERT_RENEWAL_FAILED_ALERT_PREFIX,
  );
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

function normalizeDefaultThresholds(defaultThresholds) {
  const source = Array.isArray(defaultThresholds)
    ? defaultThresholds
    : DEFAULT_ALERT_THRESHOLDS;
  return source.filter((threshold) => Number.isFinite(threshold));
}

function resolveEffectiveThresholds(asset, resolvedGroup, defaultThresholds) {
  let thresholds = normalizeDefaultThresholds(defaultThresholds);
  if (Array.isArray(asset.alert_thresholds)) {
    thresholds = asset.alert_thresholds.filter((threshold) =>
      Number.isFinite(threshold),
    );
  }

  if (
    resolvedGroup &&
    Array.isArray(resolvedGroup.thresholds) &&
    resolvedGroup.thresholds.length > 0
  ) {
    const override = resolvedGroup.thresholds
      .map((threshold) => Number(threshold))
      .filter(
        (threshold) =>
          Number.isFinite(threshold) && threshold >= -365 && threshold <= 730,
      );
    if (override.length > 0) thresholds = override;
  }

  return [...new Set(thresholds)].sort((a, b) => b - a);
}

function resolveEligibleChannels(asset, resolvedGroup) {
  const channels = [];
  if (asset.ws_email_alerts_enabled !== false && hasEmailContacts(resolvedGroup)) {
    channels.push("email");
  }

  const webhooks = Array.isArray(asset.webhook_urls)
    ? asset.webhook_urls
    : [];
  if (resolvedGroup && hasWebhookNames(resolvedGroup)) {
    let hasWebhook = false;
    try {
      const names = getWebhookNames(resolvedGroup);
      hasWebhook = webhooks.some((webhook) =>
        names.includes(String(webhook.name || "").trim()),
      );
    } catch (_) {
      hasWebhook = true;
    }
    if (hasWebhook) channels.push("webhooks");
  }

  if (hasWhatsAppContacts(resolvedGroup)) channels.push("whatsapp");
  return channels;
}

function thresholdKind(threshold) {
  if (threshold < 0) return "post_expiry";
  if (threshold === 0) return "expiry_day";
  return "pre_expiry";
}

function findNextThreshold(asset, thresholds, referenceDate) {
  const referenceDay = utcDay(referenceDate);
  if (referenceDay === null) return null;

  const candidates = thresholds
    .map((threshold) => ({
      threshold,
      day: thresholdDateUtc(asset.expiration, threshold),
    }))
    .filter((candidate) => candidate.day !== null && candidate.day > referenceDay)
    .sort((a, b) => a.day - b.day);
  if (candidates.length === 0) return null;
  return {
    threshold: candidates[0].threshold,
    at: formatUtcDay(candidates[0].day),
  };
}

function evaluateAlertEligibility(
  asset = {},
  { defaultThresholds = DEFAULT_ALERT_THRESHOLDS, referenceDate = new Date() } = {},
) {
  const daysUntilExpiry = computeDaysLeft(asset.expiration, referenceDate);
  const resolvedGroup = resolveContactGroup({
    contactGroups: asset.contact_groups,
    contactGroupId: asset.contact_group_id,
    defaultContactGroupId: asset.default_contact_group_id,
  });
  const effectiveThresholds = resolveEffectiveThresholds(
    asset,
    resolvedGroup,
    defaultThresholds,
  );
  const eligibleChannels = resolveEligibleChannels(asset, resolvedGroup);
  const importedDay = utcDay(asset.imported_at);
  const expirationDay = calendarDay(asset.expiration);
  const expiredAtImport =
    importedDay !== null &&
    expirationDay !== null &&
    importedDay > expirationDay;
  const base = {
    status: "outside_threshold",
    reason: "threshold_not_reached",
    days_until_expiry: daysUntilExpiry,
    effective_threshold: null,
    effective_thresholds: effectiveThresholds,
    threshold_type: null,
    threshold_date: null,
    next_evaluation_at: null,
    next_threshold: null,
    eligible_channels: eligibleChannels,
    contact_group_id: resolvedGroup?.id || null,
    contact_group_name: resolvedGroup?.name || null,
    metadata: {
      expiration_date: formatCalendarDay(asset.expiration),
      imported_at: asset.imported_at || null,
      expired_at_import: expiredAtImport,
      certificate_lifecycle_status: asset.cert_lifecycle_status || null,
    },
  };

  if (shouldSkipRetiredCertificateAlert(asset.cert_lifecycle_status)) {
    return {
      ...base,
      status: "suppressed",
      reason: "retired_certificate",
    };
  }

  if (daysUntilExpiry === null) {
    return { ...base, reason: "invalid_expiration" };
  }

  const thresholdResult = findThresholdWindow(
    daysUntilExpiry,
    effectiveThresholds,
  );
  if (!thresholdResult) {
    const next = findNextThreshold(asset, effectiveThresholds, referenceDate);
    const hasPostExpiryThreshold = effectiveThresholds.some(
      (threshold) => threshold < 0,
    );
    return {
      ...base,
      reason:
        daysUntilExpiry < 0 && !hasPostExpiryThreshold
          ? "post_expiry_threshold_not_configured"
          : "threshold_not_reached",
      next_evaluation_at: next?.at || null,
      next_threshold: next?.threshold ?? null,
    };
  }

  const { thresholdReached, negativeWindow } = thresholdResult;
  const thresholdDate = formatUtcDay(
    thresholdDateUtc(asset.expiration, thresholdReached),
  );
  const reached = {
    ...base,
    effective_threshold: thresholdReached,
    threshold_type: thresholdKind(thresholdReached),
    threshold_date: thresholdDate,
  };

  if (
    isStaleImportThreshold(
      asset.imported_at,
      asset.expiration,
      thresholdReached,
      negativeWindow,
    )
  ) {
    const next = findNextThreshold(asset, effectiveThresholds, referenceDate);
    return {
      ...reached,
      status: "suppressed",
      reason: "stale_import_threshold",
      next_evaluation_at: next?.at || null,
      next_threshold: next?.threshold ?? null,
      metadata: {
        ...reached.metadata,
        imported_after_threshold: true,
      },
    };
  }

  if (eligibleChannels.length === 0) {
    return {
      ...reached,
      status: "suppressed",
      reason: "no_eligible_channels",
    };
  }

  return {
    ...reached,
    status: "due",
    reason: "threshold_reached",
  };
}

module.exports = {
  DEFAULT_ALERT_THRESHOLDS,
  RETIRED_CERT_LIFECYCLE_STATUSES,
  RETIRED_CERT_SUPPRESSED_ALERT_PREFIXES,
  RETIRED_CERT_UNSENT_ALERT_STATUSES,
  TOKEN_EXPIRY_ALERT_PREFIX,
  CERT_RENEWAL_FAILED_ALERT_PREFIX,
  computeDaysLeft,
  findThresholdWindow,
  isStaleImportThreshold,
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
  isRetiredCertLifecycleStatus,
  isTokenExpiryAlertKey,
  isRenewalFailureAlertKey,
  isRetiredCertificateSuppressedAlertKey,
  parseCertRenewalFailedJobId,
  shouldSkipRetiredCertificateAlert,
  shouldDiscardRetiredCertificateAlert,
  resolveEffectiveThresholds,
  resolveEligibleChannels,
  evaluateAlertEligibility,
};
