"use strict";

const RENEWAL_THRESHOLD_ENV = "CERTOPS_RENEWAL_THRESHOLD_DAYS";
const DEFAULT_RENEWAL_THRESHOLD_DAYS = 30;
const SUBDAY_LEAD_LIFETIME_DAYS = 2;
const MAX_ADAPTIVE_LIFETIME_DAYS = 90;
const MIN_RENEWAL_LEAD_DAYS = 7;
const SHORT_CERTIFICATE_LIFETIME_DAYS = 10;
const RENEWAL_LIFETIME_SHARE = 0.33;
const SECONDS_PER_DAY = 86400;

function resolveRenewalThresholdPolicy(env = process.env) {
  const configured = Number.parseInt(env[RENEWAL_THRESHOLD_ENV], 10);
  const adaptive = !Number.isSafeInteger(configured) || configured <= 0;
  return {
    thresholdDays: adaptive ? DEFAULT_RENEWAL_THRESHOLD_DAYS : configured,
    adaptive,
  };
}

function resolveRenewalThresholdDays(env = process.env) {
  return resolveRenewalThresholdPolicy(env).thresholdDays;
}

function resolveCertificateRenewalThresholdDays(row, env = process.env) {
  // SQL can return a fractional computed lead for short-lived certificates.
  const effective = row?.effective_renew_before_days;
  if (effective != null && Number.isFinite(Number(effective)) && Number(effective) >= 0) {
    return Number(effective);
  }
  const stored = row?.profile_renew_before_days;
  const override = Number(stored);
  if (stored != null && Number.isSafeInteger(override) && override >= 0) {
    return override;
  }

  const { thresholdDays, adaptive } = resolveRenewalThresholdPolicy(env);
  if (!adaptive || row?.not_before == null || row?.not_after == null) {
    return thresholdDays;
  }
  const lifetime =
    (new Date(row.not_after).getTime() - new Date(row.not_before).getTime()) /
    (SECONDS_PER_DAY * 1000);
  if (!(lifetime > 0 && lifetime < MAX_ADAPTIVE_LIFETIME_DAYS)) {
    return thresholdDays;
  }
  if (lifetime < SUBDAY_LEAD_LIFETIME_DAYS) {
    return lifetime / 2;
  }
  if (lifetime < SHORT_CERTIFICATE_LIFETIME_DAYS) {
    return Math.floor(lifetime / 2);
  }
  return Math.min(
    Math.floor(lifetime) - 1,
    Math.max(MIN_RENEWAL_LEAD_DAYS, Math.floor(lifetime * RENEWAL_LIFETIME_SHARE)),
  );
}

// All database renewal reads use the same expression and the mc/cp aliases.
// Cap the lead time below the issued lifetime to avoid immediate renewals.
function renewalThresholdDaysSql(parameter, adaptive) {
  const fallback = `${parameter}::numeric`;
  const lifetime =
    `(EXTRACT(EPOCH FROM (mc.not_after - mc.not_before)) / ${SECONDS_PER_DAY})`;
  const defaultDays = adaptive
    ? `CASE
         WHEN ${lifetime} > 0
          AND ${lifetime} < ${MAX_ADAPTIVE_LIFETIME_DAYS}
         THEN CASE WHEN ${lifetime} < ${SUBDAY_LEAD_LIFETIME_DAYS}
                   THEN ${lifetime} / 2
                   WHEN ${lifetime} < ${SHORT_CERTIFICATE_LIFETIME_DAYS}
                   THEN FLOOR(${lifetime} / 2)
                   ELSE LEAST(FLOOR(${lifetime}) - 1,
                    GREATEST(${MIN_RENEWAL_LEAD_DAYS}, FLOOR(${lifetime} * ${RENEWAL_LIFETIME_SHARE}))) END
         ELSE ${fallback}
       END`
    : fallback;
  return `COALESCE(cp.renew_before_days, ${defaultDays})`;
}

module.exports = {
  DEFAULT_RENEWAL_THRESHOLD_DAYS,
  RENEWAL_THRESHOLD_ENV,
  renewalThresholdDaysSql,
  resolveCertificateRenewalThresholdDays,
  resolveRenewalThresholdDays,
  resolveRenewalThresholdPolicy,
};
