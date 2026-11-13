"use strict";

// Private process-local marker set only after both machine IP and prefix limits.
const CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED = Symbol("certopsExecutorPreAuthLimiterApplied");
function hasCertOpsExecutorPreAuthLimit(req) { return Boolean(req?.[CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED]); }
function markCertOpsExecutorPreAuthLimit(req) {
  Object.defineProperty(req, CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED, { configurable: false, enumerable: false, value: true });
}
module.exports = { CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED, hasCertOpsExecutorPreAuthLimit, markCertOpsExecutorPreAuthLimit };
