/*
 * VENDORED COPY for self-contained agent distribution.
 * Source of truth: packages/contracts/certops/adcs-preflight-freshness.cjs (@tokentimer/contracts).
 * Refresh with: node packages/agent/scripts/sync-vendor.js
 * Keep the value identical to upstream so the agent cache and the scheduler
 * agree on how long a preflight is usable.
 */
"use strict";

/**
 * How long a safe adcs-preflight stays usable. The agent reuses its cached CA
 * pin and template OID only inside this window, and the control plane only
 * starts an AD CS renewal on a preflight this recent. One value, so the two
 * sides cannot disagree about when a CA check goes stale.
 */
const ADCS_PREFLIGHT_MAX_AGE_MS = 24 * 60 * 60 * 1000;

module.exports = Object.freeze({ ADCS_PREFLIGHT_MAX_AGE_MS });
