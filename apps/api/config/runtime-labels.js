"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_LABELS = Object.freeze({
  service: "tokentimer-core-api",
  rateLabel: "oss",
  plan: "oss",
  limitsKey: "oss",
});

const MODE_LABELS = Object.freeze({
  oss: DEFAULT_LABELS,
  core: DEFAULT_LABELS,
  enterprise: Object.freeze({
    service: "tokentimer-enterprise-api",
    rateLabel: "enterprise",
    plan: "enterprise",
    limitsKey: "enterprise",
  }),
  cloud: Object.freeze({
    service: "tokentimer-cloud",
    rateLabel: "cloud",
    plan: "cloud",
    limitsKey: "cloud",
  }),
});

let cachedLabels;

/**
 * Resolve deployment mode from env or /.tokentimer-variant (written by variant images).
 * @returns {string}
 */
function normalizeMode() {
  const fromEnv = process.env.TT_MODE || process.env.TT_VARIANT;
  if (fromEnv && String(fromEnv).trim()) {
    return String(fromEnv).trim().toLowerCase();
  }
  try {
    const variantPath = path.join(process.cwd(), ".tokentimer-variant");
    if (!fs.existsSync(variantPath)) return "oss";
    const text = fs.readFileSync(variantPath, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const match = /^variant=(.+)$/.exec(line.trim());
      if (match) return match[1].trim().toLowerCase();
    }
  } catch (_) {
    /* optional file */
  }
  return "oss";
}

/**
 * Logging, rate-limit log types, and default plan/limit keys for this runtime.
 * Env overrides: LOG_SERVICE_NAME, API_RATE_LIMIT_LOG_LABEL, API_RATE_LIMIT_PLAN, API_RATE_LIMIT_LIMITS_KEY.
 * @returns {{ service: string, rateLabel: string, plan: string, limitsKey: string }}
 */
function getRuntimeLabels() {
  if (cachedLabels) return cachedLabels;
  const preset = MODE_LABELS[normalizeMode()] || DEFAULT_LABELS;
  cachedLabels = Object.freeze({
    service:
      String(process.env.LOG_SERVICE_NAME || "").trim() || preset.service,
    rateLabel:
      String(process.env.API_RATE_LIMIT_LOG_LABEL || "").trim() ||
      preset.rateLabel,
    plan: String(process.env.API_RATE_LIMIT_PLAN || "").trim() || preset.plan,
    limitsKey:
      String(process.env.API_RATE_LIMIT_LIMITS_KEY || "").trim() ||
      preset.limitsKey,
  });
  return cachedLabels;
}

/** @param {string} mode */
function resetRuntimeLabelsCacheForTests(mode) {
  cachedLabels = undefined;
  if (mode === undefined) {
    delete process.env.TT_MODE;
    delete process.env.TT_VARIANT;
    return;
  }
  process.env.TT_MODE = mode;
}

module.exports = {
  getRuntimeLabels,
  normalizeMode,
  resetRuntimeLabelsCacheForTests,
};
