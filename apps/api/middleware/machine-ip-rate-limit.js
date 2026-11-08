"use strict";

const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");
const { requestIpKey } = require("./request-ip-key");

const MAX_TIMER_MS = 2 ** 31 - 1;

function positiveEnv(name, fallback, max = Number.MAX_SAFE_INTEGER) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw)) || Number(raw) < 1 || Number(raw) > max) {
    throw new Error(`Invalid positive integer for ${name}`);
  }
  return Number(raw);
}

// This aggregate boundary executes before prefix-key allocation and JSON parsing.
function createCertOpsMachineIpRateLimit() {
  const limit = rateLimit({
    windowMs: positiveEnv("CERTOPS_MACHINE_IP_RATE_LIMIT_WINDOW_MS", 60_000, MAX_TIMER_MS),
    limit: positiveEnv("CERTOPS_MACHINE_IP_RATE_LIMIT_MAX", 3_000),
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: requestIpKey,
    message: { error: "CertOps machine IP rate limit exceeded", code: "CERTOPS_MACHINE_IP_RATE_LIMITED" },
  });
  const delayMs = positiveEnv("CERTOPS_MACHINE_IP_SLOWDOWN_DELAY_MS", 500);
  const slowdown = slowDown({
    windowMs: positiveEnv("CERTOPS_MACHINE_IP_SLOWDOWN_WINDOW_MS", 900_000, MAX_TIMER_MS),
    delayAfter: positiveEnv("CERTOPS_MACHINE_IP_SLOWDOWN_DELAY_AFTER", 30_000),
    delayMs: () => delayMs,
    keyGenerator: requestIpKey, validate: { delayMs: false },
  });
  return (req, res, next) => limit(req, res, (err) => err ? next(err) : slowdown(req, res, next));
}

module.exports = { createCertOpsMachineIpRateLimit };
