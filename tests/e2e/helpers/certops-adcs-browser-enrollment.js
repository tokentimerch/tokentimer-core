"use strict";

/** Local contract for browser preflight, confirmation, then enrollment.
 * Confirmation is required before submit. This module does not launch a
 * browser. A missing browser fails closed. nativeExecutionQualified stays false.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SUITE = "adcs-browser-enrollment";
const SOURCE = "tests/e2e/helpers/certops-adcs-browser-enrollment.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "browser-preflight-confirmation-enrollment";
const DEFAULT_REPORT = "qualification-results/adcs-browser-enrollment.json";
const JOURNEY = Object.freeze(["preflight", "confirmation", "enrollment"]);
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-browser-preflight",
  "adcs-browser-confirmation-before-submit",
  "adcs-browser-enrollment",
]);
const REQUIRED_CAPABILITIES = Object.freeze([
  "windows",
  "domain",
  "api",
  "browser",
  "qualifiedBuild",
]);
const REQUIRED_SOURCES = Object.freeze([
  SOURCE,
  "scripts/certops-adcs-browser-enrollment.js",
  "docs/certops/adcs/browser-enrollment.md",
  ".github/workflows/certops-adcs-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "journey",
  "confirmationBeforeSubmit",
  "browserLaunched",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);

function assessLab(env = process.env, platform = process.platform) {
  const missing = [];
  if (platform !== "win32") missing.push("win32");
  if (env.CERTOPS_ADCS_DISPOSABLE_LAB !== "1") missing.push("CERTOPS_ADCS_DISPOSABLE_LAB");
  try {
    if (new URL(env.CERTOPS_ADCS_API_URL || "").protocol !== "https:") missing.push("CERTOPS_ADCS_API_URL");
  } catch {
    missing.push("CERTOPS_ADCS_API_URL");
  }
  return {
    ok: missing.length === 0,
    missing,
    passed: false,
    nativeQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function assessBrowser(probe) {
  const required = ["browser", "ownedPage", "confirmationControl"];
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) {
    return {
      available: false,
      missing: required,
      passed: false,
      nativeQualified: false,
      hostCapabilityAbsentIsPass: false,
    };
  }
  const missing = required.filter((name) => probe[name] !== true);
  return {
    available: missing.length === 0,
    missing,
    passed: false,
    nativeQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function assertJourney(events) {
  assert.ok(Array.isArray(events), "Browser enrollment journey is required");
  let confirmed = false;
  let sawPreflight = false;
  const seen = [];
  for (const event of events) {
    const step = event && event.step;
    if (step === "submit" && !confirmed) throw new Error("Confirmation is required before submit");
    if (step === "preflight") {
      if (seen.length !== 0) throw new Error("Browser enrollment journey order required");
      sawPreflight = true;
    } else if (step === "confirmation") {
      if (!sawPreflight || confirmed) throw new Error("Browser enrollment journey order required");
      confirmed = true;
    } else if (step === "enrollment") {
      if (!confirmed) throw new Error("Confirmation is required before submit");
    } else {
      throw new Error("Browser enrollment journey order required");
    }
    seen.push(step);
  }
  assert.deepEqual(seen, [...JOURNEY]);
  return true;
}

function acceptJourney(events) {
  assertJourney(events);
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    journey: [...JOURNEY],
    confirmationBeforeSubmit: true,
    browserLaunched: false,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return proof;
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.deepEqual(value.journey, [...JOURNEY]);
  assert.equal(value.confirmationBeforeSubmit, true);
  assert.equal(value.browserLaunched, false);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

function qualifyBrowserEnrollment(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  const browser = assessBrowser(context.browser);
  if (!browser.available) throw new Error(`Browser is required: ${browser.missing.join(",")}`);
  throw new Error("Browser enrollment contract does not launch a browser");
}

function buildClosedReport(reason) {
  const now = new Date().toISOString();
  const candidate = process.env.GITHUB_SHA;
  return {
    schemaVersion: 1,
    suite: SUITE,
    strict: true,
    evidenceLevel: EVIDENCE_LEVEL,
    status: "failed",
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    disposableForestRan: false,
    browserLaunched: false,
    startedAt: now,
    finishedAt: now,
    candidateSha: /^[a-f0-9]{40}$/i.test(candidate || "") ? candidate : "0".repeat(40),
    requiredCapabilities: [...REQUIRED_CAPABILITIES],
    capabilities: {},
    requiredScenarios: [...REQUIRED_SCENARIOS],
    missingScenarios: [...REQUIRED_SCENARIOS],
    missingCapabilities: [...REQUIRED_CAPABILITIES],
    scenarios: [],
    cleanup: { status: "failed", summary: String(reason).slice(0, 512) },
    fixturePrerequisite: "No disposable forest executed this journey. A failed report is not native qualification.",
  };
}

function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const browser = assessBrowser(options.browser);
  const reportPath = options.reportPath || env.CERTOPS_ADCS_BROWSER_ENROLLMENT_REPORT || DEFAULT_REPORT;
  const reason = !lab.ok
    ? `Disposable AD CS forest is required: ${lab.missing.join(",")}`
    : !browser.available
      ? `Browser is required: ${browser.missing.join(",")}`
      : "Browser enrollment contract does not launch a browser";
  writeReport(reportPath, buildClosedReport(reason));
  console.error(reason);
  return 1;
}

if (require.main === module) process.exitCode = dispatch();

module.exports = {
  SUITE,
  SOURCE,
  SCOPE,
  EVIDENCE_LEVEL,
  JOURNEY,
  REQUIRED_SCENARIOS,
  REQUIRED_CAPABILITIES,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  DEFAULT_REPORT,
  assessLab,
  assessBrowser,
  assertJourney,
  acceptJourney,
  verifyProof,
  qualifyBrowserEnrollment,
  buildClosedReport,
  dispatch,
};
