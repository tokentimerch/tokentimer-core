"use strict";

/** Local contract for browser preflight, confirmation, then enrollment.
 * Confirmation is required before submit. This module does not launch a
 * browser. A missing browser fails closed. nativeExecutionQualified stays false.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

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
// Native qualification reuses the complete supported browser renewal journey.
// Local marker/ordering contracts never enter this projection.
function nativeRequiredScenarios() {
  return ["adcs-real-installed-native-language", "adcs-real-agent-registration-system", ...require("./certops-adcs-browser-journey").REQUIRED_SCENARIOS, "adcs-real-owned-cleanup"];
}
function nativeRequiredSources() {
  return [...new Set([SOURCE, ...require("./certops-adcs-browser-journey").REQUIRED_SOURCES])];
}
function verifyNativeProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "nativeExecutionQualified", "browserLaunched", "disposableForestRan", "hostCapabilityAbsentIsPass", "confirmationBeforeSubmit", "parentSuite", "nativeBrowserJourney"].sort());
  assert.equal(value.scope, "native-browser-preflight-confirmation-profile-enrollment");
  for (const field of ["nativeExecutionQualified", "browserLaunched", "disposableForestRan", "confirmationBeforeSubmit"]) assert.equal(value[field], true);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  assert.equal(value.parentSuite, "enterprise-adcs-real");
  require("./certops-adcs-browser-journey").verifyProof(value.nativeBrowserJourney);
  assert.equal(value.nativeBrowserJourney.noEnrollmentBeforeConfirmation, true);
  return true;
}
function createNativeReport(parent, { candidateSha = process.env.GITHUB_SHA, root = path.resolve(__dirname, "../../..") } = {}) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  assert.equal(parent.suite, "enterprise-adcs-real");
  assert.equal(parent.experimental === true || parent.qualificationStatus === "not-qualified", false);
  assert.equal(parent.artifactQualification, "workflow-checkout-source");
  assert.equal(parent.platform, "win32"); assert.equal(parent.architecture, "x64");
  for (const [field, value] of Object.entries({osFamily:"windows",osVersion:"2022",nativeLanguage:"en-US",identity:"LocalSystem",measurement:"native"})) assert.equal(parent.qualificationEnvironment?.[field], value);
  assert.equal(parent.cleanup?.status, "passed");
  assert.deepEqual(require("../../../scripts/certops-qualification-report").verifyReport(parent, undefined, {expectedSha:candidateSha}), []);
  const fingerprint = file => ({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  assert.deepEqual(parent.fixtureSource, fingerprint("tests/e2e/certops-adcs-real-e2e.test.js"));
  const fixtureSources = nativeRequiredSources().map(file => {
    const actual = fingerprint(file), entries = parent.fixtureSources?.filter(entry => entry.file === file);
    assert.equal(entries?.length, 1, "Native browser producer source must be observed exactly once");
    assert.deepEqual(entries[0], actual);
    return actual;
  });
  const requiredScenarios = nativeRequiredScenarios();
  const scenarios = requiredScenarios.map(id => {
    const records = parent.scenarios.filter(entry => entry.id === id);
    assert.equal(records.length, 1); assert.equal(records[0].status, "passed");
    assert.equal(records[0].evidenceLevel, "real-host");
    return {...records[0]};
  });
  const ordered = scenarios;
  for (let i=1;i<ordered.length;i++) assert.ok(Date.parse(ordered[i-1].finishedAt) <= Date.parse(ordered[i].startedAt), "Actual browser stages must complete in order");
  const proof = {scope:"native-browser-preflight-confirmation-profile-enrollment",nativeExecutionQualified:true,browserLaunched:true,disposableForestRan:true,hostCapabilityAbsentIsPass:false,confirmationBeforeSubmit:true,parentSuite:parent.suite,nativeBrowserJourney:structuredClone(parent.nativeBrowserAdcs)};
  verifyNativeProof(proof);
  const report = {...parent,suite:SUITE,evidenceLevel:"real-host",fixtureSource:fingerprint(SOURCE),fixtureSources,requiredScenarios,scenarios,
    requiredCapabilities:["windows","elevated","domain","api","qualifiedBuild","browserRuntime","dashboard"],missingScenarios:[],missingCapabilities:[],nativeAdcsBrowserEnrollment:proof};
  // Copy only bounded public fields; do not republish unrelated native receipts.
  const keys = ["schemaVersion","suite","strict","status","candidateSha","startedAt","finishedAt","platform","architecture","cleanup","qualificationEnvironment","artifactQualification","evidenceLevel","fixtureSource","fixtureSources","requiredScenarios","scenarios","requiredCapabilities","capabilities","missingScenarios","missingCapabilities","nativeAdcsBrowserEnrollment"];
  const result = Object.fromEntries(keys.map(key => [key,report[key]]));
  assert.deepEqual(require("../../../scripts/certops-qualification-report").verifyReport(result, undefined, {expectedSha:candidateSha}), []);
  return result;
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
  nativeRequiredScenarios,
  nativeRequiredSources,
  verifyNativeProof,
  createNativeReport,
  writeReport,
};
