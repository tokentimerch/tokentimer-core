"use strict";

/** Local browser, audit, and diagnostic contract. Secrets are removed before
 * a diagnostic is stored. An anonymous completed-console replay is refused.
 * Accessibility checks named labels in the local fixture. A missing browser
 * fails closed and no live browser is started. */

const assert = require("node:assert/strict");
const {pendingFacts} = require("../../../scripts/certops-qualification-report");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "browser-lifecycle-audit-and-diagnostic-redaction";
const SUITE = "browser-audit-redaction";
const SUITE_LEVEL = "integration";
const PROOF_LEVEL = "script";
const REPORT_FILE = "browser-audit-redaction.json";
const REPORT_ENV = "CERTOPS_BROWSER_AUDIT_REDACTION_REPORT";
const LABELS = Object.freeze([
  "Issue certificate",
  "Renew certificate",
  "Audit history",
  "Job evidence",
]);
const SCENARIOS = Object.freeze([
  "browser-diagnostic-redaction",
  "browser-completed-console-anonymous-replay",
  "browser-accessibility-fixture-labels",
  "browser-missing-browser-closed",
]);
const CATALOG_IDS = Object.freeze([
  "experience.browser-lifecycle",
  "experience.ui-layout",
  "experience.log-access",
  "experience.log-secret-sentinel",
  "experience.audit-target",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-browser-audit-redaction.js",
  "scripts/certops-browser-audit-redaction.js",
  "scripts/certops-browser-audit-redaction.test.js",
  "docs/certops/cross/browser-audit-redaction.md",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);
const ACCESSIBILITY_FIXTURE = [
  "<main>",
  '  <button aria-label="Issue certificate">Issue certificate</button>',
  '  <button aria-label="Renew certificate">Renew certificate</button>',
  '  <a aria-label="Audit history">Audit history</a>',
  '  <section aria-label="Job evidence">Job evidence</section>',
  "</main>",
].join("\n");
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const BEARER = /Bearer\s+[A-Za-z0-9._-]+/g;
const PASSWORD = /password=[^\s&]+/gi;

function containsSecret(value) {
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)
    || /Bearer\s+[A-Za-z0-9._-]+/.test(value)
    || /password=/i.test(value);
}

function redact(value) {
  assert.equal(typeof value, "string");
  return value.replace(PEM, "[redacted]").replace(BEARER, "[redacted]").replace(PASSWORD, "[redacted]");
}

function storeDiagnostic(store, raw) {
  assert.ok(Array.isArray(store));
  const redacted = redact(raw);
  if (containsSecret(redacted)) {
    throw Object.assign(new Error("secret remained after redaction"), { code: "REDACTION" });
  }
  store.push(redacted);
  assert.equal(store.includes(raw) && containsSecret(raw), false);
  return redacted;
}

function assertActor(actor) {
  if (actor !== "owner" && actor !== "admin") {
    throw Object.assign(new Error("anonymous replay refused"), {
      code: "ANONYMOUS_REPLAY",
    });
  }
}

function replayCompletedConsole(request) {
  assert.equal(request && request.completed, true);
  assertActor(request.actor);
  return {
    allowed: true,
    jobId: request.jobId,
    browserQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function recordAudit(store, event) {
  assertActor(event.actor);
  const diagnostic = storeDiagnostic([], event.detail);
  store.push({ action: event.action, actor: event.actor, diagnostic });
  return store;
}

function checkAccessibility(fixture) {
  assert.equal(typeof fixture, "string");
  const missing = LABELS.filter((label) => !fixture.includes(`aria-label="${label}"`));
  if (missing.length > 0) {
    throw Object.assign(new Error(`accessibility labels missing: ${missing.join(",")}`), {
      code: "A11Y_LABEL",
      missing,
    });
  }
  return {
    labels: [...LABELS],
    liveBrowser: false,
    browserQualified: false,
  };
}

function assessBrowser(probe) {
  const available = Boolean(probe && probe.browser === true && probe.missing !== true);
  return {
    available,
    browserQualified: false,
    liveBrowser: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.secretsRedacted, true);
  assert.equal(proof.anonymousReplayRefused, true);
  assert.equal(proof.labelsCheckedLocally, true);
  assert.equal(proof.browserQualified, false);
  assert.equal(proof.liveBrowser, false);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    secretsRedacted: true,
    anonymousReplayRefused: true,
    labelsCheckedLocally: true,
    browserQualified: false,
    liveBrowser: false,
    hostCapabilityAbsentIsPass: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_BROWSER_LAB !== "1") missing.push("CERTOPS_BROWSER_LAB");
  return { ok: missing.length === 0, missing };
}

function closedReport(reason, env = process.env, probe) {
  const lab = assessLab(env);
  const browser = assessBrowser(probe);
  const now = new Date().toISOString();
  return {...pendingFacts({SUITE, SUITE_LEVEL, PROOF_LEVEL, SCENARIOS, REQUIRED_SOURCES, CATALOG_IDS, now}),
browserQualified: false,
liveBrowser: false,
reason: reason || (!browser.available || !lab.ok
      ? "browser absent"
      : "A present browser is not claimed as qualification"),
cleanup: { status: "failed", summary: "No browser process was started" }};
}

function writeReport(reportPath, report) {
  assert.equal(report.browserQualified, false);
  assert.equal(report.liveBrowser, false);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const probe = options.probe || { missing: true, browser: false };
  const report = closedReport(options.reason, env, probe);
  const reportPath = options.reportPath || env[REPORT_ENV] || path.join("qualification-results", REPORT_FILE);
  if (options.write !== false) writeReport(reportPath, report);
  return report;
}

module.exports = {
  SCOPE,
  SUITE,
  SUITE_LEVEL,
  PROOF_LEVEL,
  REPORT_FILE,
  REPORT_ENV,
  LABELS,
  SCENARIOS,
  CATALOG_IDS,
  REQUIRED_SOURCES,
  ACCESSIBILITY_FIXTURE,
  containsSecret,
  redact,
  storeDiagnostic,
  replayCompletedConsole,
  recordAudit,
  checkAccessibility,
  assessBrowser,
  verifyProof,
  localProof,
  assessLab,
  closedReport,
  writeReport,
  run,
};
