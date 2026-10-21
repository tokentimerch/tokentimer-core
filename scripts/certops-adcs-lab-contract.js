"use strict";
/** Shared prerequisite and failed-report plumbing for unfinished AD CS journeys.
 * These checks never execute a forest or qualify a native operation. */
const fs = require("node:fs"),
  path = require("node:path");
function assessLab(env = process.env, platform = process.platform) {
  const missing = [];
  if (platform !== "win32") missing.push("win32");
  if (env.CERTOPS_ADCS_DISPOSABLE_LAB !== "1")
    missing.push("CERTOPS_ADCS_DISPOSABLE_LAB");
  try {
    if (new URL(env.CERTOPS_ADCS_API_URL || "").protocol !== "https:")
      missing.push("CERTOPS_ADCS_API_URL");
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
function createClosedReport(
  { SUITE, EVIDENCE_LEVEL, REQUIRED_CAPABILITIES, REQUIRED_SCENARIOS },
  extra = {},
  statusExtra = {},
) {
  return function buildClosedReport(reason) {
    const now = new Date().toISOString();
    const candidate = process.env.GITHUB_SHA;
    return {
      schemaVersion: 1,
      suite: SUITE,
      strict: true,
      evidenceLevel: EVIDENCE_LEVEL,
      status: "failed",
      ...statusExtra,
      nativeExecutionQualified: false,
      hostCapabilityAbsentIsPass: false,
      disposableForestRan: false,
      ...extra,
      startedAt: now,
      finishedAt: now,
      candidateSha: /^[a-f0-9]{40}$/i.test(candidate || "")
        ? candidate
        : "0".repeat(40),
      requiredCapabilities: [...REQUIRED_CAPABILITIES],
      capabilities: {},
      requiredScenarios: [...REQUIRED_SCENARIOS],
      missingScenarios: [...REQUIRED_SCENARIOS],
      missingCapabilities: [...REQUIRED_CAPABILITIES],
      scenarios: [],
      cleanup: { status: "failed", summary: String(reason).slice(0, 512) },
      fixturePrerequisite:
        "No disposable forest executed this journey. A failed report is not native qualification.",
    };
  };
}
function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}
module.exports = { assessLab, createClosedReport, writeReport };
