"use strict";
/** Synthetic verifier fixtures only. This module never produces host execution evidence. */
function reportFacts({
  ids,
  capabilities,
  evidenceLevel,
  startedAt,
  finishedAt,
}) {
  return {
    schemaVersion: 1,
    strict: true,
    status: "passed",
    cleanup: { status: "passed" },
    requiredScenarios: ids,
    requiredCapabilities: capabilities,
    missingScenarios: [],
    missingCapabilities: [],
    capabilities: Object.fromEntries(
      capabilities.map((name) => [name, { available: true }]),
    ),
    scenarios: ids.map((id) => ({
      id,
      status: "passed",
      evidenceLevel,
      startedAt,
      finishedAt,
    })),
  };
}
function matrixErrors(value, slot, candidateSha) {
  return require("../certops-release-qualification").verifyMatrix([value], {
    candidateSha,
    specification: { schemaVersion: 1, slots: [slot] },
  });
}
module.exports = { reportFacts, matrixErrors };
