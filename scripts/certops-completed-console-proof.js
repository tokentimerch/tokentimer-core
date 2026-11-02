"use strict";

/** Public evidence contract for authorization changes in a completed console.
 * Real Chromium/API cases establish these observations; report validation must
 * not confuse a final log stream with a successful job or native execution.
 * No console text, cookies, membership identifiers or credentials belong here.
 */
const assert = require("node:assert/strict");
const FIELDS = Object.freeze([
  "finalStreamDoesNotCompleteJob",
  "claimBoundResultCompletesNoop",
  "completedViewerTextWithdrawn",
  "restoredHistoryWithoutDuplicates",
  "removedMemberTextWithdrawn",
  "sameConsoleRemainedMounted",
  "authoritativeTerminalStatePreserved",
  "foregroundRevalidationWithinThirtySeconds",
  "noNativeExecutionClaim",
]);

function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof), "Completed-console authorization proof required");
  assert.deepEqual(Object.keys(proof).sort(), [...FIELDS].sort(), "Only bounded completed-console authorization facts are accepted");
  for (const field of FIELDS) assert.equal(proof[field], true, field);
  return true;
}

module.exports = { FIELDS, verifyProof };
