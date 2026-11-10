"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { verifyFencedJob } = require("../e2e/helpers/certops-acme-lease-loss");
const jobId = "owned-job";
const reason = "Qualification native mutation-time lease loss";
const cancelled = { status: "cancelled", error_code: "CERTOPS_AGENT_FORCE_RETIRED" };
const orphaned = { status: "orphaned_unknown_effect", error_code: "CERTOPS_AGENT_FORCE_RETIRED_UNKNOWN_EFFECT", needs_operator_reconciliation: true, reconciliation_reason: reason };
const fenced = (cancelledJobIds, orphanedJobIds) => ({ cancelledJobIds, orphanedJobIds });
test("retirement proof binds claimed and running transitions to the exact fenced job", () => {
  verifyFencedJob(fenced([jobId], []), jobId, cancelled);
  verifyFencedJob(fenced([], [jobId]), jobId, orphaned);
  for (const [result, row] of [
    [fenced([], []), cancelled], [fenced([jobId], [jobId]), cancelled],
    [fenced([jobId, jobId], []), cancelled], [fenced(["other"], []), cancelled],
    [fenced([jobId], []), orphaned], [fenced([], [jobId]), cancelled],
    [fenced([], [jobId]), { ...orphaned, needs_operator_reconciliation: false }],
    [fenced([], [jobId]), { ...orphaned, reconciliation_reason: "other" }],
    [fenced([], [jobId]), { ...orphaned, error_code: "other" }],
  ]) assert.throws(() => verifyFencedJob(result, jobId, row));
});
