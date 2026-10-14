"use strict";
// These are synthetic report rejection tests. Only the separate exclusive API/
// PostgreSQL workflow can prove a real worker and five elapsed minutes.
const { test } = require("node:test"), assert = require("node:assert/strict");
const { verifyFacts } = require("./certops-log-maintenance-report");
function facts() { return { defaultGraceMs: 300000, observedMonotonicMs: 300100, actualDatabaseExpired: true, timestampsRewritten: false, originalJobSucceeded: true, abandonedStreams: 1, lateUploadRefused: true, purgedLines: 2, tombstoneRetained: true, repeatedPurgeDeleted: 0, onlySelectedWorkerSweeps: true, retentionDays: 0, scope: "actual-default-five-minute-grace-and-supported-retention-zero" }; }
test("maintenance evidence distinguishes actual default grace from zero-day storage policy", () => assert.equal(verifyFacts(facts()), true));
test("short waits, forged timestamps and changed job outcomes cannot qualify", () => {
  for (const patch of [{ observedMonotonicMs: 299999 }, { observedMonotonicMs: Infinity }, { defaultGraceMs: 2000 }, { timestampsRewritten: true }, { actualDatabaseExpired: false }, { originalJobSucceeded: false }, { lateUploadRefused: false }, { onlySelectedWorkerSweeps: false }, { purgedLines: 0 }, { tombstoneRetained: false }, { repeatedPurgeDeleted: 2 }, { retentionDays: 1 }, { scope: "simulated-one-day" }]) assert.throws(() => verifyFacts({ ...facts(), ...patch }));
});
