"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { uidDiagnostic } = require("../tests/e2e/linux-systemd-real-journey");

test("UID diagnostics retain comparisons and PID stability without exposing proc values", () => {
  const uid = 123456, other = 789012;
  const cases = [
    [`Uid:\t${uid}\t${uid}\t${uid}\t${uid}`, [true, true, true, true]],
    [`Uid:\t${other}\t${uid}\t${uid}\t${uid}`, [false, true, true, true]],
    [`Uid:\t${uid}\t${other}\t${uid}\t${uid}`, [true, false, true, true]],
    [`Uid:\t${uid}\t${uid}\t${other}\t${uid}`, [true, true, false, true]],
    [`Uid:\t${uid}\t${uid}\t${uid}\t${other}`, [true, true, true, false]],
  ];
  for (const [row, expected] of cases) {
    const report = uidDiagnostic(`private-sentinel\n${row}\n`, uid, true);
    assert.equal(report.uidRowParsed, true);
    assert.deepEqual([report.realMatches, report.effectiveMatches, report.savedMatches, report.filesystemMatches], expected);
    assert.equal(report.mainPidUnchanged, true);
    assert.doesNotMatch(JSON.stringify(report), /123456|789012|private-sentinel/);
  }
  const unstable = uidDiagnostic(`Uid:\t${uid}\t${uid}\t${uid}\t${other}`, uid, false);
  assert.equal(unstable.mainPidUnchanged, false);
  assert.equal(uidDiagnostic("Uid: private-sentinel", uid, undefined).mainPidUnchanged, null);
  const malformed = uidDiagnostic("Uid: private-sentinel", uid, undefined);
  assert.equal(malformed.uidRowParsed, false);
  for (const field of ["realMatches", "effectiveMatches", "savedMatches", "filesystemMatches"]) assert.equal(malformed[field], null);
  assert.doesNotMatch(JSON.stringify(malformed), /private-sentinel/);
});
