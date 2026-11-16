"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { uidDiagnostic, executedMainPid } = require("../tests/e2e/linux-systemd-real-journey");

test("Type=simple readiness waits for exec without filtering the process UID", () => {
  const expected = "/candidate/node";
  let executable = "/usr/lib/systemd/systemd";
  const reads = { readMainPid: () => 123, readBirth: () => "456", readExecutable: () => executable };
  assert.equal(executedMainPid(expected, reads), false);
  executable = expected;
  // Readiness deliberately knows nothing about UID. A root Node process must
  // reach the caller's existing UID assertion immediately, rather than retry.
  assert.equal(executedMainPid(expected, reads), 123);
});

test("native readiness refuses a changing PID, birth or executable", () => {
  for (const changed of ["readMainPid", "readBirth", "readExecutable"]) {
    let calls = 0;
    const reads = { readMainPid: () => 123, readBirth: () => "456", readExecutable: () => "/candidate/node" };
    const original = reads[changed];
    reads[changed] = () => ++calls === 1 ? original() : changed === "readMainPid" ? 124 : "changed";
    assert.equal(executedMainPid("/candidate/node", reads), false);
  }
});

test("native readiness retries an absent process but preserves unexpected inspection errors", () => {
  const reads = { readMainPid: () => 123, readBirth: () => "456", readExecutable: () => { throw Object.assign(new Error("withheld"), { code: "ENOENT" }); } };
  assert.equal(executedMainPid("/candidate/node", reads), false);
  reads.readExecutable = () => { throw Object.assign(new Error("withheld"), { code: "EACCES" }); };
  assert.throws(() => executedMainPid("/candidate/node", reads), { code: "EACCES" });
  assert.equal(executedMainPid("/candidate/node", { readMainPid: () => 0 }), false);
});

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
  const root = uidDiagnostic("Uid:\t0\t0\t0\t0", uid, true, {phase:"restart", executableMatches:false, birthUnchanged:true, serviceState:"activating"});
  assert.equal(root.phase, "restart");
  assert.deepEqual([root.realIsRoot, root.effectiveIsRoot, root.savedIsRoot, root.filesystemIsRoot], [true, true, true, true]);
  assert.equal(root.executableMatches, false);
  assert.equal(root.birthUnchanged, true);
  assert.equal(root.serviceState, "activating");
  const untrusted = uidDiagnostic("Uid: private-sentinel", uid, null, {phase:"private-sentinel", executableMatches:"private-sentinel", birthUnchanged:"private-sentinel", serviceState:"private-sentinel"});
  assert.equal(untrusted.phase, null);
  assert.equal(untrusted.executableMatches, null);
  assert.equal(untrusted.birthUnchanged, null);
  assert.equal(untrusted.serviceState, null);
  assert.doesNotMatch(JSON.stringify(untrusted), /private-sentinel/);
});
