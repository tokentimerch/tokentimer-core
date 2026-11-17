"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { beginNativeServiceObservation } = require("./native-service-observation.cjs");

const file = "bin/tokentimer-agent.js";
const files = { [file]: "a".repeat(64) };
const agentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const rowId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
function sample(mainPid, procStartTicks, overrides = {}) {
  return { agentId, observation: { unit: "tokentimer-agent.service", activeState: "active", subState: "running",
    mainPid, procPid: mainPid, procStartTicks, serviceUid: 10001, procUid: 10001,
    commandPackageEntry: file, processEntrySha256: files[file], ...overrides } };
}
async function start(second, { heartbeatChanged = true, enrollmentRowId = rowId } = {}) {
  const observations = [sample(980, "402", {}), second];
  let calls = 0;
  return beginNativeServiceObservation({ files, async readEnrolledAgent(id) {
    assert.equal(id, agentId);
    return { id: calls++ === 0 ? rowId : enrollmentRowId, agentId: id,
      lastSeenAt: calls === 1 || !heartbeatChanged ? "2026-11-17T20:00:01Z" : "2026-11-17T20:00:15Z" };
  } }, (inputFiles, executable) => {
    assert.equal(inputFiles, files);
    assert.equal(executable, process.execPath);
    return observations.shift();
  });
}

test("binds separate pre/post restart observations to the same enrolled agent and archive inventory", async () => {
  const finish = await start(sample(981, "450"));
  const proof = await finish();
  assert.equal(proof.agentId, proof.enrolledAgentId);
  assert.equal(proof.installedFileHashes, files);
  assert.equal(proof.before.mainPid, 980);
  assert.equal(proof.after.mainPid, 981);
});

test("refuses a process, installation, enrollment or heartbeat that cannot prove recovery", async () => {
  for (const [observed, overrides] of [
    [sample(980, "402"), {}],
    [sample(981, "450", { procUid: 0 }), {}],
    [sample(981, "450", { processEntrySha256: "e".repeat(64) }), {}],
    [sample(981, "450"), { heartbeatChanged: false }],
    [sample(981, "450"), { enrollmentRowId: "cccccccc-cccc-cccc-cccc-cccccccccccc" }],
  ]) {
    const finish = await start(observed, overrides);
    await assert.rejects(finish);
  }
});
