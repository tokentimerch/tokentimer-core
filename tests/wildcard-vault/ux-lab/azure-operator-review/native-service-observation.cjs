"use strict";
// Sample the default documented Linux installation before and after the journey's
// actual restart. The caller owns enrollment, restart, and verified cleanup.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const { digest, verifyInstalled } = require("../../../../scripts/certops-agent-package");
const { verifyNative } = require("../../../../scripts/certops-final-package-evidence.cjs");
const { uidDiagnostic } = require("../../../e2e/linux-systemd-real-journey");

const UNIT = "tokentimer-agent.service";
const USER = "tokentimer-agent";
const ROOT = "/opt/tokentimer-agent";
const ENTRY = "bin/tokentimer-agent.js";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const WIRE_AGENT_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

function systemdProperties() {
  const args = ["show", UNIT, "--property=MainPID,ActiveState,SubState,User"];
  const lines = execFileSync("systemctl", args, { encoding: "utf8", timeout: 10000, maxBuffer: 4096 }).trim().split("\n");
  return Object.fromEntries(lines.map(line => line.split("=", 2)));
}

function processBirth(pid) {
  const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const commEnd = raw.lastIndexOf(")");
  const startTicks = raw.slice(commEnd + 2).trim().split(/\s+/)[19];
  assert.ok(raw.startsWith(`${pid} (`) && commEnd > 0 && /^[1-9][0-9]{0,19}$/.test(startTicks));
  return startTicks;
}

function readInstalledAgent(files, nodeExecutable) {
  assert.ok(process.platform === "linux" && process.getuid() === 0, "native Linux systemd observation requires local root");
  const service = systemdProperties();
  assert.ok(service.User === USER && service.ActiveState === "active" && service.SubState === "running", "installed service must run under its product account");
  assert.match(service.MainPID, /^[1-9][0-9]{0,9}$/);
  const pid = Number(service.MainPID), birth = processBirth(pid), proc = `/proc/${pid}`;
  const uid = Number(execFileSync("id", ["-u", USER], { encoding: "utf8", timeout: 10000, maxBuffer: 4096 }).trim());
  const identity = uidDiagnostic(fs.readFileSync(proc + "/status", "utf8"), uid);
  assert.ok(identity.realMatches && identity.effectiveMatches && identity.savedMatches && identity.filesystemMatches, "installed agent process UID mismatch");
  const args = fs.readFileSync(proc + "/cmdline", "utf8").split("\0");
  assert.ok(args.length === 3 && args[1] === ROOT + "/app/" + ENTRY && fs.realpathSync(proc + "/exe") === fs.realpathSync(nodeExecutable),
    "MainPID must run the expected Node executable and installed package entry");
  const processRoot = proc + "/root" + ROOT;
  verifyInstalled(files, processRoot + "/app");
  const processEntrySha256 = digest(processRoot + "/app/" + ENTRY);
  assert.equal(processEntrySha256, files[ENTRY]);
  let agentId;
  try { agentId = JSON.parse(fs.readFileSync(processRoot + "/state/config.json", "utf8")).agentId; }
  catch { throw new Error("installed enrollment configuration is not readable"); }
  assert.ok(typeof agentId === "string" && WIRE_AGENT_ID.test(agentId), "installed agent ID is invalid");
  assert.deepEqual(systemdProperties(), service, "unit changed during observation");
  assert.equal(processBirth(pid), birth, "agent process changed during observation");
  return { agentId, observation: { unit: UNIT, activeState: service.ActiveState, subState: service.SubState,
    mainPid: pid, procPid: pid, procStartTicks: birth, serviceUid: uid, procUid: uid,
    commandPackageEntry: ENTRY, processEntrySha256 } };
}

async function beginNativeServiceObservation({ files, readEnrolledAgent, nodeExecutable = process.execPath }, read = readInstalledAgent) {
  async function sample() {
    const { agentId, observation } = read(files, nodeExecutable);
    const enrollment = await readEnrolledAgent(agentId);
    assert.ok(enrollment?.agentId === agentId && UUID.test(enrollment.id || ""), "public fleet did not identify the installed agent");
    const seenAt = Date.parse(enrollment.lastSeenAt);
    assert.ok(Number.isFinite(seenAt), "public fleet did not observe a heartbeat");
    return { observation, agentId, enrollmentRowId: enrollment.id, seenAt };
  }
  const before = await sample();
  return async function finish() {
    const after = await sample();
    assert.ok(before.agentId === after.agentId && before.enrollmentRowId === after.enrollmentRowId && before.seenAt < after.seenAt,
      "restart must preserve enrollment and advance the public heartbeat");
    // Both samples match the installed wire identity to the same fleet row.
    // The receipt identifies that public enrollment by its row UUID.
    const result = { kind: "installed-linux-systemd", installedFileHashes: files, agentId: before.enrollmentRowId,
      enrolledAgentId: after.enrollmentRowId, before: before.observation, after: after.observation };
    verifyNative(result, files);
    return result;
  };
}

module.exports = { beginNativeServiceObservation };
