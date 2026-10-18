"use strict";
/** Pure resident admission/source controls; no native execution or elapsed claim. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), { spawnSync } = require("node:child_process");
const contract = require("./certops-adcs-ttl24h-contract"), resident = require("./certops-adcs-ttl24h-resident"), credential = require("./certops-adcs-ttl24h-resume-credential");
function fixture() {
  const uuid = "11111111-1111-1111-1111-111111111111", nonce = "a".repeat(64), lease = contract.createLease({ candidateSha: "b".repeat(40), runId: "123", runAttempt: "1", nonce, vmResourceId: `/subscriptions/${uuid}/resourceGroups/tt-certops-123-1/providers/Microsoft.Compute/virtualMachines/windows-agent`, vmId: uuid, taskName: contract.TASK_PREFIX + nonce, nodeSha256: "c".repeat(64), keeperSha256: "d".repeat(64) }, "2026-10-15T12:00:00.000Z"), directory = `C:\\ttqualification\\adcs-ttl24h\\${nonce}`;
  return { file: path.win32.join(directory, "runtime-private.json"), config: { schemaVersion: 1, kind: contract.KIND, lease, baseUrl: "https://10.64.0.6/", workspaceId: uuid, credentialReceipt: { file: credential.localPath(lease), fileId: "1234", sha256: "e".repeat(64) }, preparedFile: path.win32.join(directory, "prepared.json"), preparedSha256: "f".repeat(64), stateDir: path.win32.join(directory, "agent"), drainedTree: [{ pid: 1234, createdAt: "2026-10-15T12:00:01Z" }] } };
}
test("resident config has a closed private shape and exact isolated ownership paths", () => {
  const { config, file } = fixture(); assert.equal(resident.verifyConfig(config, file), true);
  for (const mutate of [value => value.baseUrl = "https://foreign.example.test/", value => value.stateDir = "C:\\foreign", value => value.credentialReceipt.file = "C:\\foreign", value => value.credentialReceipt.password = "sentinel", value => value.drainedTree.push(value.drainedTree[0]), value => value.drainedTree = [], value => value.extra = true]) { const bad = structuredClone(config); mutate(bad); assert.throws(() => resident.verifyConfig(bad, file)); }
});
test("unqualified real resident entry refuses before reading config or issuing native commands", () => {
  const env = { ...process.env }; for (const name of Object.keys(env)) if (/^CERTOPS_ADCS_(?:DISPOSABLE_LAB|TTL24H)$/i.test(name)) delete env[name]; const result = spawnSync(process.execPath, ["-e", "require('./scripts/certops-adcs-ttl24h-resident').run('absent','invalid','absent').then(()=>process.exitCode=2).catch(e=>{process.exitCode=e.code==='ERR_ASSERTION'?0:3;})"], { cwd: path.resolve(__dirname, ".."), env, timeout: 30000, windowsHide: true }); assert.ok(!result.error && result.status === 0);
});
test("resident source keeps actual day, original state, native survivors and no lease mutation", () => {
  const source = fs.readFileSync(path.join(__dirname, "certops-adcs-ttl24h-resident.js"), "utf8"); assert.ok(source.includes("process.hrtime.bigint()")); assert.ok(source.includes("elapsed >= contract.DAY")); assert.ok(source.includes("inspectMachineKeySurvivors")); assert.ok(source.includes("survivors.shared === false")); assert.ok(source.includes("lease.phase, \"resident-owned\"")); assert.doesNotMatch(source, /Start-Service|Stop-Service|Set-Acl|scheduleDueEnrollments|renewalSweep|Set-Date|utimes|writeEnrollmentJournal/); assert.ok(source.includes("timing-only-native-oracles-required")); assert.equal(typeof resident.verifyProof, "undefined");
});
