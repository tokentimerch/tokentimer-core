"use strict";
/** Actual supporting Windows file-level delivery barriers with benign temp IO.
 * No certreq, candidate execution, agent, service, CA or certificate/key operation.
 * This is not qualification; real source-path acquisition and native requester
 * identity remain separate work. Failures preserve the private guarded root. */
const assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto"), { spawn } = require("node:child_process");
const scope = "supporting-temporary-level1-input-output-barriers-not-certreq";
const flags = Object.freeze(["inputLevelOneGranted", "actualInputReadBreak", "threeOutputLevelOneGranted", "outputsArmedBeforeReadRelease", "actualSelectedOutputOpenBreak", "readerIdentityBoundBeforeAccess", "inputBytesVerified", "allOutputsZeroBeforeLoss", "exactChildExitAndAbsence", "holdersReleasedAfterExactDrain", "allOutputsZeroAfterRelease", "inputAndGuardIdentityUnchanged"]);
const driver = path.join(__dirname, "certops-response-barrier-driver.ps1"), worker = path.join(__dirname, "certops-response-barrier-worker.ps1");
function hash(file) { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); }
function identity(file) { const value = fs.lstatSync(file, { bigint: true }); assert.equal(value.isSymbolicLink(), false); return `${value.dev}:${value.ino}`; }
function nativeFileIdentity(file) { const value = fs.lstatSync(file, { bigint: true }); assert.equal(value.isSymbolicLink(), false); assert.ok(value.dev >= 0n && value.dev <= 0xffffffffn && value.ino >= 0n && value.ino <= 0xffffffffffffffffn); return `${value.dev.toString(16).padStart(8, "0")}:${value.ino.toString(16).padStart(16, "0")}`; }
function verifyCase(value) { assert.deepEqual(Object.keys(value).sort(), ["outputIndex", ...flags].sort()); assert.ok([0, 1, 2].includes(value.outputIndex)); for (const flag of flags) assert.equal(value[flag], true, flag); return true; }
function verifyProof(value) { assert.deepEqual(Object.keys(value).sort(), ["scope", "nativeAdcsQualified", "sourceAcquisitionRaceQualified", "cases"].sort()); assert.equal(value.scope, scope); assert.equal(value.nativeAdcsQualified, false); assert.equal(value.sourceAcquisitionRaceQualified, false); assert.equal(value.cases.length, 3); assert.deepEqual(value.cases.map(item => item.outputIndex).sort(), [0, 1, 2]); for (const item of value.cases) verifyCase(item); return true; }
function assertCleanupSafe(root, token) {
  const resolved = path.resolve(root); assert.equal(path.dirname(resolved), path.resolve(os.tmpdir())); assert.match(path.basename(resolved), /^certops-response-barrier-support-[a-f0-9-]{36}$/);
  assert.equal(fs.realpathSync(resolved).toLowerCase(), resolved.toLowerCase()); assert.equal(fs.readFileSync(path.join(resolved, ".owner"), "utf8"), token);
  const guardFile = path.join(resolved, ".active-guard.json"), drainedFile = path.join(resolved, ".drained.json");
  assert.ok(fs.existsSync(guardFile) && fs.existsSync(drainedFile), "Incomplete supporting guard: preserve root");
  const guard = JSON.parse(fs.readFileSync(guardFile, "utf8")), drained = JSON.parse(fs.readFileSync(drainedFile, "utf8"));
  assert.equal(guard.token, token); assert.equal(drained.token, token); assert.equal(guard.root.toLowerCase(), resolved.toLowerCase()); assert.equal(drained.root.toLowerCase(), resolved.toLowerCase());
  assert.equal(guard.scope, "supporting-temporary-file-barriers-not-certreq"); assert.equal(drained.guardHash, hash(guardFile));
  assert.equal(guard.rootIdentity, nativeFileIdentity(resolved)); assert.equal(guard.inputIdentity, nativeFileIdentity(path.join(resolved, "request.req"))); assert.equal(guard.inputHash, hash(path.join(resolved, "request.req")));
  for (const flag of ["childExited", "childPidAbsent", "holdersReleasedAfterDrain"]) assert.equal(drained[flag], true, "Undrained writer: preserve holders and root");
  assert.ok(Number.isSafeInteger(drained.workerPid) && drained.workerPid > 0); assert.match(drained.workerCreated, /^[0-9TZ:.+\-]{16,40}$/);
  assert.match(drained.guardIdentity, /^[a-f0-9]{8}:[a-f0-9]{16}$/);
  assert.equal(drained.guardIdentity, nativeFileIdentity(guardFile));
  assert.equal(alive(drained.workerPid), false, "Supporting writer PID still exists; preserve root"); assert.ok(Number.isSafeInteger(guard.driverPid) && guard.driverPid > 0); assert.equal(alive(guard.driverPid), false, "Supporting holder PID still exists; preserve root");
  assert.ok(Array.isArray(guard.outputStates) && guard.outputStates.length === 3);
  for (const [index, name] of ["issued.cer", "chain.p7b", "submit-response.rsp"].entries()) { const file = path.join(resolved, name); assert.match(guard.outputStates[index], /^[a-f0-9]{8}:[a-f0-9]{16}:0:0:[0-9]{1,10}$/); assert.equal(guard.outputStates[index].split(":").slice(0, 2).join(":"), nativeFileIdentity(file)); assert.equal(fs.statSync(file).size, 0); }
  for (const entry of fs.readdirSync(resolved, { withFileTypes: true })) assert.equal(entry.isSymbolicLink(), false);
  return true;
}
function alive(pid) { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === "ESRCH") return false; throw error; } }
async function runCase(outputIndex) {
  assert.equal(process.platform, "win32"); assert.ok([0, 1, 2].includes(outputIndex));
  const token = crypto.randomBytes(16).toString("hex"), root = path.join(os.tmpdir(), `certops-response-barrier-support-${crypto.randomUUID()}`);
  fs.mkdirSync(root); fs.writeFileSync(path.join(root, ".owner"), token, { flag: "wx" });
  const request = path.join(root, "request.req"); fs.writeFileSync(request, `Public temporary supporting input ${crypto.randomUUID()}`, { flag: "wx" });
  for (const name of ["issued.cer", "chain.p7b", "submit-response.rsp"]) fs.writeFileSync(path.join(root, name), "", { flag: "wx" });
  const rootId = identity(root), inputId = identity(request), inputHash = hash(request), ownerId = identity(path.join(root, ".owner")), sourceHashes = [hash(driver), hash(worker)];
  let passed = false;
  try {
    const child = spawn(path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe"), ["-NoProfile", "-NonInteractive", "-File", driver, "-Root", root, "-Token", token, "-OwnerPid", String(process.pid), "-OutputIndex", String(outputIndex)], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let output = "", overflow = false, closed = false, code, failure;
    const cancel = () => { const file = path.join(root, ".cancel"); if (!fs.existsSync(file)) fs.writeFileSync(file, token, { flag: "wx" }); };
    child.stdout.on("data", bytes => { if (Buffer.byteLength(output) + bytes.length > 8192) { overflow = true; cancel(); } else output += bytes.toString(); }); child.stderr.resume();
    const completion = new Promise(resolve => { child.once("error", () => { failure = true; cancel(); }); child.once("close", value => { closed = true; code = value; resolve(); }); });
    const timer = setTimeout(cancel, 60000); let drainTimer;
    try { await Promise.race([completion, new Promise((_, reject) => { drainTimer = setTimeout(() => reject(new Error("Supporting holder did not drain; preserve guarded temporary root")), 90000); })]); }
    finally { clearTimeout(timer); clearTimeout(drainTimer); }
    // Never kill a holder to make a timeout pass; its exact-worker custodian
    // must retain output barriers if termination cannot be proved.
    assert.equal(closed, true); assert.equal(alive(child.pid), false); assert.equal(failure, undefined); assert.equal(overflow, false); assert.equal(code, 0, "Supporting barrier failed; owned root preserved");
    const proof = JSON.parse(output); verifyCase(proof); assert.equal(proof.outputIndex, outputIndex);
    assert.deepEqual([hash(driver), hash(worker)], sourceHashes); assert.equal(identity(root), rootId); assert.equal(identity(request), inputId); assert.equal(hash(request), inputHash); assert.equal(identity(path.join(root, ".owner")), ownerId);
    for (const name of ["issued.cer", "chain.p7b", "submit-response.rsp"]) assert.equal(fs.statSync(path.join(root, name)).size, 0);
    assertCleanupSafe(root, token); passed = true;
    return proof;
  } finally { if (passed) { assertCleanupSafe(root, token); fs.rmSync(path.resolve(root), { recursive: true }); } }
}
async function main() { assert.equal(process.env.CERTOPS_RESPONSE_BARRIER_SUPPORT, "1", "Explicit supporting temp-native opt-in required"); const cases = []; for (const index of [0, 1, 2]) cases.push(await runCase(index)); const proof = { scope, nativeAdcsQualified: false, sourceAcquisitionRaceQualified: false, cases }; verifyProof(proof); console.log(JSON.stringify(proof)); return proof; }
if (require.main === module) main().catch(() => { console.error("Supporting response barrier failed; preserve private temporary receipts and any undrained holder"); process.exitCode = 1; });
module.exports = { scope, flags, verifyCase, verifyProof, assertCleanupSafe, nativeFileIdentity, runCase, main };
