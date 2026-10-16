"use strict";
/** Controlled proof and cleanup refusal checks only. Native supporting execution
 * is a separate explicit command and never runs from these tooling regressions. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const helper = require("./certops-response-barrier-support");
const { spawnSync } = require("node:child_process");
const caseProof = outputIndex => ({ outputIndex, ...Object.fromEntries(helper.flags.map(flag => [flag, true])) });
test("supporting barrier cannot become native AD CS or source-acquisition qualification", () => {
  const make = () => ({ scope: helper.scope, nativeAdcsQualified: false, sourceAcquisitionRaceQualified: false, cases: [0, 1, 2].map(caseProof) });
  assert.equal(helper.verifyProof(make()), true);
  for (const flag of helper.flags) for (const wrong of [false, 1, null, "true"]) { const value = make(); value.cases[0][flag] = wrong; assert.throws(() => helper.verifyProof(value)); }
  for (const mutate of [value => value.nativeAdcsQualified = true, value => value.sourceAcquisitionRaceQualified = true, value => value.cases.pop(), value => value.cases[1] = value.cases[0], value => value.cases[0].privateReceipt = "unexpected"]) { const value = make(); mutate(value); assert.throws(() => helper.verifyProof(value)); }
});
test("active, changed and undrained supporting receipts preserve the owned directory", () => {
  const root = path.join(os.tmpdir(), `certops-response-barrier-support-${crypto.randomUUID()}`), token = crypto.randomBytes(16).toString("hex"); fs.mkdirSync(root); fs.writeFileSync(path.join(root, ".owner"), token);
  const exited = spawnSync(process.execPath, ["-e", ""], { windowsHide: true }); assert.equal(exited.status, 0);
  fs.writeFileSync(path.join(root, "request.req"), "public controlled input"); const names = ["issued.cer", "chain.p7b", "submit-response.rsp"]; for (const name of names) fs.writeFileSync(path.join(root, name), "");
  const guard = { token, root, scope: "supporting-temporary-file-barriers-not-certreq", rootIdentity: helper.nativeFileIdentity(root), inputIdentity: helper.nativeFileIdentity(path.join(root, "request.req")), inputHash: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "request.req"))).digest("hex"), driverPid: exited.pid, outputStates: names.map(name => `${helper.nativeFileIdentity(path.join(root, name))}:0:0:32`) }, guardFile = path.join(root, ".active-guard.json"), drainedFile = path.join(root, ".drained.json");
  const writeDrained = () => fs.writeFileSync(drainedFile, JSON.stringify({ token, root, guardHash: crypto.createHash("sha256").update(fs.readFileSync(guardFile)).digest("hex"), guardIdentity: helper.nativeFileIdentity(guardFile), workerPid: exited.pid, workerCreated: "2026-10-14T00:00:00.000Z", childExited: true, childPidAbsent: true, holdersReleasedAfterDrain: true }));
  try {
    assert.throws(() => helper.assertCleanupSafe(root, token)); fs.writeFileSync(guardFile, JSON.stringify(guard)); assert.throws(() => helper.assertCleanupSafe(root, token));
    writeDrained(); assert.equal(helper.assertCleanupSafe(root, token), true);
    for (const field of ["childExited", "childPidAbsent", "holdersReleasedAfterDrain"]) { writeDrained(); const value = JSON.parse(fs.readFileSync(drainedFile)); value[field] = false; fs.writeFileSync(drainedFile, JSON.stringify(value)); assert.throws(() => helper.assertCleanupSafe(root, token)); }
    writeDrained(); { const value = JSON.parse(fs.readFileSync(drainedFile)); value.workerPid = process.pid; fs.writeFileSync(drainedFile, JSON.stringify(value)); assert.throws(() => helper.assertCleanupSafe(root, token)); }
    writeDrained(); fs.writeFileSync(path.join(root, "issued.cer"), "unwanted output"); assert.throws(() => helper.assertCleanupSafe(root, token)); fs.truncateSync(path.join(root, "issued.cer"), 0);
    fs.writeFileSync(path.join(root, "request.req"), "changed public input"); assert.throws(() => helper.assertCleanupSafe(root, token)); fs.writeFileSync(path.join(root, "request.req"), "public controlled input");
    fs.writeFileSync(guardFile, JSON.stringify({ ...guard, rootIdentity: "00000000:0000000000000000" })); writeDrained(); assert.throws(() => helper.assertCleanupSafe(root, token)); fs.writeFileSync(guardFile, JSON.stringify(guard));
    writeDrained(); const saved = path.join(root, ".saved-guard.json"), bytes = fs.readFileSync(guardFile); assert.equal(path.dirname(saved), root);
    fs.renameSync(guardFile, saved);
    try { fs.writeFileSync(guardFile, bytes); assert.throws(() => helper.assertCleanupSafe(root, token), "A byte-identical replacement receipt has a different file identity"); }
    finally { fs.rmSync(guardFile); fs.renameSync(saved, guardFile); }
    writeDrained(); fs.appendFileSync(guardFile, " "); assert.throws(() => helper.assertCleanupSafe(root, token)); assert.equal(fs.existsSync(root), true);
    fs.writeFileSync(path.join(root, ".owner"), "foreign"); assert.throws(() => helper.assertCleanupSafe(root, token));
  } finally { assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); for (const name of [".owner", ".active-guard.json", ".drained.json", "request.req", ...names]) fs.rmSync(path.join(root, name), { force: true }); fs.rmdirSync(root); }
});
