"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { tarInspectionDiagnostic } = require("./pack-release");
const { createHostGate } = require("./host-gate");

test("tar failure classification is bounded and does not include stderr", () => {
  for (const [stderr, category] of [["secret permission denied", "permission-denied"], ["secret file name too long", "path-too-long"], ["secret unrecognized archive", "invalid-archive"], ["secret cannot create", "create-failed"], ["secret cannot open", "open-failed"], ["secret arbitrary", "other"]]) {
    const result = tarInspectionDiagnostic({ status: 1, stderr });
    assert.deepEqual(result, { exitStatus: 1, spawnCode: null, category });
    assert.doesNotMatch(JSON.stringify(result), /secret/);
  }
  assert.deepEqual(tarInspectionDiagnostic({ status: null, error: { code: "ENOENT" } }), { exitStatus: null, spawnCode: "ENOENT", category: "other" });
  assert.equal(tarInspectionDiagnostic({ error: { code: "secret" } }).spawnCode, null);
});

test("host gate retains only allowlisted tar failure metadata", async () => {
  const gate = createHostGate({ suite: "fixture", strict: true, reportPath: null, continueOnFailure: true });
  await gate.preflight();
  const error = Object.assign(new Error("secret host path"), { code: "CERTOPS_TAR_INSPECTION_FAILED", qualificationTarInspection: { exitStatus: 1, spawnCode: "secret", category: "secret", stderr: "secret" } });
  await gate.scenario("tar-check", async () => { throw error; });
  const failure = gate.report.scenarios[0].failure;
  assert.deepEqual(failure.tarInspection, { exitStatus: 1, spawnCode: null, category: "other" });
  assert.doesNotMatch(JSON.stringify(failure), /secret/);
});

test("an unreadable real archive still fails closed with structured diagnostics", () => {
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
  const { assertNoPrivateKeyMaterial } = require("./pack-release");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-tar-inspection-test-"));
  try {
    const archive = path.join(directory, "invalid.tgz");
    fs.writeFileSync(archive, "not an archive");
    assert.throws(() => assertNoPrivateKeyMaterial(archive), error => {
      assert.equal(error.code, "CERTOPS_TAR_INSPECTION_FAILED");
      assert.notEqual(error.qualificationTarInspection.exitStatus, 0);
      return true;
    });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
