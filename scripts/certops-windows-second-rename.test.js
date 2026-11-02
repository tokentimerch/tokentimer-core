"use strict";

/** Second-rename failure proof. No installer process is launched. A missing
 * host must not be reported as a pass. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-second-rename");

const RUN = "cd".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-ren-${RUN}`,
  });
}

function assertWorkflow() {
  const root = path.resolve(__dirname, "..");
  const workflow = fs.readFileSync(
    path.join(root, ".github/workflows/certops-windows-coverage-variants.yml"),
    "utf8",
  );
  assert.match(workflow, /^on:\r?\n {2}workflow_dispatch:\r?\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.match(workflow, /contents: read/);
  assert.doesNotMatch(workflow, /\bgh\b/);
  assert.match(workflow, /process\.exit\(1\)/);
  assert.match(workflow, /qualified: false/);
  for (const rel of helper.LOCAL_REQUIRED_SOURCES) {
    assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
  }
}

test("a second rename failure leaves the original name and keeps the in-use binary and key", () => {
  const owned = manifest();
  const result = helper.applySecondRenameFailure(owned);
  helper.verifyProof(result.proof);
  assert.equal(result.liveName, owned.originalName);
  assert.equal(result.binaryPresent, true);
  assert.equal(result.keyPresent, true);
  assert.equal(result.proof.secondRenameFailed, true);
  assert.equal(result.proof.inUseBinaryDeleted, false);
  assert.equal(result.proof.inUseKeyDeleted, false);
  assert.equal(result.proof.evidenceLevel, "script");
  assert.equal(result.passed, false);
  assert.throws(() =>
    helper.assertNoInUseDeletion(owned, [
      { file: "certutil.exe", args: ["-delkey", owned.key.container] },
    ]),
  );
  assert.throws(() =>
    helper.assertNoInUseDeletion(owned, [
      { file: "powershell.exe", args: ["Remove-Item", "-LiteralPath", owned.binary] },
    ]),
  );
  assert.throws(() =>
    helper.assertNoInUseDeletion(owned, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]),
  );
  for (const flag of helper.LOCAL_CLOSED) {
    assert.throws(() => helper.verifyProof({ ...result.proof, [flag]: true }), flag);
  }
  helper.verifyProof({ ...result.proof, crashDumpContainmentQualified: false });
  assert.throws(() => helper.verifyProof({ ...result.proof, crashDumpContainmentQualified: true }));
});

test("command entry fails closed without claiming native execution", () => {
  const script = path.resolve(__dirname, "certops-windows-second-rename.js");
  const absent = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(absent.status, 1);
  const absentBody = JSON.parse(absent.stdout);
  assert.equal(absentBody.passed, false);
  assert.equal(absentBody.nativeQualified, false);
  const entry = require("./certops-windows-second-rename");
  assert.equal(entry.run({ probe: {} }).reason, "host capability absent");
  const ready = { windows: true, installer: true, ownedTarget: true };
  assert.equal(entry.run({ probe: ready, execute: false }).reason, "host execution not requested");
  const planned = entry.run({ probe: ready, execute: true, manifest: manifest() });
  assert.equal(planned.passed, false);
  assert.equal(planned.nativeQualified, false);
  assert.equal(planned.planSafe, true);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-ren-"));
  try {
    const file = path.join(dir, "manifest.json");
    fs.writeFileSync(file, JSON.stringify({ runId: RUN, root: `C:\\qualification\\tt-ren-${RUN}` }));
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    assert.equal(JSON.parse(checked.stdout).passed, false);
    helper.verifyProof(JSON.parse(checked.stdout).proof);
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: `C:\\qualification\\tt-ren-${RUN}`,
        extraCommands: [{ file: "netsh.exe", args: ["int", "ip", "reset"] }],
      }),
    );
    const refused = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.equal(JSON.parse(refused.stdout).passed, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assertWorkflow();
});
