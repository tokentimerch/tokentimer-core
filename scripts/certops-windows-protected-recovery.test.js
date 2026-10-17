"use strict";

/** Protected journal recovery fails closed. The protected key is not deleted. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-protected-recovery");

const RUN = "f6".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-rec-${RUN}`,
  });
}

test("orphan, weak ACL, and unreadable journals keep the protected key", () => {
  const owned = manifest();
  for (const defect of helper.DEFECTS) {
    const result = helper.failClosed(owned, defect);
    helper.verifyProof(result.proof);
    assert.equal(result.proof.defect, defect);
    assert.equal(result.proof.failedClosed, true);
    assert.equal(result.proof.protectedKeyDeleted, false);
    assert.equal(result.proof.inUseKeyDeleted, false);
    assert.equal(result.keyDeleted, false);
    assert.equal(result.passed, false);
    assert.equal(result.commands.some((command) => command.args.includes(owned.key.container) && /delete/i.test(command.args.join(" "))), false);
  }
  assert.throws(() => helper.failClosed(owned, "torn-write"));
  assert.throws(() =>
    helper.assertNoProtectedKeyDeletion(owned, [
      { file: "certutil.exe", args: ["-delkey", owned.key.container] },
    ]),
  );
  assert.throws(() =>
    helper.assertNoProtectedKeyDeletion(owned, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]),
  );
  const proof = helper.failClosed(owned, "orphan-journal").proof;
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: true }), flag);
  }
  helper.verifyProof({ ...proof, crashDumpContainmentQualified: false });
});

test("a missing protected-key host is not a pass", () => {
  const entry = require("./certops-windows-protected-recovery");
  assert.equal(entry.run({ probe: {} }).passed, false);
  assert.equal(helper.assessHostCapabilities({ windows: true }).passed, false);
  const script = path.resolve(__dirname, "certops-windows-protected-recovery.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-rec-"));
  try {
    const file = path.join(dir, "defect.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: `C:\\qualification\\tt-rec-${RUN}`,
        defect: "unreadable-journal",
      }),
    );
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    const body = JSON.parse(checked.stdout);
    assert.equal(body.passed, false);
    assert.equal(body.proof.protectedKeyDeleted, false);
    helper.verifyProof(body.proof);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.resolve(__dirname, "..");
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
