"use strict";

/** Re-registration keeps the same CNG container. Ambiguous custody fails
 * closed. An in-use key is never deleted. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-reregister-custody");

const RUN = "d4".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-reg-${RUN}`,
  });
}

test("re-registration keeps the same container and ambiguous custody fails closed", () => {
  const owned = manifest();
  const result = helper.reRegister(owned, { container: owned.key.container });
  helper.verifyProof(result.proof);
  assert.equal(result.proof.sameContainer, true);
  assert.equal(result.proof.ambiguousCustody, false);
  assert.equal(result.proof.custody, owned.key.container);
  assert.equal(result.keyDeleted, false);
  assert.equal(result.passed, false);
  assert.deepEqual(result.commands[1].args, ["start", owned.serviceName]);
  assert.throws(() => helper.reRegister(owned, { container: "other-container" }), /ambiguous custody/);
  assert.throws(
    () => helper.reRegister(owned, { containers: [owned.key.container, "other-container"] }),
    /ambiguous custody/,
  );
  assert.throws(() => helper.reRegister(owned, { container: owned.key.container, ambiguous: true }), /ambiguous custody/);
  assert.throws(() =>
    helper.assertNoInUseKeyDeletion(owned, [
      { file: "certutil.exe", args: ["-delkey", owned.key.container] },
    ]),
  );
  assert.throws(() =>
    helper.assertNoInUseKeyDeletion(owned, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]),
  );
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...result.proof, [flag]: true }), flag);
  }
  helper.verifyProof({ ...result.proof, crashDumpContainmentQualified: false });
});

test("a missing custody host is not a pass", () => {
  const entry = require("./certops-windows-reregister-custody");
  assert.equal(entry.run({ probe: {} }).passed, false);
  assert.equal(entry.run({ probe: {} }).nativeQualified, false);
  const script = path.resolve(__dirname, "certops-windows-reregister-custody.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-reg-"));
  try {
    const owned = manifest();
    const file = path.join(dir, "custody.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: owned.root,
        request: { container: owned.key.container },
      }),
    );
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    const body = JSON.parse(checked.stdout);
    assert.equal(body.passed, false);
    helper.verifyProof(body.proof);
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: owned.root,
        request: { containers: [owned.key.container, "foreign"] },
      }),
    );
    const refused = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.equal(JSON.parse(refused.stdout).passed, false);
    assert.match(JSON.parse(refused.stdout).reason, /ambiguous custody/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.resolve(__dirname, "..");
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
