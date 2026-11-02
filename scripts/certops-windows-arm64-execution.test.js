"use strict";

/** ARM64 execution proof. Any other architecture, or a missing host, is a
 * failure. This contract never reports a pass. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-arm64-execution");

const RUN = "a1".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-arm-${RUN}`,
  });
}

test("non-arm64 and absent hosts fail and never qualify ARM64 execution", () => {
  const owned = manifest();
  for (const probe of [
    undefined,
    {},
    { windows: true, architecture: "x64", arm64Host: false },
    { windows: true, architecture: "arm64", arm64Host: false, realArm64Probe: false },
    { windows: false, architecture: "arm64", arm64Host: true, realArm64Probe: true, probeSource: "arm64-host" },
  ]) {
    const result = helper.evaluate(owned, probe);
    assert.equal(result.passed, false);
    assert.equal(result.nativeArm64ExecutionQualified, false);
    helper.verifyProof(result.proof);
    assert.equal(result.proof.nativeArm64ExecutionQualified, false);
    assert.equal(result.proof.arm64HostPresent, false);
  }
  const gate = helper.assessHostCapabilities({
    windows: true,
    architecture: "arm64",
    arm64Host: true,
    realArm64Probe: true,
    probeSource: "arm64-host",
  });
  assert.equal(gate.passed, false);
  assert.equal(gate.nativeArm64ExecutionQualified, false);
  if (process.arch !== "arm64") assert.equal(gate.available, false);
  const proof = helper.evaluate(owned, { architecture: "ia32" }).proof;
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: true }), flag);
  }
  assert.throws(() => helper.verifyProof({ ...proof, nativeArm64ExecutionQualified: true }));
  helper.verifyProof({ ...proof, crashDumpContainmentQualified: false });
  assert.throws(() =>
    helper.assertOwnedCommands(owned, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]),
  );
});

test("the ARM64 entry fails closed on this host", () => {
  const entry = require("./certops-windows-arm64-execution");
  const probed = entry.run({ probe: entry.probeHost() });
  assert.equal(probed.passed, false);
  assert.equal(probed.nativeArm64ExecutionQualified, false);
  assert.equal(entry.probeHost().arm64Host, false);
  const script = path.resolve(__dirname, "certops-windows-arm64-execution.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  const body = JSON.parse(spawned.stdout);
  assert.equal(body.passed, false);
  assert.equal(body.nativeArm64ExecutionQualified, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-arm-"));
  try {
    const file = path.join(dir, "probe.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: `C:\\qualification\\tt-arm-${RUN}`,
        probe: { windows: true, architecture: process.arch, arm64Host: false },
      }),
    );
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    const checkedBody = JSON.parse(checked.stdout);
    assert.equal(checkedBody.passed, false);
    assert.equal(checkedBody.nativeArm64ExecutionQualified, false);
    helper.verifyProof(checkedBody.proof);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.resolve(__dirname, "..");
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
