"use strict";

/** Stage interruption proof. No service is stopped and no process is killed.
 * Recovery starts the same owned target. Power loss and reboot stay false. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-operation-interruption");

const RUN = "c3".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-op-${RUN}`,
  });
}

test("each certificate-operation stage records a point and restarts the same target", () => {
  const owned = manifest();
  const modes = ["service-stop", "process-kill", "service-stop", "process-kill"];
  helper.STAGES.forEach((stage, index) => {
    const mode = modes[index];
    const recorded = helper.recordPoint({
      manifest: owned,
      stage,
      kind: index % 2 === 0 ? "ledger" : "cng",
      sequence: index + 1,
      payload: Buffer.from(`${stage}-${RUN}`),
      mode,
      pid: 4242,
      image: `${owned.root}\\host.exe`,
    });
    const commands = helper.buildInterruptionPlan(recorded.point);
    const result = helper.recover({ point: recorded.point, bytes: recorded.bytes, commands });
    helper.verifyProof(result.proof);
    assert.equal(result.proof.stage, stage);
    assert.equal(result.proof.sameOwnedTarget, true);
    assert.equal(result.proof.inUseKeyDeleted, false);
    assert.equal(result.proof.powerLossDurabilityQualified, false);
    assert.equal(result.proof.realRebootQualified, false);
    assert.equal(result.keyDeleted, false);
    if (mode === "service-stop") {
      assert.deepEqual(commands[1].args, ["start", owned.serviceName]);
    } else {
      assert.equal(commands[1].file, recorded.point.image);
      assert.equal(commands[0].args.includes("/IM"), false);
    }
  });
  const sample = helper.recordPoint({
    manifest: owned,
    stage: "bind",
    kind: "cng",
    sequence: 4,
    payload: Buffer.from("bind"),
    mode: "process-kill",
    pid: 4242,
    image: `${owned.root}\\host.exe`,
  });
  assert.throws(() =>
    helper.assertNoInUseKeyDeletion(sample.point, [
      { file: "certutil.exe", args: ["-delkey", owned.key.container] },
    ]),
  );
  assert.throws(() => helper.buildInterruptionPlan({ ...sample.point, mode: "reboot" }));
  const commands = helper.buildInterruptionPlan(sample.point);
  const changed = Buffer.from(sample.bytes);
  changed[0] ^= 0xff;
  assert.throws(
    () => helper.recover({ point: sample.point, bytes: changed, commands }),
    /Preserve unresolved interruption point/,
  );
  for (const flag of helper.CLOSED) {
    const proof = helper.recover({ point: sample.point, bytes: sample.bytes, commands }).proof;
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: true }), flag);
  }
});

test("a missing interruption host is not a pass", () => {
  const entry = require("./certops-windows-operation-interruption");
  assert.equal(entry.run({ probe: {} }).passed, false);
  assert.equal(entry.run({ probe: {} }).nativeQualified, false);
  const ready = { windows: true, serviceControl: true, processControl: true, ownedTarget: true };
  assert.equal(helper.assessHostCapabilities(ready).passed, false);
  assert.equal(entry.run({ probe: ready, execute: false }).reason, "host execution not requested");
  const script = path.resolve(__dirname, "certops-windows-operation-interruption.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-op-"));
  try {
    const recorded = helper.recordPoint({
      manifest: manifest(),
      stage: "key-generation",
      kind: "ledger",
      sequence: 2,
      payload: Buffer.from("key-generation"),
      mode: "service-stop",
    });
    const file = helper.writePoint(dir, recorded);
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    const body = JSON.parse(checked.stdout);
    assert.equal(body.passed, false);
    assert.equal(body.powerLossDurabilityQualified, false);
    assert.equal(body.realRebootQualified, false);
    assert.equal(body.proof.stage, "key-generation");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.resolve(__dirname, "..");
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
