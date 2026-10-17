"use strict";

/** Recorded-point and key-retention proof. No service is stopped and no
 * process is killed. A missing host must not be reported as a pass. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const recovery = require("../tests/e2e/helpers/certops-windows-installed-interruption");

const RUN = "cd".repeat(16);

function ledgerPoint() {
  return recovery.recordPoint({
    kind: "ledger",
    runId: RUN,
    sequence: 7,
    payload: Buffer.from(`ledger-row-${RUN}`),
    mode: "service-stop",
    root: `C:\\qualification\\tt-int-${RUN}`,
  });
}

function cngPoint() {
  return recovery.recordPoint({
    kind: "cng",
    runId: RUN,
    sequence: 8,
    payload: Buffer.from(`cng-container-${RUN}`),
    mode: "process-kill",
    pid: 4242,
    image: `C:\\qualification\\tt-int-${RUN}\\host.exe`,
    root: `C:\\qualification\\tt-int-${RUN}`,
  });
}

test("service stop at a ledger point starts the same owned service", () => {
  const recorded = ledgerPoint();
  assert.equal(recorded.point.kind, "ledger");
  assert.equal(recorded.point.key.inUse, true);
  const commands = recovery.buildInterruptionPlan(recorded.point);
  assert.deepEqual(commands[0], {
    step: "interrupt",
    file: "sc.exe",
    args: ["stop", recorded.point.serviceName],
  });
  assert.deepEqual(commands[1].args, ["start", recorded.point.serviceName]);
  const result = recovery.recover({
    point: recorded.point,
    bytes: recorded.bytes,
    commands,
  });
  recovery.verifyProof(result.proof);
  assert.equal(result.keyDeleted, false);
  assert.equal(result.proof.powerLossDurabilityQualified, false);
  assert.equal(result.proof.realRebootQualified, false);
  assert.equal(result.proof.evidenceLevel, "host-integration");
  const changed = Buffer.from(recorded.bytes);
  changed[0] ^= 0xff;
  assert.throws(
    () =>
      recovery.recover({
        point: recorded.point,
        bytes: changed,
        commands,
      }),
    /Preserve unresolved interruption point/,
  );
});

test("process kill at a CNG point restarts only the owned image and keeps the key", () => {
  const recorded = cngPoint();
  const commands = recovery.buildInterruptionPlan(recorded.point);
  assert.deepEqual(commands[0].args, ["/PID", "4242", "/F"]);
  assert.equal(commands[0].args.includes("/IM"), false);
  assert.equal(commands[1].file, recorded.point.image);
  const result = recovery.recover({
    point: recorded.point,
    bytes: recorded.bytes,
    commands,
  });
  assert.equal(result.proof.pointKind, "cng");
  assert.equal(result.proof.inUseKeyDeleted, false);
  assert.throws(() =>
    recovery.assertNoInUseKeyDeletion(recorded.point, [
      {
        file: "certutil.exe",
        args: ["-delkey", recorded.point.key.container],
      },
    ]),
  );
  assert.throws(() =>
    recovery.buildInterruptionPlan({ ...recorded.point, mode: "reboot" }),
  );
  assert.throws(() =>
    recovery.recordPoint({
      kind: "cng",
      runId: RUN,
      sequence: 1,
      payload: Buffer.from("x"),
      mode: "process-kill",
      pid: 4,
      image: recorded.point.image,
      root: recorded.point.root,
    }),
  );
});

test("recorded point roundtrip preserves the digest before startup", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-int-"));
  try {
    const recorded = ledgerPoint();
    recovery.writePoint(dir, recorded);
    const loaded = recovery.readPoint(dir);
    const result = recovery.recover({
      point: loaded.point,
      bytes: loaded.bytes,
      commands: recovery.buildInterruptionPlan(loaded.point),
    });
    assert.equal(result.started, true);
    assert.equal(result.proof.recordedSequence, 7);
    assert.equal(fs.existsSync(path.join(dir, "interruption-point.json")), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing host capability is not a pass", () => {
  const absent = recovery.assessHostCapabilities({
    windows: true,
    serviceControl: true,
    processControl: true,
    ownedTarget: false,
  });
  assert.equal(absent.available, false);
  assert.equal(absent.passed, false);
  assert.equal(absent.nativeQualified, false);
  const entry = require("./certops-windows-installed-interruption");
  assert.equal(entry.run({ probe: absent }).reason, "host capability absent");
  const ready = {
    windows: true,
    serviceControl: true,
    processControl: true,
    ownedTarget: true,
  };
  assert.equal(recovery.assessHostCapabilities(ready).passed, false);
  const recorded = ledgerPoint();
  const checked = entry.run({
    probe: ready,
    execute: true,
    point: recorded.point,
    bytes: recorded.bytes,
  });
  assert.equal(checked.passed, false);
  assert.equal(checked.nativeQualified, false);
  assert.equal(checked.planSafe, true);
});

test("command entry and workflow stay manual and fail closed", () => {
  const root = path.resolve(__dirname, "..");
  const script = path.join(root, "scripts", "certops-windows-installed-interruption.js");
  const absent = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(absent.status, 1);
  const body = JSON.parse(absent.stdout);
  assert.equal(body.passed, false);
  assert.equal(body.nativeQualified, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-int-plan-"));
  try {
    const recorded = cngPoint();
    const file = recovery.writePoint(dir, recorded);
    const checked = spawnSync(process.execPath, [script, "--check-point", file], {
      encoding: "utf8",
    });
    assert.equal(checked.status, 0);
    const planBody = JSON.parse(checked.stdout);
    assert.equal(planBody.passed, false);
    assert.equal(planBody.evidenceLevel, "host-integration");
    assert.equal(planBody.powerLossDurabilityQualified, false);
    assert.equal(planBody.realRebootQualified, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const ps1 = fs.readFileSync(
    path.join(root, "scripts", "certops-windows-installed-interruption.ps1"),
    "utf8",
  );
  const workflow = fs.readFileSync(
    path.join(root, ".github", "workflows", "certops-windows-installed-interruption.yml"),
    "utf8",
  );
  assert.ok(ps1.indexOf("host capability absent") < ps1.indexOf("& $sc"));
  assert.match(ps1, /CERTOPS_WINDOWS_INTERRUPTION_REQUIRED/);
  assert.match(ps1, /in-use key/);
  assert.doesNotMatch(ps1, /delkey/);
  assert.doesNotMatch(ps1, /certutil/);
  assert.doesNotMatch(ps1, /Restart-Computer/);
  assert.doesNotMatch(ps1, /shutdown/);
  assert.match(workflow, /^on:\n {2}workflow_dispatch:\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /actions\/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd/);
  assert.match(workflow, /actions\/setup-node@53b83947a5a98c8d113130e565377fae1a50d02f/);
  assert.doesNotMatch(workflow, /Restart-Computer/);
  assert.doesNotMatch(workflow, /shutdown/);
  assert.doesNotMatch(workflow, /\.ps1/);
  for (const rel of recovery.REQUIRED_SOURCES) {
    assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
  }
});
