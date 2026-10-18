"use strict";

/** Crash-dump containment stays unqualified. A report that sets the flag true
 * is rejected. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-crash-dump");

const RUN = "a7".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-dump-${RUN}`,
  });
}

test("crash dump containment cannot be reported as qualified", () => {
  const owned = manifest();
  const proof = helper.unqualifiedProof(owned);
  helper.verifyProof(proof);
  assert.equal(proof.crashDumpContainmentQualified, false);
  assert.equal(proof.nativeExecutionQualified, false);
  const reviewed = helper.review(owned, {});
  assert.equal(reviewed.passed, false);
  assert.equal(reviewed.qualified, false);
  helper.verifyProof(reviewed.proof);
  assert.throws(
    () => helper.rejectReport({ crashDumpContainmentQualified: true }),
    /crash dump containment is unqualified/,
  );
  assert.throws(
    () => helper.review(owned, { crashDumpContainmentQualified: true, nativeExecutionQualified: false }),
    /crash dump containment is unqualified/,
  );
  assert.throws(() => helper.verifyProof({ ...proof, crashDumpContainmentQualified: true }));
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: true }), flag);
  }
  assert.throws(() =>
    helper.assertOwnedCommands(owned, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]),
  );
});

test("the crash-dump entry fails closed and rejects a qualified report", () => {
  const entry = require("./certops-windows-crash-dump");
  const absent = entry.run({ probe: {} });
  assert.equal(absent.passed, false);
  assert.equal(absent.crashDumpContainmentQualified, false);
  const ready = { windows: true, crashDumpPolicy: true, ownedTarget: true };
  assert.equal(helper.assessHostCapabilities(ready).passed, false);
  assert.equal(helper.assessHostCapabilities(ready).crashDumpContainmentQualified, false);
  const executed = entry.run({ probe: ready, execute: true, manifest: manifest(), report: {} });
  assert.equal(executed.passed, false);
  assert.equal(executed.qualified, false);
  helper.verifyProof(executed.proof);
  assert.throws(() => entry.run({ probe: ready, execute: true, manifest: manifest(), report: { crashDumpContainmentQualified: true } }));
  const script = path.resolve(__dirname, "certops-windows-crash-dump.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  assert.equal(JSON.parse(spawned.stdout).crashDumpContainmentQualified, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-dump-"));
  try {
    const file = path.join(dir, "report.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: `C:\\qualification\\tt-dump-${RUN}`,
        report: { crashDumpContainmentQualified: true },
      }),
    );
    const refused = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.equal(JSON.parse(refused.stdout).passed, false);
    assert.match(JSON.parse(refused.stdout).reason, /unqualified/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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
  assert.match(workflow, /qualified: false/);
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
