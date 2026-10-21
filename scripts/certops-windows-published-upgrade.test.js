"use strict";

/** Published predecessor archives lack service-host executables. This proof
 * does not synthesize an upgrade. A missing host is not a pass. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-published-upgrade");

const RUN = "ef".repeat(16);

function manifest(version = "0.17.3") {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-pub-${RUN}`,
    predecessorVersion: version,
  });
}

test("published predecessors fail closed without a synthesized service host", () => {
  for (const row of helper.PREDECESSORS) {
    const owned = manifest(row.version);
    const members = [
      "package/package.json",
      "package/scripts/install-agent.ps1",
      `package/${row.archive}`,
    ];
    const result = helper.inspectPublishedArchive(owned, members);
    helper.verifyProof(result.proof);
    assert.equal(result.proof.serviceHostPresent, false);
    assert.equal(result.proof.publishedPackageMigrationQualified, false);
    assert.equal(result.proof.upgradeSynthesized, false);
    assert.equal(result.passed, false);
    assert.throws(
      () =>
        helper.inspectPublishedArchive(owned, [
          ...members,
          "package/bin/tokentimer-agent-host-amd64.exe",
        ]),
      /refusing to synthesize a service host/,
    );
  }
  assert.throws(() =>
    helper.assertOwnedCommands(manifest(), [
      { file: "netsh.exe", args: ["int", "ip", "reset"] },
    ]),
  );
  const proof = helper.inspectPublishedArchive(manifest(), []).proof;
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: true }), flag);
  }
  assert.throws(() => helper.verifyProof({ ...proof, publishedPackageMigrationQualified: true }));
  helper.verifyProof({ ...proof, crashDumpContainmentQualified: false });
  assert.throws(() => helper.verifyProof({ ...proof, crashDumpContainmentQualified: true }));
});

test("a missing published archive host is not a pass", () => {
  for (const probe of [undefined, {}, { windows: true, publishedArchive: true, serviceHostInArchive: true }]) {
    const gate = helper.assessHostCapabilities(probe);
    assert.equal(gate.available, false);
    assert.equal(gate.passed, false);
    assert.equal(gate.publishedPackageMigrationQualified, false);
  }
  const entry = require("./certops-windows-published-upgrade");
  const absent = entry.run({ probe: {} });
  assert.equal(absent.passed, false);
  assert.equal(absent.publishedPackageMigrationQualified, false);
  const script = path.resolve(__dirname, "certops-windows-published-upgrade.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-pub-"));
  try {
    const file = path.join(dir, "archive.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: `C:\\qualification\\tt-pub-${RUN}`,
        predecessorVersion: "0.17.2",
        members: ["package/package.json"],
      }),
    );
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    const body = JSON.parse(checked.stdout);
    assert.equal(body.passed, false);
    assert.equal(body.publishedPackageMigrationQualified, false);
    helper.verifyProof(body.proof);
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
  assert.doesNotMatch(workflow, /\bgh\b/);
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
