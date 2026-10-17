"use strict";

/** ACL, quoted-path, and SYSTEM environment refusals. A missing host is not
 * a pass. hostCapabilityAbsentIsPass stays false. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-acl-path-env");

const RUN = "b2".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-acl-${RUN}`,
  });
}

test("weak ACLs, unquoted spaced paths, and a missing SYSTEM environment are refused", () => {
  const owned = manifest();
  assert.ok(owned.binaryPath.includes(" "));
  assert.ok(owned.site.physicalPath.includes("site files"));
  const weak = helper.refuseWeakAcl(owned, { everyoneRead: true, daclProtected: false });
  const unquoted = helper.refuseUnquotedPath(owned, { binaryPath: owned.binaryPath, quoted: false });
  const environment = helper.refuseMissingSystemEnvironment(owned, { identity: "NetworkService" });
  for (const result of [weak, unquoted, environment]) {
    helper.verifyProof(result.proof);
    assert.equal(result.passed, false);
    assert.equal(result.proof.refused, true);
    assert.equal(result.proof.hostCapabilityAbsentIsPass, false);
  }
  assert.deepEqual(
    [weak.proof.refusal, unquoted.proof.refusal, environment.proof.refusal],
    helper.REFUSALS,
  );
  assert.throws(() => helper.refuseWeakAcl(owned, { everyoneRead: false, daclProtected: true }));
  assert.throws(() =>
    helper.refuseUnquotedPath(owned, { binaryPath: owned.quotedBinaryPath, quoted: true }),
  );
  assert.throws(() =>
    helper.refuseMissingSystemEnvironment(owned, {
      identity: "LocalSystem",
      systemRoot: "C:\\Windows",
    }),
  );
  assert.throws(() =>
    helper.assertOwnedCommands(owned, [{ file: "netsh.exe", args: ["winsock", "reset"] }]),
  );
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...weak.proof, [flag]: true }), flag);
  }
  helper.verifyProof({ ...weak.proof, crashDumpContainmentQualified: false });
});

test("a missing ACL host is not a pass", () => {
  for (const probe of [undefined, {}, { windows: true, acl: true }]) {
    const gate = helper.assessHostCapabilities(probe);
    assert.equal(gate.available, false);
    assert.equal(gate.passed, false);
    assert.equal(gate.nativeQualified, false);
  }
  const entry = require("./certops-windows-acl-path-env");
  assert.equal(entry.run({ probe: {} }).passed, false);
  const ready = { windows: true, acl: true, quotedPath: true, systemEnvironment: true };
  assert.equal(entry.run({ probe: ready, execute: true }).reason, "owned refusal absent");
  const script = path.resolve(__dirname, "certops-windows-acl-path-env.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-acl-"));
  try {
    const owned = manifest();
    const file = path.join(dir, "refusal.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        runId: RUN,
        root: owned.root,
        refusal: "unquoted-path",
        path: { binaryPath: owned.binaryPath, quoted: false },
      }),
    );
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 0);
    const body = JSON.parse(checked.stdout);
    assert.equal(body.passed, false);
    assert.equal(body.proof.refusal, "unquoted-path");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.resolve(__dirname, "..");
  const workflow = fs.readFileSync(
    path.join(root, ".github/workflows/certops-windows-coverage-variants.yml"),
    "utf8",
  );
  assert.match(workflow, /^on:\n {2}workflow_dispatch:\n/m);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\npush:/);
  assert.match(workflow, /contents: read/);
  assert.doesNotMatch(workflow, /\bgh\b/);
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
