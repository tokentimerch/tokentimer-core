"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { verifyCandidateArchives, verifyReleaseDistributionCandidate } = require("./certops-agent-package");

test("all three candidate archives must have matching checksums and no extra archive", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-package-composition-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const names = ["agent.tgz", "agent-windows-amd64.tgz", "agent-windows-arm64.tgz"];
  for (const name of names) {
    const bytes = Buffer.from(`synthetic ${name}`);
    fs.writeFileSync(path.join(dir, name), bytes);
    const hash = crypto.createHash("sha256").update(bytes).digest("hex");
    fs.writeFileSync(path.join(dir, `${name}.sha256`), `${hash}  ${name}\n`);
  }
  assert.equal(Object.keys(verifyCandidateArchives(dir, names)).length, 3);
  for (const name of names) {
    const sidecar = path.join(dir, `${name}.sha256`);
    const prior = fs.readFileSync(sidecar);
    fs.writeFileSync(sidecar, `${"0".repeat(64)}  ${name}\n`);
    assert.throws(() => verifyCandidateArchives(dir, names));
    fs.writeFileSync(sidecar, prior);
  }
  fs.writeFileSync(path.join(dir, "unexpected.tgz"), "fixture");
  assert.throws(() => verifyCandidateArchives(dir, names), /Unexpected candidate archive set/);
});

test("Linux-only and bundled Windows packaging modes reject combination before building", () => {
  const script = path.resolve(__dirname, "../packages/agent/scripts/pack-release.js");
  const result = spawnSync(process.execPath, [script, "--linux-only", "--windows-runtime-dir", "fixture"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /cannot be combined/);
});

test("distribution candidate binds exact bytes, source and all tool versions", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-distribution-composition-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archive = "tokentimer-agent-0.20.0.tgz";
  const candidate = "a".repeat(40);
  const versions = { nodeVersion: "24.22.3", npmVersion: "11.19.1", goVersion: "1.26.10" };
  const bytes = Buffer.from("synthetic distribution fixture");
  const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  const receipt = { archive, candidateSha: candidate, sha256, nodeVersion: `v${versions.nodeVersion}`, npmVersion: versions.npmVersion };
  const provenance = { archive, sourceSha: candidate, archiveSha256: sha256, status: "passed", goVersion: `go${versions.goVersion}` };
  fs.mkdirSync(path.join(root, "artifacts"));
  fs.writeFileSync(path.join(root, "artifacts", archive), bytes);
  const write = (r, p) => {
    fs.writeFileSync(path.join(root, "artifact.json"), JSON.stringify(r));
    fs.writeFileSync(path.join(root, "native-provenance.json"), JSON.stringify(p));
  };
  write(receipt, provenance);
  assert.equal(verifyReleaseDistributionCandidate(root, sha256, versions), sha256);
  for (const field of ["nodeVersion", "npmVersion", "goVersion"]) {
    assert.throws(() => verifyReleaseDistributionCandidate(root, sha256, { ...versions, [field]: "wrong" }));
  }
  for (const altered of [
    { sourceSha: "b".repeat(40) }, { archiveSha256: "0".repeat(64) },
    { status: "failed" }, { archive: "foreign.tgz" },
  ]) {
    write(receipt, { ...provenance, ...altered });
    assert.throws(() => verifyReleaseDistributionCandidate(root, sha256, versions));
  }
  write({ ...receipt, sha256: "0".repeat(64) }, provenance);
  assert.throws(() => verifyReleaseDistributionCandidate(root, sha256, versions));
  write(receipt, provenance);
  fs.writeFileSync(path.join(root, "artifacts", archive), "tampered");
  assert.throws(() => verifyReleaseDistributionCandidate(root, sha256, versions));
});
