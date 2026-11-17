"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const { create } = require("./azure-package-input.cjs");
const { stage } = require("./stage-supplied-package.cjs");
test("issuer and consumer extract the same supplied bytes without invoking a builder", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-package-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archivePath = path.join(root, "agent.tgz"); fs.writeFileSync(archivePath, "fixture bytes");
  const sha = crypto.createHash("sha256").update("fixture bytes").digest("hex"), candidate = "a".repeat(40), seen = [];
  const pkg = create({ archivePath, archiveSha256: sha, candidateSha: candidate, expectedCandidateSha: candidate, root: path.join(root, "installs"),
    extractVerified: ({tarball,expectedSha256,destination}) => { seen.push({tarball,expectedSha256}); fs.mkdirSync(destination, {recursive:true}); return {root:destination,files:["fixture"]}; },
    verifyInstalled: (files, installed) => { assert.deepEqual(files, ["fixture"]); assert.ok(fs.existsSync(installed)); },
  });
  assert.notEqual(pkg.prepare("issuer"), pkg.prepare("nginx")); pkg.verify("issuer"); pkg.verify("nginx");
  assert.deepEqual(seen, [{tarball:archivePath,expectedSha256:sha},{tarball:archivePath,expectedSha256:sha}]);
  assert.throws(() => pkg.prepare("issuer"), /already prepared/);
  assert.throws(() => create({ archivePath, archiveSha256:"b".repeat(64), candidateSha:candidate, expectedCandidateSha:candidate, root, extractVerified:()=>{}, verifyInstalled:()=>{} }), /digest mismatch/);
});
test("stages the exact three-file archive from the caller-authenticated producer", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-stage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, "artifacts"), destination = path.join(root, "staged");
  fs.mkdirSync(directory);
  const { CAPABILITIES } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
  const { candidate } = require("../../../../scripts/test-support/final-package-evidence.cjs");
  const candidateSha = "a".repeat(40);
  const { entries, digest: archiveSha256 } = candidate(t, candidateSha);
  for (const [name, bytes] of entries) fs.writeFileSync(path.join(directory, name), bytes);
  const archive = "tokentimer-agent-0.20.0.tgz", archivePath = path.join(directory, archive), receiptPath = path.join(directory, "artifact.json");
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  const input = { directory, archiveSha256, candidateSha, destination, producerRunId: "123", artifactId: "456" };
  const selection = stage(input);
  assert.deepEqual(selection, {
    packageArtifact: { candidateSha, packageSha256: archiveSha256, runId: "123", artifactId: "456", capabilities: CAPABILITIES, packageVersion: "0.20.0" },
    provenance: "caller-authentication-required",
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(destination, "harness-input.json"), "utf8")), selection);
  assert.deepEqual(fs.readFileSync(path.join(destination, "artifact.json")), fs.readFileSync(receiptPath));
  assert.deepEqual(fs.readFileSync(path.join(destination, "artifacts", archive)), fs.readFileSync(archivePath));
  assert.deepEqual(fs.readFileSync(path.join(destination, "artifacts", archive + ".sha256")), fs.readFileSync(archivePath + ".sha256"));
  assert.throws(() => stage(input), /exist/i);

  const refused = { ...input, destination: path.join(root, "refused") };
  assert.throws(() => stage({ ...refused, artifactId: "0" }));
  assert.throws(() => stage({ ...refused, candidateSha: "b".repeat(40) }));
  fs.writeFileSync(receiptPath, JSON.stringify({ ...receipt, sourceKind: "local-worktree" }));
  assert.throws(() => stage(refused));
  fs.writeFileSync(receiptPath, JSON.stringify(receipt));
  fs.writeFileSync(archivePath + ".sha256", `${"e".repeat(64)}  ${archive}\n`);
  assert.throws(() => stage(refused));
  assert.equal(fs.existsSync(refused.destination), false);
});
test("real extractor installs and checks the same archive for issuer and consumer", t => {
  const { spawnSync } = require("node:child_process");
  const { extractVerified, verifyInstalled } = require("../../../../scripts/certops-agent-package.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-real-extract-"));
  t.after(() => fs.rmSync(root, {recursive:true,force:true}));
  for (const file of ["bin/tokentimer-agent.js", "scripts/install-agent.ps1", "scripts/install-agent.sh", "package.json"]) {
    const name = path.join(root, "package", file); fs.mkdirSync(path.dirname(name), {recursive:true}); fs.writeFileSync(name, "fixture");
  }
  const archivePath = path.join(root, "tokentimer-agent-0.20.0.tgz");
  const tar = spawnSync("tar", ["-czf", archivePath, "package"], {cwd:root,encoding:"utf8"});
  assert.equal(tar.status, 0, tar.stderr);
  const archiveSha256 = crypto.createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex"), candidateSha = "a".repeat(40);
  fs.mkdirSync(path.join(root,"roles"));
  const pkg = create({archivePath,archiveSha256,candidateSha,expectedCandidateSha:candidateSha,root:path.join(root,"roles"),extractVerified,verifyInstalled});
  pkg.prepare("issuer"); pkg.prepare("nginx"); pkg.verify("issuer"); pkg.verify("nginx");
});
