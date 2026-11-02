"use strict";
/* Candidate-package supporting qualification for windows-host.test.js. Verifies exact archive
 * checksum names/bytes and native PE architecture, then inspects owned extracted files. Candidate
 * source packaging is distinct from a verified historical published release.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
function sha256(file) { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); }
function verifyArchiveDigest(archive, checksum) {
  const declaration = fs.readFileSync(checksum, "utf8").trim();
  const match = /^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$/.exec(declaration);
  assert.ok(match, "invalid archive checksum sidecar");
  assert.equal(match[2], path.basename(archive), "checksum declaration must name this exact archive");
  assert.equal(sha256(archive), match[1], "archive checksum mismatch");
  return match[1];
}
function verifyPeArchitecture(file, expected) {
  const bytes = fs.readFileSync(file);
  assert.ok(bytes.length > 64 && bytes.readUInt16LE(0) === 0x5a4d, "native helper must be a DOS/PE executable");
  const offset = bytes.readUInt32LE(0x3c);
  assert.ok(offset >= 64 && offset + 6 <= bytes.length, "invalid PE header offset");
  assert.equal(bytes.readUInt32LE(offset), 0x00004550);
  assert.equal(bytes.readUInt16LE(offset + 4), expected, "helper architecture does not match its package filename");
}
async function qualifyPackage({ powershell, run, workDir, gate }) {
  const packageRoot = path.resolve(__dirname, "../..");
  const artifactDir = path.join(workDir, "release-package");
  const { main: pack, assertNoPrivateKeyMaterial } = require("../pack-release");
  const artifact = pack(["--out-dir", artifactDir]);
  const digest = verifyArchiveDigest(artifact.tarballPath, artifact.checksumPath);
  assert.equal(digest, powershell(`(Get-FileHash -Algorithm SHA256 -LiteralPath '${artifact.tarballPath.replace(/'/g, "''")}').Hash.ToLowerInvariant()`),
    "independent native archive digest must match product sidecar");
  assertNoPrivateKeyMaterial(artifact.tarballPath);
  const extracted = path.join(artifactDir, "extracted");
  fs.mkdirSync(extracted);
  run("tar.exe", ["-xzf", artifact.tarballPath, "-C", extracted]);
  const root = path.join(extracted, "package");
  const expected = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json")));
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, "package.json"))).version, expected.version);
  const artifacts = {};
  for (const [arch, machine] of [["amd64", 0x8664], ["arm64", 0xaa64]]) {
    const name = `tokentimer-agent-host-${arch}.exe`;
    const shipped = path.join(root, "bin", name);
    verifyPeArchitecture(shipped, machine);
    assert.equal(sha256(shipped), sha256(path.join(packageRoot, "bin", name)), "archive must contain the freshly built helper bytes");
    artifacts[name] = { sha256: sha256(shipped), machine };
  }
  const probe = spawnSync(process.execPath, ["-e",
    "const fs=require('fs');const path=require('path');const root=process.cwd();if(typeof require(path.join(root,'src/index.js')).runAgent!=='function')process.exit(2);for(const module of ['protocol','signing','windows-cert-store','windows-discovery','windows-iis','windows-retention','issuers'])require(path.join(root,'src',module));console.log('isolated-shipped-imports-ok')"],
  { cwd: root, encoding: "utf8", timeout: 30000, env: { ...process.env, NODE_PATH: "" } });
  assert.equal(probe.status, 0, "shipped native modules must import outside the repository without installed dependencies");
  assert.match(probe.stdout, /isolated-shipped-imports-ok/);
  assert.equal(typeof gate?.scenario, "function", "Packaged runtime qualification requires the actual host gate");
  await gate.scenario("windows-packaged-chain-runtime-protocol-refusal", async () => {
    const helper = require("./packaged-helper-runtime-fixture");
    gate.report.nativePackagedChainRuntime = await helper.qualifyPackagedHelperRuntime({ extractedRoot: root, artifactDir,
      expectedChainSha256: sha256(path.join(packageRoot, "bin/tokentimer-adcs-chain-amd64.exe")),
      expectedHostSha256: sha256(path.join(packageRoot, "bin/tokentimer-agent-host-amd64.exe")) });
    helper.verifyProof(gate.report.nativePackagedChainRuntime);
  }, { evidenceLevel: "real-host", oracle: "Actual extracted candidate bridge/native metadata query from Unicode, space and literal-bracket paths, actual wrong-protocol candidate PE refusal, owned child close and exact original file restoration followed by a fresh successful native query; no CMC/verifier/service qualification" });

  const state = path.join(artifactDir, "malformed-config-state");
  fs.mkdirSync(state);
  const credential = path.join(state, "credential");
  fs.writeFileSync(credential, "qualification-state-marker");
  const before = sha256(credential);
  const config = path.join(state, "config.json");
  const childEnv = { ...process.env, NODE_PATH: "", TOKENTIMER_AGENT_CONFIG_DIR: state,
    TOKENTIMER_AGENT_SERVER_URL: "https://127.0.0.1:1" };
  for (const [input, reason] of [["{", /failed to parse/], ["[]", /must contain a JSON object/],
    ["null", /must contain a JSON object/], ["\uFEFF{}", /failed to parse/],
    [JSON.stringify({ windows: { supersededRetentionHours: 0 } }), /supersededRetentionHours must be an integer/]]) {
    fs.writeFileSync(config, input);
    const rejected = spawnSync(process.execPath, [path.join(root, "bin", "tokentimer-agent.js")],
      { cwd: root, encoding: "utf8", timeout: 15000, env: childEnv });
    assert.equal(rejected.status, 1, "shipped entrypoint must fail promptly for malformed configuration");
    assert.match(rejected.stderr + rejected.stdout, reason);
    assert.equal(sha256(credential), before, "configuration failure must preserve existing state bytes");
  }
  fs.writeFileSync(config, JSON.stringify({ serverUrl: "https://127.0.0.1:1" }));
  const repaired = spawnSync(process.execPath, ["-e",
    "require('./src/config').loadAgentConfig();console.log('repaired-config-ok')"],
  { cwd: root, encoding: "utf8", timeout: 15000, env: childEnv });
  assert.equal(repaired.status, 0, "repaired configuration must load from the extracted candidate");
  assert.match(repaired.stdout, /repaired-config-ok/);
  assert.equal(sha256(credential), before);
  const tampered = path.join(artifactDir, "tampered", path.basename(artifact.tarballPath));
  fs.mkdirSync(path.dirname(tampered));
  fs.copyFileSync(artifact.tarballPath, tampered);
  fs.appendFileSync(tampered, Buffer.from([1]));
  assert.throws(() => verifyArchiveDigest(tampered, artifact.checksumPath), /checksum mismatch/);
  const wrongName = path.join(artifactDir, "wrong-archive-name.sha256");
  fs.writeFileSync(wrongName, `${digest}  different-candidate.tgz\n`);
  assert.throws(() => verifyArchiveDigest(artifact.tarballPath, wrongName), /must name this exact archive/);
  const corruptedHelper = path.join(artifactDir, "truncated-helper.exe");
  fs.writeFileSync(corruptedHelper, fs.readFileSync(path.join(root, "bin", "tokentimer-agent-host-amd64.exe")).subarray(0, 64));
  assert.throws(() => verifyPeArchitecture(corruptedHelper, 0x8664), /DOS\/PE executable/);
  assert.throws(() => verifyPeArchitecture(path.join(root, "bin", "tokentimer-agent-host-arm64.exe"), 0x8664), /architecture does not match/);
  // Only public digests/architecture metadata are retained as evidence.
  fs.writeFileSync(path.join(workDir, "windows-release-package.log"), JSON.stringify({ version: expected.version,
    archiveSha256: digest, artifacts, unsignedCandidate: true, isolatedImports: true, checksumTamperRejected: true,
    wrongArchiveNameRejected: true, truncatedHelperRejected: true, mismatchedHelperArchitectureRejected: true,
    malformedConfigurationRefused: true, repairedConfigurationLoaded: true, stateMarkerPreserved: true }));
}
module.exports = { qualifyPackage, verifyArchiveDigest, verifyPeArchitecture };
