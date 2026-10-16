"use strict";
/** Read-only native packaged chain/store-query integration. Only disposable host
 * qualification invokes these executables. The wrong-protocol control is the
 * actual candidate service-host PE, with an intentionally absent child command,
 * isolated environment/state and exact ChildProcess close drainage. No service,
 * certificate or key is installed, generated, exported or removed here. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");
const SCOPE = "extracted-candidate-native-chain-metadata-path-and-protocol-refusal";
const FLAGS = ["candidateHelperDigestMatched", "literalUnicodeSpaceBracketPath", "defaultPackagedResolverUsed", "nativeMetadataPositiveBeforeFault", "actualCandidateWrongProtocolPeUsed", "realBridgeRefusedWrongProtocol", "ownedChildClosedBeforeRestore", "exactOriginalFileIdentityRestored", "nativeMetadataPositiveAfterRestore"];
const REQUIRED_SOURCES = ["packages/agent/scripts/host/packaged-helper-runtime-fixture.js", "packages/agent/scripts/host/package-fixture.js", "packages/agent/scripts/host/windows-host.test.js", "packages/agent/src/windows-key-survivors/index.js", "packages/agent/src/issuers/chain-helper.js", "packages/agent/src/windows-cert-store/index.js", "packages/agent/scripts/pack-release.js", "packages/agent/scripts/build-windows-chain-helper.js", "packages/agent/windows-service-host/main.go", "packages/agent/windows-service-host/host.go", "packages/agent/windows-service-host/console_windows.go", "packages/agent/windows-service-host/service_windows.go", "packages/agent/reference/adcs-chain/main.go", "packages/agent/reference/adcs-chain/keyrefs/scan_windows.go", "packages/agent/reference/adcs-chain/keyrefs/result.go", "packages/agent/reference/adcs-chain/go.mod", "packages/agent/reference/adcs-chain/go.sum"];
const guards = new Set();
const digest = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function identity(file) {
  const info = fs.lstatSync(file, { bigint: true });
  assert.ok(info.isFile() && !info.isSymbolicLink() && info.ino > 0n, "Exact regular-file identity required");
  return { dev: String(info.dev), ino: String(info.ino), size: String(info.size), sha256: digest(file) };
}
function assertIdentity(file, expected) { assert.deepEqual(identity(file), expected, "Preserve changed helper file identity or bytes"); }
function assertCleanupSafe(workDir) {
  const root = path.resolve(workDir);
  for (const guard of guards) { const relative = path.relative(root, guard.root); assert.ok(relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative), "Preserve owned package while native child or helper restoration is unresolved"); }
  return true;
}
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), ["scope", "metadataOnly", "serviceInstalled", "cmcPackagedQualified", "nativeGoVerifierPackagedQualified", "architecture", "chainHelperSha256", "wrongProtocolHostSha256", ...FLAGS].sort());
  assert.equal(proof.scope, SCOPE); assert.equal(proof.metadataOnly, true);
  for (const field of ["serviceInstalled", "cmcPackagedQualified", "nativeGoVerifierPackagedQualified"]) assert.equal(proof[field], false);
  assert.equal(proof.architecture, "amd64");
  for (const key of ["chainHelperSha256", "wrongProtocolHostSha256"]) assert.match(proof[key], /^[a-f0-9]{64}$/);
  assert.notEqual(proof.chainHelperSha256, proof.wrongProtocolHostSha256);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  return true;
}
function restoreOriginal({ target, backup, original, replacement }) {
  assertIdentity(backup, original);
  assertIdentity(target, replacement);
  fs.unlinkSync(target);
  fs.renameSync(backup, target);
  assertIdentity(target, original);
  assert.equal(fs.existsSync(backup), false);
}
async function qualifyPackagedHelperRuntime({ extractedRoot, artifactDir, expectedChainSha256, expectedHostSha256 }) {
  assert.equal(process.platform, "win32"); assert.equal(process.arch, "x64");
  const root = path.join(artifactDir, "runtime with spaces café [literal]");
  assert.equal(fs.existsSync(root), false, "Refuse pre-existing runtime copy");
  fs.cpSync(extractedRoot, root, { recursive: true, force: false, errorOnExist: true });
  const rootInfo = fs.lstatSync(root, { bigint: true }); assert.ok(rootInfo.isDirectory() && !rootInfo.isSymbolicLink());
  const target = path.join(root, "bin/tokentimer-adcs-chain-amd64.exe"), host = path.join(root, "bin/tokentimer-agent-host-amd64.exe"), backup = target + ".qualification-original";
  assert.match(expectedChainSha256, /^[a-f0-9]{64}$/); assert.match(expectedHostSha256, /^[a-f0-9]{64}$/);
  const bin = path.dirname(target), binInfo = fs.lstatSync(bin, { bigint: true }); assert.ok(binInfo.isDirectory() && !binInfo.isSymbolicLink());
  const assertDirectories = () => { for (const [directory, expected] of [[root, rootInfo], [bin, binInfo]]) { const current = fs.lstatSync(directory, { bigint: true }); assert.ok(current.isDirectory() && !current.isSymbolicLink()); assert.equal(current.dev, expected.dev); assert.equal(current.ino, expected.ino); } };
  const original = identity(target); assert.equal(original.sha256, expectedChainSha256); assert.equal(digest(host), expectedHostSha256);
  assert.notEqual(expectedChainSha256, expectedHostSha256); assert.equal(fs.existsSync(backup), false);
  const state = path.join(root, "owned native state [literal]"); fs.mkdirSync(state);
  const systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT; assert.ok(systemRoot && path.isAbsolute(systemRoot));
  const search = [root, path.join(systemRoot, "System32"), systemRoot];
  // The wrong PE interprets argv[1] as a child program. Prove this deliberately
  // invalid command absent from every allowed lookup directory, including cwd.
  for (const directory of search) assert.equal(fs.readdirSync(directory).some(name => /^--key-survivors(?:\.|$)/i.test(name)), false);
  const env = { ...process.env, PATH: search.slice(1).join(path.delimiter), TOKENTIMER_AGENT_CONFIG_DIR: state, TOKENTIMER_AGENT_HOST_STOP_TIMEOUT_MS: "1000" };
  for (const name of Object.keys(env)) if (["node_options", "node_path", "path", "tokentimer_agent_config_dir", "tokentimer_agent_host_stop_timeout_ms"].includes(name.toLowerCase())) delete env[name];
  env.PATH = search.slice(1).join(path.delimiter);
  env.TOKENTIMER_AGENT_CONFIG_DIR = state; env.TOKENTIMER_AGENT_HOST_STOP_TIMEOUT_MS = "1000";
  const guard = { root }; guards.add(guard);
  const children = [];
  const containerName = `tokentimer-enr-${crypto.randomUUID()}`;
  const execute = (file, args, options, callback) => {
    assertDirectories(); assert.equal(file, target); assert.deepEqual(args, ["--key-survivors", "--container", containerName]);
    const record = { closed: false }; children.push(record);
    const child = execFile(file, args, { ...options, cwd: root, env, timeout: 15000, windowsHide: true }, callback);
    record.child = child;
    record.done = new Promise(resolve => child.once("close", (code, signal) => { record.closed = true; record.code = code; record.signal = signal; resolve(); }));
    return child;
  };
  const drain = async () => {
    for (const record of children) {
      if (record.closed) continue;
      let timer;
      try { await Promise.race([record.done, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Owned native helper close timed out; preserve candidate")), 20000); })]); }
      finally { clearTimeout(timer); }
      assert.equal(record.closed, true);
    }
  };
  const adapter = require(path.join(root, "src/windows-key-survivors"));
  const resolver = require(path.join(root, "src/issuers/chain-helper"));
  assert.equal(resolver.resolveAdcsChainHelperPath().path, target, "Use the extracted candidate's default resolver");
  const inspect = async () => { const result = await adapter.inspectMachineKeySurvivors({ containerName, execFileImpl: execute }); await drain(); return result; };
  let replacement, moved = false, primary;
  try {
    const before = await inspect(); assert.equal(before.ok, true); assert.equal(before.complete, true); assert.equal(before.shared, false); assert.equal(before.matches, 0); assert.ok(before.storesScanned > 0);
    assertDirectories(); assertIdentity(target, original); fs.renameSync(target, backup); moved = true;
    fs.copyFileSync(host, target, fs.constants.COPYFILE_EXCL); const copied = identity(target); assert.equal(copied.sha256, expectedHostSha256); replacement = copied;
    const refused = await inspect(); assert.equal(refused.ok, false); assert.equal(refused.shared, true); assert.ok(["inventory_failed", "inventory_unreadable"].includes(refused.reason));
    const wrongChild = children.at(-1); assert.ok(Number.isInteger(wrongChild.child.pid) && wrongChild.child.pid > 0); assert.equal(wrongChild.code, 1); assert.equal(wrongChild.signal, null);
    const hostLog = path.join(state, "host.log"); assert.ok(fs.statSync(hostLog).size > 0 && fs.statSync(hostLog).size <= 4096);
    const log = fs.readFileSync(hostLog, "utf8"); assert.match(log, /tokentimer-agent-host: agentHost: failed to start --key-survivors:/); assert.doesNotMatch(log, /started child pid=/);

  } catch (error) { primary = error; }
  finally {
    await drain();
    assertDirectories();
    if (moved) {
      if (replacement) restoreOriginal({ target, backup, original, replacement });
      else { assert.equal(fs.existsSync(target), false, "Preserve unverified replacement"); assertIdentity(backup, original); fs.renameSync(backup, target); assertIdentity(target, original); }
    }
    assertIdentity(target, original);
    if (primary) guards.delete(guard);
  }
  if (primary) throw primary;
  const after = await inspect(); assert.equal(after.ok, true); assert.equal(after.complete, true); assert.equal(after.shared, false); assert.equal(after.matches, 0); assert.ok(after.storesScanned > 0);
  const proof = { scope: SCOPE, metadataOnly: true, serviceInstalled: false, cmcPackagedQualified: false, nativeGoVerifierPackagedQualified: false, architecture: "amd64", chainHelperSha256: expectedChainSha256, wrongProtocolHostSha256: expectedHostSha256, ...Object.fromEntries(FLAGS.map(flag => [flag, true])) };
  verifyProof(proof); guards.delete(guard); return proof;
}
module.exports = { SCOPE, FLAGS, REQUIRED_SOURCES, verifyProof, identity, assertIdentity, restoreOriginal, assertCleanupSafe, qualifyPackagedHelperRuntime };
