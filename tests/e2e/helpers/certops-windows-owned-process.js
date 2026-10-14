"use strict";
/** Existing installed-process interruption with native handles retained only in
 * ONE PowerShell invocation. The earlier CIM snapshot is an ownership receipt,
 * not a serialized handle. This does not provide atomic tree containment. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const platform = require("../../../packages/agent/src/platform");
const guardName = ".preserve-owned-native-process.json",
  resources = new WeakMap(),
  active = new Set();
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-owned-process.js",
  "tests/e2e/helpers/certops-windows-owned-process.ps1",
  "packages/agent/src/platform/index.js",
  "tests/e2e/helpers/certops-windows-installed-paths.js",
]);
const FLAGS = Object.freeze([
  "retainedNativeHandles",
  "freshIdentityReverified",
  "capturedHandlesExited",
  "capturedLineageAbsent",
  "fixtureCommandPathsAbsent",
]);
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function fileId(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.ok(s.ino > 0n);
  assert.equal(s.isSymbolicLink(), false);
  assert.equal(
    fs.realpathSync(file).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return String(s.ino);
}
function assertCleanupSafe(workDir) {
  assert.equal(
    active.has(path.resolve(workDir).toLowerCase()),
    false,
    "Unresolved native process ownership remains active",
  );
  assert.equal(
    fs.existsSync(path.join(workDir, guardName)),
    false,
    "Unresolved retained native process ownership; preserve all fixture state",
  );
}
function validateIdentity(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    ["pid", "parentPid", "createdAt", "executable", "commandSha256"].sort(),
  );
  for (const key of ["pid", "parentPid"])
    assert.ok(
      Number.isInteger(value[key]) &&
        value[key] > 0 &&
        value[key] <= 0xffffffff,
    );
  assert.match(
    value.createdAt,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,7}Z$/,
  );
  assert.ok(Number.isFinite(Date.parse(value.createdAt)));
  assert.ok(path.win32.isAbsolute(value.executable));
  assert.match(value.commandSha256, /^[a-f0-9]{64}$/);
  return true;
}
function sameIdentity(value, expected) {
  validateIdentity(value);
  validateIdentity(expected);
  assert.equal(value.pid, expected.pid);
  assert.equal(value.parentPid, expected.parentPid);
  assert.equal(value.createdAt, expected.createdAt);
  assert.ok(
    value.executable.toLowerCase() === expected.executable.toLowerCase(),
    "Original executable identity changed",
  );
  assert.equal(value.commandSha256, expected.commandSha256);
  return true;
}
function verifyProof(value, identity) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "rootPid",
      "rootNativeCreatedTicks",
      "capturedProcessCount",
      "atomicTreeContainmentQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, "exact-owned-native-process-handle-termination");
  assert.equal(value.rootPid, identity.pid);
  assert.match(value.rootNativeCreatedTicks, /^[1-9][0-9]{10,19}$/);
  assert.ok(
    Number.isInteger(value.capturedProcessCount) &&
      value.capturedProcessCount >= 1 &&
      value.capturedProcessCount <= 128,
  );
  assert.equal(value.atomicTreeContainmentQualified, false);
  for (const key of FLAGS) assert.equal(value[key], true, key);
  return true;
}
function makeOwnership(workDir) {
  assertCleanupSafe(workDir);
  active.add(path.resolve(workDir).toLowerCase());
  const root = path.resolve(workDir),
    rootId = fileId(root),
    directory = fs.mkdtempSync(path.join(root, "native-process-")),
    nonce = crypto.randomBytes(16).toString("hex");
  platform.applyRestrictivePermissions(directory, { kind: "directory" });
  const guard = path.join(root, guardName);
  fs.writeFileSync(
    guard,
    JSON.stringify({ schemaVersion: 1, nonce, directory }),
    { flag: "wx" },
  );
  platform.applyRestrictivePermissions(guard, { kind: "file" });
  active.add(root.toLowerCase());
  const directoryId = fileId(directory),
    guardId = fileId(guard),
    guardHash = sha(fs.readFileSync(guard));
  return {
    root,
    directory,
    nonce,
    guard,
    check() {
      assert.equal(fileId(root), rootId);
      assert.equal(fileId(directory), directoryId);
      assert.equal(fileId(guard), guardId);
      assert.equal(sha(fs.readFileSync(guard)), guardHash);
    },
    release() {
      assert.equal(fileId(root), rootId);
      assert.equal(fileId(guard), guardId);
      assert.equal(sha(fs.readFileSync(guard)), guardHash);
      fs.unlinkSync(guard);
      active.delete(root.toLowerCase());
    },
  };
}
function snapshotScript(pid) {
  assert.ok(Number.isInteger(pid) && pid > 0 && pid <= 0xffffffff);
  return `$p=Get-CimInstance Win32_Process -Filter "ProcessId=${pid}";if(!$p -or !$p.ExecutablePath -or !$p.CommandLine){throw 'Original process identity absent'};$h=[Security.Cryptography.SHA256]::Create();try{@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=[string]$p.ExecutablePath;commandSha256=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$p.CommandLine)))).Replace('-','').ToLowerInvariant()}|ConvertTo-Json -Compress}finally{$h.Dispose()}`;
}
function captureWithOwner({
  expectedIdentity,
  powershell,
  ownership,
  commandRoots,
}) {
  validateIdentity(expectedIdentity);
  ownership.check();
  let actual;
  try {
    actual = JSON.parse(powershell(snapshotScript(expectedIdentity.pid)));
  } catch {
    throw new Error("Original process snapshot refused; preserve owned state");
  }
  sameIdentity(actual, expectedIdentity);
  assert.ok(
    Array.isArray(commandRoots) &&
      commandRoots.length >= 1 &&
      commandRoots.length <= 8,
  );
  for (const root of commandRoots) {
    assert.ok(path.isAbsolute(root));
    const relative = path.relative(ownership.root, path.resolve(root));
    assert.ok(
      relative && !relative.startsWith("..") && !path.isAbsolute(relative),
      "Only exact fixture-specific command roots may authorize observation",
    );
  }
  const identity = Object.freeze({ ...actual });
  resources.set(identity, {
    ownership,
    commandRoots: [...new Set(commandRoots)],
  });
  return identity;
}
function captureProcessIdentity({
  expectedIdentity,
  powershell,
  workDir,
  commandRoots,
}) {
  const ownership = makeOwnership(workDir);
  return captureWithOwner({
    expectedIdentity,
    powershell,
    ownership,
    commandRoots,
  });
}
function captureInstalledAgentIdentity({
  powershell,
  workDir,
  configDir,
  nodePath,
  commandRoots,
}) {
  const ownership = makeOwnership(workDir),
    host = path.join(workDir, "app/bin/tokentimer-agent-host-amd64.exe"),
    entry = path.join(workDir, "app/bin/tokentimer-agent.js"),
    q = (value) => value.replace(/'/g, "''");
  const argvPrelude = require("./certops-windows-installed-paths")
    .observationScript()
    .split("$s=Get-CimInstance Win32_Service")[0];
  let identity;
  try {
    identity = JSON.parse(
      powershell(
        `${argvPrelude}
$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'";if(!$s -or $s.State -ne 'Running' -or $s.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM')){throw 'Owned SYSTEM service absent'};$hostProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)";if(!$hostProcess -or $hostProcess.ExecutablePath -ine '${q(host)}'){throw 'Foreign SCM executable'};$r=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{$values=@($r.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($values.Count-ne 1 -or $values[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine '${q(configDir)}'){throw 'Foreign service state root'}}finally{$r.Dispose()};$nodes=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($s.ProcessId)"|Where-Object {$_.ExecutablePath -ieq '${q(nodePath)}' -and $_.CommandLine.IndexOf('${q(entry)}',[StringComparison]::OrdinalIgnoreCase)-ge 0});if($nodes.Count-ne 1){throw 'Exactly one owned installed Node child required'};$p=$nodes[0];$serviceArgs=@([CertOpsPathArgv]::Parse($s.PathName));$childArgs=@([CertOpsPathArgv]::Parse($p.CommandLine));if($serviceArgs.Count-ne 3 -or $serviceArgs[0] -ine '${q(host)}' -or $serviceArgs[1] -ine '${q(nodePath)}' -or $serviceArgs[2] -ine '${q(entry)}' -or $childArgs.Count-ne 2 -or $childArgs[0] -ine '${q(nodePath)}' -or $childArgs[1] -ine '${q(entry)}' -or $p.CreationDate -lt $hostProcess.CreationDate){throw 'Exact installed argv and parent chronology required'};$h=[Security.Cryptography.SHA256]::Create();try{@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=[string]$p.ExecutablePath;commandSha256=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$p.CommandLine)))).Replace('-','').ToLowerInvariant()}|ConvertTo-Json -Compress}finally{$h.Dispose()}`,
      ),
    );
  } catch {
    throw new Error(
      "Original installed service child could not be captured; preserve state",
    );
  }
  return captureWithOwner({
    expectedIdentity: identity,
    powershell,
    ownership,
    commandRoots,
  });
}
function terminateOwnedProcessTree({ identity, run }) {
  const state = resources.get(identity);
  assert.ok(
    state,
    "Original captured ownership receipt required; no PID-only fallback",
  );
  const { ownership, commandRoots } = state;
  ownership.check();
  const context = path.join(ownership.directory, "context.json"),
    bytes = Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        nonce: ownership.nonce,
        identity,
        commandRoots,
        ownerExecutable: process.execPath,
      }),
    );
  fs.writeFileSync(context, bytes, { flag: "wx" });
  platform.applyRestrictivePermissions(context, { kind: "file" });
  const contextId = fileId(context);
  let proof;
  try {
    proof = JSON.parse(
      run("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(__dirname, "certops-windows-owned-process.ps1"),
        "-ContextFile",
        context,
        "-ContextSha256",
        sha(bytes),
        "-OwnerProcessId",
        String(process.pid),
      ]),
    );
  } catch {
    throw new Error(
      "Retained native process interruption or drainage failed; preserve owned state",
    );
  }
  verifyProof(proof, identity);
  ownership.check();
  assert.equal(fileId(context), contextId);
  assert.equal(sha(fs.readFileSync(context)), sha(bytes));
  assert.deepEqual(fs.readdirSync(ownership.directory), ["context.json"]);
  fs.unlinkSync(context);
  fs.rmdirSync(ownership.directory);
  ownership.release();
  resources.delete(identity);
  return proof;
}
const PUBLIC_FLAGS = Object.freeze([
  "retainedNativeHandles",
  "freshIdentityReverified",
  "capturedHandlesExited",
  "capturedLineageAbsent",
  "fixtureCommandPathsAbsent",
  "fixtureAdjustedLeaseRecovery",
  "unresolvedAttemptNotReplayed",
  "startupOrphanKeyRemoved",
  "priorTrustedTlsPreserved",
]);
function verifyPublicProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      ...PUBLIC_FLAGS,
      "atomicTreeContainmentQualified",
      "productionLeaseGraceQualified",
    ].sort(),
  );
  assert.equal(
    value.scope,
    "installed-system-native-handle-crash-fixture-lease-recovery",
  );
  for (const flag of PUBLIC_FLAGS) assert.equal(value[flag], true, flag);
  assert.equal(value.atomicTreeContainmentQualified, false);
  assert.equal(value.productionLeaseGraceQualified, false);
  return true;
}
function publicProof(native) {
  verifyProof(native, { pid: native.rootPid });
  const value = {
    scope: "installed-system-native-handle-crash-fixture-lease-recovery",
    ...Object.fromEntries(PUBLIC_FLAGS.map((flag) => [flag, true])),
    atomicTreeContainmentQualified: false,
    productionLeaseGraceQualified: false,
  };
  verifyPublicProof(value);
  return value;
}
module.exports = {
  scenarioName:
    "real Windows: retained native handles interrupt the installed agent and fixture lease recovery preserves custody",
  PUBLIC_FLAGS,
  verifyPublicProof,
  publicProof,
  captureProcessIdentity,
  captureInstalledAgentIdentity,
  terminateOwnedProcessTree,
  assertCleanupSafe,
  validateIdentity,
  sameIdentity,
  verifyProof,
  snapshotScript,
  guardName,
  FLAGS,
  REQUIRED_SOURCES,
};
