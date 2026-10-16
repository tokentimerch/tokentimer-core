"use strict";

// Ordinary SCM restart of the exact qualification-created domain agent. The
// read-only observer retains original process handles before stop. No PID kill
// or assumption of atomic ownership of future descendants is permitted.
const assert = require("node:assert/strict"),
  path = require("node:path");
const observer = require("./certops-windows-stop-observer-process");
const installed = require("./certops-windows-installed-paths");
const { windowsSystem32Tool } = require("../../../packages/agent/src/platform");
const q = (value) => value.replace(/'/g, "''");
function stoppedInventoryScript(commandRoots, ownerPid) {
  assert.ok(Array.isArray(commandRoots) && commandRoots.length === 3);
  for (const value of commandRoots)
    assert.ok(typeof value === "string" && value.length > 0);
  assert.ok(
    Number.isSafeInteger(ownerPid) && ownerPid > 0 && ownerPid <= 0xffffffff,
  );
  // Keep the process object distinct from the nested command-root pipeline.
  // Reusing $_ there would inspect the string instead of the actual process.
  return `$needles=@(${commandRoots.map((value) => `'${q(value)}'`).join(",")});$foreign=@(Get-CimInstance Win32_Process|Where-Object {$p=$_;$p.ProcessId-ne$PID-and$p.ProcessId-ne${ownerPid}-and$p.CommandLine-and@($needles|Where-Object {([string]$p.CommandLine).IndexOf([string]$_,[StringComparison]::OrdinalIgnoreCase)-ge 0}).Count-gt 0});if($foreign.Count){throw 'Unexpected fixture process while stopped'};'stopped'`;
}
function identityScript(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0 && pid <= 0xffffffff);
  return `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}' -ErrorAction Stop;if(!$p-or!$p.ExecutablePath-or!$p.CommandLine){throw 'Complete original process identity required'};$h=[Security.Cryptography.SHA256]::Create();try{@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=[string]$p.ExecutablePath;commandSha256=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$p.CommandLine)))).Replace('-','').ToLowerInvariant()}|ConvertTo-Json -Compress}finally{$h.Dispose()}`;
}
function verifyStoppedResult(value) {
  for (const key of ["rootExitCode", "nodeExitCode"])
    assert.equal(value[key], 0, "Ordinary graceful service stop required");
  for (const key of [
    "allCapturedHandlesExited",
    "capturedLineageAbsent",
    "fixtureCommandPathsAbsent",
    "readOnlyObservation",
    "nativeHandlesClosed",
  ])
    assert.equal(value[key], true);
  assert.equal(value.atomicTreeContainmentQualified, false);
  return true;
}
function createServiceController({
  workDir,
  configDir,
  ps,
  command,
  until,
  onCreated,
}) {
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  for (const fn of [ps, command, until, onCreated])
    assert.equal(typeof fn, "function");
  const root = path.resolve(__dirname, "../../.."),
    state = path.resolve(workDir),
    config = path.resolve(configDir);
  assert.equal(config, path.join(state, "agent"));
  const host = path.join(
      root,
      "packages/agent/bin/tokentimer-agent-host-amd64.exe",
    ),
    entry = path.join(root, "packages/agent/bin/tokentimer-agent.js"),
    node = process.execPath;
  const prelude = installed
    .observationScript()
    .split("$s=Get-CimInstance Win32_Service")[0];
  const serviceCheck = `${prelude}
$m=Get-CimInstance Win32_ComputerSystem;if($m.Name-ine'tt-agent'-or$m.Domain-ine'lab.certops.test'-or[Security.Principal.WindowsIdentity]::GetCurrent().User.Value-ne'S-1-5-18'){throw 'Original disposable SYSTEM domain member required'};
$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'" -ErrorAction Stop;if(!$s-or$s.StartName-notin @('LocalSystem','NT AUTHORITY\\SYSTEM')-or$s.StartMode-ne'Manual'){throw 'Exact owned manual SYSTEM service required'};
$a=@([CertOpsPathArgv]::Parse($s.PathName));if($a.Count-ne 3-or$a[0]-ine'${q(host)}'-or$a[1]-ine'${q(node)}'-or$a[2]-ine'${q(entry)}'){throw 'Foreign service command refused'};
$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{$e=@($k.GetValue('Environment'));$c=@($e|Where-Object {$_-like'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($c.Count-ne 1-or$c[0]-cne'TOKENTIMER_AGENT_CONFIG_DIR=${q(config)}'-or$null-ne$k.GetValue('FailureActions')-or@($e|Where-Object {$_-match'^(TOKENTIMER_AGENT_SERVER_URL|NODE_OPTIONS)='}).Count-ne 0){throw 'Foreign service environment or recovery refused'}}finally{$k.Dispose()};
`;
  const processCheck = `
$h=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)";if(!$h-or$h.ExecutablePath-ine'${q(host)}'){throw 'Original service host required'};
$nodes=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($s.ProcessId)");if($nodes.Count-ne 1){throw 'Exactly one original Node child required'};$n=$nodes[0];$a=@([CertOpsPathArgv]::Parse($n.CommandLine));if($n.ExecutablePath-ine'${q(node)}'-or$a.Count-ne 2-or$a[0]-ine'${q(node)}'-or$a[1]-ine'${q(entry)}'-or$n.CreationDate-lt$h.CreationDate){throw 'Foreign service child refused'};
foreach($p in @($h,$n)){$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;if($o.ReturnValue-ne 0-or$o.Sid-ne'S-1-5-18'){throw 'Original SYSTEM process principal required'}};
@{hostPid=[int]$h.ProcessId;nodePid=[int]$n.ProcessId}|ConvertTo-Json -Compress`;
  const running = () => {
    const value = JSON.parse(
      ps(
        `${serviceCheck}if($s.State-ne'Running'-or$s.ProcessId-lt 1){throw 'Original service is not running'};${processCheck}`,
      ),
    );
    assert.ok(
      Number.isSafeInteger(value.hostPid) &&
        Number.isSafeInteger(value.nodePid) &&
        value.hostPid > 0 &&
        value.nodePid > 0 &&
        value.hostPid !== value.nodePid,
    );
    return value;
  };
  let stopped = false,
    lastStop;
  const assertStopped = () => {
    assert.equal(
      stopped,
      true,
      "Retained original handles must drain before config writes",
    );
    verifyStoppedResult(lastStop);
    assert.equal(
      ps(
        `${serviceCheck}if($s.State-ne'Stopped'-or$s.ProcessId-ne 0){throw 'Exact service must remain stopped'};${stoppedInventoryScript([host, entry, config], process.pid)}`,
      ),
      "stopped",
    );
    return true;
  };
  return {
    observeRunning: running,
    assertStopped,
    async stop() {
      assert.equal(stopped, false);
      const actual = running();
      const resource = await observer.startStopObservation({
        workDir: state,
        powershell: windowsSystem32Tool("WindowsPowerShell\\v1.0\\powershell"),
        ownerIdentity: JSON.parse(ps(identityScript(process.pid))),
        hostIdentity: JSON.parse(ps(identityScript(actual.hostPid))),
        nodeIdentity: JSON.parse(ps(identityScript(actual.nodePid))),
        commandRoots: [host, entry, config],
        onCreated,
      });
      command(windowsSystem32Tool("sc"), ["stop", "TokenTimerAgent"]);
      lastStop = await resource.waitForCompletion();
      verifyStoppedResult(lastStop);
      stopped = true;
      assertStopped();
      return lastStop;
    },
    async start() {
      assertStopped();
      command(windowsSystem32Tool("sc"), ["start", "TokenTimerAgent"]);
      await until(() => {
        const ready = ps(
          `${serviceCheck}if($s.State-in @('Stopped','Start Pending','StartPending')){'waiting'}elseif($s.State-eq'Running'-and$s.ProcessId-gt 0){'running'}else{throw 'Unexpected service startup state'}`,
        );
        return ready === "running";
      }, 180000);
      const actual = running();
      stopped = false;
      return actual;
    },
  };
}
module.exports = {
  identityScript,
  stoppedInventoryScript,
  verifyStoppedResult,
  createServiceController,
  assertCleanupSafe: observer.assertCleanupSafe,
};
