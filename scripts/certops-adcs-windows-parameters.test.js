"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const runtimes = process.platform === "win32" ? ["pwsh", "powershell.exe"] : ["pwsh"];
const privateValue = "fixture-private-value & | < > ^ %PATH% ! ' \" ` $(throw 'unexpected') =\r\n next";
const parameters = [
  { name: "Secret", value: privateValue },
  { name: "Empty", value: "" },
  { name: "Equals", value: "  prefix=a=b==  " },
  { name: "Unicode", value: "Grüße 日本語 🔒\r\n" },
  { name: "Count", value: "7" },
];
const receipt = String.raw`
[IO.File]::WriteAllText($env:CERTOPS_GUEST_PATH_RECEIPT,$PSCommandPath)
$sourceBytes=[IO.File]::ReadAllBytes($PSCommandPath)
if($sourceBytes[0] -ne 239 -or $sourceBytes[1] -ne 187 -or $sourceBytes[2] -ne 191){throw 'Original source BOM missing'}
if([Environment]::OSVersion.Platform -eq 'Win32NT'){
 $acl=Get-Acl -LiteralPath $PSScriptRoot
 if(-not $acl.AreAccessRulesProtected){throw 'Private source ACL inherited'}
 $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.IdentityReference.Value -notin $allowed){throw 'Unexpected private source access'}}
}
`;
const original = String.raw`[CmdletBinding()]
param([string]$Secret,[string]$Empty,[string]$Equals,[string]$Unicode,[int]$Count)
` + receipt + String.raw`
$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:CERTOPS_PARAMETER_FIXTURE))|ConvertFrom-Json
foreach($item in $expected){if([string](Get-Variable -Name $item.name -ValueOnly) -cne $item.value){throw 'Parameter roundtrip mismatch'}}
if('Grüße 日本語 🔒' -cne $Unicode.Trim()){throw 'Original Unicode source changed'}
Add-Content -LiteralPath $env:CERTOPS_GUEST_MARKER -Value 'executed'
Write-Output 'WINDOWS_PARAMETER_ROUNDTRIP_PASSED'
`;

function setup(t, runtime, mode = "windows") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-parameters-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const fixture = Buffer.from(JSON.stringify(parameters)).toString("base64");
  const env = { ...process.env, CERTOPS_ARM_HELPER: path.resolve(__dirname, "../infra/certops-adcs/arm-operation.ps1"), CERTOPS_PARAMETER_FIXTURE: fixture, CERTOPS_ORIGINAL: Buffer.from(original).toString("base64"), CERTOPS_CAPTURE: path.join(dir, "body.json"), CERTOPS_GUEST_MARKER: path.join(dir, "executed.txt"), CERTOPS_GUEST_PATH_RECEIPT: path.join(dir, "source-path.txt"), CERTOPS_PARAMETER_MODE: mode };
  const host = path.join(dir, "host.ps1");
  fs.writeFileSync(host, String.raw`$ErrorActionPreference='Stop'
. $env:CERTOPS_ARM_HELPER
$global:submitted=$false
function Invoke-CertOpsArmOperation {
 param($Uri,$SubscriptionId,$Body,$RefreshAuthentication,$TimeoutSeconds,$PollSeconds)
 $global:submitted=$true
 [IO.File]::WriteAllText($env:CERTOPS_CAPTURE,$Body,[Text.UTF8Encoding]::new($false))
 [pscustomobject]@{value=@([pscustomobject]@{message='fixture'})}
}
$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:CERTOPS_PARAMETER_FIXTURE))|ConvertFrom-Json
$parameters=@($fixture|ForEach-Object {$_.name+'='+$_.value})
$script=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:CERTOPS_ORIGINAL))
$machine='windows-agent'
switch($env:CERTOPS_PARAMETER_MODE){
 'linux' {$machine='control-plane';$script='printf fixture'}
 'empty' {$parameters=@();$script='Write-Output fixture'}
 'duplicate' {$parameters=@('Secret=fixture-private-value','secret=second')}
 'oversize' {$parameters=@('Secret='+('x'*262144))}
 'script-oversize' {$script='x'*1048577}
 'count' {$parameters=@(1..129|ForEach-Object {'Parameter'+$_+'=value'})}
}
try {
 $null=Invoke-CertOpsVmRunCommand -SubscriptionId '11111111-1111-4111-8111-111111111111' -ResourceGroup tt-certops-123-1 -Machine $machine -Script $script -Parameters $parameters
 if($env:CERTOPS_PARAMETER_MODE -in 'duplicate','oversize','script-oversize','count'){throw 'Invalid input was submitted'}
}catch{
 if($env:CERTOPS_PARAMETER_MODE -notin 'duplicate','oversize','script-oversize','count'){throw}
 if($global:submitted){throw 'Invalid input reached ARM'}
 if($_.Exception.Message.Contains('fixture-private-value')){throw 'Private input escaped'}
 Write-Output 'REJECTED_BEFORE_SUBMISSION'
}
`);
  const result = invoke(runtime, host, env);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.ok(!result.stdout.includes("fixture-private-value"));
  return { dir, env, result, body: fs.existsSync(env.CERTOPS_CAPTURE) ? JSON.parse(fs.readFileSync(env.CERTOPS_CAPTURE, "utf8")) : null };
}
function invoke(runtime, file, env) {
  // PowerShell itself removes incompatible inherited module paths when crossing
  // versions. Node's direct process launch must provide the same clean startup.
  const childEnv = Object.fromEntries(Object.entries(env).filter(([key]) => key.toLowerCase() !== "psmodulepath"));
  return spawnSync(runtime, ["-NoProfile", "-NonInteractive", "-File", file], { encoding: "utf8", windowsHide: true, timeout: 20000, env: childEnv });
}
function executeGuest(runtime, state, script) {
  const guest = path.join(state.dir, "guest.ps1");
  fs.writeFileSync(guest, script);
  return invoke(runtime, guest, state.env);
}
function replaceEnvelope(script, bytes) {
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  return script.replace(/\$certopsGuestEnvelope='[^']*'/, "$certopsGuestEnvelope='" + bytes.toString("base64") + "'").replace(/\$certopsGuestDigest='[a-f0-9]+'/, "$certopsGuestDigest='" + digest + "'");
}
function replaceOriginal(script, originalScript) {
  const payload = JSON.parse(Buffer.from(script.match(/\$certopsGuestEnvelope='([^']*)'/)[1], "base64"));
  payload.script = originalScript;
  return replaceEnvelope(script, Buffer.from(JSON.stringify(payload)));
}
function assertCleaned(state) {
  const file = fs.readFileSync(state.env.CERTOPS_GUEST_PATH_RECEIPT, "utf8");
  assert.ok(!fs.existsSync(file), "private source file remains");
  assert.ok(!fs.existsSync(path.dirname(file)), "private source directory remains");
}

for (const runtime of runtimes) {
  test(`${runtime}: Windows named parameters roundtrip exact literal values without command-line arguments`, t => {
    const state = setup(t, runtime);
    assert.deepEqual(state.body.parameters, []);
    assert.ok(!state.body.script[0].includes(privateValue));
    const result = executeGuest(runtime, state, state.body.script[0]);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /WINDOWS_PARAMETER_ROUNDTRIP_PASSED/);
    assert.equal(fs.readFileSync(state.env.CERTOPS_GUEST_MARKER, "utf8").trim(), "executed");
    assertCleaned(state);
  });
  test(`${runtime}: digest corruption fails closed without executing or exposing parameter values`, t => {
    const state = setup(t, runtime);
    const script = state.body.script[0].replace(/(\$certopsGuestDigest=')[a-f0-9]/, "$1z");
    const result = executeGuest(runtime, state, script);
    assert.notEqual(result.status, 0);
    assert.ok(!fs.existsSync(state.env.CERTOPS_GUEST_MARKER));
    assert.match(result.stderr, /Invalid encoded guest parameters/);
    assert.ok(!(result.stdout + result.stderr).includes("fixture-private-value"));
  });
  for (const [name, value] of [
    ["duplicate names", { schemaVersion: 1, parameters: [{ name: "Secret", value: privateValue }, { name: "secret", value: "second" }] }],
    ["non-string value", { schemaVersion: 1, parameters: [{ name: "Secret", value: 1 }] }],
    ["invalid schema", { schemaVersion: 2, parameters: [] }],
    ["invalid name", { schemaVersion: 1, parameters: [{ name: "bad-name", value: privateValue }] }],
  ]) {
    test(`${runtime}: decoded ${name} cannot execute the original script`, t => {
      const state = setup(t, runtime);
      const result = executeGuest(runtime, state, replaceEnvelope(state.body.script[0], Buffer.from(JSON.stringify({ script: original, ...value }))));
      assert.notEqual(result.status, 0);
      assert.ok(!fs.existsSync(state.env.CERTOPS_GUEST_MARKER));
      assert.ok(!(result.stdout + result.stderr).includes("fixture-private-value"));
    });
  }
  test(`${runtime}: invalid UTF-8 fails before executing the original script`, t => {
    const state = setup(t, runtime);
    const result = executeGuest(runtime, state, replaceEnvelope(state.body.script[0], Buffer.from([0xc3, 0x28])));
    assert.notEqual(result.status, 0);
    assert.ok(!fs.existsSync(state.env.CERTOPS_GUEST_MARKER));
    assert.ok(!(result.stdout + result.stderr).includes("fixture-private-value"));
  });
  test(`${runtime}: malformed base64 and oversized decoded input fail without execution`, t => {
    const state = setup(t, runtime);
    const malformed = state.body.script[0].replace(/\$certopsGuestEnvelope='[^']*'/, "$certopsGuestEnvelope='*invalid*'");
    for (const script of [malformed, replaceEnvelope(state.body.script[0], Buffer.alloc(2097153, 0x61))]) {
      const result = executeGuest(runtime, state, script);
      assert.notEqual(result.status, 0);
      assert.ok(!fs.existsSync(state.env.CERTOPS_GUEST_MARKER));
      assert.match(result.stderr, /Invalid encoded guest parameters/);
      assert.ok(!(result.stdout + result.stderr).includes("fixture-private-value"));
    }
  });
  test(`${runtime}: original script failures propagate after a single execution`, t => {
    const state = setup(t, runtime);
    const fail = receipt + "Add-Content -LiteralPath $env:CERTOPS_GUEST_MARKER -Value 'executed'\nthrow 'EXPECTED_ORIGINAL_FAILURE'";
    const result = executeGuest(runtime, state, replaceOriginal(state.body.script[0], fail));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /EXPECTED_ORIGINAL_FAILURE/);
    assert.doesNotMatch(result.stderr, /Invalid encoded guest parameters/);
    assert.equal(fs.readFileSync(state.env.CERTOPS_GUEST_MARKER, "utf8").trim(), "executed");
    assertCleaned(state);
  });
  test(`${runtime}: original self-reentry binds additional child switches and parameters`, t => {
    const state = setup(t, runtime);
    const source = String.raw`[CmdletBinding()]
param([string]$Secret,[string]$Empty,[string]$Equals,[string]$Unicode,[int]$Count,[switch]$Worker,[string]$Extra)
` + receipt + String.raw`
if($Worker){if($Extra -ne 'added' -or $Count -ne 11){throw 'Child arguments changed'}; Write-Output 'SELF_REENTRY_WORKER_RECEIVED'; return}
if($env:CERTOPS_REENTRY_DEPTH -eq '1'){throw 'Worker switch lost'}
$env:CERTOPS_REENTRY_DEPTH='1'
$runtime=(Get-Process -Id $PID).Path
& $runtime -NoProfile -NonInteractive -File $PSCommandPath -Secret synthetic -Worker -Extra added -Count 11
if($LASTEXITCODE -ne 0){throw 'Self-reentry child failed'}
`;
    const result = executeGuest(runtime, state, replaceOriginal(state.body.script[0], source));
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /SELF_REENTRY_WORKER_RECEIVED/);
    assertCleaned(state);
  });
  for (const [name, body, expected] of [
    ["explicit nonzero exit", "exit 7", 7],
    ["explicit successful exit", "exit 0", 0],
    ["successful script with stale native exit", "$global:LASTEXITCODE=9; Write-Output done", 0],
    ["returned script with stale native exit", "$global:LASTEXITCODE=9; return", 0],
    ["unchecked native status in a normally completed script", process.platform === "win32" ? "cmd.exe /c exit 9" : "sh -c 'exit 9'", 0],
  ]) {
    test(`${runtime}: ${name} preserves cleanup and qualification status`, t => {
      const state = setup(t, runtime);
      const result = executeGuest(runtime, state, replaceOriginal(state.body.script[0], receipt + body));
      assert.equal(result.status, expected, result.stdout + result.stderr);
      assertCleaned(state);
    });
  }
  for (const mode of ["duplicate", "oversize", "script-oversize", "count"]) {
    test(`${runtime}: ${mode} input is rejected before ARM submission`, t => {
      const state = setup(t, runtime, mode);
      assert.equal(state.body, null);
      assert.match(state.result.stdout, /REJECTED_BEFORE_SUBMISSION/);
    });
  }
  test(`${runtime}: Linux and parameter-free Windows scripts retain their existing transport`, t => {
    const linux = setup(t, runtime, "linux");
    assert.equal(linux.body.commandId, "RunShellScript");
    assert.deepEqual(linux.body.script, ["printf fixture"]);
    assert.deepEqual(linux.body.parameters, parameters);
    const empty = setup(t, runtime, "empty");
    assert.deepEqual(empty.body.script, ["Write-Output fixture"]);
    assert.deepEqual(empty.body.parameters, []);
  });
}
