"use strict";

// Extracts the real BuildImage helper and runs it against a docker double, so one
// transient dependency-download failure cannot fail a distribution lab while a
// persistent build failure still fails closed.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const script = path.resolve(__dirname, "../tests/wildcard-vault/ux-lab/run.ps1");

function run(t, failures) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-ux-build-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const probe = path.join(dir, "probe.ps1");
  fs.writeFileSync(probe, String.raw`
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:CERTOPS_UX_RUN_SCRIPT,[ref]$null,[ref]$null)
$fn=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'BuildImage'},$true)
if(-not $fn){throw 'BuildImage missing'}
$script:builds=0
function Start-Sleep { param($Seconds) }
function docker {
  $script:builds++
  $global:LASTEXITCODE=if($script:builds -le [int]$env:CERTOPS_UX_BUILD_FAILURES){1}else{0}
}
. ([scriptblock]::Create($fn.Extent.Text))
try { BuildImage 'Dockerfile' 'tt-test'; Write-Output ('BUILD_OK builds='+$script:builds) }
catch { Write-Output ('BUILD_FAILED builds='+$script:builds+' message='+$_.Exception.Message) }
`);
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-File", probe], {
    encoding: "utf8", windowsHide: true, timeout: 30000,
    env: { ...process.env, CERTOPS_UX_RUN_SCRIPT: script, CERTOPS_UX_BUILD_FAILURES: String(failures) },
  });
}

test("image build succeeds first time without retrying", (t) => {
  const result = run(t, 0);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /BUILD_OK builds=1\b/);
});

test("a transient build failure is retried and recovers", (t) => {
  const result = run(t, 2);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /BUILD_OK builds=3\b/);
});

test("a persistent build failure is bounded to three attempts and still fails", (t) => {
  const result = run(t, 99);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /BUILD_FAILED builds=3 message=Image build failed: tt-test/);
});
