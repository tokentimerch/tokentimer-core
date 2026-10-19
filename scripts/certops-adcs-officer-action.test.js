"use strict";

// Runs the real officer-action.ps1 with the domain guard and remoting replaced by doubles, so each
// failure maps to one fixed step name and success keeps its exact output contract.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const script = fs.readFileSync(path.resolve(__dirname, "../infra/certops-adcs/officer-action.ps1"), "utf8");

function run(t, behavior) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-officer-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // Only the host-side guard lines are replaced; the failure mapping under test is the real code.
  const guarded = script
    .replace("if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Officer action requires isolated qualification forest'}", "")
    .replace("if(-not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Isolated officer credential absent'}", "");
  assert.notEqual(guarded, script, "guard lines must exist to be replaced");
  const probe = path.join(dir, "officer-action.ps1");
  fs.writeFileSync(probe, guarded);
  const wrapper = path.join(dir, "wrapper.ps1");
  fs.writeFileSync(wrapper, String.raw`
$env:CERTOPS_ADCS_OFFICER_PASSWORD='unused'
function Invoke-Command {
  param($ComputerName,$Credential,$ArgumentList,$ScriptBlock)
  switch($env:CERTOPS_OFFICER_BEHAVIOR){
    'ok' {Write-Output 'CERTOPS_OFFICER=revoke'}
    'revoke-exit' {Write-Output 'CERTOPS_OFFICER_EXIT=-2147024891';throw 'Native owned certificate revocation failed SECRET'}
    'decision-exit' {Write-Output 'CERTOPS_OFFICER_EXIT=1';throw 'Native officer decision failed'}
    default {throw $env:CERTOPS_OFFICER_BEHAVIOR}
  }
}
& $env:CERTOPS_OFFICER_SCRIPT -RequestId 5 -Action revoke -CommonName certops-adcs-0123456789-capacity0.example.test
exit $LASTEXITCODE
`);
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-File", wrapper], {
    encoding: "utf8", windowsHide: true, timeout: 30000,
    env: { ...process.env, CERTOPS_OFFICER_SCRIPT: probe, CERTOPS_OFFICER_BEHAVIOR: behavior },
  });
}

test("a successful officer action keeps its exact output and exit code", (t) => {
  const result = run(t, "ok");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(result.stdout.trim(), "CERTOPS_OFFICER=revoke");
});

test("each officer failure reports one fixed step and exits non-zero", (t) => {
  for (const [message, step] of [
    ["Owned pending CA request not found", "not-found"],
    ["Refusing action on foreign request identity", "foreign-identity"],
    ["Ambiguous request identity", "ambiguous"],
    ["Only an exact owned still-pending request may be deleted", "not-pending"],
    ["Owned issued request lacks a native certificate serial", "serial"],
    ["Native owned certificate revocation failed", "revoke"],
    ["Native officer decision failed", "decision"],
    ["The WinRM client cannot process the request SECRET", "remoting"],
  ]) {
    const result = run(t, message);
    assert.equal(result.status, 1, `${message}: ${result.stdout}${result.stderr}`);
    assert.match(result.stdout, new RegExp(`^CERTOPS_OFFICER_FAILURE=${step}\\r?$`, "m"), message);
    assert.doesNotMatch(result.stdout, /SECRET/);
  }
});

test("certutil exit codes are forwarded as numbers alongside the step", (t) => {
  const revoke = run(t, "revoke-exit");
  assert.equal(revoke.status, 1, revoke.stdout + revoke.stderr);
  assert.match(revoke.stdout, /^CERTOPS_OFFICER_EXIT=-2147024891\r?$/m);
  assert.match(revoke.stdout, /^CERTOPS_OFFICER_FAILURE=revoke\r?$/m);
  const decision = run(t, "decision-exit");
  assert.match(decision.stdout, /^CERTOPS_OFFICER_EXIT=1\r?$/m);
  assert.match(decision.stdout, /^CERTOPS_OFFICER_FAILURE=decision\r?$/m);
});
