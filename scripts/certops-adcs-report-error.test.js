"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
test("report diagnostics expose only an allowlisted code and numeric ARM status", () => {
  const helper = path.resolve(__dirname, "../infra/certops-adcs/report-error.ps1");
  const script = String.raw`
. $env:TT_REPORT_ERROR_HELPER
function classify([Exception]$e) { try { throw $e } catch { Get-CertOpsReportFailureCode $_ } }
classify ([Exception]::new('Guest report hash receipt absent'))
$e=[Exception]::new('private fixture secret'); $e.Data['CertOpsArmHttpStatus']=503; classify $e
classify ([System.Management.Automation.ParameterBindingException]::new('private fixture secret'))
classify ([System.Management.Automation.PSSecurityException]::new('private fixture secret'))
try { Get-Item -Path '' -ErrorAction Stop } catch { Get-CertOpsReportFailureCode $_ }
try { tt_missing_fixture_command_137 } catch { Get-CertOpsReportFailureCode $_ }
try { [IO.File]::ReadAllText('private fixture missing path') } catch { Get-CertOpsReportFailureCode $_ }
classify ([System.UnauthorizedAccessException]::new('private fixture secret'))
classify ([System.IO.IOException]::new('private fixture secret'))
classify ([Exception]::new('private fixture secret'))
`;
  const result = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", env: { ...process.env, TT_REPORT_ERROR_HELPER: helper }, timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trim().split(/\r?\n/), ["hash-receipt-missing", "arm-http-503", "parameter-binding", "execution-security", "parameter-binding", "command-unavailable", "unclassified", "access-denied", "local-io", "unclassified"]);
  assert.doesNotMatch(result.stdout + result.stderr, /private fixture secret/);
});

test("report reader classifies token failure before ARM without exposing token output", () => {
  const helper = path.resolve(__dirname, "../infra/certops-adcs/report-error.ps1");
  const reader = path.resolve(__dirname, "../infra/certops-adcs/read-report.ps1");
  const script = String.raw`
. $env:TT_REPORT_ERROR_HELPER
function az { $global:LASTEXITCODE=1; 'private fixture token' }
function Invoke-WebRequest { throw 'unexpected network request' }
try { & $env:TT_REPORT_READER -ResourceGroup 'tt-certops-1-1' -ReportKind qualification; throw 'unexpected success' }
catch { Get-CertOpsReportFailureCode $_ }
`;
  const result = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", env: { ...process.env, GITHUB_ACTIONS: "false", AZURE_SUBSCRIPTION_ID: "11111111-1111-4111-8111-111111111111", TT_REPORT_ERROR_HELPER: helper, TT_REPORT_READER: reader }, timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "arm-token-unavailable");
  assert.doesNotMatch(result.stdout + result.stderr, /private fixture token|unexpected network request/);
});
