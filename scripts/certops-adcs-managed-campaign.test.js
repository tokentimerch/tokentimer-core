"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { spawnSync } = require("node:child_process");

for (const mode of ["success", "failed", "missing-exit", "nonzero", "poll-error"]) {
  test(`managed comprehensive campaign requires actual successful execution: ${mode}`, t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-managed-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const probe = path.join(dir, "probe.ps1");
    fs.writeFileSync(probe, String.raw`
$ErrorActionPreference='Stop'
. $env:CERTOPS_MANAGED_HELPER
$script:submits=0;$script:polls=0
function Start-Sleep {param($Seconds)}
function Invoke-CertOpsArmOperation {
 param($Uri,$Method,$Body,$SubscriptionId,$RefreshAuthentication,$TimeoutSeconds)
 $script:submits++
 $bodyObject=$Body|ConvertFrom-Json
 if($Method -ne 'PUT' -or $bodyObject.properties.timeoutInSeconds -ne 11400 -or -not $bodyObject.properties.asyncExecution -or $bodyObject.properties.protectedParameters[0].value -ne 'private-sentinel'){throw 'Wrong managed submission'}
}
function ConvertFrom-CertOpsArmJson {param($Content) $Content|ConvertFrom-Json}
function Invoke-CertOpsArmRequest {
 param($Uri,$Method,$Body,$SubscriptionId,$RefreshAuthentication)
 $script:polls++
 if($Method -ne 'GET' -or -not $Uri.EndsWith('&$expand=instanceView')){throw 'Wrong poll'}
 if($env:CERTOPS_MANAGED_MODE -eq 'poll-error'){throw 'Unavailable'}
 $view=@{executionState='Succeeded';exitCode=0;output='CERTOPS_STAGE=passed'}
 if($script:polls -eq 1){$view.executionState='Running'}
 elseif($env:CERTOPS_MANAGED_MODE -eq 'failed'){$view.executionState='Failed';$view.error='private-sentinel'}
 elseif($env:CERTOPS_MANAGED_MODE -eq 'missing-exit'){$view.Remove('exitCode')}
 elseif($env:CERTOPS_MANAGED_MODE -eq 'nonzero'){$view.exitCode=7}
 @{StatusCode=200;Content=(@{properties=@{provisioningState='Succeeded';instanceView=$view}}|ConvertTo-Json -Depth 6)}
}
$failed=$false
try{$result=Invoke-CertOpsManagedCampaign -SubscriptionId '11111111-1111-4111-8111-111111111111' -ResourceGroup tt-certops-123-1 -Location swedencentral -Script 'fixture' -Parameters @('DomainPassword=private-sentinel')}
catch{$failed=$true;if($_.Exception.Message.Contains('private-sentinel')){throw 'Private error escaped'}}
if($script:submits -ne 1){throw 'Campaign replayed'}
if($env:CERTOPS_MANAGED_MODE -eq 'success'){
 if($failed -or $script:polls -ne 2 -or $result.value[0].message -ne 'CERTOPS_STAGE=passed'){throw 'Execution receipt missing'}
}elseif(-not $failed){throw 'Invalid execution accepted'}
'MANAGED_CAMPAIGN_PROBE_PASSED'
`);
    const result = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", probe], {
      encoding: "utf8", windowsHide: true, timeout: 15000,
      env: { ...process.env, CERTOPS_MANAGED_HELPER: path.resolve(__dirname, "../infra/certops-adcs/managed-campaign.ps1"), CERTOPS_MANAGED_MODE: mode },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /MANAGED_CAMPAIGN_PROBE_PASSED/);
  });
}
