"use strict";
// Exercise the checked-in remoting call and its real parameter declarations.
// Only the remote transport/domain probe are replaced; Boolean binding is native PowerShell.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
function invoke(t, discover, missing, mutate = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-observation-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let source = fs.readFileSync(path.resolve(__dirname, "../infra/certops-adcs/owned-request-observation.ps1"), "utf8");
  if (mutate) source = source.replace("([bool]$Discover),([bool]$AllowMissing)", "[bool]$Discover,[bool]$AllowMissing");
  const helper = path.join(dir, "observation.ps1"), wrapper = path.join(dir, "wrapper.ps1");
  fs.writeFileSync(helper, source);
  fs.writeFileSync(wrapper, String.raw`
param([string]$Helper,[int]$WantDiscover,[int]$WantMissing)
$ErrorActionPreference='Stop'
$env:CERTOPS_ADCS_OFFICER_PASSWORD='fixture-only-not-a-credential'
function Get-CimInstance {param($ClassName)[pscustomobject]@{Domain='lab.certops.test'}}
function Invoke-Command {
 param([string]$ComputerName,[pscredential]$Credential,[object[]]$ArgumentList,[scriptblock]$ScriptBlock)
 if($ComputerName -cne 'tt-ca.lab.certops.test' -or $Credential.UserName -cne 'TTQUAL\tt-lab-admin' -or $ArgumentList.Count -ne 4){throw 'Unexpected remoting target'}
 $typed=[scriptblock]::Create($ScriptBlock.Ast.ParamBlock.Extent.Text + [Environment]::NewLine + '[ordered]@{commonName=$CommonName;requestId=$RequestId;discover=$Discover;allowMissing=$AllowMissing}|ConvertTo-Json -Compress')
 & $typed @ArgumentList
}
try { & $Helper -CommonName 'certops-adcs-0000000000-capacity0.example.test' -RequestId 17 -Discover:([bool]$WantDiscover) -AllowMissing:([bool]$WantMissing) }
catch { @{error=$_.FullyQualifiedErrorId}|ConvertTo-Json -Compress;exit 2 }
finally { $env:CERTOPS_ADCS_OFFICER_PASSWORD=$null }
`);
  const env={...process.env};
  if(process.platform==="win32")for(const key of Object.keys(env))if(key.toLowerCase()==="psmodulepath")delete env[key];
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-File", wrapper, "-Helper", helper, "-WantDiscover", String(Number(discover)), "-WantMissing", String(Number(missing))], { encoding: "utf8", windowsHide: true, timeout: 30000, env });
}
for (const [discover, missing] of [[true, false], [false, false], [false, true], [true, true]]) {
  test(`actual observation remoting preserves discover=${discover}, allowMissing=${missing}`, t => {
    const child = invoke(t, discover, missing);
    assert.equal(child.status, 0, child.stderr || child.error?.message || child.stdout);
    assert.deepEqual(JSON.parse(child.stdout), {commonName:"certops-adcs-0000000000-capacity0.example.test",requestId:17,discover,allowMissing:missing});
  });
}
test("unparenthesized casts reproduce the original remote Boolean binding failure", t => {
  const child = invoke(t, true, false, true);
  assert.equal(child.status, 2, child.stderr || child.error?.message);
  assert.match(JSON.parse(child.stdout).error, /^ParameterArgumentTransformationError/);
});
