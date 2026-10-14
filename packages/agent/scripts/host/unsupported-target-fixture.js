"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { executeDeployJob, executeWindowsIisRenewJob } = require("../../src");
const { createPolicyEngine, loadPolicyConfig } = require("../../src/policy");
async function qualifyUnsupportedTargets({ binding, certificatePem, thumbprints, powershell, expectServed, originalThumbprint }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  assert.match(binding.site, /^CertOps-[a-f0-9-]{36}$/);
  assert.ok(thumbprints.every(value => /^[A-F0-9]{40}$/.test(value)));
  const allowedThumbprints = thumbprints.map(value => `'${value}'`).join(",");
  const nativeState = () => powershell(`Import-Module WebAdministration; $bindings=@(Get-WebBinding -Name '${binding.site}' -Protocol https | Sort-Object bindingInformation | Select-Object bindingInformation,sslFlags,certificateHash,certificateStoreName); $certificates=@(foreach($c in @(Get-ChildItem 'Cert:\\LocalMachine\\My' | Where-Object { $_.Thumbprint -in @(${allowedThumbprints}) } | Sort-Object Thumbprint)) { $k=$null; try { if($c.HasPrivateKey){$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}; [pscustomobject]@{thumbprint=$c.Thumbprint;keyPresent=$c.HasPrivateKey;container=if($null -ne $k){$k.Key.KeyName}else{$null};exportPolicy=if($null -ne $k){[string]$k.Key.ExportPolicy}else{$null}} } finally { if($null -ne $k){$k.Dispose()};$c.Dispose() } }); [pscustomobject]@{bindings=$bindings;certificates=$certificates} | ConvertTo-Json -Depth 5 -Compress`);
  const before = nativeState();
  const policyEngine = createPolicyEngine(loadPolicyConfig({}));
  const target = { type: "windows-iis", reference: "localhost", store: "My", binding };
  const certificateId = crypto.randomUUID();
  const standalone = await executeDeployJob({ job: { action: "deploy", certificateId, target, certificatePem }, jobId: crypto.randomUUID(), policyEngine, executionContext: { execution: {} } });
  assert.equal(standalone.status, "failed"); assert.match(standalone.errorMessage, /deploy action does not yet support windows-iis/);
  assert.equal(nativeState(), before); await expectServed(binding.port, originalThumbprint);
  const multiple = await executeWindowsIisRenewJob({ job: { action: "renew", certificateId, keyMode: "os-store-managed", target, sans: ["localhost"], deploymentTargets: [
    { ...target, binding: { ...binding, sniHost: "first.example.test" } },
    { ...target, binding: { ...binding, sniHost: "second.example.test" } },
  ] }, jobId: crypto.randomUUID(), policyEngine, executionContext: { execution: {} } });
  assert.equal(multiple.status, "failed"); assert.match(multiple.errorMessage, /multi-target windows-iis renewal is not supported yet/);
  assert.equal(nativeState(), before); await expectServed(binding.port, originalThumbprint);
}
module.exports = { qualifyUnsupportedTargets };
