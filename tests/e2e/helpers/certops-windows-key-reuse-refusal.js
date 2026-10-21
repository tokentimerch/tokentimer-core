/*
 * Qualification notes: acme-key-rotation-policy
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Windows ACME requires rotateOnRenew=true; omitted inventory-derived policy defaults true, while
 * explicit false remains refused with WINDOWS_ACME_KEY_REUSE_UNSUPPORTED until an operator edits it.
 * Signed keyRotation=false is rejected before native work/CA allocation even for dry runs; legacy
 * omission still creates fresh keys. Exercise public invalid profile admission against the genuinely
 * issued installed certificate, independently preserving stored profile, job inventory, custody,
 * HTTP.sys/TLS and observed DNS traffic. This is admission refusal, not invalid signed dispatch. Linux
 * reuse and AD CS frozen enrollment remain separate. Require windows-acme-public-key-reuse-refusal in
 * all ten normal cells.
 */
"use strict";
/** Public Windows reuse-policy refusal on a genuinely issued installed CNG/IIS
 * fixture. The parent owns native cleanup; this helper only observes native
 * state and submits an invalid public profile edit. No CA or clock injection. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const scenarioName = "windows-acme-public-key-reuse-refusal";
const requiredSources = ["tests/e2e/helpers/certops-windows-key-reuse-refusal.js", "tests/e2e/windows-real-journey.js", "apps/api/routes/certops.js", "apps/api/services/certops/renewalProfileAdmin.js", "apps/api/services/certops/renewalProfile.js", "packages/agent/src/index.js", "packages/contracts/certops/job-payload.schema.json", "packages/contracts/certops/renewal-profile.schema.json"];
const fields = ["publicAdmissionRefused", "profileUnchanged", "noJobAllocated", "nativeInventoryAndCustodyUnchanged", "trustedTlsUnchanged"];
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), ["scope", ...fields].sort());
  assert.equal(proof.scope, "public-windows-acme-profile-reuse-refusal");
  for (const field of fields) assert.equal(proof[field], true, field);
  return true;
}
async function qualifyKeyReuseRefusal({ publicSession, pool, workspaceId, certificateId, profileId, configDir, domain, port, roots, thumbprint, powershell: ps, run, dnsRequestCount }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.match(thumbprint, /^[A-Fa-f0-9]{40}$/);
  assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"), "S-1-5-18");
  const identity = () => ["config.json", "credential", "signing-key-pin.json"].map(name => crypto.createHash("sha256").update(fs.readFileSync(path.join(configDir, name))).digest("hex"));
  // Keep global observations private and compare in memory. Public reports
  // contain only bounded booleans, never machine key names or inventory rows.
  const snapshot = () => ({
    certificates: ps("@(Get-ChildItem Cert:\\LocalMachine\\My | Sort-Object Thumbprint | ForEach-Object { @{thumb=$_.Thumbprint;key=$_.HasPrivateKey;der=[Convert]::ToBase64String($_.RawData)} }) | ConvertTo-Json -Depth 4 -Compress"),
    machineKeys: ps("$p=Join-Path $env:ProgramData 'Microsoft\\Crypto\\Keys';if(!(Test-Path -LiteralPath $p)){throw 'Machine CNG metadata directory missing'};@(Get-ChildItem -LiteralPath $p -Force -File | Sort-Object Name | ForEach-Object { @{name=$_.Name;length=$_.Length;write=$_.LastWriteTimeUtc.Ticks} }) | ConvertTo-Json -Depth 4 -Compress"),
    custody: ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;try{$k=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};if(!$k -or [int]$k.Key.ExportPolicy -ne 0){throw 'Expected non-exportable machine CNG custody'};@{name=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;public=[Convert]::ToBase64String($c.PublicKey.EncodedKeyValue.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`),
    binding: run("netsh.exe", ["http", "show", "sslcert", `hostnameport=${domain}:${port}`]), identity: identity(), dns: dnsRequestCount(),
  });
  const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map(root => root.pem), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(socket.getPeerCertificate().fingerprint.replace(/:/g, "")); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Reuse-refusal trusted TLS timeout"))); });
  const state = async () => ({
    profile: (await pool.query("SELECT public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2", [workspaceId, profileId])).rows[0],
    jobs: (await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 ORDER BY id", [workspaceId, String(certificateId)])).rows.map(row => row.id),
  });
  const before = await state(), nativeBefore = snapshot();
  assert.equal(before.profile?.public_metadata?.renewalProfile?.keyRotationPolicy?.rotateOnRenew, true);
  assert.equal(JSON.parse(nativeBefore.custody).machine, true);
  assert.equal((await peer()).toLowerCase(), thumbprint.toLowerCase());
  const response = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/profiles/${profileId}`, "PATCH", { renewalProfile: { keyRotationPolicy: { rotateOnRenew: false } } });
  assert.equal(response.status, 422);
  assert.match(response.body.error, /WINDOWS_ACME_KEY_REUSE_UNSUPPORTED/);
  const after = await state();
  assert.ok(isDeepStrictEqual(after.profile, before.profile), "Refused reuse changed stored profile");
  assert.deepEqual(after.jobs, before.jobs, "Refused reuse allocated a job");
  assert.ok(isDeepStrictEqual(snapshot(), nativeBefore), "Refused reuse changed native state, identity or owned DNS traffic");
  assert.equal((await peer()).toLowerCase(), thumbprint.toLowerCase());
  const proof = { scope: "public-windows-acme-profile-reuse-refusal", ...Object.fromEntries(fields.map(field => [field, true])) };
  verifyProof(proof); return proof;
}
module.exports = { scenarioName, requiredSources, fields, verifyProof, qualifyKeyReuseRefusal };
