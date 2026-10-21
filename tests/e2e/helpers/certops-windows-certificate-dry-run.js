/*
 * Qualification notes: certificate-dry-run
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * After genuine installed CNG/IIS issuance and trusted TLS, require signed deploy and renew
 * dry_run_complete with respectively3 and6 persisted authenticated plan steps. Generic public jobs
 * cannot select execution mode: explicitly use production createCertificateJob(mode="dry_run"),
 * preserving actual signing/claim/lease/evidence/result. Independently compare private My inventory,
 * CNG file metadata/identity/export policy, HTTP.sys/TLS, config/credential/pin and unchanged owned
 * DNS proxy count. Never read/hash key-file contents or publish inventories. This qualifies observed
 * state/owned DNS traffic, not ETW transient tracing, absence of arbitrary children or direct CA
 * requests. Helper creates no extra native resource; parent owns all cleanup.
 */
"use strict";
/** Installed LocalSystem certificate dry-run qualification. Genuine prior
 * issuance establishes a capable CNG/IIS/TLS fixture; signed deploy/renew plans
 * must preserve independent native observations. No key-file bytes are read.
 * The parent owns service/certificate cleanup and later real renewal controls.
 * This source runs only in the disposable hosted Windows journey. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const suite = "windows-certificate-dry-run";
const requiredScenarios = ["windows-certificate-deploy-dry-run", "windows-certificate-renew-dry-run"];
const requiredSources = ["tests/e2e/helpers/certops-windows-certificate-dry-run.js", "tests/e2e/windows-real-journey.js", "apps/api/services/certops/jobs.js", "apps/api/services/certops/agentDispatch.js", "packages/agent/src/index.js"];
const fields = ["priorRealIssuanceVerified", "authenticatedPlansPersisted", "nativeCertificateInventoryUnchanged", "machineKeyMetadataUnchanged", "exactCngCustodyUnchanged", "httpSysBindingUnchanged", "trustedTlsUnchanged", "configurationCredentialPinUnchanged", "dnsProxyRequestsUnchanged"];
const scope = "installed-windows-signed-certificate-plans-native-state-and-dns-observation";
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope", "admission", "deployPlanSteps", "renewPlanSteps"].sort());
  assert.equal(proof.scope, scope); assert.equal(proof.admission, "production-service-explicit-mode");
  for (const field of fields) assert.equal(proof[field], true, field);
  assert.equal(proof.deployPlanSteps, 3); assert.equal(proof.renewPlanSteps, 6); return true;
}
function verifyPlan(rows, operation, count) {
  const plans = rows.filter(row => row.evidence_type === "policy.checked" && typeof row.summary === "string" && row.summary.startsWith(`Dry run plan for ${operation} `));
  assert.equal(plans.length, count);
  const steps = plans.map(row => { const metadata = Array.isArray(row.metadata) ? Object.fromEntries(row.metadata.map(item => [item.name, item.value])) : row.metadata;
    assert.equal(metadata.dryRun, true); assert.equal(metadata.jobMode, "dry_run"); assert.equal(metadata.action, operation); return metadata.planStep; });
  assert.deepEqual(steps.sort((a, b) => a - b), Array.from({ length: count }, (_, index) => index + 1));
  assert.equal(rows.some(row => ["deployment.updated", "issuance.completed"].includes(row.evidence_type)), false);
}
async function qualifyCertificateDryRun({ repoRoot, pool, workspaceId, userId, agentId, certificateId, configDir, domain, port, roots, thumbprint, initialJobId, issuePayload, profile, powershell: ps, run, waitUntil, ownedJobs, dnsRequestCount }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted"); assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.match(thumbprint, /^[A-Fa-f0-9]{40}$/); assert.equal(typeof dnsRequestCount, "function");
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
  const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map(root => root.pem), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(socket.getPeerCertificate().fingerprint.replace(/:/g, "")); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Dry-run trusted TLS timeout"))); });
  const prior = (await pool.query("SELECT status,mode,operation,claim_id,claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, initialJobId])).rows[0];
  assert.equal(prior?.status, "succeeded"); assert.equal(prior.mode, "real"); assert.equal(prior.operation, "issue"); assert.ok(prior.claim_id);
  assert.equal((await pool.query("SELECT agent_id FROM certops_agents WHERE workspace_id=$1 AND id=$2", [workspaceId, prior.claimed_by_agent_id])).rows[0]?.agent_id, agentId);
  assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 LIMIT 1", [workspaceId, initialJobId])).rows.length);
  assert.equal((await peer()).toLowerCase(), thumbprint.toLowerCase());
  const baseline = snapshot(); assert.equal(JSON.parse(baseline.custody).machine, true, "The protected fixture key must be machine-wide"); assert.ok(Number.isSafeInteger(baseline.dns) && baseline.dns > 0, "Prior real issuance must exercise this DNS observer");
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, file))).digest("hex") });
  const gate = require("../../../packages/agent/scripts/host-gate").createHostGate({ suite, strict: true, evidenceLevel: "e2e", reportPath: "qualification-results/windows-certificate-dry-run.json", fixtureSource: hash(requiredSources[0]), requiredCapabilities: ["windows", "system", "installedAgent", "api", "iis"], probeCapabilities: () => ({ windows: { available: true }, system: { available: true }, installedAgent: { available: ps("(Get-Service TokenTimerAgent).Status") === "Running" }, api: { available: true }, iis: { available: true } }) });
  gate.report.fixtureSources = requiredSources.map(hash); gate.report.qualificationEnvironment.identity = "LocalSystem"; gate.report.qualificationEnvironment.keyProfile = process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048";
  await gate.preflight();
  for (const [index, operation] of ["deploy", "renew"].entries()) await gate.scenario(requiredScenarios[index], async () => {
    const payload = { ...issuePayload, certificateId, agentId, keyMode: "os-store-managed", ...(operation === "renew" ? { renewalProfile: profile } : {}) };
    // The public generic job route has no selectable mode. This explicitly
    // uses production service admission; dispatch, nonce, lease and outcomes
    // still come from the real installed agent and normal API endpoints.
    const job = await require("../../../apps/api/services/certops/jobs").createCertificateJob({ client: pool, workspaceId, requestedByUserId: userId, assignedAgentId: prior.claimed_by_agent_id, operation, source: "api", mode: "dry_run", subjectType: "managed_certificate", subjectId: certificateId, payload });
    ownedJobs.push(job.id);
    const terminal = await waitUntil(async () => { const row = (await pool.query("SELECT status,mode,claim_id,attempt_count,claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, job.id])).rows[0]; return ["dry_run_complete", "succeeded", "failed", "rejected", "blocked", "cancelled"].includes(row?.status) ? row : null; });
    assert.equal(terminal.status, "dry_run_complete"); assert.equal(terminal.mode, "dry_run"); assert.ok(terminal.claim_id); assert.equal(terminal.attempt_count, 1); assert.equal(terminal.claimed_by_agent_id, prior.claimed_by_agent_id);
    verifyPlan((await pool.query("SELECT evidence_type,metadata->>'summary' AS summary,metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 ORDER BY id", [workspaceId, job.id])).rows, operation, index ? 6 : 3);
    // Assertion diffs must not print the private machine inventory or custody
    // names into CI logs when a native observation changes.
    assert.ok(isDeepStrictEqual(snapshot(), baseline), "Windows dry-run changed native state, identity or owned DNS traffic"); assert.equal((await peer()).toLowerCase(), thumbprint.toLowerCase());
  }, { oracle: "Actual signed certificate plan persists without native CNG/store/binding/TLS/identity or owned DNS proxy changes; prior real issuance independently established the same fixture" });
  gate.report.nativeCertificateDryRun = { scope, admission: "production-service-explicit-mode", deployPlanSteps: 3, renewPlanSteps: 6, ...Object.fromEntries(fields.map(field => [field, true])) };
  verifyProof(gate.report.nativeCertificateDryRun); await gate.finish({ requireScenarios: requiredScenarios });
}
module.exports = { suite, requiredScenarios, requiredSources, fields, scope, verifyProof, verifyPlan, qualifyCertificateDryRun };
