/*
 * Qualification notes: windows-adoption-qualification
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Trusted installed Windows workflow covers5 profiles onServer2022/2025 within real
 * API/Postgres/Pebble/SYSTEM fixture. Own operator CNG nonexportable self-signed certificate/IIS SNI;
 * actual agent discovery persists it. Public renewal setup dry-run must create no profile/derivation
 * and preserve old binding/key; second request performs real installed ACME rotation with
 * trustedTLS/native requested-size custody. Actual harness outbox drain derives profile (not
 * autonomous worker scheduling). Ledger marks predecessor preexisting; fresh process reads same
 * row,incomplete owned .tmp ignored,real sweep defers ownership_unrecorded while replacementTLS
 * remains. Require5 cases/current hashes/measured build/service/cleanup. Detach automation before
 * exact owned target/native receipts deletion and independently prove key absence; stop failed service
 * only after executable-path ownership. Not every inventory gate/private-export or elapsed retention
 * qualification.
 */
/**
 * Installed Windows adoption/retention journey invoked by the dedicated owned host harness.
 * Public agent execution drives native certificate and binding operations; exact resource
 * ownership and observed key/store/TLS state constrain cleanup. Requires disposable
 * elevated Windows and does not run as part of portable report regressions. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const net = require("node:net");
const { pathToFileURL } = require("node:url");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const required = ["windows-adoption-native-operator-cng-discovered", "windows-adoption-dry-run-does-not-arm-renewal", "windows-adoption-public-confirm-renews-and-derives-profile", "windows-adoption-preexisting-predecessor-preserved", "windows-adoption-owned-cleanup"];
async function wait(check, timeout = 180000) { const deadline = Date.now() + timeout; do { const result = await check(); if (result) return result; await new Promise(resolve => setTimeout(resolve, 500)); } while (Date.now() < deadline); throw new Error("Native Windows adoption exceeded its deadline"); }
async function freePort() { return new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(error => error ? reject(error) : resolve(port)); }); }); }
async function peer(port, domain, ca) { return new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: domain, ca, rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Trusted adoption TLS observation timed out"))); }); }
module.exports = async function qualifyAdoption({ pool, baseUrl, workspaceId, agentId, configDir, workDir, repoRoot, domain, keyProfile, caEndpoint, caRoots, ps, command }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_PROTOCOL_DISPOSABLE_STACK, "1"); assert.equal(process.env.CERTOPS_CSR_DISPOSABLE_STACK, "1");
  assert.match(domain, /^certops-adopt-[a-f0-9]{12}\.example\.test$/);
  const build = Number(ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber")); const osVersion = build === 20348 ? "2022" : build === 26100 ? "2025" : null; assert.ok(osVersion);
  const reportPath = path.join(repoRoot, "qualification-results", `windows-adoption-${process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048"}.json`);
  const gate = createHostGate({ suite: "windows-adoption-retention-real", evidenceLevel: "e2e", strict: true, reportPath, requiredCapabilities: ["windows", "system", "api", "installedAgent"], probeCapabilities: async () => ({ windows: { available: true }, system: { available: ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";$p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($s.ProcessId)\";(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid") === "S-1-5-18" }, api: { available: (await fetch(new URL("/health", baseUrl), { signal: AbortSignal.timeout(10000) })).status === 200 }, installedAgent: { available: ps("(Get-Service TokenTimerAgent).Status") === "Running" } }) });
  await gate.preflight();
  gate.report.fixtureSource = { file: "tests/e2e/windows-adoption-retention-journey.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.qualificationEnvironment = { osFamily: "windows", osVersion, identity: "LocalSystem", measurement: "native" };
  const suffix = crypto.randomBytes(5).toString("hex"); const site = `CertOps-Adoption-${suffix}`; const container = `certops-operator-${crypto.randomUUID()}`; const directory = path.join(workDir, site); const port = await freePort();
  let publicSession, oldThumbprint, newThumbprint, certificateId; let siteOwned = false, endpointOwned = false, keyOwned = false, oldCertificateOwned = false; const ownedJobs = []; const cleanupErrors = []; let primaryError;
  const quote = value => value.replace(/'/g, "''");
  try {
    await gate.scenario(required[0], async () => {
      fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, "index.html"), "Native adoption fixture");
      assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(container));
      keyOwned = true;
      const fact = JSON.parse(ps(`$p=[Security.Cryptography.CngKeyCreationParameters]::new();$p.Provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$p.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey;$p.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None;$p.KeyUsage=[Security.Cryptography.CngKeyUsages]::AllUsages;$p.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes([int]2048),[Security.Cryptography.CngPropertyOptions]::None));$k=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,'${container}',$p);$rsa=[Security.Cryptography.RSACng]::new($k);try{$r=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=${domain}',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);$san=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new();$san.AddDnsName('${domain}');$r.CertificateExtensions.Add($san.Build());$oids=[Security.Cryptography.OidCollection]::new();$null=$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'));$r.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false));$c=$r.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddDays(2));try{$store=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');$store.Open('ReadWrite');try{$store.Add($c)}finally{$store.Close()};[pscustomobject]@{thumbprint=$c.Thumbprint;pem=[Convert]::ToBase64String($c.RawData);container=$k.KeyName;exportPolicy=[string]$k.ExportPolicy}|ConvertTo-Json -Compress}finally{$c.Dispose()}}finally{$rsa.Dispose();$k.Dispose()}`));
      oldThumbprint = fact.thumbprint; oldCertificateOwned = true; assert.match(oldThumbprint, /^[A-F0-9]{40}$/); assert.equal(fact.container, container); assert.equal(fact.exportPolicy, "None");
      const old = new crypto.X509Certificate(Buffer.from(fact.pem, "base64")); assert.equal(old.checkHost(domain), domain); assert.equal(old.verify(old.publicKey), true);
      ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Foreign fixture site'};& netsh.exe http show sslcert hostnameport=${domain}:${port} | Out-Null;if($LASTEXITCODE -eq 0){throw 'Foreign SNI endpoint'}`);
      siteOwned = true; endpointOwned = true;
      ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${quote(directory)}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl | Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1;(Get-WebBinding -Name '${site}' -Protocol https).AddSslCertificate('${oldThumbprint}','My')`);
      assert.equal((await peer(port, domain, old.toString())).fingerprint, old.fingerprint);
      const managed = await wait(async () => (await pool.query("SELECT id,key_mode,profile_id,deployed_agent_id FROM managed_certificates WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, old.fingerprint256.replace(/:/g, "").toLowerCase()])).rows[0]);
      certificateId = managed.id; assert.equal(managed.key_mode, "os-store-managed"); assert.equal(managed.profile_id, null); assert.equal(managed.deployed_agent_id, agentId);
      assert.ok((await pool.query("SELECT 1 FROM certificate_instances WHERE workspace_id=$1 AND managed_certificate_id=$2 AND observed_fingerprint_sha256=$3", [workspaceId, certificateId, old.fingerprint256.replace(/:/g, "").toLowerCase()])).rows.length);
      gate.report.nativePredecessor = { thumbprint: oldThumbprint, keyProvider: "Microsoft Software Key Storage Provider", exportPolicy: "None", creation: "operator-CngKey-and-CertificateRequest", observation: "actual-installed-agent" };
      const reopened = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${oldThumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);[pscustomobject]@{name=$k.Key.KeyName;exportPolicy=[string]$k.Key.ExportPolicy;bits=$k.KeySize}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`)); assert.equal(reopened.name, container); assert.equal(reopened.exportPolicy, "None"); assert.equal(reopened.bits, 2048);
      publicSession = await createApiFixture(baseUrl); await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')", [workspaceId, publicSession.userId]);
    });
    const payload = { commandRef: "qualification-acmesh", caEndpoint, acmeKind: "acme.sh", dnsProvider: "pebble-challtestsrv", dnsZone: "example.test", ...keyProfile };
    await gate.scenario(required[1], async () => {
      const idempotencyKey = crypto.randomUUID();
      const admitted = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/certificates/${certificateId}/renewal-setup`, "POST", { dryRun: true, idempotencyKey, payload }); assert.equal(admitted.status, 201); ownedJobs.push(admitted.body.job.id);
      await wait(async () => { const row = (await pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, admitted.body.job.id])).rows[0]; if (["failed", "rejected", "cancelled", "succeeded"].includes(row?.status)) throw new Error("Native renewal setup preflight did not complete as dry run"); return row?.status === "dry_run_complete"; });
      const replay = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/certificates/${certificateId}/renewal-setup`, "POST", { dryRun: true, idempotencyKey, payload }); assert.equal(replay.status, 201); assert.equal(replay.body.job.id, admitted.body.job.id, "Public dry-run retry must not create another native command");
      assert.equal((await pool.query("SELECT profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [workspaceId, certificateId])).rows[0].profile_id, null);
      assert.equal(Number((await pool.query("SELECT count(*) AS n FROM certops_outbox WHERE workspace_id=$1 AND event_type='profile_derivation_requested' AND payload->>'jobId'=$2", [workspaceId, admitted.body.job.id])).rows[0].n), 0);
      const bound=await require("../../packages/agent/src/windows-iis").queryCurrentBinding({binding:{site,address:"*",port,sniHost:domain,store:"My"}});assert.equal(bound.ok,true);assert.equal(bound.thumbprint.toUpperCase(),oldThumbprint);
      assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(container));
    });
    await gate.scenario(required[2], async () => {
      const admitted = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/certificates/${certificateId}/renewal-setup`, "POST", { idempotencyKey: crypto.randomUUID(), payload }); assert.equal(admitted.status, 201); ownedJobs.push(admitted.body.job.id);
      await wait(async () => { const row = (await pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, admitted.body.job.id])).rows[0]; if (["failed", "rejected", "cancelled"].includes(row?.status)) throw new Error("Real native adoption renewal failed"); return row?.status === "succeeded"; });
      const current = await peer(port, domain, caRoots); newThumbprint = current.fingerprint.replace(/:/g, ""); assert.notEqual(newThumbprint, oldThumbprint); assert.equal(current.checkHost(domain), domain);
      const key = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${newThumbprint}';$k=$null;try{$k=${keyProfile.keyAlgorithm === "rsa" ? "[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)" : "[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)"};[pscustomobject]@{name=$k.Key.KeyName;bits=$k.KeySize;exportPolicy=[string]$k.Key.ExportPolicy}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
      assert.notEqual(key.name, container); assert.equal(key.bits, keyProfile.keySize); assert.equal(key.exportPolicy, "None");
      gate.report.qualificationEnvironment.keyProfile = keyProfile.keyAlgorithm === "rsa" ? `rsa-${key.bits}` : `ec-p${key.bits}`;
      const worker = await import(pathToFileURL(path.join(repoRoot, "apps/worker/src/certops-worker.js")).href);
      await wait(async () => { const summary = await worker.drainCertOpsOutbox({ dbPool: pool, log: { debug() {}, info() {}, warn() {}, error() {} }, env: process.env }); assert.equal(summary.failed, 0); const row = (await pool.query("SELECT profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [workspaceId, certificateId])).rows[0]; return row?.profile_id; });
      assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, admitted.body.job.id])).rows.length);
      gate.report.adoption = { mode: "public-renewal-setup-after-native-discovery", nativeKeyRotated: true, trustedReplacementTls: true, derivation: "actual-production-outbox-drain", unattendedWorkerQualified: false };
    });
    await gate.scenario(required[3], async () => {
      const retention = require("../../packages/agent/src/windows-retention"); const ledgerDir = path.join(configDir, "windows-retention"); const row = await wait(() => retention.readLedgerRow(ledgerDir, oldThumbprint));
      const persisted = JSON.parse(require("node:child_process").execFileSync(process.execPath, ["-e", "const row=require(process.argv[1]).readLedgerRow(process.argv[2],process.argv[3]);process.stdout.write(JSON.stringify(row));", path.join(repoRoot, "packages/agent/src/windows-retention"), ledgerDir, oldThumbprint], { encoding: "utf8", timeout: 10000 })); assert.deepEqual(persisted, row, "A separate native process must observe the actual persisted predecessor ledger");
      assert.equal(row.ownershipProvenance, "preexisting"); assert.equal(row.replacementThumbprint, newThumbprint); assert.ok(row.jobOrRollbackJournalRefs.every(ref => ref.active === false));
      const orphan = path.join(ledgerDir, `adoption-${crypto.randomUUID()}.tmp`); fs.writeFileSync(orphan, "{\"incompleteAtomicWrite\":");
      let summary; try { summary = await require("../../packages/agent/src/index").runWindowsRetentionSweep({ stateDir: configDir, retentionHours: 24, log: { info() {}, error() {} } }); } finally { fs.rmSync(orphan, { force: true }); }
      assert.ok(summary.deferred.some(item => item.oldThumbprint === oldThumbprint && item.reason === "ownership_unrecorded"));
      assert.equal(ps(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${oldThumbprint}')`), "True"); assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(container)); assert.equal((await peer(port, domain, caRoots)).fingerprint.replace(/:/g, ""), newThumbprint);
    });
  } catch (error) { primaryError = error; } finally {
    try { await gate.scenario(required[4], async () => {
      const clean = async action => { try { await action(); } catch (error) { cleanupErrors.push(error); } };
      if (primaryError) await clean(async () => { const service = JSON.parse(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";[pscustomobject]@{path=$s.PathName;state=$s.State}|ConvertTo-Json -Compress")); assert.ok(service.path.toLowerCase().includes(workDir.toLowerCase()), "Refusing to stop a foreign service during failed adoption cleanup"); ps("Stop-Service TokenTimerAgent -ErrorAction Stop"); await wait(() => ps("(Get-Service TokenTimerAgent).Status") === "Stopped", 30000); });
      if(publicSession&&certificateId)await clean(async()=>assert.equal((await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/certificates/${certificateId}/profile`,"DELETE")).status,200,"Owned adoption automation must be detached before removing its target"));
      if (siteOwned) await clean(async () => ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){Remove-Website -Name '${site}'};if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Owned adoption site remains'}`));
      if (endpointOwned) await clean(async () => ps(`& netsh.exe http show sslcert hostnameport=${domain}:${port} | Out-Null;if($LASTEXITCODE -eq 0){& netsh.exe http delete sslcert hostnameport=${domain}:${port} | Out-Null;if($LASTEXITCODE -ne 0){throw 'Owned adoption endpoint cleanup failed'}};& netsh.exe http show sslcert hostnameport=${domain}:${port} | Out-Null;if($LASTEXITCODE -eq 0){throw 'Owned adoption endpoint remains'}`));
      for (const thumbprint of [newThumbprint, oldCertificateOwned ? oldThumbprint : null].filter(Boolean)) await clean(async () => ps(`$p='Cert:\\LocalMachine\\My\\${thumbprint}';if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -DeleteKey};if(Test-Path -LiteralPath $p){throw 'Owned adoption certificate remains'}`));
      if (keyOwned && !oldThumbprint) await clean(async () => ps(`Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${domain}' | ForEach-Object {$c=$_;$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($k -and $k.Key.KeyName -eq '${container}') {Remove-Item -LiteralPath ('Cert:\\LocalMachine\\My\\'+$c.Thumbprint) -DeleteKey}}finally{if($k){$k.Dispose()};$c.Dispose()}}`));
      if (keyOwned) await clean(async () => ps(`if([Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){$k=[Security.Cryptography.CngKey]::Open('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);try{$k.Delete()}finally{$k.Dispose()}};if([Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){throw 'Owned operator key remains'}`));
      const receipts=path.join(configDir,"windows-cert-store","issued-containers");
      if(certificateId&&fs.existsSync(receipts))for(const file of fs.readdirSync(receipts))await clean(async()=>{
        const record=JSON.parse(fs.readFileSync(path.join(receipts,file),"utf8"));if(String(record.certificateId)!==String(certificateId))return;
        const store=require("../../packages/agent/src/windows-cert-store");assert.equal(store.isAgentOwnedContainerName(record.containerName),true);
        const acceptedPresent = record.acceptedThumbprint && ps(`[bool](Test-Path 'Cert:\\LocalMachine\\${record.acceptedStore||"My"}\\${record.acceptedThumbprint}')`) === "True";
        const outcome=acceptedPresent ? await store.removeCertificateAndKeyContainer({thumbprint:record.acceptedThumbprint,containerName:record.containerName,store:record.acceptedStore||"My"}) : await store.removeAbandonedKeyContainer({containerName:record.containerName,allowAlreadyAbsent:true});assert.equal(outcome.ok,true);
        assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(record.containerName));
      });
      for (const jobId of ownedJobs) { await clean(() => pool.query("DELETE FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, jobId])); await clean(() => pool.query("DELETE FROM certificate_job_log WHERE workspace_id=$1 AND job_id=$2", [workspaceId, jobId])); await clean(() => pool.query("DELETE FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, jobId])); }
      if (publicSession) await clean(() => publicSession.cleanup());
      if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Native adoption fixture cleanup failed");
    }); } catch (error) { if (!cleanupErrors.includes(error)) cleanupErrors.push(error); }
    try { await gate.finish({ requiredScenarios: required }); } catch (error) { cleanupErrors.push(error); }
  }
  if (primaryError && cleanupErrors.length) throw new AggregateError([primaryError, ...cleanupErrors], "Native adoption and cleanup/report verification failed");
  if (primaryError) throw primaryError;
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Native adoption cleanup/report verification failed");
};
module.exports.requiredScenarios = required;
