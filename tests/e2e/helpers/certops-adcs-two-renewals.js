"use strict";
/* Two complete default scheduler sweeps against an already managed native AD CS
 * fixture. The unchanged six-day template remains naturally inside its stored
 * thirty-day renewal window. Every new enrollment creates a fresh protected
 * machine key; no due time, successful result or journal is manufactured.
 * The disposable parent owns all created enrollments and final native cleanup.
 */
const { verifyNativeRequestId } = require("./certops-adcs-live-enroll-acl");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { setTimeout: delay } = require("node:timers/promises");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { buildEnrollmentContainerName, readIssuedContainerRecord } = require("../../../packages/agent/src/windows-cert-store");
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-two-unattended-natural-generations",
  "adcs-real-two-unattended-native-key-cutovers",
  "adcs-real-two-unattended-profile-and-custody-preservation",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "packages/agent/src/issuers/adcs.js",
  "tests/e2e/helpers/certops-adcs-two-renewals.js",
  "infra/certops-adcs/templates.ps1",
  "infra/certops-adcs/owned-issued-request.ps1",
  "apps/api/services/certops/renewalScheduler.js",
  "apps/api/services/certops/certificateEnrollments.js",
  "apps/api/services/certops/agentDispatch.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/windows-cert-store/index.js",
]);
const FLAGS = Object.freeze([
  "defaultSqlNowSelection", "automaticSourceAndRealMode", "distinctExpiryGenerations",
  "independentCaRequests", "freshLeafSerialAndSpki", "protectedUniqueMachineKeys",
  "nativeIisAndSniCutovers", "independentTrustedTls", "claimBoundVerificationEvidence",
  "unchangedStoredProfile", "sameManagementPeriod", "predecessorCustodyPreserved",
  "actualInventoryMatchesLatest", "ownedEnrollmentCleanupRegistered", "noDateOrJournalOverrides",
]);
const normalized = value => String(value).replace(/:/g, "").toLowerCase();
const serial = value => normalized(value).replace(/^0+(?=[0-9a-f])/, "");
function describe(certificate) {
  return { certificate, fingerprint: normalized(certificate.fingerprint256),
    thumb: certificate.fingerprint.replace(/:/g, "").toUpperCase(),
    spki: crypto.createHash("sha256").update(certificate.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    serial: serial(certificate.serialNumber), expires: Date.parse(certificate.validTo) };
}
function verifyProof(proof) {
  const fields = new Set(["scope", "renewalProtocol", "schedulerInvocation", "workerIntervalQualified", "successfulAutomationCycles", "expiryCleanupQualified", "requestIds", "caRequestCounts", "fingerprints", "spkiFingerprints", "serialNumbers", "containerNames", "expiryEpochs", ...FLAGS]);
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  for (const key of Object.keys(proof)) assert.ok(fields.has(key), "Unexpected native renewal proof field");
  assert.equal(proof.scope, "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup");
  assert.equal(proof.renewalProtocol, "fresh-enrollment-with-new-key-and-csr");
  assert.equal(proof.schedulerInvocation, "qualification-invoked-production-default-sweep"); assert.equal(proof.workerIntervalQualified, false);
  assert.equal(proof.successfulAutomationCycles, 2); assert.equal(proof.expiryCleanupQualified, false);
  for (const field of FLAGS) assert.equal(proof[field], true, field);
  for (const [field, pattern] of [["requestIds", /^[1-9][0-9]{0,9}$/], ["fingerprints", /^[a-f0-9]{64}$/], ["spkiFingerprints", /^[a-f0-9]{64}$/], ["serialNumbers", /^[a-f0-9]{1,128}$/], ["containerNames", /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/]]) {
    assert.ok(Array.isArray(proof[field]) && proof[field].length === 3);
    assert.equal(new Set(proof[field]).size, 3, field);
    for (const value of proof[field]) assert.ok(typeof value === "string" && pattern.test(value), field);
  }
  assert.ok(proof.requestIds.every(value => Number(value) <= 0xffffffff));
  for (const field of ["caRequestCounts", "expiryEpochs"]) assert.ok(Array.isArray(proof[field]) && proof[field].length === 3 && proof[field].every(value => Number.isSafeInteger(value) && value > 0));
  assert.ok(proof.caRequestCounts[2] <= 1000);
  assert.equal(proof.caRequestCounts[1], proof.caRequestCounts[0] + 1);
  assert.equal(proof.caRequestCounts[2], proof.caRequestCounts[1] + 1);
  assert.ok(proof.expiryEpochs[0] < proof.expiryEpochs[1] && proof.expiryEpochs[1] < proof.expiryEpochs[2]);
  return true;
}

async function qualifyTwoRenewals(context) {
  const { gate, fixture, renewalFixture, configDir, ps, command, until, jobFinished, ownedEnrollmentIds, ownedThumbprints, tlsAuthority } = context;
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const { item, site, port, profileId, authority } = renewalFixture;
  assert.equal(item.template, "TTQualificationRSAShort"); assert.equal(item.algorithm, "rsa"); assert.equal(item.size, 2048); assert.ok(profileId);
  const root = path.resolve(__dirname, "../../..");
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
    const prior = gate.report.fixtureSources.filter(row => row.file === file);
    if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, sha256); }
    else gate.report.fixtureSources.push({ file, sha256 });
  }
  const query = (sql, args = []) => fixture.pool.query(sql, args);
  const peer = () => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port, servername: item.domain, ca: tlsAuthority(authority), rejectUnauthorized: true }, () => {
      try { assert.equal(socket.authorized, true); const leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw); assert.equal(leaf.checkHost(item.domain), item.domain); resolve(describe(leaf)); }
      catch (error) { reject(error); } finally { socket.destroy(); }
    });
    socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Two-cycle AD CS trusted TLS observation timed out")));
  });
  const nativeRequest = leaf => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", item.domain, "-FingerprintSha256", leaf.fingerprint]));
  const custody = leaf => {
    const value = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${leaf.thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
    assert.equal(value.policy, 0); assert.equal(value.machine, true); assert.equal(value.provider, "Microsoft Software Key Storage Provider"); assert.equal(value.bits, 2048); assert.ok(value.unique);
    assert.equal(normalized(new crypto.X509Certificate(Buffer.from(value.der, "base64")).fingerprint256), leaf.fingerprint);
    const receipt = readIssuedContainerRecord({ stateDir: configDir, containerName: value.container });
    assert.equal(receipt?.status, "enrolled_by_agent"); assert.equal(receipt.acceptedThumbprint, leaf.thumb); assert.equal(receipt.acceptedStore, "My");
    return { value, receipt };
  };
  const binding = leaf => {
    const value = JSON.parse(ps(`Import-Module WebAdministration;$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${port}'});if($keys.Count -ne 1){throw 'Exact owned HTTP.sys SNI selector required'};$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${item.domain}');if($b.Count -ne 1){throw 'Exact owned IIS binding required'};@{hash=[BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash')).Replace('-','');coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`));
    assert.equal(value.hash, leaf.thumb); assert.equal(value.coordinates, `*:${port}:${item.domain}`); assert.equal(value.flags, 1);
  };
  const service = () => JSON.parse(ps(`$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'";$p=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)";if($s.State -ne 'Running' -or -not $p){throw 'Owned native service absent'};@{pid=[int]$s.ProcessId;sid=(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid;created=$p.CreationDate.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress`));
  const initialService = service(); assert.equal(initialService.sid, "S-1-5-18");
  const initial = await peer(); assert.equal(initial.fingerprint, normalized(renewalFixture.observed.fingerprint256));
  const source = await until(async () => (await query("SELECT mc.id FROM managed_certificates mc JOIN certificate_instances ci ON ci.workspace_id=mc.workspace_id AND ci.managed_certificate_id=mc.id JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id WHERE mc.workspace_id=$1 AND ci.observed_fingerprint_sha256=$2 AND ct.windows_site=$3 AND mc.source='agent_windows' AND mc.profile_id=$4 ORDER BY ci.observed_at DESC LIMIT 1", [fixture.workspaceId, initial.fingerprint, site, profileId])).rows[0]);
  const managed = async () => (await query("SELECT profile_id,not_after,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, source.id])).rows[0];
  const profile = async () => (await query("SELECT issuer_id,key_mode,status,renew_before_days,public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, profileId])).rows[0];
  const period = async () => (await query("SELECT id,automation_enabled FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL", [fixture.workspaceId, source.id])).rows;
  const profileBefore = await profile(), periodBefore = await period(); assert.equal(profileBefore.renew_before_days, 30); assert.equal(periodBefore.length, 1); assert.equal(periodBefore[0].automation_enabled, true);
  const scheduler = require("../../../apps/api/services/certops/renewalScheduler");
  const leaves = [initial], requests = [nativeRequest(initial)], custodies = [custody(initial)], jobs = [], enrollments = [];
  binding(initial);
  assert.equal(custodies[0].receipt.certificateId, source.id);
  const proof = { scope: "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup", renewalProtocol: "fresh-enrollment-with-new-key-and-csr", schedulerInvocation: "qualification-invoked-production-default-sweep", workerIntervalQualified: false, successfulAutomationCycles: 2, expiryCleanupQualified: false };
  await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
    for (let cycle = 0; cycle < 2; cycle++) {
      // CA validity timestamps are second-granular. Wait real elapsed time so
      // a new actual expiry can become the next normal idempotency generation.
      const start = process.hrtime.bigint();
      while (Number(process.hrtime.bigint() - start) / 1e6 < 1100) await delay(10);
      assert.ok(Number(process.hrtime.bigint() - start) / 1e6 <= 60000, "Actual issuance-second boundary wait exceeded its reviewed bound");
      const before = await until(async () => { const row = await managed(); return normalized(row.fingerprint_sha256) === leaves[cycle].fingerprint && new Date(row.not_after).getTime() === leaves[cycle].expires ? row : null; });
      assert.ok(leaves[cycle].expires > Date.now() && leaves[cycle].expires <= Date.now() + 7 * 86400000);
      const key = scheduler.renewalIdempotencyKey(source.id, before.not_after);
      assert.equal(Number((await query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2", [fixture.workspaceId, key])).rows[0].count), 0);
      const due = await scheduler.findCertificatesDueForRenewal({ db: fixture.pool, thresholdDays: scheduler.DEFAULT_RENEWAL_THRESHOLD_DAYS, terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES });
      assert.ok(due.some(row => row.workspace_id === fixture.workspaceId && row.id === source.id), "Default SQL-NOW scanner must independently select this real observed expiry");
      const sweep = await scheduler.runRenewalSchedulerSweep({ dbPool: fixture.pool, env: process.env }); assert.equal(sweep.lockAcquired, true); assert.ok(sweep.created >= 1); assert.deepEqual(sweep.errors, []);
      const job = await until(async () => (await query("SELECT id,status,source,mode,operation,subject_id,idempotency_key,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND idempotency_key=$3", [fixture.workspaceId, String(source.id), key])).rows[0]);
      const enrollment = (await query("SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2", [fixture.workspaceId, job.id])).rows[0]; assert.ok(enrollment);
      // Register ownership before waiting for any native completion/observation.
      ownedEnrollmentIds.push(enrollment.id); enrollments.push(enrollment.id); await jobFinished(job.id);
      Object.assign(job, (await query("SELECT status,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, job.id])).rows[0]);
      assert.equal(job.source, "automation"); assert.equal(job.mode, "real"); assert.equal(job.status, "succeeded"); assert.equal(job.idempotency_key, key); assert.ok(job.claim_id);
      const leaf = await peer(); ownedThumbprints.add(leaf.thumb);
      const request = nativeRequest(leaf), native = custody(leaf), journal = readEnrollmentJournal(configDir, enrollment.id);
      assert.equal(request.disposition, 20); assert.equal(request.subjectRequestCount, requests[cycle].subjectRequestCount + 1); assert.notEqual(String(request.requestId), String(requests[cycle].requestId));
      assert.equal(serial(request.serialNumber), leaf.serial); assert.equal(normalized(request.fingerprintSha256), leaf.fingerprint);
      assert.notEqual(leaf.fingerprint, leaves[cycle].fingerprint); assert.notEqual(leaf.spki, leaves[cycle].spki); assert.notEqual(leaf.serial, leaves[cycle].serial); assert.ok(leaf.expires > leaves[cycle].expires);
      assert.equal(native.value.container, buildEnrollmentContainerName(enrollment.id)); assert.equal(native.receipt.jobId, job.id); assert.equal(native.receipt.certificateId, source.id);
      assert.equal(journal.kind, "valid"); assert.equal(journal.journal.state, "installed"); assert.equal(journal.journal.containerName, native.value.container); assert.equal(journal.journal.csrSpkiSha256, leaf.spki); verifyNativeRequestId(request.requestId, journal.journal.requestId);
      binding(leaf); assert.deepEqual(service(), initialService);
      leaves.push(leaf); requests.push(request); custodies.push(native); jobs.push(job);
    }
    Object.assign(proof, { defaultSqlNowSelection: true, automaticSourceAndRealMode: true, distinctExpiryGenerations: true, independentCaRequests: true, freshLeafSerialAndSpki: true, ownedEnrollmentCleanupRegistered: true, noDateOrJournalOverrides: true });
  }, { evidenceLevel: "real-host", oracle: "two default SQL-NOW scheduler sweeps create distinct expiry-bound automation jobs and real CA requests using unchanged naturally due six-day certificates; no direct renewal-service creation or fabricated timestamps" });
  await gate.scenario(REQUIRED_SCENARIOS[1], async () => {
    for (let generation = 0; generation < 3; generation++) {
      assert.deepEqual(custody(leaves[generation]), custodies[generation]);
      assert.equal(requests[generation].disposition, 20);
    }
    assert.equal(new Set(custodies.map(row => row.value.container)).size, 3); assert.equal(new Set(custodies.map(row => row.value.unique)).size, 3);
    assert.equal((await peer()).fingerprint, leaves[2].fingerprint); binding(leaves[2]);
    for (let cycle = 0; cycle < 2; cycle++) {
      const evidence = (await query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'", [fixture.workspaceId, jobs[cycle].id])).rows;
      assert.ok(evidence.some(row => normalized(row.metadata.fingerprintSha256) === leaves[cycle + 1].fingerprint && Date.parse(row.metadata.validTo) === leaves[cycle + 1].expires));
      const audit = (await query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_CREATED_AUTOMATIC' AND metadata->>'jobId'=$2", [fixture.workspaceId, jobs[cycle].id])).rows;
      assert.equal(audit.length, 1); assert.equal(audit[0].metadata.trigger, "renewal_scheduler"); assert.equal(audit[0].metadata.source, "automation"); assert.equal(audit[0].metadata.enrollmentId, enrollments[cycle]);
    }
    Object.assign(proof, { protectedUniqueMachineKeys: true, nativeIisAndSniCutovers: true, independentTrustedTls: true, claimBoundVerificationEvidence: true });
  }, { evidenceLevel: "real-host", oracle: "three distinct non-exportable machine KSP containers and CA-signed TLS leaves, exact native IIS/HTTP.sys SNI cutovers, stable SYSTEM service and claim-bound verification evidence for both automatic jobs" });
  await gate.scenario(REQUIRED_SCENARIOS[2], async () => {
    assert.deepEqual(await profile(), profileBefore); assert.deepEqual(await period(), periodBefore);
    const final = await until(async () => { const row = await managed(); return normalized(row.fingerprint_sha256) === leaves[2].fingerprint && new Date(row.not_after).getTime() === leaves[2].expires ? row : null; }); assert.equal(final.profile_id, profileId);
    for (let generation = 0; generation < 2; generation++) assert.deepEqual(custody(leaves[generation]), custodies[generation]);
    assert.equal(new Set(jobs.map(row => row.idempotency_key)).size, 2);
    assert.equal(Number((await query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1 AND id=ANY($2::uuid[]) AND source='automation' AND status='succeeded'", [fixture.workspaceId, jobs.map(row => row.id)])).rows[0].count), 2);
    Object.assign(proof, { unchangedStoredProfile: true, sameManagementPeriod: true, predecessorCustodyPreserved: true, actualInventoryMatchesLatest: true });
  }, { evidenceLevel: "real-host", oracle: "unchanged stored profile and active management period survive both cycles; inventory matches actual latest TLS expiry/fingerprint and both accepted predecessor certificates, native keys and ownership receipts remain intact" });
  Object.assign(proof, { requestIds: requests.map(row => String(row.requestId)), caRequestCounts: requests.map(row => row.subjectRequestCount), fingerprints: leaves.map(row => row.fingerprint), spkiFingerprints: leaves.map(row => row.spki), serialNumbers: leaves.map(row => row.serial), containerNames: custodies.map(row => row.value.container), expiryEpochs: leaves.map(row => row.expires) });
  verifyProof(proof); gate.report.nativeAdcsTwoRenewals = proof;
  renewalFixture.observed = leaves[2].certificate; renewalFixture.thumbprint = leaves[2].thumb; renewalFixture.currentEnrollmentId = enrollments[1];
}
module.exports = { qualifyTwoRenewals, verifyProof, REQUIRED_SCENARIOS, REQUIRED_SOURCES, FLAGS };
