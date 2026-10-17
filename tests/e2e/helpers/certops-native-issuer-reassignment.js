"use strict";
/* Confirmed public AD CS issuer switch, then one production scheduler renewal.
 * The successor enrollment must be frozen to the destination CA. Manual renew
 * stays refused. No due time, CA response, journal, or qualified cell is invented.
 * The parent owns the forest, store receipts, and final native cleanup.
 * The manual workflow only writes a failed report when that forest is absent.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const SUITE = "native-adcs-issuer-reassignment";
const SOURCE = "tests/e2e/helpers/certops-native-issuer-reassignment.js";
const DEFAULT_REPORT = "qualification-results/native-issuer-reassignment.json";
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "elevated", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-issuer-reassignment-confirmed-switch",
  "adcs-real-issuer-reassignment-renewal-migrates",
  "adcs-real-issuer-reassignment-cleanup",
]);
const REQUIRED_SOURCES = Object.freeze([
  SOURCE,
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "apps/api/services/certops/renewalProfileAdmin.js",
  "apps/api/services/certops/renewalScheduler.js",
  "apps/api/services/certops/certificateEnrollments.js",
  "apps/api/services/certops/jobs.js",
  "apps/api/routes/certops.js",
  "apps/api/routes/certops-enrollments.js",
  "infra/certops-adcs/owned-issued-request.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/issuers/adcs-enrollment.js",
  ".github/workflows/certops-native-issuer-reassignment.yml",
]);
const FLAGS = Object.freeze([
  "twoFreshConfirmedIssuers", "distinctConfirmedCaKeys", "originNativeInstallation",
  "publicSwitchPreservesPolicy", "singleSwitchAudit", "manualRenewRefused",
  "schedulerSweepNotManualRenew", "renewalIssuerIsDestination", "distinctNativeRequests",
  "successorLeafSignedByDestination", "predecessorReplacedOnSameIisCoordinate",
  "nonexportableMachineKey", "predecessorCustodyPreserved", "noSyntheticDueTime",
  "ownedEnrollmentCleanupRegistered",
]);
const SCOPE = "confirmed-adcs-issuer-switch-then-production-scheduler-renewal";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const normalized = value => String(value).replace(/:/g, "").toLowerCase();
function domain(run) {
  assert.match(run, /^[a-f0-9]{10}$/);
  return `certops-adcs-${run}-issuer-switch.example.test`;
}
function assessLab(env = process.env, platform = process.platform) {
  const missing = [];
  if (platform !== "win32") missing.push("win32");
  if (env.CERTOPS_ADCS_DISPOSABLE_LAB !== "1") missing.push("CERTOPS_ADCS_DISPOSABLE_LAB");
  try {
    if (new URL(env.CERTOPS_ADCS_API_URL || "").protocol !== "https:") missing.push("CERTOPS_ADCS_API_URL");
  } catch {
    missing.push("CERTOPS_ADCS_API_URL");
  }
  const origin = env.CERTOPS_ADCS_ORIGIN_CA_CONFIG;
  const destination = env.CERTOPS_ADCS_DESTINATION_CA_CONFIG;
  if (typeof origin !== "string" || !origin.includes("\\")) missing.push("CERTOPS_ADCS_ORIGIN_CA_CONFIG");
  if (typeof destination !== "string" || !destination.includes("\\") || destination === origin) missing.push("CERTOPS_ADCS_DESTINATION_CA_CONFIG");
  return { ok: missing.length === 0, missing };
}
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "renewalProtocol", "schedulerInvocation", "workerIntervalQualified", "nativeCell", "originIssuerId", "destinationIssuerId", "originCaKeySha256", "destinationCaKeySha256", "profileId", "certificateId", "requestIds", "fingerprints", "spkiFingerprints", "enrollmentIds", "jobIds", "containerNames", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.renewalProtocol, "production-scheduler-sweep-after-public-issuer-switch");
  assert.equal(value.schedulerInvocation, "qualification-invoked-production-default-sweep");
  assert.equal(value.workerIntervalQualified, false);
  assert.equal(value.nativeCell, "pending");
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  for (const field of ["originIssuerId", "destinationIssuerId", "profileId", "certificateId"]) assert.match(value[field], UUID, field);
  assert.notEqual(value.originIssuerId, value.destinationIssuerId);
  assert.match(value.originCaKeySha256, /^[a-f0-9]{64}$/);
  assert.match(value.destinationCaKeySha256, /^[a-f0-9]{64}$/);
  assert.notEqual(value.originCaKeySha256, value.destinationCaKeySha256);
  for (const [field, pattern] of [["requestIds", /^[1-9][0-9]{0,9}$/], ["fingerprints", /^[a-f0-9]{64}$/], ["spkiFingerprints", /^[a-f0-9]{64}$/], ["enrollmentIds", UUID], ["jobIds", UUID], ["containerNames", /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/]]) {
    assert.ok(Array.isArray(value[field]) && value[field].length === 2, field);
    assert.equal(new Set(value[field]).size, 2, field);
    for (const item of value[field]) assert.match(item, pattern, field);
  }
  assert.ok(value.requestIds.every(id => Number(id) <= 0xffffffff));
  return true;
}
function buildClosedReport(reason) {
  const now = new Date().toISOString();
  const candidate = process.env.GITHUB_SHA;
  return {
    schemaVersion: 1,
    suite: SUITE,
    strict: true,
    evidenceLevel: "real-host",
    status: "failed",
    nativeCell: "pending",
    startedAt: now,
    finishedAt: now,
    candidateSha: /^[a-f0-9]{40}$/i.test(candidate || "") ? candidate : "0".repeat(40),
    requiredCapabilities: [...REQUIRED_CAPABILITIES],
    capabilities: {},
    requiredScenarios: [...REQUIRED_SCENARIOS],
    missingScenarios: [...REQUIRED_SCENARIOS],
    missingCapabilities: [...REQUIRED_CAPABILITIES],
    scenarios: [],
    cleanup: { status: "failed", summary: String(reason).slice(0, 512) },
    fixturePrerequisite: "No disposable forest executed this journey. A failed report is not native qualification.",
  };
}
function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}
function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const reportPath = options.reportPath || env.CERTOPS_NATIVE_ISSUER_REASSIGNMENT_REPORT || DEFAULT_REPORT;
  // Lab markers are not a journey. This entry never calls qualifyNativeIssuerReassignment.
  const reason = lab.ok
    ? "Disposable lab markers do not execute native issuer reassignment"
    : `Disposable AD CS forest is required: ${lab.missing.join(",")}`;
  writeReport(reportPath, buildClosedReport(reason));
  console.error(reason);
  return 1;
}
async function qualifyNativeIssuerReassignment(context) {
  if (process.platform !== "win32" || process.env.CERTOPS_ADCS_DISPOSABLE_LAB !== "1") {
    throw new Error("Disposable AD CS forest is required before issuer reassignment");
  }
  const { verifyNativeRequestId } = require("./certops-adcs-live-enroll-acl");
  const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
  const { buildEnrollmentContainerName, readIssuedContainerRecord } = require("../../../packages/agent/src/windows-cert-store");
  const scheduler = require("../../../apps/api/services/certops/renewalScheduler");
  const tls = require("node:tls");
  const net = require("node:net");
  const {
    gate, fixture, api, agentRowId, caConfig, destinationCaConfig, command, ps, until, jobFinished,
    configDir, workDir, run, tlsAuthority, ownedEnrollmentIds, ownedCertificateIds, ownedSites,
    ownedThumbprints, registerOwnedStoreCertificate, reservePrimaryPreflights,
  } = context;
  assert.equal(typeof reservePrimaryPreflights, "function");
  assert.equal(typeof registerOwnedStoreCertificate, "function");
  assert.equal(typeof ownedThumbprints?.add, "function");
  assert.ok(Array.isArray(ownedEnrollmentIds) && Array.isArray(ownedCertificateIds) && Array.isArray(ownedSites));
  assert.equal(typeof caConfig, "string");
  assert.equal(typeof destinationCaConfig, "string");
  assert.ok(caConfig.includes("\\") && destinationCaConfig.includes("\\"));
  assert.notEqual(destinationCaConfig, caConfig, "Origin and destination must be different CA configs");
  assert.equal(gate.report.fixtureSource?.file, SOURCE);
  assert.equal(gate.report.suite, SUITE);
  assert.equal(gate.report.evidenceLevel, "real-host");
  reservePrimaryPreflights(4);
  const root = path.resolve(__dirname, "../../..");
  const template = "TTQualificationRSAShort";
  const subject = domain(run);
  const site = `TTAdcsIssuerSwitch${run}`;
  gate.report.nativeCell = "pending";
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
    const prior = gate.report.fixtureSources.filter(row => row.file === file);
    if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, sha256); }
    else gate.report.fixtureSources.push({ file, sha256 });
  }
  const query = (sql, values = []) => fixture.pool.query(sql, values);
  const freePort = () => new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  const authorityCert = authority => new crypto.X509Certificate(Buffer.from(authority.certificateB64, "base64"));
  const describe = certificate => ({
    certificate,
    fingerprint: normalized(certificate.fingerprint256),
    thumb: certificate.fingerprint.replace(/:/g, "").toUpperCase(),
    spki: crypto.createHash("sha256").update(certificate.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    expires: Date.parse(certificate.validTo),
  });
  const flags = {};
  const proof = {
    scope: SCOPE,
    renewalProtocol: "production-scheduler-sweep-after-public-issuer-switch",
    schedulerInvocation: "qualification-invoked-production-default-sweep",
    workerIntervalQualified: false,
    nativeCell: "pending",
  };
  let primaryError;
  let installed;
  try {
    const settings = await fixture.request(`${api}/settings`);
    assert.equal(settings.status, 200);
    assert.equal(settings.body.certOpsPaused, false);
    const declared = (await query("SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND id=$2 AND status='active' AND declared_target_selectors @> jsonb_build_array($3::text)", [fixture.workspaceId, agentRowId, subject])).rows[0];
    assert.ok(declared, "Active agent must already declare the owned issuer-switch subject");
    const confirmIssuer = async (name, config) => {
      const created = await fixture.request(`${api}/issuers`, "POST", { kind: "adcs", name });
      assert.equal(created.status, 201);
      const issuerId = created.body.issuer.id;
      const preflight = async () => {
        const response = await fixture.request(`${api}/issuers/${issuerId}/preflight`, "POST", { agentId: agentRowId, caConfig: config, template });
        assert.equal(response.status, 201);
        await jobFinished(response.body.job.id);
        const row = await until(async () => {
          const value = (await query("SELECT last_preflight,last_preflight_job_id FROM certificate_issuers WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, issuerId])).rows[0];
          return value?.last_preflight_job_id === response.body.job.id ? value.last_preflight : null;
        });
        assert.equal(row.templateCheck.verdict, "safe");
        assert.equal(row.caCheck.verdict, "safe");
        return row;
      };
      const before = await preflight();
      const authority = before.caCertificates[0];
      assert.match(authority.keySha256, /^[a-f0-9]{64}$/);
      assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: authority.keySha256, caConfig: config, template })).status, 200);
      const fresh = await preflight();
      assert.ok(fresh.caCertificates.some(row => row.keySha256 === authority.keySha256));
      return { issuerId, authority, caKeySha256: authority.keySha256 };
    };
    const origin = await confirmIssuer(`issuer-switch-origin-${run}`, caConfig);
    const destination = await confirmIssuer(`issuer-switch-destination-${run}`, destinationCaConfig);
    assert.notEqual(origin.caKeySha256, destination.caKeySha256);
    flags.twoFreshConfirmedIssuers = true;
    flags.distinctConfirmedCaKeys = true;
    const port = await freePort();
    assert.equal(Number.isInteger(port), true);
    const certificateId = crypto.randomUUID();
    const directory = path.join(workDir, "issuer-switch");
    fs.mkdirSync(directory);
    fs.writeFileSync(path.join(directory, "index.html"), "Owned issuer reassignment fixture");
    ownedSites.push(site);
    ownedCertificateIds.push(certificateId);
    const cleanup = registerOwnedStoreCertificate({ store: "My", domain: subject, certificateId });
    assert.equal(cleanup.store, "My");
    assert.equal(cleanup.domain, subject);
    assert.equal(cleanup.certificateId, certificateId);
    assert.deepEqual(cleanup.enrollmentIds, []);
    assert.deepEqual(cleanup.thumbprints, []);
    ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Issuer switch site already exists'};New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '*' -Port ${port} -HostHeader '${subject}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${subject}' -PropertyName sslFlags -Value 1`);
    const discovered = JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-request-observation.ps1"), "-CommonName", subject, "-Discover"]));
    assert.equal(discovered.subjectRequestCount, 0);
    const target = { type: "windows-iis", reference: subject, store: "My", binding: { site, port, sniHost: subject } };
    const createdProfile = await fixture.request(`${api}/profiles`, "POST", { name: `issuer-switch-${run}`, issuerId: origin.issuerId, target, keyAlgorithm: "rsa", keySize: 2048, renewBeforeDays: 30 });
    assert.equal(createdProfile.status, 201);
    const profileId = createdProfile.body.id;
    const profileUrl = `${api}/profiles/${profileId}`;
    const readProfile = async () => (await fixture.request(profileUrl)).body;
    const beforeProfile = await readProfile();
    assert.equal(beforeProfile.issuerId, origin.issuerId);
    assert.equal(beforeProfile.renewBeforeDays, 30);
    const enrolled = await fixture.request(`${api}/enrollments`, "POST", { profileId, certificateId, agentId: agentRowId, target, authorizedDnsNames: [subject], keyAlgorithm: "rsa", keySize: 2048 });
    assert.equal(enrolled.status, 201);
    const originEnrollmentId = enrolled.body.enrollmentId;
    const originJobId = enrolled.body.jobId;
    cleanup.enrollmentIds.push(originEnrollmentId);
    ownedEnrollmentIds.push(originEnrollmentId);
    await jobFinished(originJobId);
    const originRow = (await query("SELECT e.issuer_id,e.state,e.request_id,e.snapshot_bytes,j.status,j.claim_id,j.assigned_agent_id FROM certificate_enrollments e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id WHERE e.workspace_id=$1 AND e.id=$2 AND j.id=$3", [fixture.workspaceId, originEnrollmentId, originJobId])).rows[0];
    assert.equal(originRow.status, "succeeded");
    assert.equal(originRow.state, "installed");
    assert.equal(originRow.issuer_id, origin.issuerId);
    assert.equal(originRow.assigned_agent_id, agentRowId);
    assert.equal(JSON.parse(Buffer.from(originRow.snapshot_bytes).toString("utf8")).caKeySha256, origin.caKeySha256);
    const peer = async authority => new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port, servername: subject, ca: tlsAuthority(authority), rejectUnauthorized: true }, () => {
        try {
          assert.equal(socket.authorized, true);
          const leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw);
          assert.equal(leaf.checkHost(subject), subject);
          assert.equal(leaf.subject, `CN=${subject}`);
          resolve(describe(leaf));
        } catch (error) { reject(error); } finally { socket.destroy(); }
      });
      socket.once("error", reject);
      socket.setTimeout(10000, () => socket.destroy(new Error("Issuer reassignment trusted TLS observation timed out")));
    });
    const nativeRequest = leaf => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", subject, "-FingerprintSha256", leaf.fingerprint]));
    const custody = (leaf, enrollmentId, jobId) => {
      assert.match(leaf.thumb, /^[A-F0-9]{40}$/);
      const value = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${leaf.thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;policy=[int]$k.Key.ExportPolicy;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
      assert.equal(value.policy, 0);
      assert.equal(value.machine, true);
      assert.equal(value.provider, "Microsoft Software Key Storage Provider");
      assert.equal(value.bits, 2048);
      assert.equal(value.container, buildEnrollmentContainerName(enrollmentId));
      assert.equal(normalized(new crypto.X509Certificate(Buffer.from(value.der, "base64")).fingerprint256), leaf.fingerprint);
      const receipt = readIssuedContainerRecord({ stateDir: configDir, containerName: value.container });
      assert.equal(receipt?.status, "enrolled_by_agent");
      assert.equal(receipt.containerName, value.container);
      assert.equal(receipt.certificateId, certificateId);
      assert.equal(receipt.jobId, jobId);
      assert.equal(receipt.acceptedStore, "My");
      assert.equal(receipt.acceptedThumbprint, leaf.thumb);
      return { value, receipt };
    };
    const binding = leaf => {
      const value = JSON.parse(ps(`Import-Module WebAdministration;$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${subject}:${port}'});if($keys.Count -ne 1){throw 'Exact owned HTTP.sys SNI selector required'};$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${subject}');if($b.Count -ne 1){throw 'Exact owned IIS binding required'};@{hash=[BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash')).Replace('-','');store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`));
      assert.equal(value.hash, leaf.thumb);
      assert.equal(value.store, "My");
      assert.equal(value.flags, 1);
    };
    const originLeaf = await peer(origin.authority);
    assert.equal(originLeaf.certificate.verify(authorityCert(origin.authority).publicKey), true);
    assert.equal(originLeaf.certificate.verify(authorityCert(destination.authority).publicKey), false);
    const originRequest = nativeRequest(originLeaf);
    const originCustody = custody(originLeaf, originEnrollmentId, originJobId);
    binding(originLeaf);
    ownedThumbprints.add(originLeaf.thumb);
    cleanup.thumbprints.push(originLeaf.thumb);
    assert.equal(originRequest.disposition, 20);
    assert.equal(originRequest.subjectRequestCount, 1);
    const originJournal = readEnrollmentJournal(configDir, originEnrollmentId);
    assert.equal(originJournal.kind, "valid");
    assert.equal(originJournal.journal.state, "installed");
    verifyNativeRequestId(originRequest.requestId, originRow.request_id, originJournal.journal.requestId);
    assert.ok(originLeaf.expires > Date.now() && originLeaf.expires <= Date.now() + 7 * 86400000);
    const managed = await until(async () => (await query("SELECT mc.id FROM managed_certificates mc JOIN certificate_instances ci ON ci.workspace_id=mc.workspace_id AND ci.managed_certificate_id=mc.id JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id WHERE mc.workspace_id=$1 AND ci.observed_fingerprint_sha256=$2 AND ct.windows_site=$3 AND mc.source='agent_windows' AND mc.profile_id=$4 ORDER BY ci.observed_at DESC LIMIT 1", [fixture.workspaceId, originLeaf.fingerprint, site, profileId])).rows[0]);
    assert.equal(managed.id, certificateId);
    assert.equal(originCustody.receipt.certificateId, certificateId);
    flags.originNativeInstallation = true;
    installed = { origin, destination, profileId, certificateId, managedId: managed.id, originLeaf, originRequest, originCustody, originEnrollmentId, originJobId, cleanup };
    const auditCount = async () => (await query("SELECT count(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_RENEWAL_PROFILE_UPDATED' AND metadata->>'profileId'=$2", [fixture.workspaceId, profileId])).rows[0].count;
    await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
      const before = await readProfile();
      const storedBefore = (await query("SELECT issuer_id,renew_before_days,key_mode FROM certificate_profiles WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, profileId])).rows[0];
      assert.equal(before.issuerId, origin.issuerId);
      assert.equal(storedBefore.issuer_id, origin.issuerId);
      assert.equal(storedBefore.renew_before_days, 30);
      assert.equal(before.renewalProfile?.target?.type, "windows-iis");
      assert.equal(before.renewalProfile?.keyAlgorithm, "rsa");
      assert.equal(before.renewalProfile?.keySize, 2048);
      const changed = await fixture.request(profileUrl, "PATCH", { issuerId: destination.issuerId });
      assert.equal(changed.status, 200);
      assert.equal(changed.body.issuerId, destination.issuerId);
      assert.deepEqual(changed.body.renewalProfile, before.renewalProfile);
      const stored = (await query("SELECT issuer_id,renew_before_days,key_mode FROM certificate_profiles WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, profileId])).rows[0];
      assert.equal(stored.issuer_id, destination.issuerId);
      assert.equal(stored.renew_before_days, storedBefore.renew_before_days);
      assert.equal(stored.key_mode, storedBefore.key_mode);
      assert.equal(await auditCount(), 1);
      const manual = await fixture.request(`${api}/jobs`, "POST", { operation: "renew", subjectType: "managed_certificate", subjectId: managed.id });
      assert.equal(manual.status, 409);
      assert.equal(manual.body.code, "CERTOPS_ADCS_RENEWAL_NOT_MANUAL");
      assert.equal((await query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew'", [fixture.workspaceId, String(managed.id)])).rows[0].count, 0);
      Object.assign(flags, { publicSwitchPreservesPolicy: true, singleSwitchAudit: true, manualRenewRefused: true });
    }, { evidenceLevel: "real-host", oracle: "Public issuer switch keeps the stored deployment and key policy, writes one profile audit, and the manual renew route refuses the AD CS profile" });
    await gate.scenario(REQUIRED_SCENARIOS[1], async () => {
      const current = (await query("SELECT not_after,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, managed.id])).rows[0];
      assert.equal(normalized(current.fingerprint_sha256), originLeaf.fingerprint);
      assert.equal(new Date(current.not_after).getTime(), originLeaf.expires);
      const key = scheduler.renewalIdempotencyKey(managed.id, current.not_after);
      assert.equal(Number((await query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2", [fixture.workspaceId, key])).rows[0].count), 0);
      const due = await scheduler.findCertificatesDueForRenewal({ db: fixture.pool, thresholdDays: scheduler.DEFAULT_RENEWAL_THRESHOLD_DAYS, terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES });
      assert.ok(due.some(row => row.workspace_id === fixture.workspaceId && row.id === managed.id && row.profile_issuer_id === destination.issuerId));
      const sweep = await scheduler.runRenewalSchedulerSweep({ dbPool: fixture.pool, env: process.env });
      assert.equal(sweep.lockAcquired, true);
      assert.ok(sweep.created >= 1);
      assert.deepEqual(sweep.errors, []);
      const job = await until(async () => (await query("SELECT id,status,source,mode,operation,subject_id,idempotency_key,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND idempotency_key=$3", [fixture.workspaceId, String(managed.id), key])).rows[0]);
      const enrollment = (await query("SELECT id,issuer_id,snapshot_bytes FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2", [fixture.workspaceId, job.id])).rows[0];
      assert.ok(enrollment);
      const snapshot = JSON.parse(Buffer.from(enrollment.snapshot_bytes).toString("utf8"));
      assert.equal(enrollment.issuer_id, destination.issuerId);
      assert.equal(snapshot.caKeySha256, destination.caKeySha256);
      assert.equal(snapshot.caConfig, destinationCaConfig);
      assert.notEqual(snapshot.caKeySha256, origin.caKeySha256);
      cleanup.enrollmentIds.push(enrollment.id);
      ownedEnrollmentIds.push(enrollment.id);
      await jobFinished(job.id);
      Object.assign(job, (await query("SELECT status,source,mode,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, job.id])).rows[0]);
      assert.equal(job.source, "automation");
      assert.equal(job.mode, "real");
      assert.equal(job.status, "succeeded");
      assert.ok(job.claim_id);
      const successor = await peer(destination.authority);
      ownedThumbprints.add(successor.thumb);
      cleanup.thumbprints.push(successor.thumb);
      assert.equal(successor.certificate.verify(authorityCert(destination.authority).publicKey), true);
      assert.equal(successor.certificate.verify(authorityCert(origin.authority).publicKey), false);
      const request = nativeRequest(successor);
      const native = custody(successor, enrollment.id, job.id);
      const journal = readEnrollmentJournal(configDir, enrollment.id);
      assert.equal(request.disposition, 20);
      assert.equal(request.subjectRequestCount, originRequest.subjectRequestCount + 1);
      assert.notEqual(String(request.requestId), String(originRequest.requestId));
      verifyNativeRequestId(request.requestId, journal.journal.requestId);
      assert.equal(journal.kind, "valid");
      assert.equal(journal.journal.state, "installed");
      assert.equal(journal.journal.containerName, native.value.container);
      assert.notEqual(successor.fingerprint, originLeaf.fingerprint);
      assert.notEqual(successor.spki, originLeaf.spki);
      assert.notEqual(native.value.container, originCustody.value.container);
      binding(successor);
      assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My\\${originLeaf.thumb}).Count`), "1");
      const evidence = (await query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'", [fixture.workspaceId, job.id])).rows;
      assert.ok(evidence.some(row => normalized(row.metadata.fingerprintSha256) === successor.fingerprint));
      installed.successor = successor;
      installed.successorRequest = request;
      installed.successorCustody = native;
      installed.renewalEnrollmentId = enrollment.id;
      installed.renewalJobId = job.id;
      Object.assign(flags, {
        schedulerSweepNotManualRenew: true, renewalIssuerIsDestination: true, distinctNativeRequests: true,
        successorLeafSignedByDestination: true, predecessorReplacedOnSameIisCoordinate: true,
        nonexportableMachineKey: true, noSyntheticDueTime: true,
      });
    }, { evidenceLevel: "real-host", oracle: "Default SQL-NOW sweep creates one automation renewal frozen to the destination issuer; the successor leaf is signed by that CA and replaces the same IIS coordinate" });
  } catch (error) {
    primaryError = error;
  }
  if (primaryError) throw new AggregateError([primaryError], "Native AD CS issuer reassignment failed; preserve unresolved native ownership");
  await gate.scenario(REQUIRED_SCENARIOS[2], async () => {
    assert.ok(ownedEnrollmentIds.includes(installed.originEnrollmentId));
    assert.ok(ownedEnrollmentIds.includes(installed.renewalEnrollmentId));
    assert.ok(ownedCertificateIds.includes(installed.certificateId));
    assert.ok(ownedSites.includes(site));
    const predecessor = custodyOf(installed.originLeaf);
    assert.equal(predecessor.container, installed.originCustody.value.container);
    assert.equal(predecessor.policy, 0);
    assert.equal(predecessor.receipt?.status, "enrolled_by_agent");
    assert.equal(predecessor.receipt.acceptedThumbprint, installed.originLeaf.thumb);
    assert.equal(predecessor.receipt.jobId, installed.originJobId);
    assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My\\${installed.originLeaf.thumb}).Count`), "1");
    assert.equal((await readProfileAgain()).issuerId, installed.destination.issuerId);
    Object.assign(flags, { predecessorCustodyPreserved: true, ownedEnrollmentCleanupRegistered: true });
    Object.assign(proof, flags, {
      originIssuerId: installed.origin.issuerId,
      destinationIssuerId: installed.destination.issuerId,
      originCaKeySha256: installed.origin.caKeySha256,
      destinationCaKeySha256: installed.destination.caKeySha256,
      profileId: installed.profileId,
      certificateId: installed.managedId,
      requestIds: [String(installed.originRequest.requestId), String(installed.successorRequest.requestId)],
      fingerprints: [installed.originLeaf.fingerprint, installed.successor.fingerprint],
      spkiFingerprints: [installed.originLeaf.spki, installed.successor.spki],
      enrollmentIds: [installed.originEnrollmentId, installed.renewalEnrollmentId],
      jobIds: [installed.originJobId, installed.renewalJobId],
      containerNames: [installed.originCustody.value.container, installed.successorCustody.value.container],
    });
    verifyProof(proof);
    gate.report.nativeIssuerReassignment = proof;
    gate.report.nativeCell = "pending";
  }, { evidenceLevel: "real-host", oracle: "Predecessor key and store custody remain registered to the parent while the profile stays on the destination issuer. This run does not qualify the native cell." });
  return proof;

  function custodyOf(leaf) {
    assert.match(leaf.thumb, /^[A-F0-9]{40}$/);
    const value = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${leaf.thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;policy=[int]$k.Key.ExportPolicy}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
    return { ...value, receipt: readIssuedContainerRecord({ stateDir: configDir, containerName: value.container }) };
  }
  async function readProfileAgain() {
    return (await fixture.request(`${api}/profiles/${installed.profileId}`)).body;
  }
}
if (require.main === module) process.exitCode = dispatch();
module.exports = {
  qualifyNativeIssuerReassignment, verifyProof, assessLab, dispatch, buildClosedReport,
  REQUIRED_SCENARIOS, REQUIRED_SOURCES, REQUIRED_CAPABILITIES, FLAGS, SCOPE, SUITE, SOURCE, domain,
};
