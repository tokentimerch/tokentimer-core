"use strict";
/** Actual public AD CS per-issuer capacity, with genuine two-person approval
 * and native issuance as the terminal-release control. No successful jobs,
 * CA requests, journals, due times or capacity settings are synthesized.
 * The parent owns all native state, accepted-store receipts and API fixtures. */
const { verifyNativeRequestId } = require("./certops-adcs-live-enroll-acl");
const assert = require("node:assert/strict"), crypto = require("node:crypto"), fs = require("node:fs"), path = require("node:path"), net = require("node:net"), tls = require("node:tls");
const { createApiFixture } = require("./certops-api-fixture");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { buildEnrollmentContainerName, readIssuedContainerRecord } = require("../../../packages/agent/src/windows-cert-store");
const REQUIRED_SCENARIOS = Object.freeze(["adcs-real-capacity-five-public-approvals", "adcs-real-capacity-sixth-atomic-refusal", "adcs-real-capacity-native-issuance-releases-slot", "adcs-real-capacity-approval-policy-restored"]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "packages/agent/src/issuers/adcs.js","tests/e2e/helpers/certops-adcs-capacity.js", "tests/e2e/helpers/certops-api-fixture.js", "infra/certops-adcs/owned-request-observation.ps1", "infra/certops-adcs/owned-issued-request.ps1", "apps/api/routes/certops-enrollments.js", "apps/api/services/certops/renewalCapacity.js", "apps/api/services/certops/certificateEnrollments.js", "apps/api/services/certops/jobs.js", "apps/api/services/certops/jobApprovals.js", "packages/agent/src/adcs-windows-iis.js", "packages/agent/src/windows-cert-store/index.js", "packages/agent/src/issuers/adcs-enrollment-journal.js"]);
const FLAGS = Object.freeze(["freshConfirmedIssuer", "actualPostConfirmationPreflight", "sixConcurrentPublicRequests", "fivePersistedPendingApprovals", "sixthTransactionRolledBack", "noCaRequestsBeforeApproval", "noNativeKeysBeforeApproval", "distinctAuthorizedApprover", "firstNativeCompletionFreesSlot", "refusedSubjectReenteredPublicly", "twoClaimBoundNativeInstallations", "twoDistinctOwnedCaRequests", "twoNonexportableMachineKeys", "twoNativeIisAndTrustedTls", "fourUnapprovedJobsPubliclyRejected", "approvalSettingRestored"]);
const SCOPE = "actual-native-adcs-per-issuer-five-public-approvals-and-terminal-release";
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const normalized = value => String(value).replace(/:/g, "").toLowerCase();
function domains(run) { assert.match(run, /^[a-f0-9]{10}$/); return Array.from({ length: 6 }, (_, i) => `certops-adcs-${run}-capacity${i}.example.test`); }
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "cap", "initialAccepted", "initialRefused", "nativeCompleted", "requestIds", "fingerprints", "enrollmentIds", "jobIds", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE); assert.equal(value.cap, 5); assert.equal(value.initialAccepted, 5); assert.equal(value.initialRefused, 1); assert.equal(value.nativeCompleted, 2);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  for (const [field, pattern] of [["requestIds", /^[1-9][0-9]{0,9}$/], ["fingerprints", /^[a-f0-9]{64}$/], ["enrollmentIds", /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/], ["jobIds", /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/]]) {
    assert.ok(Array.isArray(value[field]) && value[field].length === 2); for (const item of value[field]) { assert.equal(typeof item, "string"); assert.match(item, pattern); } assert.equal(new Set(value[field]).size, 2);
  }
  assert.ok(value.requestIds.every(id => Number(id) <= 0xffffffff)); return true;
}
function freePort() { return new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); }); }); }
async function qualifyCapacity(context) {
  const { gate, fixture, api, baseUrl, caConfig, agentRowId, configDir, workDir, run, command, ps, until, jobFinished, ownedApiFixtures, ownedSites, ownedCertificateIds, ownedEnrollmentIds, tlsAuthority, reservePrimaryPreflights, registerOwnedStoreCertificate } = context;
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(typeof reservePrimaryPreflights, "function"); assert.equal(typeof registerOwnedStoreCertificate, "function"); assert.ok(Array.isArray(ownedApiFixtures));
  reservePrimaryPreflights(2); // Account for both real dispatches in the parent's existing rate budget.
  const root = path.resolve(__dirname, "../../.."), template = "TTQualificationRSAShort", items = [], accepted = [], completed = [];
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) { const digest = sha(fs.readFileSync(path.join(root, file))), prior = gate.report.fixtureSources.filter(row => row.file === file); if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, digest); } else gate.report.fixtureSources.push({ file, sha256: digest }); }
  const settings = await fixture.request(`${api}/settings`); assert.equal(settings.status, 200); assert.equal(settings.body.certOpsPaused, false);
  const previousApproval = settings.body.certOpsRequireApprovalAlways; assert.equal(typeof previousApproval, "boolean");
  const flags = {}, proof = { scope: SCOPE, cap: 5, initialAccepted: 5, initialRefused: 1, nativeCompleted: 2 };
  let changed = false, primaryError;
  const query = (sql, values = []) => fixture.pool.query(sql, values);
  const counts = async issuerId => (await query("SELECT count(*)::int AS enrollments,count(j.id)::int AS jobs,count(*) FILTER(WHERE j.status='pending_approval')::int AS pending FROM certificate_enrollments e LEFT JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id WHERE e.workspace_id=$1 AND e.issuer_id=$2", [fixture.workspaceId, issuerId])).rows[0];
  const nativeKeys = () => sha(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"])); // Metadata only; never persisted.
  const observe = item => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-request-observation.ps1"), "-CommonName", item.domain, "-Discover"]));
  const requestBody = (issuerId, item) => ({ issuerId, certificateId: item.certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: item.domain, store: "My", binding: { site: item.site, port: item.port, sniHost: item.domain } }, authorizedDnsNames: [item.domain], keyAlgorithm: "rsa", keySize: 2048 });
  const register = (item, response) => { assert.equal(response.status, 201); item.enrollmentId = response.body.enrollmentId; item.jobId = response.body.jobId; ownedEnrollmentIds.push(item.enrollmentId); item.cleanup.enrollmentIds.push(item.enrollmentId); };
  try {
    const created = await fixture.request(`${api}/issuers`, "POST", { kind: "adcs", name: `capacity-${run}` }); assert.equal(created.status, 201); const issuerId = created.body.issuer.id;
    const preflight = async () => { const response = await fixture.request(`${api}/issuers/${issuerId}/preflight`, "POST", { agentId: agentRowId, caConfig, template }); assert.equal(response.status, 201); await jobFinished(response.body.job.id); const row = await until(async () => { const value = (await query("SELECT last_preflight,last_preflight_job_id FROM certificate_issuers WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, issuerId])).rows[0]; return value?.last_preflight_job_id === response.body.job.id ? value.last_preflight : null; }); assert.equal(row.templateCheck.verdict, "safe"); assert.equal(row.caCheck.verdict, "safe"); return row; };
    const before = await preflight(), authority = before.caCertificates[0]; assert.match(authority.keySha256, /^[a-f0-9]{64}$/);
    assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: authority.keySha256, caConfig, template })).status, 200);
    const fresh = await preflight(); assert.ok(fresh.caCertificates.some(row => row.keySha256 === authority.keySha256)); flags.freshConfirmedIssuer = true; flags.actualPostConfirmationPreflight = true;
    const approver = await createApiFixture(baseUrl); ownedApiFixtures.push(approver); assert.notEqual(approver.userId, fixture.userId);
    // Identity/membership prerequisite only. Every decision uses the real public approval route.
    await query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')", [fixture.workspaceId, approver.userId]); flags.distinctAuthorizedApprover = true;
    for (const [index, domain] of domains(run).entries()) {
      const item = { domain, site: `TTAdcsCapacity${run}${index}`, port: await freePort(), certificateId: crypto.randomUUID() }, directory = path.join(workDir, `capacity${index}`);
      fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, "index.html"), "Owned capacity fixture"); ownedSites.push(item.site); ownedCertificateIds.push(item.certificateId); items.push(item);
      // The parent must install a store-qualified cleanup guard BEFORE public
      // dispatch, including partial native acceptance without a result/TLS.
      item.cleanup = registerOwnedStoreCertificate({ store: "My", domain, certificateId: item.certificateId });
      assert.equal(item.cleanup.store, "My"); assert.equal(item.cleanup.domain, domain); assert.equal(item.cleanup.certificateId, item.certificateId); assert.deepEqual(item.cleanup.enrollmentIds, []); assert.deepEqual(item.cleanup.thumbprints, []);
      ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${item.site}'){throw 'Capacity site already exists'};New-Website -Name '${item.site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '*' -Port ${item.port} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${item.site}' -BindingInformation '*:${item.port}:${domain}' -PropertyName sslFlags -Value 1`);
      assert.equal(observe(item).subjectRequestCount, 0);
    }
    changed = true; // An uncertain settings response still requires restoration.
    assert.equal((await fixture.request(`${api}/settings`, "PUT", { certOpsRequireApprovalAlways: true, reason: "Owned native AD CS capacity admission control" })).status, 200);
    const keyBaseline = nativeKeys(); let refused;
    await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
      const outcomes = await Promise.allSettled(items.map(item => fixture.request(`${api}/enrollments`, "POST", requestBody(issuerId, item))));
      for (let i = 0; i < outcomes.length; i++) if (outcomes[i].status === "fulfilled" && outcomes[i].value.status === 201) { register(items[i], outcomes[i].value); accepted.push(items[i]); }
      assert.equal(outcomes.every(row => row.status === "fulfilled"), true); assert.equal(accepted.length, 5);
      const denied = outcomes.map((row, index) => ({ response: row.value, item: items[index] })).filter(row => row.response.status !== 201); assert.equal(denied.length, 1); refused = denied[0].item; assert.equal(denied[0].response.status, 409); assert.equal(denied[0].response.body.code, "CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED");
      assert.deepEqual(await counts(issuerId), { enrollments: 5, jobs: 5, pending: 5 });
      for (const item of accepted) { assert.equal(readEnrollmentJournal(configDir, item.enrollmentId).kind, "not_found"); assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(buildEnrollmentContainerName(item.enrollmentId))); }
      for (const item of items) assert.equal(observe(item).subjectRequestCount, 0); assert.equal(nativeKeys(), keyBaseline);
      Object.assign(flags, { sixConcurrentPublicRequests: true, fivePersistedPendingApprovals: true, noCaRequestsBeforeApproval: true, noNativeKeysBeforeApproval: true });
    }, { evidenceLevel: "real-host", oracle: "Six real public enrollments reserve exactly five pending approvals on one fresh confirmed AD CS issuer, with no CA requests, CNG generation or execution journals before approval" });
    await gate.scenario(REQUIRED_SCENARIOS[1], async () => {
      const absent = (await query("SELECT (SELECT count(*)::int FROM certificate_enrollments WHERE workspace_id=$1 AND certificate_id=$2) AS enrollments,(SELECT count(*)::int FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2::text) AS jobs,(SELECT count(*)::int FROM certops_outbox WHERE workspace_id=$1 AND payload->>'subjectId'=$2::text) AS intents", [fixture.workspaceId, refused.certificateId])).rows[0]; assert.deepEqual(absent, { enrollments: 0, jobs: 0, intents: 0 });
      assert.equal(observe(refused).subjectRequestCount, 0); assert.equal(nativeKeys(), keyBaseline); assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq 'CN=${refused.domain}').Count`), "0"); flags.sixthTransactionRolledBack = true;
    }, { evidenceLevel: "real-host", oracle: "Capacity refusal rolls back its enrollment/job/outbox atomically; exact rejected subject has no CA row or public certificate and native key metadata remains unchanged" });
    const issue = async item => {
      if(context.approvalActor)await context.approvalActor.approveJob({jobId:item.jobId,enrollmentId:item.enrollmentId,approver});
      else assert.equal((await approver.request(`${api}/jobs/${item.jobId}/approve`, "POST", { reason: "Independent manager approves owned native capacity control" })).status, 200); await jobFinished(item.jobId);
      const row = (await query("SELECT j.status,j.claim_id,j.assigned_agent_id,e.state,e.request_id FROM certificate_jobs j JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.current_job_id=j.id WHERE j.workspace_id=$1 AND j.id=$2 AND e.id=$3", [fixture.workspaceId, item.jobId, item.enrollmentId])).rows[0]; assert.equal(row.status, "succeeded"); assert.equal(row.state, "installed"); assert.ok(row.claim_id); assert.equal(row.assigned_agent_id, agentRowId);
      const journal = readEnrollmentJournal(configDir, item.enrollmentId); assert.equal(journal.kind, "valid"); assert.equal(journal.journal.state, "installed");
      const leaf = await new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: item.port, servername: item.domain, ca: tlsAuthority(authority), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Capacity trusted TLS observation timed out"))); });
      assert.equal(leaf.checkHost(item.domain), item.domain); assert.equal(leaf.subject, `CN=${item.domain}`); assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(authority.certificateB64, "base64")).publicKey), true);
      const thumbprint = normalized(leaf.fingerprint).toUpperCase(), fingerprint = normalized(leaf.fingerprint256), container = buildEnrollmentContainerName(item.enrollmentId);
      item.cleanup.thumbprints.push(thumbprint);
      const native = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;policy=[int]$k.Key.ExportPolicy;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`)); assert.equal(native.container, container); assert.equal(native.provider, "Microsoft Software Key Storage Provider"); assert.equal(native.machine, true); assert.equal(native.policy, 0); assert.equal(native.bits, 2048); assert.equal(native.der, leaf.raw.toString("base64"));
      const receipt = readIssuedContainerRecord({ stateDir: configDir, containerName: container }); assert.ok(receipt); assert.equal(receipt.status, "enrolled_by_agent"); assert.equal(receipt.containerName, container); assert.equal(receipt.certificateId, item.certificateId); assert.equal(receipt.jobId, item.jobId); assert.equal(receipt.acceptedStore, "My"); assert.equal(receipt.acceptedThumbprint, thumbprint);
      const request = JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", item.domain, "-FingerprintSha256", fingerprint])); assert.equal(request.subjectRequestCount, 1); assert.equal(request.disposition, 20); verifyNativeRequestId(request.requestId, row.request_id, journal.journal.requestId);
      const binding = JSON.parse(ps(`Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${item.site}' -Protocol https|Where-Object bindingInformation -eq '*:${item.port}:${item.domain}');$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${item.port}'});if($b.Count -ne 1 -or $keys.Count -ne 1){throw 'Exact capacity IIS/HTTP.sys coordinate absent'};@{hash=[BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash')).Replace('-','');store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`)); assert.equal(binding.hash, thumbprint); assert.equal(binding.store, "My"); assert.equal(binding.flags, 1);
      const evidence = (await query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'", [fixture.workspaceId, item.jobId])).rows; assert.ok(evidence.some(value => normalized(value.metadata.fingerprintSha256) === fingerprint));
      completed.push({ requestId: String(request.requestId), fingerprint, enrollmentId: item.enrollmentId, jobId: item.jobId });
    };
    await gate.scenario(REQUIRED_SCENARIOS[2], async () => {
      await issue(accepted[0]); assert.deepEqual(await counts(issuerId), { enrollments: 5, jobs: 5, pending: 4 }); flags.firstNativeCompletionFreesSlot = true;
      const retry = await fixture.request(`${api}/enrollments`, "POST", requestBody(issuerId, refused)); register(refused, retry); accepted.push(refused); assert.deepEqual(await counts(issuerId), { enrollments: 6, jobs: 6, pending: 5 }); flags.refusedSubjectReenteredPublicly = true;
      await issue(refused); assert.notEqual(completed[0].requestId, completed[1].requestId); assert.notEqual(completed[0].fingerprint, completed[1].fingerprint);
      Object.assign(flags, { twoClaimBoundNativeInstallations: true, twoDistinctOwnedCaRequests: true, twoNonexportableMachineKeys: true, twoNativeIisAndTrustedTls: true });
    }, { evidenceLevel: "real-host", oracle: "Independent manager approval produces a genuine claim-bound native CA/CNG/IIS/TLS installation, releases a capacity slot, and the originally refused subject enters publicly and completes its own distinct real issuance" });
    if (context.cancelActor) await context.cancelActor.cancelRenewal({ issuerId, item: refused, authority, priorCompleted: completed[1] });
    if(context.approvalActor){const item=accepted.find(item=>!completed.some(row=>row.jobId===item.jobId));assert.ok(item);await context.approvalActor.rejectJob({item,approver});}
  } catch (error) { primaryError = error; }
  finally {
    const errors = [];
    for (const item of accepted) try { const row = (await query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, item.jobId])).rows[0]; if (row.status === "pending_approval") { assert.equal((await fixture.request(`${api}/jobs/${item.jobId}/reject`, "POST", { reason: "Withdraw never-approved owned capacity request" })).status, 200); assert.equal(observe(item).subjectRequestCount, 0); assert.equal(readEnrollmentJournal(configDir, item.enrollmentId).kind, "not_found"); assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(buildEnrollmentContainerName(item.enrollmentId))); } } catch (error) { errors.push(error); }
    if (changed) try { assert.equal((await fixture.request(`${api}/settings`, "PUT", { certOpsRequireApprovalAlways: previousApproval, reason: "Restore original approval policy after owned native capacity control" })).status, 200); assert.equal((await fixture.request(`${api}/settings`)).body.certOpsRequireApprovalAlways, previousApproval); flags.approvalSettingRestored = true; } catch (error) { errors.push(error); }
    if (primaryError || errors.length) throw new AggregateError([...(primaryError ? [primaryError] : []), ...errors], "Native AD CS capacity control or policy restoration failed; preserve unresolved native ownership");
  }
  await gate.scenario(REQUIRED_SCENARIOS[3], async () => {
    const rows = (await query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=ANY($2::uuid[])", [fixture.workspaceId, accepted.map(item => item.jobId)])).rows; assert.equal(rows.filter(row => row.status === "rejected").length, 4); assert.equal(rows.filter(row => row.status === "succeeded").length, 2); flags.fourUnapprovedJobsPubliclyRejected = true;
    Object.assign(proof, flags, { requestIds: completed.map(row => row.requestId), fingerprints: completed.map(row => row.fingerprint), enrollmentIds: completed.map(row => row.enrollmentId), jobIds: completed.map(row => row.jobId) }); verifyProof(proof);
  }, { evidenceLevel: "real-host", oracle: "Four unapproved requests are publicly rejected without CA allocation and the exact original workspace approval policy is restored, even when native control cleanup fails" });
  if(context.approvalActor)await context.approvalActor.observeNativeCompletion(proof);
  return proof;
}
module.exports = { qualifyCapacity, verifyProof, REQUIRED_SCENARIOS, REQUIRED_SOURCES, FLAGS, SCOPE, domains };
