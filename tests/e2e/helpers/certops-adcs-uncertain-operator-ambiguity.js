"use strict";
/** Real public recovery from operator-created ambiguity. The owning zero-request
 * transport/phase fixture supplies its untouched CSR and protected key. Two real
 * SYSTEM CA submissions deliberately create matching candidates; this is not
 * represented as lost-submit-response timing or fabricated enrollment state. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), tls = require("node:tls");
const { pathToFileURL } = require("node:url");
const { readEnrollmentJournal, createAdcsIssuer, assertIssuanceOutcome, resolveAdcsCmcHelperPath } = require("../../../packages/agent/src/issuers");
const { readIssuedContainerRecord } = require("../../../packages/agent/src/windows-cert-store");
const { DEFAULT_RECONCILE_WINDOW } = require("../../../packages/agent/src/issuers/adcs-enrollment-reconcile");
const SCOPE = "native-zero-request-uncertainty-with-operator-created-same-csr-ambiguity";
const REQUIRED_SCENARIOS = ["adcs-real-uncertain-operator-created-ambiguity-refuses-attachment", "adcs-real-uncertain-public-explicit-request-recovers", "adcs-real-uncertain-unused-operator-request-revoked"];
const FLAGS = ["ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "originalOrphanPreserved", "recoveryPolicyUnchanged", "operatorCreatedSameCsrAmbiguity", "nativeCaOwnershipVerified", "automaticAttachmentRefused", "unacceptedKeyPreserved", "unrelatedTrustedTlsPreserved", "publicExplicitReconcileAudited", "exactSelectedRequestInstalled", "claimBoundVerification", "sameProtectedMachineKeyInstalled", "unusedOwnedRequestRevoked", "unusedLeafNeverAccepted"];
const REQUIRED_SOURCES = [...new Set([...require("./certops-adcs-uncertain-abandon").REQUIRED_SOURCES, "tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity.js", "tests/e2e/certops-adcs-real-e2e.test.js", "infra/certops-adcs/owned-issued-request.ps1", "infra/certops-adcs/owned-ca-checkpoint.ps1", "infra/certops-adcs/officer-action.ps1", "packages/agent/src/issuers/index.js", "packages/agent/src/issuers/chain-helper.js", "packages/agent/src/windows-iis/index.js", "apps/api/routes/certops-enrollments.js"] )];
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), ["scope", "resolvedIssuingCaAddress", "leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs", "caRequestsAtFault", "caRequestsAfterOperatorSubmissions", "caRequestsAfterAmbiguousRecovery", "caRequestsAfterExplicitRecovery", "requestIds", "fingerprints", "serialNumbers", "csrSpkiSha256", "csrSha256", "selectedRequestId", "unusedRequestId", "enrollmentId", "containerName", "jobIds", "reconcileSearchFrom", "scanWindowSize", "fixtureOrigin", ...FLAGS].sort());
  assert.equal(proof.scope, SCOPE); assert.equal(proof.fixtureOrigin, "operator-created-two-real-system-submissions-of-the-same-public-csr"); assert.equal(proof.resolvedIssuingCaAddress, "10.64.0.4");
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  assert.equal(proof.caRequestsAtFault, 0); for (const field of ["caRequestsAfterOperatorSubmissions", "caRequestsAfterAmbiguousRecovery", "caRequestsAfterExplicitRecovery"]) assert.equal(proof[field], 2);
  for (const field of ["leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs"]) assert.ok(Number.isInteger(proof[field]) && proof[field] >= 0 && proof[field] <= 900000);
  assert.equal(proof.recoveryWaitBudgetMs, proof.leaseRemainingAtFaultMs + 90000); assert.ok(proof.actualLeaseWaitMs + 1000 >= proof.leaseRemainingAtFaultMs + 60000); assert.ok(proof.actualLeaseWaitMs <= proof.recoveryWaitBudgetMs + 1000);
  assert.match(proof.enrollmentId, UUID); assert.match(proof.containerName, /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/); assert.equal(proof.containerName, `tokentimer-enr-${proof.enrollmentId}`);
  for (const field of ["csrSpkiSha256", "csrSha256"]) assert.match(proof[field], /^[a-f0-9]{64}$/);
  assert.ok(Number.isInteger(proof.reconcileSearchFrom) && proof.reconcileSearchFrom >= 1 && proof.reconcileSearchFrom <= 0xffffffff); assert.equal(proof.scanWindowSize, 16);
  for (const [field, count, pattern] of [["requestIds", 2, /^[1-9][0-9]{0,9}$/], ["fingerprints", 2, /^[a-f0-9]{64}$/], ["serialNumbers", 2, /^[a-f0-9]{1,128}$/], ["jobIds", 3, UUID]]) {
    assert.ok(Array.isArray(proof[field])); assert.equal(proof[field].length, count); assert.equal(new Set(proof[field].map(item => String(item).toLowerCase())).size, count);
    for (const value of proof[field]) assert.match(value, pattern);
  }
  for (const value of proof.requestIds) assert.ok(Number(value) <= 0xffffffff && Number(value) >= proof.reconcileSearchFrom && Number(value) < proof.reconcileSearchFrom + proof.scanWindowSize);
  assert.ok(proof.requestIds.includes(proof.selectedRequestId)); assert.ok(proof.requestIds.includes(proof.unusedRequestId)); assert.notEqual(proof.selectedRequestId, proof.unusedRequestId); return true;
}
function peer(port, domain, authority) {
  return new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: authority, rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Operator ambiguity trusted TLS deadline exceeded"))); });
}
async function runOperatorCreatedAmbiguity(session) {
  const { context, original, created, domain, site, port, proof, keyIdentity, keyIdentityBefore, restartService, leaseMeasurementStart } = session;
  const { gate, fixture, api, configDir, workDir, run, command, ps, until, jobFinished, renewalFixture: live, tlsAuthority, ownedThumbprints } = context;
  const root = path.resolve(__dirname, "../../.."), id = created.body.enrollmentId, requests = [];
  assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"), "S-1-5-18");
  const query = (sql, args = []) => fixture.pool.query(sql, args);
  const enrollment = async () => (await query("SELECT state,request_id,operator_request_id,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const job = async jobId => (await query("SELECT status,error_message,claim_id,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0];
  const native = (script, args) => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, `infra/certops-adcs/${script}.ps1`), ...args]));
  const issued = fingerprint => native("owned-issued-request", ["-CommonName", domain, "-FingerprintSha256", fingerprint]);
  const observation = requestId => native("owned-request-observation", ["-CommonName", domain, "-RequestId", String(requestId)]);
  const officer = requestId => command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/officer-action.ps1"), "-CommonName", domain, "-RequestId", String(requestId), "-Action", "revoke"]);
  const preservedPeer = await peer(live.port, live.item.domain, tlsAuthority(live.authority)); assert.equal(preservedPeer.fingerprint256, live.observed.fingerprint256);
  const preserveUnrelatedTls = async () => assert.equal((await peer(live.port, live.item.domain, tlsAuthority(live.authority))).fingerprint256, preservedPeer.fingerprint256);
  const unaccepted = async () => {
    const current = readEnrollmentJournal(configDir, id); assert.equal(current.kind, "valid"); assert.equal(current.journal.state, "submission_uncertain");
    for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256"]) assert.equal(current.journal[field], original.journal[field]);
    assert.equal(current.artifacts.csrPem, original.artifacts.csrPem); assert.equal(current.artifacts.leafPem, null); assert.equal(keyIdentity(current.journal.containerName), keyIdentityBefore);
    const record = readIssuedContainerRecord({ stateDir: configDir, containerName: current.journal.containerName }); assert.equal(record.status, "generated"); assert.equal(record.acceptedThumbprint, null);
    assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq 'CN=${domain}').Count`), "0");
    const binding = await require("../../../packages/agent/src/windows-iis").queryCurrentBinding({ binding: { site, port, sniHost: domain } }); assert.equal(binding.ok, true); assert.equal(binding.thumbprint, null);
    await preserveUnrelatedTls(); return current;
  };
  const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
  let recovery, explicit;
  await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
    assert.equal(DEFAULT_RECONCILE_WINDOW, 16, "Reviewed default scan bound changed; do not manufacture a compatible floor");
    assert.equal(original.journal.caConfig, context.caConfig); assert.equal(original.journal.template, "TTQualificationRSAShort");
    const floor = original.journal.reconcileSearchFrom; assert.ok(Number.isInteger(floor) && floor >= 1);
    const before = native("owned-ca-checkpoint", ["-RunId", run]); assert.ok(before.highestRequestId + 2 < floor + 16, "Actual CA head is outside the captured default search window; never rewrite its floor");
    const scratch = path.join(workDir, "operator-created-ambiguity"); fs.mkdirSync(scratch, { mode: 0o700 });
    const authorityPath = path.join(scratch, "public-ca.cer"); fs.writeFileSync(authorityPath, Buffer.from(live.authority.certificateB64, "base64"));
    const helper = resolveAdcsCmcHelperPath(); assert.equal(helper.error, undefined);
    const issuer = createAdcsIssuer({ caConfig: original.journal.caConfig, template: original.journal.template, caKeySha256: live.authority.keySha256, caCertPath: authorityPath, helperPath: helper.path, scratchDir: scratch, jobId: `operator-ambiguity-${run}-${crypto.randomUUID()}`, enrollmentId: id, timeoutMs: 30000 });
    for (let index = 0; index < 2; index++) {
      const result = assertIssuanceOutcome(await issuer.submit({ csrPem: original.artifacts.csrPem, domains: [domain] })); assert.equal(result.outcome, "issued");
      const leaf = new crypto.X509Certificate(result.certificatePem), fingerprint = leaf.fingerprint256.replace(/:/g, "").toLowerCase();
      assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(live.authority.certificateB64, "base64")).publicKey), true); assert.equal(leaf.checkHost(domain), domain);
      assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"), original.journal.csrSpkiSha256);
      const actual = issued(fingerprint); assert.equal(actual.disposition, 20); assert.equal(actual.subjectRequestCount, index + 1); assert.ok(actual.requestId >= floor && actual.requestId < floor + 16);
      for (const prior of requests) { assert.notEqual(String(actual.requestId), prior.requestId); assert.notEqual(leaf.serialNumber, prior.leaf.serialNumber); assert.notEqual(fingerprint, prior.fingerprint); }
      requests.push({ requestId: String(actual.requestId), leaf, fingerprint });
    }
    const after = native("owned-ca-checkpoint", ["-RunId", run]); assert.equal(after.nativeTotalRequestCount, before.nativeTotalRequestCount + 2); assert.equal(after.nativeRequesterCount, before.nativeRequesterCount + 2);
    proof.caRequestsAfterOperatorSubmissions = 2;
    const worker = await import(pathToFileURL(path.join(root, "apps/worker/src/certops-worker.js")).href);
    await until(async () => { const client = await fixture.pool.connect(); try { await worker.reapExpiredLeases({ client, hardGraceMs: 60000, offlineAfterMs: 60000, log: { debug() {}, info() {}, warn() {}, error() {} } }); } finally { client.release(); } const originalJob = await job(created.body.jobId); return originalJob.status === "orphaned_unknown_effect" && originalJob.needs_operator_reconciliation === true; }, Math.max(1, proof.recoveryWaitBudgetMs - Math.floor(performance.now() - leaseMeasurementStart)));
    proof.actualLeaseWaitMs = Math.floor(performance.now() - leaseMeasurementStart);
    recovery = await fixture.request(`${api}/enrollments/${id}/recover`, "POST", { orphanedJobId: created.body.jobId, acknowledgeUnknownEffect: true, reason: "Owned zero-request submitting fault inspected; operator deliberately submitted this exact public CSR twice to exercise ambiguous candidate refusal" }); assert.equal(recovery.status, 201); restartService();
    await until(async () => { const row = await job(recovery.body.jobId); if (row.status === "succeeded") throw new Error("Ambiguous real candidates were automatically attached"); return row.status === "failed" ? row : null; });
    assert.match((await job(recovery.body.jobId)).error_message, /found 2 SPKI matches/);
    const current = await enrollment(); assert.equal(current.state, "submission_uncertain"); assert.equal(current.request_id, null); assert.equal(current.operator_request_id, null); await unaccepted();
    for (let attempt = 0; attempt < 2; attempt++) assert.equal((await scheduler.scheduleDueEnrollments({ client: fixture.pool })).filter(row => row.enrollmentId === id).length, 0);
    for (const request of requests) { const actual = issued(request.fingerprint); assert.equal(actual.subjectRequestCount, 2); assert.equal(String(actual.requestId), request.requestId); }
    proof.caRequestsAfterAmbiguousRecovery = 2;
    const audits = (await query("SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.recovery_requested' AND metadata->>'enrollmentId'=$2", [fixture.workspaceId, id])).rows; assert.equal(audits.length, 1); assert.equal(audits[0].metadata.acknowledgeUnknownEffect, true); assert.equal(String(audits[0].actor_user_id), String(fixture.userId));
  }, { evidenceLevel: "real-host", oracle: "actual zero-request fault, two explicitly operator-created same-CSR CA leaves, real lease/grace and public recovery refuse two matches without another CA request, key loss or TLS mutation" });
  const foreignAttempt=context.foreignReconcileActor ? await context.foreignReconcileActor.beforeExplicit(session) : null;
  if(foreignAttempt){assert.equal(foreignAttempt.additionalProposalCount,1);assert.match(foreignAttempt.failedJobId,UUID);assert.match(foreignAttempt.foreignRequestId,/^[1-9][0-9]{0,9}$/);}
  await gate.scenario(REQUIRED_SCENARIOS[1], async () => {
    const selected = requests[0];
    if(context.reconcileActor)await context.reconcileActor.reconcileEnrollment(id, selected.requestId);
    else assert.equal((await fixture.request(`${api}/enrollments/${id}/reconcile`, "POST", { requestId: Number(selected.requestId) })).status, 204);
    explicit = (await scheduler.scheduleDueEnrollments({ client: fixture.pool })).find(row => row.enrollmentId === id); assert.ok(explicit); await jobFinished(explicit.jobId);
    const installed = await enrollment(); assert.equal(installed.state, "installed"); assert.equal(String(installed.request_id), selected.requestId);
    const final = readEnrollmentJournal(configDir, id); assert.equal(final.kind, "valid"); assert.equal(final.journal.state, "installed");
    for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256"]) assert.equal(final.journal[field], original.journal[field]);
    assert.equal(final.artifacts.csrPem, original.artifacts.csrPem); assert.equal(keyIdentity(final.journal.containerName), keyIdentityBefore); assert.equal(new crypto.X509Certificate(final.artifacts.leafPem).fingerprint256, selected.leaf.fingerprint256);
    const receipt = readIssuedContainerRecord({ stateDir: configDir, containerName: final.journal.containerName }); assert.equal(receipt.status, "enrolled_by_agent"); assert.equal(receipt.acceptedThumbprint, selected.leaf.fingerprint.replace(/:/g, "").toUpperCase()); ownedThumbprints.add(receipt.acceptedThumbprint);
    assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${receipt.acceptedThumbprint}';$k=$null;$p=$null;try{if([Convert]::ToBase64String($c.RawData) -ne '${selected.leaf.raw.toString("base64")}'){throw 'Wrong accepted leaf'};$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($k.Key.KeyName -ne '${original.journal.containerName}' -or $k.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or !$k.Key.IsMachineKey -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or $k.KeySize -ne 2048){throw 'Wrong accepted native custody'};$d=[Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString());$s=$k.SignData($d,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);$p=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c);if(!$p.VerifyData($d,$s,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Accepted key possession failed'};'True'}finally{if($p){$p.Dispose()};if($k){$k.Dispose()};$c.Dispose()}`), "True");
    assert.equal((await peer(port, domain, tlsAuthority(live.authority))).fingerprint256, selected.leaf.fingerprint256); await preserveUnrelatedTls();
    const evidence = (await query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'", [fixture.workspaceId, explicit.jobId])).rows;
    assert.ok(evidence.some(row => String(row.metadata.fingerprintSha256).replace(/:/g, "").toLowerCase() === selected.fingerprint));
    const audits = (await query("SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ENROLLMENT_RECONCILE_PROPOSED' AND metadata->>'enrollmentId'=$2", [fixture.workspaceId, id])).rows; assert.equal(audits.length, foreignAttempt ? 2 : 1);const selectedAudits=audits.filter(row=>String(row.metadata.requestId)===selected.requestId);assert.equal(selectedAudits.length,1);assert.equal(String(selectedAudits[0].actor_user_id),String(fixture.userId));if(foreignAttempt){const foreignAudits=audits.filter(row=>String(row.metadata.requestId)===foreignAttempt.foreignRequestId);assert.equal(foreignAudits.length,1);assert.equal(String(foreignAudits[0].actor_user_id),String(fixture.userId));}
    for (const request of requests) { const actual = issued(request.fingerprint); assert.equal(actual.subjectRequestCount, 2); assert.equal(String(actual.requestId), request.requestId); }
    proof.caRequestsAfterExplicitRecovery = 2; const orphan = await job(created.body.jobId); assert.equal(orphan.status, "orphaned_unknown_effect"); assert.equal(orphan.needs_operator_reconciliation, true);
  }, { evidenceLevel: "real-host", oracle: "public operator RequestId proposal plus real-now signed continuation validates and installs only the selected actual same-CSR CA leaf with unchanged protected key, claim-bound evidence and distinct action audit" });
  await gate.scenario(REQUIRED_SCENARIOS[2], async () => {
    const unused = requests[1], thumb = unused.leaf.fingerprint.replace(/:/g, "").toUpperCase(); const actual = issued(unused.fingerprint); assert.equal(String(actual.requestId), unused.requestId); assert.equal(actual.disposition, 20);
    // Metadata-only complete LocalMachine enumeration: never revoke a leaf
    // that was unexpectedly accepted anywhere, even when another assertion failed.
    assert.equal(ps(`$ownedCertCount=0;$unusedLeafCount=0;Get-ChildItem Cert:\\LocalMachine -Recurse -ErrorAction Stop|ForEach-Object {if($_ -is [Security.Cryptography.X509Certificates.X509Certificate2]){if(++$ownedCertCount -gt 100000){throw 'Certificate metadata scope exceeded'};if($_.Thumbprint -eq '${thumb}'){$unusedLeafCount++}}};$unusedLeafCount`), "0");
    assert.equal(officer(unused.requestId), "CERTOPS_OFFICER=revoke"); assert.equal(observation(unused.requestId).disposition, 21); assert.equal(observation(unused.requestId).subjectRequestCount, 2);
    assert.equal((await peer(port, domain, tlsAuthority(live.authority))).fingerprint256, requests[0].leaf.fingerprint256); await preserveUnrelatedTls();
    Object.assign(proof, Object.fromEntries(FLAGS.filter(flag => !["ownedObserverDrained", "recoveryPolicyUnchanged"].includes(flag)).map(flag => [flag, true])), { scope: SCOPE, fixtureOrigin: "operator-created-two-real-system-submissions-of-the-same-public-csr", requestIds: requests.map(row => row.requestId), fingerprints: requests.map(row => row.fingerprint), serialNumbers: requests.map(row => row.leaf.serialNumber.toLowerCase()), csrSpkiSha256: original.journal.csrSpkiSha256, csrSha256: original.journal.csrSha256, selectedRequestId: requests[0].requestId, unusedRequestId: requests[1].requestId, enrollmentId: id, containerName: original.journal.containerName, jobIds: [created.body.jobId, recovery.body.jobId, explicit.jobId], reconcileSearchFrom: original.journal.reconcileSearchFrom, scanWindowSize: 16 });
  }, { evidenceLevel: "real-host", oracle: "exact native requester/CSR/leaf ownership and complete accepted-store absence fence revocation of only the unused operator-created CA issuance; selected trusted TLS remains live" });
}
async function qualifyOperatorCreatedAmbiguity(context) {
  if(context.reconcileActor){assert.equal(typeof context.reconcileActor.reconcileEnrollment,"function");assert.equal(typeof context.reconcileActor.observeNativeCompletion,"function");}
  await require("./certops-adcs-uncertain-abandon").qualifyUncertainScenario(context, "operator-created-ambiguity");
  // The original fixture verifies its complete native proof only AFTER fault
  // restoration. Browser evidence cannot finish on an intermediate assertion.
  if(context.reconcileActor)await context.reconcileActor.observeNativeCompletion(context.gate.report.nativeUncertainOperatorAmbiguity);
  if(context.foreignReconcileActor)await context.foreignReconcileActor.observeNativeCompletion(context.gate.report.nativeUncertainOperatorAmbiguity);
}
module.exports = { SCOPE, FLAGS, REQUIRED_SCENARIOS, REQUIRED_SOURCES, verifyProof, runOperatorCreatedAmbiguity, qualifyOperatorCreatedAmbiguity };
