"use strict";
/** Experimental real accepted-before-bind crash recovery. An independently
 * observed native window is mandatory; a missed window fails. This source and
 * its supporting proof tests never promote an experiment to release evidence. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), tls = require("node:tls");
const { spawn } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { buildEnrollmentContainerName, readIssuedContainerRecord } = require("../../../packages/agent/src/windows-cert-store");
const { recoveryWaitBudget } = require("./certops-adcs-uncertain-abandon");
const PHASE = "accepted-before-bind";
const FLAGS = ["nativeAcceptedLeafAtFault", "oldTrustedBindingAtFault", "sameRequestLeafCsrAndKey", "sameNativePublicKey", "actualLeaseExpiry", "acknowledgedRecoveryAudit", "originalUnknownEffectPreserved", "trustedRecoveredTls", "noAdditionalCaRequest", "sameAcceptedCustodyReceipt", "ownedObserverDrained", "scmPolicyUnchanged"];
const REQUIRED_SOURCES = ["tests/e2e/helpers/certops-adcs-accepted-install-recovery.js", "infra/certops-adcs/accepted-install-phase-fault.ps1", "tests/e2e/certops-adcs-real-e2e.test.js", "packages/agent/src/adcs-windows-iis.js", "packages/agent/src/index.js", "packages/agent/src/windows-cert-store/index.js", "packages/agent/src/issuers/adcs-enrollment-journal.js", "apps/api/services/certops/certificateEnrollments.js", "apps/worker/src/certops-worker.js", "infra/certops-adcs/owned-issued-request.ps1", "tests/e2e/helpers/certops-adcs-uncertain-abandon.js", "packages/agent/src/windows-iis/index.js", "packages/agent/src/issuers/adcs-enrollment.js", "packages/agent/src/issuers/adcs.js", "packages/agent/src/issuers/chain-helper.js", "scripts/certops-adcs-journal-phase-report.js", ".github/workflows/certops-enterprise-adcs-journal-phase-experiment.yml", "infra/certops-adcs/provision-lab.ps1", "infra/certops-adcs/run-windows-tests.ps1", "infra/certops-adcs/control-plane.sh"];
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function verifyFault(value) {
  assert.deepEqual(Object.keys(value).sort(), ["phase", "observedDurablePhase", "unchangedAfterTermination", "ownedServiceTree", "ownedNativeChildrenAbsent", "nativeIdentity", "acceptedExactLeafAndCng", "predecessorIisUnchanged", "enrollmentId", "jobId", "snapshotSha256", "requestId", "fingerprint"].sort());
  assert.equal(value.phase, PHASE); assert.equal(value.nativeIdentity, "LocalSystem");
  for (const field of ["observedDurablePhase", "unchangedAfterTermination", "ownedServiceTree", "ownedNativeChildrenAbsent", "acceptedExactLeafAndCng", "predecessorIisUnchanged"]) assert.equal(value[field], true);
  for (const field of ["enrollmentId", "jobId"]) assert.match(value[field], UUID);
  for (const field of ["snapshotSha256", "fingerprint"]) assert.match(value[field], /^[a-f0-9]{64}$/);
  assert.match(value.requestId, /^[1-9][0-9]{0,9}$/); assert.ok(Number(value.requestId) <= 0xffffffff); return true;
}
function startObserver({ workDir, configDir, root, spawnImpl = spawn, timeoutMs = 195000, phase = PHASE }) {
  assert.ok([PHASE, "bound-before-complete"].includes(phase));
  const bound = phase === "bound-before-complete";
  const verifyEvidence = bound ? require("./certops-adcs-bound-install-recovery").verifyFault : verifyFault;
  const env = Object.fromEntries(["SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "PSModulePath", "CERTOPS_ADCS_DISPOSABLE_LAB"].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  const child = spawnImpl("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, bound ? "infra/certops-adcs/bound-install-phase-fault.ps1" : "infra/certops-adcs/accepted-install-phase-fault.ps1"), "-OwnedDirectory", workDir, "-ConfigDirectory", configDir, "-RepositoryRoot", root, "-NodeExecutable", process.execPath], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let output = "", overflow = false, closed = false, nativeDrainProven = false, readyResolve, readyReject, resolveResult, rejectResult, seenReady = false;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; }); ready.catch(() => {});
  const result = new Promise((resolve, reject) => { resolveResult = resolve; rejectResult = reject; }); result.catch(() => {});
  let closeResolve; const close = new Promise(resolve => { closeResolve = resolve; });
  const timer = setTimeout(() => child.kill(), timeoutMs);
  child.stdout.on("data", chunk => { if (Buffer.byteLength(output) + chunk.length > 8192) { overflow = true; child.kill(); return; } if (!overflow) output += chunk.toString("utf8"); if (output.includes("CERTOPS_ACCEPTED_INSTALL_READY")) { seenReady = true; readyResolve(); } });
  child.stderr.resume(); child.once("error", () => { readyReject(new Error("Owned accepted-install observer could not start")); rejectResult(new Error("Owned accepted-install observer could not start")); });
  child.once("close", code => {
    clearTimeout(timer); closed = true; closeResolve();
    if (!seenReady) readyReject(new Error("Accepted-install observer ownership prerequisite failed"));
    try { assert.equal(code, 0); assert.equal(overflow, false); const evidence = JSON.parse(output.replace("CERTOPS_ACCEPTED_INSTALL_READY", "").trim()); verifyEvidence(evidence); nativeDrainProven = true; resolveResult(evidence); }
    catch { rejectResult(new Error("Accepted-before-bind window/custody/process drainage was not proven")); }
  });
  return { ready, result,
    // A failed observer cannot attest its interrupted native children drained.
    // Preserve parent cleanup guards even after the observer itself has exited.
    hasLiveChild: () => !closed || !nativeDrainProven,
    async stopAndDrain() { clearTimeout(timer); if (!closed) child.kill(); let drainTimer; try { await Promise.race([close, new Promise((_, reject) => { drainTimer = setTimeout(() => reject(new Error("Owned accepted-install observer did not drain")), 30000); })]); } finally { clearTimeout(drainTimer); } },
  };
}
function verifyReport(report, root = path.resolve(__dirname, "../../..")) {
  assert.deepEqual(Object.keys(report).sort(), ["schemaVersion", "scope", "phase", "qualificationStatus", "experimental", "status", "candidateSha", "fixtureSource", "fixtureSources", "fault", "leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs", "caRequestsAtFault", "caRequestsAfterRecovery", ...FLAGS].sort());
  assert.equal(report.schemaVersion, 1); assert.equal(report.scope, "enterprise-adcs-journal-phase-experimental"); assert.equal(report.phase, PHASE); assert.equal(report.qualificationStatus, "not-qualified"); assert.equal(report.experimental, true); assert.equal(report.status, "passed");
  assert.match(report.candidateSha, /^[a-f0-9]{40}$/i); verifyFault(report.fault);
  for (const flag of FLAGS) assert.equal(report[flag], true, flag);
  for (const name of ["caRequestsAtFault", "caRequestsAfterRecovery"]) assert.ok(Number.isInteger(report[name]) && report[name] >= 1 && report[name] <= 1000);
  assert.equal(report.caRequestsAfterRecovery, report.caRequestsAtFault);
  for (const name of ["leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs"]) assert.ok(Number.isInteger(report[name]) && report[name] >= 0 && report[name] <= 900000);
  assert.equal(report.recoveryWaitBudgetMs, report.leaseRemainingAtFaultMs + 90000); assert.ok(report.actualLeaseWaitMs + 1000 >= report.leaseRemainingAtFaultMs + 60000);
  assert.ok(report.actualLeaseWaitMs <= report.recoveryWaitBudgetMs + 1000);
  const digest = file => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
  assert.deepEqual(report.fixtureSource, { file: REQUIRED_SOURCES[0], sha256: digest(REQUIRED_SOURCES[0]) });
  assert.ok(Array.isArray(report.fixtureSources)); assert.equal(report.fixtureSources.length, REQUIRED_SOURCES.length);
  for (const file of REQUIRED_SOURCES) { const rows = report.fixtureSources.filter(row => row.file === file); assert.equal(rows.length, 1); assert.deepEqual(rows[0], { file, sha256: digest(file) }); }
  return true;
}
async function qualifyObservedInstallRecovery(context, phase = PHASE) {
  assert.ok([PHASE, "bound-before-complete"].includes(phase));
  const bound = phase === "bound-before-complete";
  const variant = bound ? require("./certops-adcs-bound-install-recovery") : { FLAGS, REQUIRED_SOURCES, verifyReport };
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1"); assert.equal(context.serviceOwned, true);
  const { fixture, api, agentRowId, configDir, workDir, renewalFixture: owned, ps, command, until, jobFinished, tlsAuthority, ownedEnrollmentIds, ownedThumbprints, ownedPhaseObservers } = context;
  const root = path.resolve(__dirname, "../../.."), targetReceipt = path.join(workDir, "accepted-install-target.json");
  const reportPath = process.env.CERTOPS_ADCS_JOURNAL_PHASE_REPORT || "C:\\ttqualification\\journal-phase-experimental.json";
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") });
  const report = { schemaVersion: 1, scope: "enterprise-adcs-journal-phase-experimental", phase, qualificationStatus: "not-qualified", experimental: true, status: "running", candidateSha: process.env.GITHUB_SHA, fixtureSource: hash(bound ? "tests/e2e/helpers/certops-adcs-bound-install-recovery.js" : REQUIRED_SOURCES[0]), fixtureSources: variant.REQUIRED_SOURCES.map(hash) };
  const query = (sql, args = []) => fixture.pool.query(sql, args);
  const job = async id => (await query("SELECT status,lease_expires_at,lease_renewed_at,needs_operator_reconciliation,NOW() AS measured_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const binding = { site: owned.site, port: owned.port, sniHost: owned.item.domain };
  const nativeBinding = () => require("../../../packages/agent/src/windows-iis").queryCurrentBinding({ binding });
  const served = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: owned.port, servername: owned.item.domain, ca: tlsAuthority(owned.authority), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Accepted-install trusted TLS deadline exceeded"))); });
  const policy = () => ps(`$r=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{$o=@($r.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($o.Count -ne 1 -or $o[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine '${configDir.replace(/'/g, "''")}'){throw 'Foreign service policy'};if($null -ne $r.GetValue('FailureActions')){throw 'Automatic recovery is not disabled'};[string]$r.GetValue('FailureActionsOnNonCrashFailures','absent')}finally{$r.Dispose()}`);
  let observer, created, primary, stopped = false;
  try {
    const originalPolicy = policy(), previous = await served(), beforeBinding = await nativeBinding(); assert.equal(beforeBinding.ok, true);
    assert.equal(previous.fingerprint256, owned.observed.fingerprint256);
    const previousThumb = previous.fingerprint.replace(/:/g, "").toUpperCase(); assert.equal(beforeBinding.thumbprint.toUpperCase(), previousThumb);
    const retention = bound ? require("../../../packages/agent/src/windows-retention") : null;
    const ledgerDir = path.join(configDir, "windows-retention");
    const predecessorContainer = bound ? buildEnrollmentContainerName(owned.currentEnrollmentId) : null;
    const keyIdentityFor = container => ps(`$k=[Security.Cryptography.CngKey]::Open('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);try{if($k.KeyName -ne '${container}' -or !$k.IsMachineKey -or $k.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Protected key changed'};[Convert]::ToBase64String($k.Export([Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob))}finally{$k.Dispose()}`);
    const predecessorKey = bound ? keyIdentityFor(predecessorContainer) : null;
    if (bound) {
      assert.equal(retention.readLedgerRow(ledgerDir, previousThumb), null, "Predecessor was already superseded before the observed new cutover");
      assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${previousThumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);$k.Key.KeyName}finally{if($k){$k.Dispose()};$c.Dispose()}`), predecessorContainer);
    }
    observer = startObserver({ workDir, configDir, root, phase }); ownedPhaseObservers.push(observer); await observer.ready;
    created = await fixture.request(`${api}/enrollments`, "POST", { issuerId: owned.issuerId, certificateId: owned.certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: owned.item.domain, store: "My", binding }, authorizedDnsNames: [owned.item.domain], keyAlgorithm: "rsa", keySize: 2048 });
    assert.equal(created.status, 201); const id = created.body.enrollmentId; ownedEnrollmentIds.push(id);
    const container = buildEnrollmentContainerName(id);
    fs.writeFileSync(targetReceipt, JSON.stringify({ enrollmentId: id, jobId: created.body.jobId, snapshotSha256: created.body.snapshotSha256, containerName: container, predecessorThumbprint: previousThumb, site: owned.site, port: owned.port, domain: owned.item.domain }), { flag: "wx" });
    report.fault = await observer.result; await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false); stopped = true;
    assert.equal(report.fault.enrollmentId, id); assert.equal(report.fault.jobId, created.body.jobId); assert.equal(report.fault.snapshotSha256, created.body.snapshotSha256);
    const initial = readEnrollmentJournal(configDir, id); assert.equal(initial.kind, "valid"); assert.equal(initial.journal.state, "installing"); assert.equal(initial.journal.installStep, "bind"); assert.equal(initial.journal.containerName, container);
    const leaf = new crypto.X509Certificate(initial.artifacts.leafPem); assert.equal(crypto.createHash("sha256").update(leaf.raw).digest("hex"), report.fault.fingerprint); assert.notEqual(leaf.fingerprint256, previous.fingerprint256);
    assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(owned.authority.certificateB64, "base64")).publicKey), true);
    assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"), initial.journal.csrSpkiSha256);
    const thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase(); ownedThumbprints.add(thumb);
    const receiptBefore = readIssuedContainerRecord({ stateDir: configDir, containerName: container }); assert.equal(receiptBefore?.status, "enrolled_by_agent"); assert.equal(receiptBefore.acceptedThumbprint, thumb);
    const keyIdentity = () => keyIdentityFor(container);
    const originalKey = keyIdentity(); assert.ok(originalKey.length < 2048);
    const observe = () => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", owned.item.domain, "-FingerprintSha256", report.fault.fingerprint]));
    const ca = observe(); assert.equal(String(ca.requestId), report.fault.requestId); assert.equal(String(initial.journal.requestId), report.fault.requestId); report.caRequestsAtFault = ca.subjectRequestCount;
    let retentionAtFault = null;
    const verifyRetention = (row, allowedJobIds) => {
      assert.ok(row); assert.equal(row.oldThumbprint, previousThumb); assert.equal(row.replacementThumbprint, thumb);
      assert.equal(row.cngKeyContainerId, predecessorContainer); assert.equal(row.ownershipProvenance, "tokentimer_installed"); assert.equal(row.store, "My"); assert.equal(row.lifecycleState, "pending_retention");
      assert.equal(Date.parse(row.oldNotAfter), Date.parse(previous.validTo)); assert.ok(Number.isFinite(Date.parse(row.verifiedCutoverAt)) && Date.parse(row.verifiedCutoverAt) <= Date.now() + 1000);
      assert.equal(row.jobOrRollbackJournalRefs.length, 1); assert.ok(allowedJobIds.includes(row.jobOrRollbackJournalRefs[0].ref)); assert.equal(row.jobOrRollbackJournalRefs[0].active, false);
    };
    if (bound) {
      const currentBinding = await nativeBinding(); assert.equal(currentBinding.ok, true); assert.equal(currentBinding.thumbprint.toUpperCase(), thumb); assert.equal((await served()).fingerprint256, leaf.fingerprint256);
      retentionAtFault = retention.readLedgerRow(ledgerDir, previousThumb);
      if (retentionAtFault) verifyRetention(retentionAtFault, [created.body.jobId]);
      report.retentionAtFault = retentionAtFault ? "matching-existing-row" : "absent"; report.preVerificationWindowClaimed = false;
    } else { assert.deepEqual(await nativeBinding(), beforeBinding); assert.equal((await served()).fingerprint256, previous.fingerprint256); }
    const originalJob = await job(created.body.jobId); assert.ok(originalJob.lease_renewed_at); Object.assign(report, recoveryWaitBudget(originalJob.lease_expires_at, originalJob.measured_at)); const started = performance.now();
    const worker = await import(pathToFileURL(path.join(root, "apps/worker/src/certops-worker.js")).href);
    await until(async () => { const client = await fixture.pool.connect(); try { await worker.reapExpiredLeases({ client, hardGraceMs: 60000, offlineAfterMs: 60000, log: { debug() {}, info() {}, warn() {}, error() {} } }); } finally { client.release(); } const row = await job(created.body.jobId); return row.status === "orphaned_unknown_effect" && row.needs_operator_reconciliation === true; }, report.recoveryWaitBudgetMs);
    report.actualLeaseWaitMs = Math.floor(performance.now() - started);
    const recovery = await fixture.request(`${api}/enrollments/${id}/recover`, "POST", { orphanedJobId: created.body.jobId, acknowledgeUnknownEffect: true, reason: "Owned native accepted leaf/key and unchanged outgoing IIS binding independently inspected after exact service-tree interruption" }); assert.equal(recovery.status, 201);
    assert.equal(policy(), originalPolicy); ps("Start-Service TokenTimerAgent -ErrorAction Stop"); stopped = false; await jobFinished(recovery.body.jobId);
    const final = readEnrollmentJournal(configDir, id); assert.equal(final.kind, "valid"); assert.equal(final.journal.state, "installed");
    for (const field of ["containerName", "requestId", "snapshotSha256", "csrSha256", "csrSpkiSha256", "leafSha256"]) assert.equal(final.journal[field], initial.journal[field]);
    assert.equal(final.artifacts.csrPem, initial.artifacts.csrPem); assert.equal(final.artifacts.leafPem, initial.artifacts.leafPem); assert.equal(keyIdentity(), originalKey);
    const receiptAfter = readIssuedContainerRecord({ stateDir: configDir, containerName: container });
    for (const field of ["containerName", "status", "acceptedThumbprint", "acceptedStore", "jobId", "certificateId", "issuedAt"]) assert.equal(receiptAfter?.[field], receiptBefore[field]);
    assert.ok(Date.parse(receiptAfter.acceptedAt) >= Date.parse(receiptBefore.acceptedAt));
    const current = (await query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0]; assert.equal(current.state, "installed"); assert.equal(String(current.request_id), report.fault.requestId);
    const afterBinding = await nativeBinding(); assert.equal(afterBinding.ok, true); assert.equal(afterBinding.thumbprint.toUpperCase(), thumb); assert.equal((await served()).fingerprint256, leaf.fingerprint256);
    if (bound) {
      const evidence = (await query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'", [fixture.workspaceId, recovery.body.jobId])).rows;
      assert.ok(evidence.some(row => String(row.metadata.fingerprintSha256).replace(/:/g, "").toLowerCase() === report.fault.fingerprint && Date.parse(row.metadata.validTo) === Date.parse(leaf.validTo)));
      const completion = (await query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='deployment.updated' AND e.metadata->>'step'='iis-bind'", [fixture.workspaceId, recovery.body.jobId])).rows;
      assert.ok(completion.some(row => row.metadata.idempotentSkip === true && String(row.metadata.boundThumbprint).toUpperCase() === thumb), "Recovery must report the inspected existing cutover rather than a new native rebind");
      const finalRetention = retention.readLedgerRow(ledgerDir, previousThumb); verifyRetention(finalRetention, [created.body.jobId, recovery.body.jobId]);
      if (retentionAtFault) assert.deepEqual(finalRetention, retentionAtFault, "Idempotent completion must preserve the already observed retention row");
      assert.equal(fs.readdirSync(ledgerDir).filter(name => name.toUpperCase() === `${previousThumb}.json`.toUpperCase()).length, 1);
      assert.equal(keyIdentityFor(predecessorContainer), predecessorKey);
      assert.equal(ps(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${previousThumb}')`), "True");
    }
    const afterCa = observe(); assert.equal(String(afterCa.requestId), String(ca.requestId)); assert.equal(afterCa.subjectRequestCount, ca.subjectRequestCount); report.caRequestsAfterRecovery = afterCa.subjectRequestCount;
    const audits = (await query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.recovery_requested' AND metadata->>'enrollmentId'=$2", [fixture.workspaceId, id])).rows; assert.equal(audits.length, 1); assert.equal(audits[0].metadata.acknowledgeUnknownEffect, true);
    const orphan = await job(created.body.jobId); assert.equal(orphan.status, "orphaned_unknown_effect"); assert.equal(orphan.needs_operator_reconciliation, true); assert.equal(policy(), originalPolicy);
    Object.assign(report, Object.fromEntries(variant.FLAGS.map(field => [field, true]))); report.status = "passed"; variant.verifyReport(report);
    owned.observed = leaf; owned.currentEnrollmentId = id;
  } catch (error) { primary = error; report.status = "failed"; }
  finally {
    const errors = [];
    try { if (observer) { await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false, "Preserve native state while observer/tree drainage is unproven"); } } catch (error) { errors.push(error); }
    if (!errors.length) {
      try { if (stopped) ps("Start-Service TokenTimerAgent -ErrorAction Stop"); } catch (error) { errors.push(error); }
      try { if (created && fs.existsSync(targetReceipt)) { const receipt = JSON.parse(fs.readFileSync(targetReceipt, "utf8")); assert.equal(receipt.enrollmentId, created.body.enrollmentId); assert.equal(receipt.jobId, created.body.jobId); fs.unlinkSync(targetReceipt); } } catch (error) { errors.push(error); }
    }
    if (errors.length) report.status = "failed";
    fs.writeFileSync(reportPath, JSON.stringify(report));
    if (errors.length) throw new AggregateError([...(primary ? [primary] : []), ...errors], "Accepted-install experiment cleanup unproven");
  }
  if (primary) throw primary; return report;
}
const qualifyAcceptedInstallRecovery = context => qualifyObservedInstallRecovery(context, PHASE);
module.exports = { qualifyAcceptedInstallRecovery, qualifyObservedInstallRecovery, startObserver, verifyFault, verifyReport, PHASE, FLAGS, REQUIRED_SOURCES };
