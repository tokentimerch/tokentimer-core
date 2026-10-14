"use strict";
/* Deterministic native uncertain submission: block only this machine's certreq
 * transport to the disposable CA before interrupting the owned agent at its
 * real durable submitting barrier. No journal, job clock or CA result is forged.
 * Full execution belongs exclusively to the protected disposable forest lane.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const dns = require("node:dns/promises");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const startObserver = require("./certops-adcs-journal-phase");
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-uncertain-abandon.js",
  "tests/e2e/helpers/certops-adcs-journal-phase.js",
  "infra/certops-adcs/journal-phase-fault.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "infra/certops-adcs/main.bicep",
  "apps/worker/src/certops-worker.js",
  "apps/api/services/certops/certificateEnrollments.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/issuers/adcs-enrollment-reconcile.js",
  "packages/agent/src/issuers/adcs-enrollment.js",
  "packages/agent/src/issuers/adcs.js",
]);

// Both root and subordinate lab modes place the issuing CA on domain-ca (.4);
// .7 is the separate offline root. Resolve and verify the exact configured CA
// rather than silently faulting a DNS server or a different issuer endpoint.
function validateDisposableCaAddress(caConfig, addresses) {
  assert.equal(caConfig, "tt-ca.lab.certops.test\\TTQualificationRoot");
  assert.ok(Array.isArray(addresses));
  const unique = [...new Set(addresses.map(item => item.address))];
  assert.equal(unique.length, 1, "Issuing CA must resolve to one owned IPv4 address");
  assert.equal(net.isIPv4(unique[0]), true);
  assert.match(unique[0], /^10\.64\.0\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/);
  assert.equal(unique[0], "10.64.0.4", "Resolved address must match the provisioned domain-ca VM");
  return unique[0];
}
function recoveryWaitBudget(leaseExpiresAt, measuredAt) {
  const expiry = new Date(leaseExpiresAt).getTime(), measured = new Date(measuredAt).getTime();
  assert.ok(Number.isFinite(expiry) && Number.isFinite(measured), "Actual persisted lease measurement required");
  const leaseRemainingAtFaultMs = Math.max(0, expiry - measured);
  const recoveryWaitBudgetMs = leaseRemainingAtFaultMs + 60000 + 30000;
  assert.ok(recoveryWaitBudgetMs <= 900000, "Persisted lease exceeds the reviewed fifteen-minute recovery budget");
  return { leaseRemainingAtFaultMs, recoveryWaitBudgetMs };
}

function assertProof(value) {
  const allowed = new Set(["scope", "resolvedIssuingCaAddress", "leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs", "ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "publicAbandonAudited", "unacceptedKeyRemoved", "originalOrphanPreserved", "recoveryPolicyUnchanged", "caRequestsAtFault", "caRequestsAfterRecovery", "caRequestsAfterAbandon"]);
  for (const key of Object.keys(value)) assert.ok(allowed.has(key), "Unexpected native proof field");
  assert.equal(value.scope, "native-zero-request-uncertain-abandon");
  assert.equal(value.resolvedIssuingCaAddress, "10.64.0.4");
  for (const field of ["ownedObserverDrained", "ownedTransportBlock", "observedSubmittingTermination", "actualLeaseExpiry", "acknowledgedPublicRecovery", "sameCsrAndKey", "noAutomaticResubmit", "publicAbandonAudited", "unacceptedKeyRemoved", "originalOrphanPreserved", "recoveryPolicyUnchanged"]) assert.equal(value[field], true, field);
  assert.equal(value.caRequestsAtFault, 0);
  assert.equal(value.caRequestsAfterRecovery, 0);
  assert.equal(value.caRequestsAfterAbandon, 0);
  for (const key of ["leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs"]) assert.ok(Number.isInteger(value[key]) && value[key] >= 0 && value[key] <= 900000, key);
  assert.equal(value.recoveryWaitBudgetMs, value.leaseRemainingAtFaultMs + 90000);
  assert.ok(value.actualLeaseWaitMs + 1000 >= value.leaseRemainingAtFaultMs);
  return true;
}

async function qualifyUncertainAbandon(context) {
  const { gate, fixture, api, agentRowId, configDir, workDir, run, preflight, ps, command, until, jobFinished, ownedSites, ownedCertificateIds, ownedEnrollmentIds, ownedFirewallRules, ownedPhaseObservers, serviceOwned, caConfig } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(serviceOwned, true);
  assert.ok(Array.isArray(ownedPhaseObservers));
  const root = path.resolve(__dirname, "../../..");
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
    const prior = gate.report.fixtureSources.filter(item => item.file === file);
    if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, sha256); }
    else gate.report.fixtureSources.push({ file, sha256 });
  }
  const domain = `certops-adcs-${run}-uncertain.example.test`;
  const site = `TTADCS-${run}-uncertain`;
  const rule = `TTQualification-Uncertain-${run}`;
  const targetReceipt = path.join(workDir, "journal-phase-target.json");
  assert.equal(fs.existsSync(targetReceipt), false, "Never overwrite another observer receipt");
  const proof = { scope: "native-zero-request-uncertain-abandon" };
  const caAddress = validateDisposableCaAddress(caConfig, await dns.lookup(caConfig.split("\\")[0], { family: 4, all: true }));
  proof.resolvedIssuingCaAddress = caAddress;
  let original, keyIdentityBefore, leaseMeasurementStart;
  const keyIdentity = container => ps(`$k=[Security.Cryptography.CngKey]::Open('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$sha=[Security.Cryptography.SHA256]::Create();try{if($k.KeyName -ne '${container}' -or -not $k.IsMachineKey -or $k.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Owned native key custody changed'};[Convert]::ToBase64String($sha.ComputeHash($k.Export([Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)))}finally{$sha.Dispose();$k.Dispose()}`);
  const observe = () => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-request-observation.ps1"), "-CommonName", domain, "-Discover"]));
  const getJob = async id => (await fixture.pool.query("SELECT status,lease_expires_at,lease_renewed_at,needs_operator_reconciliation,NOW() AS measured_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  let observer, created, stopped, primaryError, recoveryPolicy;
  const enrollment = async () => (await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, created.body.enrollmentId])).rows[0];
  const policy = () => JSON.parse(ps(`$r=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{$o=@($r.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($o.Count -ne 1 -or $o[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine '${configDir.replace(/'/g, "''")}'){throw 'Foreign service recovery policy'};@{actions=$(if($null -eq $r.GetValue('FailureActions')){$null}else{[Convert]::ToBase64String($r.GetValue('FailureActions'))});nonCrash=$r.GetValue('FailureActionsOnNonCrashFailures',$null)}|ConvertTo-Json -Compress}finally{$r.Dispose()}`));
  try {
    assert.equal(observe().subjectRequestCount, 0);
    const { issuerId, result } = await preflight("TTQualificationRSAShort");
    assert.equal(result.caCheck.verdict, "safe");
    assert.equal(result.templateCheck.verdict, "safe");
    assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: result.caCertificates[0].keySha256, caConfig, template: "TTQualificationRSAShort" })).status, 200);
    const port = await new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const selected = server.address().port; server.close(error => error ? reject(error) : resolve(selected)); }); });
    const directory = path.join(workDir, site); fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, "index.html"), "Native uncertain abandonment");
    ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Existing uncertain site'};if(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue){throw 'Existing uncertain firewall rule'};if(@(Get-NetFirewallProfile|Where-Object Enabled -ne True).Count){throw 'Firewall enforcement required'}`);
    ownedSites.push(site);
    ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1`);
    ownedFirewallRules.push(rule);
    ps(`New-NetFirewallRule -Name '${rule}' -DisplayName '${rule}' -Group '${rule}' -Direction Outbound -Action Block -Enabled True -Profile Any -Program "$env:SystemRoot\\System32\\certreq.exe" -RemoteAddress '${caAddress}'|Out-Null;$r=Get-NetFirewallRule -Name '${rule}';$p=$r|Get-NetFirewallApplicationFilter;$a=$r|Get-NetFirewallAddressFilter;if($r.Action -ne 'Block' -or $r.Direction -ne 'Outbound' -or $r.Enabled -ne 'True' -or $p.Program -ine "$env:SystemRoot\\System32\\certreq.exe" -or @($a.RemoteAddress).Count -ne 1 -or [string]$a.RemoteAddress[0] -ne '${caAddress}'){throw 'Transport fault scope invalid'}`);
    proof.ownedTransportBlock = true;
    recoveryPolicy = policy();
    assert.equal(recoveryPolicy.actions, null, "Owned manually created service must have no automatic SCM recovery");
    observer = startObserver({ ownedDirectory: workDir, configDirectory: configDir, repositoryRoot: root, phase: "submitting" });
    ownedPhaseObservers.push(observer);
    await observer.ready;
    const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    created = await fixture.request(`${api}/enrollments`, "POST", { issuerId, certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: domain, store: "My", binding: { site, port, sniHost: domain } }, authorizedDnsNames: [domain], keyAlgorithm: "rsa", keySize: 2048 });
    assert.equal(created.status, 201); ownedEnrollmentIds.push(created.body.enrollmentId);
    fs.writeFileSync(targetReceipt, JSON.stringify({ enrollmentId: created.body.enrollmentId, jobId: created.body.jobId, snapshotSha256: created.body.snapshotSha256, containerName: `tokentimer-enr-${created.body.enrollmentId}` }));
    await gate.scenario("adcs-real-uncertain-zero-request-owned-termination", async () => {
      const fault = await observer.result; stopped = true;
      assert.equal(fault.jobId, created.body.jobId); assert.equal(fault.enrollmentId, created.body.enrollmentId);
      await until(() => ps("(Get-Service TokenTimerAgent).Status") === "Stopped", 30000);
      original = readEnrollmentJournal(configDir, created.body.enrollmentId); assert.equal(original.kind, "valid"); assert.equal(original.journal.state, "submitting");
      assert.ok(original.artifacts.csrPem?.includes("BEGIN CERTIFICATE REQUEST")); assert.equal(original.artifacts.leafPem, null);
      proof.caRequestsAtFault = observe().subjectRequestCount; assert.equal(proof.caRequestsAtFault, 0);
      proof.observedSubmittingTermination = true;
      keyIdentityBefore = keyIdentity(original.journal.containerName); assert.match(keyIdentityBefore, /^[A-Za-z0-9+/]{43}=$/);
      const job = await getJob(created.body.jobId); assert.ok(job.lease_renewed_at); assert.ok(job.lease_expires_at);
      Object.assign(proof, recoveryWaitBudget(job.lease_expires_at, job.measured_at));
      leaseMeasurementStart = performance.now();
    }, { evidenceLevel: "real-host", oracle: "exact owned service process termination at observed durable submitting journal while verified native certreq RPC block and independent CA database prove zero requests" });
    // Restore transport while the agent is stopped. A zero CA count after
    // recovery must prove no resubmission, rather than an ongoing network block.
    ps(`$r=Get-NetFirewallRule -Name '${rule}' -ErrorAction Stop;if($r.Group -ne '${rule}' -or $r.DisplayName -ne '${rule}'){throw 'Foreign transport fault'};Remove-NetFirewallRule -Name '${rule}';if(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue){throw 'Transport remains blocked'}`);
    await gate.scenario("adcs-real-uncertain-zero-request-acknowledged-recovery", async () => {
      const worker = await import(pathToFileURL(path.join(root, "apps/worker/src/certops-worker.js")).href);
      await until(async () => { const client = await fixture.pool.connect(); try { await worker.reapExpiredLeases({ client, hardGraceMs: 60000, offlineAfterMs: 60000, log: { debug() {}, info() {}, warn() {}, error() {} } }); } finally { client.release(); } const row = await getJob(created.body.jobId); return row?.status === "orphaned_unknown_effect" && row.needs_operator_reconciliation === true; }, proof.recoveryWaitBudgetMs);
      proof.actualLeaseWaitMs = Math.floor(performance.now() - leaseMeasurementStart);
      proof.actualLeaseExpiry = true;
      const recovered = await fixture.request(`${api}/enrollments/${created.body.enrollmentId}/recover`, "POST", { orphanedJobId: created.body.jobId, acknowledgeUnknownEffect: true, reason: "Disposable qualification verified exact stopped service tree and zero native CA requests; preserve the original CSR and key" }); assert.equal(recovered.status, 201);
      ps("Start-Service TokenTimerAgent -ErrorAction Stop"); stopped = false;
      await until(async () => (await enrollment())?.state === "submission_uncertain");
      await until(async () => ["failed", "blocked"].includes((await getJob(recovered.body.jobId))?.status));
      const current = readEnrollmentJournal(configDir, created.body.enrollmentId); assert.equal(current.kind, "valid"); assert.equal(current.journal.state, "submission_uncertain");
      for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256"]) assert.equal(current.journal[field], original.journal[field]);
      assert.equal(current.artifacts.csrPem, original.artifacts.csrPem);
      assert.equal(keyIdentity(current.journal.containerName), keyIdentityBefore);
      assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(current.journal.containerName));
      proof.caRequestsAfterRecovery = observe().subjectRequestCount; assert.equal(proof.caRequestsAfterRecovery, 0);
      const audit = (await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.recovery_requested' AND metadata->>'enrollmentId'=$2", [fixture.workspaceId, created.body.enrollmentId])).rows;
      assert.equal(audit.length, 1); assert.equal(audit[0].metadata.acknowledgeUnknownEffect, true);
      proof.acknowledgedPublicRecovery = proof.sameCsrAndKey = proof.noAutomaticResubmit = true;
    }, { evidenceLevel: "real-host", oracle: "actual wall-clock lease expiry plus audited acknowledged public recovery preserves native CSR/key identity and reaches submission_uncertain without another CA request" });
    await gate.scenario("adcs-real-uncertain-zero-request-public-abandon-cleans-key", async () => {
      assert.equal((await fixture.request(`${api}/enrollments/${created.body.enrollmentId}/abandon`, "POST", {})).status, 204);
      const scheduled = (await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({ client: fixture.pool, now: new Date() })).find(row => row.enrollmentId === created.body.enrollmentId); assert.ok(scheduled); await jobFinished(scheduled.jobId);
      const final = readEnrollmentJournal(configDir, created.body.enrollmentId); assert.equal(final.kind, "valid"); assert.equal(final.journal.state, "abandoned");
      assert.equal((await enrollment()).state, "abandoned");
      assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(final.journal.containerName));
      assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq 'CN=${domain}').Count`), "0");
      proof.caRequestsAfterAbandon = observe().subjectRequestCount; assert.equal(proof.caRequestsAfterAbandon, 0);
      const audits = (await fixture.pool.query("SELECT action FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ENROLLMENT_ABANDONED' AND metadata->>'enrollmentId'=$2", [fixture.workspaceId, created.body.enrollmentId])).rows; assert.equal(audits.length, 1);
      const original = await getJob(created.body.jobId); assert.equal(original.status, "orphaned_unknown_effect"); assert.equal(original.needs_operator_reconciliation, true);
      proof.publicAbandonAudited = proof.unacceptedKeyRemoved = proof.originalOrphanPreserved = true;
    }, { evidenceLevel: "real-host", oracle: "public abandon and normal cleanup job remove only the proven unaccepted owned key; actual CA count remains zero, no certificate installed, original unknown-effect job retained" });
  } catch (error) { primaryError = error; }
  finally {
    const errors = [];
    try { if (observer) { await observer.stopAndDrain(); proof.ownedObserverDrained = true; } } catch (error) { errors.push(error); }
    try { ps(`$r=Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue;if($r){if($r.Group -ne '${rule}' -or $r.DisplayName -ne '${rule}'){throw 'Foreign firewall rule'};Remove-NetFirewallRule -Name '${rule}'};if(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue){throw 'Owned transport fault remains'}`); } catch (error) { errors.push(error); }
    try { if (recoveryPolicy) { assert.deepEqual(policy(), recoveryPolicy); proof.recoveryPolicyUnchanged = true; } } catch (error) { errors.push(error); }
    try { if (stopped || ps("(Get-Service TokenTimerAgent).Status") === "Stopped") ps("Start-Service TokenTimerAgent -ErrorAction Stop"); } catch (error) { errors.push(error); }
    try { if (created && fs.existsSync(targetReceipt)) { assert.equal(observer?.hasLiveChild(), false, "Retain observer ownership receipt until its exact child drains"); const receipt = JSON.parse(fs.readFileSync(targetReceipt, "utf8")); assert.equal(receipt.enrollmentId, created.body.enrollmentId); assert.equal(receipt.jobId, created.body.jobId); fs.unlinkSync(targetReceipt); } } catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError([...(primaryError ? [primaryError] : []), ...errors], "Uncertain abandon and owned fault restoration failed");
  }
  if (primaryError) throw primaryError;
  assertProof(proof);
  gate.report.nativeUncertainAbandon = proof;
}
module.exports = { qualifyUncertainAbandon, assertProof, validateDisposableCaAddress, recoveryWaitBudget, REQUIRED_SOURCES };
