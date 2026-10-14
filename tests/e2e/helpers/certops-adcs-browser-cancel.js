"use strict";
/** Supported requested-enrollment Cancel UI. One additional sequential public
 * approval-gated renewal reuses the capacity fixture's already issued subject.
 * It is separate from the original six-way capacity experiment and never
 * submits a new CA request. Parent retains exact native cleanup ownership. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const session = require("./certops-adcs-browser-session");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");
const { TERMINAL_JOB_STATUSES } = require("../../../apps/api/services/certops/jobs");
const REQUIRED_SCENARIOS = ["adcs-real-browser-requested-renewal-cancel", "adcs-real-browser-cancel-native-custody-and-capacity"];
const REQUIRED_SOURCES = [...new Set([...session.REQUIRED_SOURCES, "tests/e2e/helpers/certops-adcs-browser-cancel.js", "tests/e2e/helpers/certops-adcs-capacity.js", "tests/e2e/helpers/certops-adcs-webhosting-renewal.js", "tests/e2e/certops-adcs-real-e2e.test.js", "apps/dashboard/src/pages/certops/CertOpsAdcs.jsx", "apps/dashboard/src/components/certops/certopsEnrollmentsApi.js", "apps/api/routes/certops-enrollments.js", "apps/api/services/certops/certificateEnrollments.js", "apps/api/services/certops/jobs.js", "apps/api/services/certops/renewalCapacity.js", "packages/agent/src/issuers/adcs-enrollment-journal.js", "packages/agent/src/windows-cert-store/index.js", "infra/certops-adcs/owned-issued-request.ps1"])];
const FLAGS = ["additionalSequentialPublicRenewal", "requestedPendingApprovalObserved", "newJobNeverClaimed", "exactPublicCancelAcknowledged", "browserAndTrustDrained", "onlyNewEnrollmentAndJobCancelled", "oldInstalledEnrollmentUnchanged", "oldProtectedCngAndIisUnchanged", "oldTrustedTlsUnchanged", "newContainerAndJournalAbsent", "subjectCaRequestsUnchanged", "exactHumanCancelAudit", "capacitySlotReleased", "cleanupOwnershipRegistered"];
const SCOPE = "browser-cancel-requested-approval-gated-renewal-preserves-issued-native-custody";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyRequest(request, { origin, workspaceId, enrollmentId }) {
  assert.match(workspaceId, UUID); assert.match(enrollmentId, UUID);
  const url = new URL(request.url()); assert.equal(request.method(), "POST"); assert.equal(url.origin, origin);
  assert.equal(url.pathname, `/api/v1/workspaces/${workspaceId}/certops/enrollments/${enrollmentId}/cancel`); assert.equal(url.search, ""); assert.equal(url.hash, "");
  assert.ok(request.postData() === null || request.postData() === "", "Cancel must have no invented request body"); return true;
}
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "enrollmentId", "jobId", "priorEnrollmentId", "priorJobId", "priorRequestId", "fingerprint", "cancelPosts", "otherMutations", "capacityBeforeCancel", "capacityAfterCancel", "initialSixConcurrencyQualified", "caSubmissionCancellationQualified", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE);
  for (const key of ["enrollmentId", "jobId", "priorEnrollmentId", "priorJobId"]) assert.match(value[key], UUID);
  assert.equal(new Set([value.enrollmentId, value.jobId, value.priorEnrollmentId, value.priorJobId]).size, 4);
  assert.match(value.priorRequestId, /^[1-9][0-9]{0,9}$/); assert.ok(Number(value.priorRequestId) <= 0xffffffff); assert.match(value.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(value.cancelPosts, 1); assert.equal(value.otherMutations, 0); assert.equal(value.capacityBeforeCancel, 5); assert.equal(value.capacityAfterCancel, 4);
  assert.equal(value.initialSixConcurrencyQualified, false); assert.equal(value.caSubmissionCancellationQualified, false);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag); return true;
}
function verifyCrossProof(value, capacity) {
  verifyProof(value); require("./certops-adcs-capacity").verifyProof(capacity);
  assert.equal(value.priorEnrollmentId, capacity.enrollmentIds[1]); assert.equal(value.priorJobId, capacity.jobIds[1]); assert.equal(value.priorRequestId, capacity.requestIds[1]); assert.equal(value.fingerprint, capacity.fingerprints[1]); return true;
}
function canWithdrawRequested(row, jobId) {
  return !!row && row.current_job_id === jobId && row.state === "requested" && row.job_status === "pending_approval" && row.claim_id === null && row.claimed_by_agent_id === null && row.attempt_count === 0 && row.request_id === null;
}
function assertUnclaimedCancelled(row, jobId) {
  assert.equal(row.current_job_id, jobId); assert.equal(row.state, "cancelled"); assert.equal(row.job_status, "cancelled"); assert.equal(row.claim_id, null); assert.equal(row.claimed_by_agent_id, null); assert.equal(row.attempt_count, 0); assert.equal(row.request_id, null); assert.equal(row.next_poll_at, null);
}
function createBrowserCancelActor(context) {
  const { gate, fixture, api, configDir, command, ps, until, ownedEnrollmentIds, tlsAuthority } = context, root = path.resolve(__dirname, "../../..");
  let used = false;
  return { async cancelRenewal({ issuerId, item, authority, priorCompleted }) {
    assert.equal(used, false); used = true;
    assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
    assert.match(issuerId, UUID); assert.match(item.certificateId, UUID); assert.match(item.domain, /^certops-adcs-[a-f0-9]{10}-capacity[0-5]\.example\.test$/); assert.match(item.site, /^TTAdcsCapacity[a-f0-9]{10}[0-5]$/); assert.ok(Number.isInteger(item.port) && item.port > 1024 && item.port < 65536);
    assert.equal(priorCompleted.enrollmentId, item.enrollmentId); assert.equal(priorCompleted.jobId, item.jobId); assert.equal(item.cleanup.store, "My"); assert.equal(item.cleanup.certificateId, item.certificateId); assert.equal(item.cleanup.domain, item.domain);
    gate.report.fixtureSources ??= [];
    for (const file of REQUIRED_SOURCES) { const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex"), prior = gate.report.fixtureSources.filter(row => row.file === file); if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, sha256); } else gate.report.fixtureSources.push({ file, sha256 }); }
    const query = (sql, values = []) => fixture.pool.query(sql, values);
    const state = async id => (await query("SELECT e.id,e.state,e.current_job_id,e.request_id,e.next_poll_at,j.status AS job_status,j.claim_id,j.claimed_by_agent_id,j.attempt_count FROM certificate_enrollments e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id WHERE e.workspace_id=$1 AND e.id=$2", [fixture.workspaceId, id])).rows[0];
    const inFlight = async () => (await query("SELECT count(*)::int AS count FROM certificate_jobs j JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.current_job_id=j.id WHERE j.workspace_id=$1 AND e.issuer_id=$2 AND j.operation=ANY($3::text[]) AND NOT(j.status=ANY($4::text[]))", [fixture.workspaceId, issuerId, ["issue", "renew"], [...TERMINAL_JOB_STATUSES]])).rows[0].count;
    const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: item.port, servername: item.domain, ca: tlsAuthority(authority), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); const leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw); assert.equal(leaf.checkHost(item.domain), item.domain); resolve(leaf); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Cancel-preservation trusted TLS timed out"))); });
    const leaf = await peer(), fingerprint = leaf.fingerprint256.replace(/:/g, "").toLowerCase(), thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase(); assert.equal(fingerprint, priorCompleted.fingerprint);
    const native = () => ps(`Import-Module WebAdministration;$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k-or$k.Key.Provider.Provider-ne'Microsoft Software Key Storage Provider'-or!$k.Key.IsMachineKey-or[int]$k.Key.ExportPolicy-ne 0-or$k.KeySize-ne 2048){throw 'Prior protected machine key required'};$b=@(Get-WebBinding -Name '${item.site}' -Protocol https|Where-Object bindingInformation -eq '*:${item.port}:${item.domain}');$h=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${item.port}'});if($b.Count-ne 1-or$h.Count-ne 1){throw 'Exact prior native binding required'};@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;der=[Convert]::ToBase64String($c.RawData);store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags;httpStore=[string]$h[0].GetValue('SslCertStoreName');hash=[BitConverter]::ToString([byte[]]$h[0].GetValue('SslCertHash')).Replace('-','')}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`);
    const parsed = JSON.parse(native()); assert.equal(parsed.container, buildEnrollmentContainerName(item.enrollmentId)); assert.equal(parsed.der, leaf.raw.toString("base64")); assert.equal(parsed.store, "My"); assert.equal(parsed.httpStore, "My"); assert.equal(parsed.flags, 1); assert.equal(parsed.hash, thumb);
    const ca = () => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", item.domain, "-FingerprintSha256", fingerprint]));
    const priorCa = ca(); assert.equal(priorCa.subjectRequestCount, 1); assert.equal(String(priorCa.requestId), priorCompleted.requestId);
    const priorState = await state(item.enrollmentId); assert.equal(priorState.state, "installed"); assert.equal(priorState.job_status, "succeeded"); assert.equal(priorState.current_job_id, item.jobId); assert.equal(await inFlight(), 4);
    assert.equal((await fixture.request(`${api}/settings`)).body.certOpsRequireApprovalAlways, true);
    let created, primary;
    try {
      await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
        const response = await fixture.request(`${api}/enrollments`, "POST", { issuerId, certificateId: item.certificateId, agentId: context.agentRowId, target: { type: "windows-iis", reference: item.domain, store: "My", binding: { site: item.site, port: item.port, sniHost: item.domain } }, authorizedDnsNames: [item.domain], keyAlgorithm: "rsa", keySize: 2048 });
        assert.equal(response.status, 201); created = { enrollmentId: response.body.enrollmentId, jobId: response.body.jobId }; assert.match(created.enrollmentId, UUID); assert.match(created.jobId, UUID);
        // Register before any further assertion, so a partial failure preserves
        // the parent's exact new enrollment/key cleanup ownership.
        ownedEnrollmentIds.push(created.enrollmentId); item.cleanup.enrollmentIds.push(created.enrollmentId); item.cleanup.guiCancelPendingVerification = true;
        const pending = await state(created.enrollmentId); assert.equal(pending.state, "requested"); assert.equal(pending.job_status, "pending_approval"); assert.equal(pending.current_job_id, created.jobId); assert.equal(pending.claim_id, null); assert.equal(pending.claimed_by_agent_id, null); assert.equal(pending.attempt_count, 0); assert.equal(pending.request_id, null); assert.equal(await inFlight(), 5);
        assert.equal(readEnrollmentJournal(configDir, created.enrollmentId).kind, "not_found");
        const absent = ps(`[Security.Cryptography.CngKey]::Exists('${buildEnrollmentContainerName(created.enrollmentId)}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`); assert.equal(absent, "False");
        await session.withOwnedAdcsBrowserPage(context, async (page, { origin }) => {
          const button = page.getByRole("button", { name: `Cancel enrollment ${created.enrollmentId.slice(0, 8)}`, exact: true }); await button.waitFor(); assert.equal(await button.count(), 1);
          let writes = 0, wrong = false; const expected = { origin, workspaceId: fixture.workspaceId, enrollmentId: created.enrollmentId };
          page.on("request", request => { const url = new URL(request.url()); if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method()) && /^\/api\/v1\/workspaces\/[^/]+\/certops(?:\/|$)/.test(url.pathname)) { writes++; try { verifyRequest(request, expected); } catch { wrong = true; } } });
          const endpoint = `${api}/enrollments/${created.enrollmentId}/cancel`;
          const [cancelled] = await Promise.all([page.waitForResponse(response => response.request().method() === "POST" && new URL(response.url()).origin === origin && new URL(response.url()).pathname === endpoint), button.click()]);
          assert.equal(cancelled.status(), 204); verifyRequest(cancelled.request(), expected); await button.waitFor({ state: "detached" }); assert.equal(writes, 1); assert.equal(wrong, false);
        });
      }, { evidenceLevel: "real-host", oracle: "One additional sequential public renewal remains requested/pending approval and never claimed; actual dashboard Cancel sends exactly one bodyless own-origin request acknowledged204; owned browser/trust drain" });
      await gate.scenario(REQUIRED_SCENARIOS[1], async () => {
        const cancelled = await until(async () => { const value = await state(created.enrollmentId); return value?.state === "cancelled" && value.job_status === "cancelled" ? value : null; });
        assert.equal(cancelled.current_job_id, created.jobId); assert.equal(cancelled.claim_id, null); assert.equal(cancelled.claimed_by_agent_id, null); assert.equal(cancelled.attempt_count, 0); assert.equal(cancelled.request_id, null); assert.equal(cancelled.next_poll_at, null);
        assert.equal(readEnrollmentJournal(configDir, created.enrollmentId).kind, "not_found"); assert.equal(ps(`[Security.Cryptography.CngKey]::Exists('${buildEnrollmentContainerName(created.enrollmentId)}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`), "False");
        assert.ok(isDeepStrictEqual(await state(item.enrollmentId), priorState), "Prior installed enrollment/job changed"); assert.ok(isDeepStrictEqual(JSON.parse(native()), parsed), "Prior native custody or binding changed"); assert.equal((await peer()).fingerprint256.replace(/:/g, "").toLowerCase(), fingerprint);
        const afterCa = ca(); assert.equal(afterCa.subjectRequestCount, priorCa.subjectRequestCount); assert.equal(String(afterCa.requestId), priorCompleted.requestId); assert.equal(await inFlight(), 4);
        const audit = (await query("SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ENROLLMENT_CANCELLED' AND metadata->>'enrollmentId'=$2", [fixture.workspaceId, created.enrollmentId])).rows; assert.equal(audit.length, 1); assert.equal(String(audit[0].actor_user_id), String(fixture.userId));
        const proof = { scope: SCOPE, ...created, priorEnrollmentId: item.enrollmentId, priorJobId: item.jobId, priorRequestId: priorCompleted.requestId, fingerprint, cancelPosts: 1, otherMutations: 0, capacityBeforeCancel: 5, capacityAfterCancel: 4, initialSixConcurrencyQualified: false, caSubmissionCancellationQualified: false, ...Object.fromEntries(FLAGS.map(flag => [flag, true])) }; verifyProof(proof); gate.report.nativeBrowserCancel = proof; item.cleanup.guiCancelPendingVerification = false;
      }, { evidenceLevel: "real-host", oracle: "Only the never-claimed new job/enrollment cancels; prior accepted CA leaf, protected machine key, IIS/SNI/trusted TLS and old installed row remain; exact new key/journal absent, one human audit and issuer capacity falls5to4" });
    } catch (error) { primary = error; }
    finally {
      if (primary && created) {
        try {
          const row = await state(created.enrollmentId);
          if (canWithdrawRequested(row, created.jobId)) assert.equal((await fixture.request(`${api}/enrollments/${created.enrollmentId}/cancel`, "POST", {})).status, 204);
          // Unknown, claimed or active work never authorizes withdrawal or native
          // cleanup. A failed GUI qualification remains failed after safe fallback.
          const cancelled = await state(created.enrollmentId); assertUnclaimedCancelled(cancelled, created.jobId);
          assert.equal(readEnrollmentJournal(configDir, created.enrollmentId).kind, "not_found");
          assert.equal(ps(`[Security.Cryptography.CngKey]::Exists('${buildEnrollmentContainerName(created.enrollmentId)}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`), "False");
          item.cleanup.guiCancelPendingVerification = false;
        }
        catch (error) { throw new AggregateError([primary, error], "GUI Cancel failed and owned pending withdrawal remains unresolved"); }
      }
    }
    if (primary) throw primary; return gate.report.nativeBrowserCancel;
  } };
}
module.exports = { REQUIRED_SCENARIOS, REQUIRED_SOURCES, FLAGS, SCOPE, verifyRequest, verifyProof, verifyCrossProof, canWithdrawRequested, createBrowserCancelActor };
