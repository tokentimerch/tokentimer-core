"use strict";
/* Actual owned CA service outage during pending continuation. Snapshots service state, restores
 * it in finally and proves the same request/key resumes without issuing a replacement request.
 * Called only by the protected disposable-forest AD CS harness; native qualification requires
 * that workflow to execute.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const tls = require("node:tls");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");

async function qualifyCaOutage({ gate, fixture, api, agentRowId, configDir, run, ps, command, until, jobFinished, ownedCertificateIds, ownedEnrollmentIds, ownedThumbprints, pendingRecoveryFixtures, tlsAuthority, ownedCaServiceFaults }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const owned = pendingRecoveryFixtures.cancel; assert.ok(owned);
  const nativeAction = action => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/ca-service-outage.ps1"), "-Action", action, "-RunId", run]));
  const observe = requestId => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/owned-request-observation.ps1"), "-CommonName", owned.item.domain, "-RequestId", String(requestId)]));
  const enrollment = async id => (await fixture.pool.query("SELECT state,request_id,next_poll_at FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const served = () => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port: owned.port, servername: owned.item.domain, ca: tlsAuthority(owned.authority), rejectUnauthorized: true }, () => {
      try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); }
      catch (error) { reject(error); } finally { socket.destroy(); }
    });
    socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("CA outage trusted IIS oracle timed out")));
  });
  await gate.scenario("adcs-real-pending-ca-service-outage-recovers-same-request", async () => {
    // The preceding audited installation retry left this exact owned site
    // serving a real accepted certificate. A new pending enrollment must not
    // disturb that still-working binding when the CA becomes unavailable.
    const previousLeaf = await served();
    const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    const created = await fixture.request(`${api}/enrollments`, "POST", { issuerId: owned.issuerId, certificateId, agentId: agentRowId,
      target: { type: "windows-iis", reference: owned.item.domain, store: "My", binding: { site: owned.site, port: owned.port, sniHost: owned.item.domain } },
      authorizedDnsNames: [owned.item.domain], keyAlgorithm: "rsa", keySize: 2048 }); assert.equal(created.status, 201);
    const id = created.body.enrollmentId; ownedEnrollmentIds.push(id);
    const pending = await until(async () => { const row = await enrollment(id); return row?.state === "pending_issuance" && row.request_id ? row : null; });
    const original = readEnrollmentJournal(configDir, id); assert.equal(original.kind, "valid");
    const nativeBefore = observe(pending.request_id); assert.equal(nativeBefore.disposition, 9);
    const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
    let faultMayExist = false; let primaryError; let restoreError;
    try {
      faultMayExist = true; ownedCaServiceFaults.add(run);
      const stopped = nativeAction("stop"); assert.equal(stopped.status, "Stopped"); assert.equal(stopped.snapshotPresent, true);
      assert.equal(nativeAction("status").status, "Stopped");
      const continuation = (await scheduler.scheduleDueEnrollments({ client: fixture.pool, now: new Date(new Date(pending.next_poll_at).getTime() + 1000) })).find(row => row.enrollmentId === id); assert.ok(continuation);
      await until(async () => { const job = (await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, continuation.jobId])).rows[0]; if (["succeeded", "rejected"].includes(job?.status)) throw new Error("Unavailable native CA unexpectedly completed or refused a known pending request"); return job?.status === "failed"; });
      const retained = await enrollment(id); assert.equal(retained.state, "pending_issuance"); assert.equal(String(retained.request_id), String(pending.request_id)); assert.ok(Number.isFinite(new Date(retained.next_poll_at).getTime()));
      const journal = readEnrollmentJournal(configDir, id); assert.equal(journal.kind, "valid");
      for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256", "requestId"]) assert.equal(journal.journal[field], original.journal[field]);
      assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(original.journal.containerName));
      assert.equal((await served()).fingerprint256, previousLeaf.fingerprint256);
    } catch (error) { primaryError = error; }
    finally {
      if (faultMayExist) try { const restored = nativeAction("restore"); assert.equal(restored.status, "Running"); assert.equal(restored.snapshotPresent, false); ownedCaServiceFaults.delete(run); } catch (error) { restoreError = error; }
    }
    if (primaryError && restoreError) throw new AggregateError([primaryError, restoreError], "Native CA outage and owned service restoration failed");
    if (restoreError) throw restoreError;
    if (primaryError) throw primaryError;
    assert.deepEqual(observe(pending.request_id), nativeBefore, "Outage must not duplicate or mutate the actual pending CA request");
    command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/officer-action.ps1"), "-RequestId", String(pending.request_id), "-Action", "approve", "-CommonName", owned.item.domain]);
    const retained = await enrollment(id);
    const resumed = (await scheduler.scheduleDueEnrollments({ client: fixture.pool, now: new Date(new Date(retained.next_poll_at).getTime() + 1000) })).find(row => row.enrollmentId === id); assert.ok(resumed);
    await jobFinished(resumed.jobId); assert.equal((await enrollment(id)).state, "installed");
    const finalNative = observe(pending.request_id); assert.equal(finalNative.disposition, 20); assert.equal(finalNative.subjectRequestCount, nativeBefore.subjectRequestCount);
    const finalJournal = readEnrollmentJournal(configDir, id); assert.equal(finalJournal.kind, "valid"); assert.equal(finalJournal.journal.state, "installed");
    for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256", "requestId"]) assert.equal(finalJournal.journal[field], original.journal[field]);
    const leaf = await served(); assert.equal(leaf.checkHost(owned.item.domain), owned.item.domain); assert.notEqual(leaf.fingerprint256, previousLeaf.fingerprint256); ownedThumbprints.add(leaf.fingerprint.replace(/:/g, ""));
    assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${leaf.fingerprint.replace(/:/g, "")}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($k.Key.KeyName -ne '${original.journal.containerName}' -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'CA recovery changed or exposed the retained native key'};'same-nonexportable-cng'}finally{if($k){$k.Dispose()};$c.Dispose()}`), "same-nonexportable-cng");
    gate.report.caOutage = { fault: "actual-owned-CertSvc-stop", phase: "known-pending-retrieve", requestId: String(pending.request_id), requestCountUnchanged: true, protectedKeyPreserved: true, previousBindingPreserved: true, restoredCaService: true, trustedRecoveredTls: true, syntheticSubmitClassification: false };
  }, { evidenceLevel: "real-host", oracle: "actual isolated CA service/RPC outage during known pending retrieval, unchanged request/CSR/key and old trusted IIS binding, real service restoration and officer approval followed by same-key native install" });
}
module.exports = { qualifyCaOutage };
