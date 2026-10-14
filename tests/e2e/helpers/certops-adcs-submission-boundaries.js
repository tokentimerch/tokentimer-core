"use strict";
/* Initial native RPC-unreachable and issued-template mismatch cases with scoped owned faults,
 * genuine CA observations and original CSR/key/TLS preservation. Called only by the protected
 * disposable-forest AD CS harness; native qualification requires that workflow to execute.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const tls = require("node:tls");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { readCertificateTemplateOid } = require("../../../packages/agent/src/issuers/der-extensions");

async function qualifySubmissionBoundaries(context) {
  const { gate, fixture, api, agentRowId, configDir, workDir, run, preflight, ps, command, until, jobFinished, ownedSites, ownedCertificateIds, ownedEnrollmentIds, ownedThumbprints, ownedFirewallRules, pendingRecoveryFixtures, tlsAuthority } = context;
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
  const getEnrollment = async id => (await fixture.pool.query("SELECT state,request_id,next_poll_at,last_error_code FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const count = domain => Number(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/ca-safety-flags.ps1"), "-Action", "request-count", "-RunId", run, "-CommonName", domain]));
  const served = (port, domain, authority) => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: tlsAuthority(authority), rejectUnauthorized: true }, () => {
      try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); }
      catch (error) { reject(error); } finally { socket.destroy(); }
    });
    socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("AD CS boundary trusted TLS oracle timed out")));
  });
  await gate.scenario("adcs-real-initial-certreq-rpc-unreachable-retries-same-csr-key", async () => {
    const domain = `certops-adcs-${run}-transport.example.test`; const site = `TTADCS-${run}-transport`;
    const port = await new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(error => error ? reject(error) : resolve(port)); }); });
    const directory = path.join(workDir, "transport"); fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, "index.html"), "Native submit transport boundary");
    const { issuerId, result } = await preflight("TTQualificationRSAShort"); const authority = result.caCertificates[0];
    assert.equal(result.templateCheck.verdict, "safe"); assert.equal(result.caCheck.verdict, "safe");
    assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: authority.keySha256, caConfig: "tt-ca.lab.certops.test\\TTQualificationRoot", template: "TTQualificationRSAShort" })).status, 200);
    ownedSites.push(site); ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1`);
    const rule = `TTQualification-Certreq-${run}-${crypto.randomBytes(4).toString("hex")}`;
    ps(`if(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue){throw 'Refusing existing transport fault rule'};if(@(Get-NetFirewallProfile|Where-Object Enabled -ne True).Count){throw 'Native firewall profiles must enforce the scoped transport fault'}`);
    const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId); let created, prepared; let primaryError, cleanupError;
    ownedFirewallRules.push(rule);
    try {
      ps(`New-NetFirewallRule -Name '${rule}' -DisplayName '${rule}' -Group '${rule}' -Direction Outbound -Action Block -Enabled True -Profile Any -Program "$env:SystemRoot\\System32\\certreq.exe" -RemoteAddress '10.64.0.4'|Out-Null;$r=Get-NetFirewallRule -Name '${rule}';$p=$r|Get-NetFirewallApplicationFilter;$a=$r|Get-NetFirewallAddressFilter;if($r.Action -ne 'Block' -or $r.Direction -ne 'Outbound' -or $r.Enabled -ne 'True' -or $p.Program -ine "$env:SystemRoot\\System32\\certreq.exe" -or @($a.RemoteAddress).Count -ne 1 -or [string]$a.RemoteAddress[0] -ne '10.64.0.4'){throw 'Actual native transport rule did not match required scope'}`);
      assert.equal(count(domain), 0);
      created = await fixture.request(`${api}/enrollments`, "POST", { issuerId, certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: domain, store: "My", binding: { site, port, sniHost: domain } }, authorizedDnsNames: [domain], keyAlgorithm: "rsa", keySize: 2048 }); assert.equal(created.status, 201); ownedEnrollmentIds.push(created.body.enrollmentId);
      await until(async () => { const job = (await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, created.body.jobId])).rows[0]; if (["succeeded", "rejected"].includes(job?.status)) throw new Error("Actual submit fault did not exercise the proven no-submit retry outcome"); return job?.status === "failed"; });
      const row = await getEnrollment(created.body.enrollmentId); assert.equal(row.state, "submitting"); assert.equal(row.last_error_code, "ADCS_CA_UNREACHABLE"); assert.equal(row.request_id, null); assert.ok(row.next_poll_at);
      prepared = readEnrollmentJournal(configDir, created.body.enrollmentId); assert.equal(prepared.kind, "valid"); assert.equal(prepared.journal.state, "prepared"); assert.ok(prepared.artifacts.csrPem?.includes("BEGIN CERTIFICATE REQUEST")); assert.equal(prepared.artifacts.leafPem, null); assert.equal(prepared.artifacts.chainPem, null);
      assert.equal(count(domain), 0, "Independent CA database must prove the request was never committed");
      assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(prepared.journal.containerName));
      assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq 'CN=${domain}').Count`), "0");
    } catch (error) { primaryError = error; }
    finally {
      try { ps(`$r=Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue;if($r){if($r.DisplayName -ne '${rule}' -or $r.Group -ne '${rule}'){throw 'Refusing foreign transport rule'};Remove-NetFirewallRule -Name '${rule}'};if(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue){throw 'Owned transport rule remains'}`); } catch (error) { cleanupError = error; }
    }
    if (primaryError && cleanupError) throw new AggregateError([primaryError, cleanupError], "Native submit fault and owned firewall cleanup failed"); if (cleanupError) throw cleanupError; if (primaryError) throw primaryError;
    const row = await getEnrollment(created.body.enrollmentId);
    const resumed = (await scheduler.scheduleDueEnrollments({ client: fixture.pool, now: new Date(new Date(row.next_poll_at).getTime() + 1000) })).find(entry => entry.enrollmentId === created.body.enrollmentId); assert.ok(resumed); await jobFinished(resumed.jobId);
    assert.equal((await getEnrollment(created.body.enrollmentId)).state, "installed"); assert.equal(count(domain), 1);
    const journal = readEnrollmentJournal(configDir, created.body.enrollmentId); assert.equal(journal.kind, "valid"); assert.equal(journal.journal.state, "installed");
    for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256"]) assert.equal(journal.journal[field], prepared.journal[field]);
    const leaf = await served(port, domain, authority); assert.equal(leaf.checkHost(domain), domain); ownedThumbprints.add(leaf.fingerprint.replace(/:/g, ""));
    assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"), prepared.journal.csrSpkiSha256);
    const nativeRequest = JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", domain, "-FingerprintSha256", leaf.fingerprint256.replace(/:/g, "").toLowerCase()])); assert.equal(nativeRequest.subjectRequestCount, 1); assert.equal(nativeRequest.disposition, 20);
    assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${leaf.fingerprint.replace(/:/g, "")}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($k.Key.KeyName -ne '${prepared.journal.containerName}' -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Transport retry changed or exposed its original native key'};'same-nonexportable-cng'}finally{if($k){$k.Dispose()};$c.Dispose()}`), "same-nonexportable-cng");
    gate.report.initialSubmitFault = { caRequestId: String(nativeRequest.requestId), fault: "native-certreq-executable-outbound-RPC-block", caBeforeAndDuringRequestCount: 0, caAfterRecoveryRequestCount: 1, nativeJournalPrepared: true, csrAndKeyPreserved: true, supportedSchedulerEligibilityInput: true, syntheticCaOutcome: false, trustedRecoveredTls: true };
  }, { evidenceLevel: "real-host", oracle: "actual scoped certreq RPC block, real unreachable HRESULT classification/prepared CSR/no response artifacts plus independent zero CA requests, native restored retry exactly once with same protected CSR/key and trusted IIS TLS" });

  await gate.scenario("adcs-real-issued-template-mismatch-refuses-installation", async () => {
    const owned = pendingRecoveryFixtures.cancel; assert.ok(owned); const previous = await served(owned.port, owned.item.domain, owned.authority);
    const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    const created = await fixture.request(`${api}/enrollments`, "POST", { issuerId: owned.issuerId, certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: owned.item.domain, store: "My", binding: { site: owned.site, port: owned.port, sniHost: owned.item.domain } }, authorizedDnsNames: [owned.item.domain], keyAlgorithm: "rsa", keySize: 2048 }); assert.equal(created.status, 201);
    const id = created.body.enrollmentId; ownedEnrollmentIds.push(id); let requestId; let primaryError, cleanupError;
    const nativeDisposition = () => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/owned-request-observation.ps1"), "-CommonName", owned.item.domain, "-RequestId", String(requestId)]));
    try {
      const pending = await until(async () => { const row = await getEnrollment(id); return row?.state === "pending_issuance" && row.request_id ? row : null; }); requestId = pending.request_id;
      const original = readEnrollmentJournal(configDir, id); assert.equal(original.kind, "valid"); assert.equal(nativeDisposition().disposition, 9);
      const fault = JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/issued-template-fault.ps1"), "-CommonName", owned.item.domain, "-RequestId", String(requestId), "-RunId", run, "-FrozenTemplateOid", original.journal.templateOid])); assert.notEqual(fault.issuedTemplateOid, original.journal.templateOid);
      command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/officer-action.ps1"), "-RequestId", String(requestId), "-Action", "approve", "-CommonName", owned.item.domain]);
      const native = JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/owned-ca-request-certificate.ps1"), "-CommonName", owned.item.domain, "-RequestId", String(requestId)]));
      const leaf = new crypto.X509Certificate(Buffer.from(native.certificateB64, "base64")); assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(owned.authority.certificateB64, "base64")).publicKey), true); assert.equal(leaf.checkHost(owned.item.domain), owned.item.domain);
      assert.equal(readCertificateTemplateOid(leaf.raw), fault.issuedTemplateOid, "Fault must produce a genuinely CA-signed leaf under the wrong template"); assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"), original.journal.csrSpkiSha256);
      const continuation = (await scheduler.scheduleDueEnrollments({ client: fixture.pool, now: new Date(new Date(pending.next_poll_at).getTime() + 1000) })).find(row => row.enrollmentId === id); assert.ok(continuation);
      const failed = await until(async () => { const job = (await fixture.pool.query("SELECT status,error_message FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, continuation.jobId])).rows[0]; if (job?.status === "succeeded") throw new Error("Wrong-template issued material was installed"); return job?.status === "failed" ? job : null; }); assert.match(failed.error_message, /template OID/i);
      assert.equal((await getEnrollment(id)).state, "rejected_invalid"); assert.equal(ps(`[bool](Test-Path 'Cert:\\LocalMachine\\My\\${leaf.fingerprint.replace(/:/g, "")}')`), "False");
      assert.equal((await served(owned.port, owned.item.domain, owned.authority)).fingerprint256, previous.fingerprint256);
      gate.report.templateMismatch = { caRequestId: String(requestId), frozenTemplateOid: original.journal.templateOid, actualIssuedTemplateOid: fault.issuedTemplateOid, actualCaSignature: true, frozenSpkiMatched: true, rejectedBeforeAccept: true, previousTrustedBindingPreserved: true };
    } catch (error) { primaryError = error; }
    finally {
      if (requestId) try { const native = nativeDisposition(); const action = native.disposition === 9 ? "deny" : native.disposition === 20 ? "revoke" : null; if (action) command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/officer-action.ps1"), "-RequestId", String(requestId), "-Action", action, "-CommonName", owned.item.domain]); } catch (error) { cleanupError = error; }
    }
    if (primaryError && cleanupError) throw new AggregateError([primaryError, cleanupError], "Native wrong-template refusal and owned request cleanup failed"); if (cleanupError) throw cleanupError; if (primaryError) throw primaryError;
  }, { evidenceLevel: "real-host", oracle: "native officer changes only an owned pending request to another real safe template, actual CA-issued signed leaf/SPKI/template inspected independently, frozen-template validator refuses before accept while prior trusted IIS binding survives" });
}
module.exports = { qualifySubmissionBoundaries };
