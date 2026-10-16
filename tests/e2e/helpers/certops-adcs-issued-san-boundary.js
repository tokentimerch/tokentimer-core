"use strict";
/** Actual CA-issued wrong-SAN refusal, using an already installed matching
 * issuer/template control. Source only until protected forest execution.
 * The parent must register unaccepted custody before dispatch and preserve
 * all state until exact stopped-service key cleanup has succeeded. */
const assert = require("node:assert/strict"), crypto = require("node:crypto"), path = require("node:path"), tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const fs = require("node:fs");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { readCertificateTemplateOid } = require("../../../packages/agent/src/issuers/der-extensions");
const { parseDnsSans } = require("../../../packages/agent/src/issuers/issued-certificate-validation");
const SCOPE = "actual-ca-issued-owned-wrong-san-refused-before-accept";
const REQUIRED_SCENARIOS = Object.freeze(["adcs-real-issued-wrong-san-preserves-predecessor"]);
const FLAGS = Object.freeze(["matchingNativePositiveControl", "actualOwnedPendingCaMutation", "actualCaSignature", "sameRequestCsrSpkiAndTemplate", "exactUnauthorizedDnsSan", "productionSignedContinuationRefused", "rejectedBeforeCertificateAccept", "predecessorBindingTlsAndCngUnchanged", "unacceptedKeyRemovedAndJournalPreserved", "noCaResubmission", "ownedCaRequestRevoked", "cleanupOwnershipRegistered"]);
const REQUIRED_SOURCES = Object.freeze(["tests/e2e/helpers/certops-adcs-issued-san-boundary.js", "tests/e2e/helpers/certops-adcs-unaccepted-cleanup.js", "tests/e2e/helpers/certops-adcs-native-cleanup-guard.js", "packages/agent/src/windows-key-survivors/index.js", "infra/certops-adcs/issued-san-fault.ps1", "infra/certops-adcs/owned-ca-request-certificate.ps1", "infra/certops-adcs/owned-request-observation.ps1", "infra/certops-adcs/officer-action.ps1", "packages/agent/src/adcs-windows-iis.js", "packages/agent/src/issuers/issued-certificate-validation.js", "packages/agent/src/issuers/adcs-enrollment-journal.js", "packages/agent/src/windows-cert-store/index.js", "apps/api/services/certops/certificateEnrollments.js"]);
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "requestId", "enrollmentId", "continuationJobId", "errorCode", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE); assert.equal(value.errorCode, "ADCS_CERTIFICATE_INVALID");
  assert.match(value.requestId, /^[1-9][0-9]{0,9}$/); assert.ok(Number(value.requestId) <= 0xffffffff);
  for (const key of ["enrollmentId", "continuationJobId"]) assert.match(value[key], /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag); return true;
}
function verifyIssuedLeaf({ native, authority, journal, domain, wrongDnsName }) {
  assert.equal(String(native.requestId), String(journal.requestId)); assert.equal(native.disposition, 20);
  const leaf = new crypto.X509Certificate(Buffer.from(native.certificateB64, "base64"));
  assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(authority.certificateB64, "base64")).publicKey), true);
  assert.equal(leaf.subject, `CN=${domain}`); assert.deepEqual(parseDnsSans(leaf.subjectAltName), [wrongDnsName]);
  assert.equal(leaf.checkHost(domain), undefined); assert.equal(leaf.checkHost(wrongDnsName), wrongDnsName);
  assert.equal(readCertificateTemplateOid(leaf.raw), journal.templateOid);
  assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"), journal.csrSpkiSha256);
  return leaf;
}
async function qualifyIssuedSanBoundary(context) {
  const { gate, fixture, api, agentRowId, configDir, run, pendingRecoveryFixtures, command, ps, until, tlsAuthority, ownedCertificateIds, ownedEnrollmentIds, registerOwnedUnacceptedEnrollment } = context;
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1"); assert.match(run, /^[a-f0-9]{10}$/);
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) { const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../..", file))).digest("hex"), prior = gate.report.fixtureSources.filter(item => item.file === file); if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, sha256); } else gate.report.fixtureSources.push({ file, sha256 }); }
  assert.equal(typeof registerOwnedUnacceptedEnrollment, "function", "Parent must guard cleanup custody before public dispatch");
  const owned = pendingRecoveryFixtures.cancel; assert.ok(owned);
  assert.equal(owned.site, `TTADCS-${run}-cancel`); assert.ok(Number.isInteger(owned.port) && owned.port > 0 && owned.port <= 65535);
  const domain = owned.item.domain; assert.match(domain, new RegExp(`^certops-adcs-${run}-[a-z0-9]+\\.example\\.test$`));
  const wrongDnsName = `certops-adcs-${run}-wrongsan.example.test`;
  const invoke = (file, args) => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/", file), ...args]));
  const served = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: owned.port, servername: domain, ca: tlsAuthority(owned.authority), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Owned SAN predecessor TLS timed out"))); });
  const row = async id => (await fixture.pool.query("SELECT state,request_id,next_poll_at,last_error_code FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const custody = (thumbprint, containerName) => JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($k.Key.KeyName -ne '${containerName}' -or $k.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or -not $k.Key.IsMachineKey -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Owned predecessor custody mismatch'};Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${owned.site}' -Protocol https|Where-Object bindingInformation -eq '*:${owned.port}:${domain}');if($b.Count -ne 1){throw 'Owned binding missing'};@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;hash=[string]$b[0].certificateHash;store=[string]$b[0].certificateStoreName;sslFlags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
  await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
    const previous = await served(); assert.equal(previous.checkHost(domain), domain); assert.equal(previous.verify(new crypto.X509Certificate(Buffer.from(owned.authority.certificateB64, "base64")).publicKey), true);
    const previousThumbprint = previous.fingerprint.replace(/:/g, "");
    const matches = ownedEnrollmentIds.map(id => readEnrollmentJournal(configDir, id)).filter(value => value.kind === "valid" && value.journal.state === "installed" && value.artifacts.leafPem && new crypto.X509Certificate(value.artifacts.leafPem).fingerprint256 === previous.fingerprint256);
    assert.equal(matches.length, 1, "Served positive control must match exactly one registered native installed journal"); const previousJournal = matches[0];
    const before = custody(previousThumbprint, previousJournal.journal.containerName);
    const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    const receipt = registerOwnedUnacceptedEnrollment({ certificateId, domain }); assert.ok(receipt && Array.isArray(receipt.enrollmentIds));
    let id, requestId, continuationJobId, primary, cleanup;
    try {
      const created = await fixture.request(`${api}/enrollments`, "POST", { issuerId: owned.issuerId, certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: domain, store: "My", binding: { site: owned.site, port: owned.port, sniHost: domain } }, authorizedDnsNames: [domain], keyAlgorithm: "rsa", keySize: 2048 });
      assert.equal(created.status, 201); id = created.body.enrollmentId; receipt.enrollmentIds.push(id); ownedEnrollmentIds.push(id);
      const pending = await until(async () => { const value = await row(id); return value?.state === "pending_issuance" && value.request_id ? value : null; }); requestId = String(pending.request_id);
      const original = readEnrollmentJournal(configDir, id); assert.equal(original.kind, "valid"); assert.equal(String(original.journal.requestId), requestId); assert.equal(original.journal.templateOid, previousJournal.journal.templateOid);
      const observe = () => invoke("owned-request-observation.ps1", ["-CommonName", domain, "-RequestId", requestId]); const initial = observe(); assert.equal(initial.disposition, 9);
      const csrDerSha256 = crypto.createHash("sha256").update(Buffer.from(original.artifacts.csrPem.replace(/-----[^-]+-----|\s/g, ""), "base64")).digest("hex");
      const fault = invoke("issued-san-fault.ps1", ["-RunId", run, "-CommonName", domain, "-RequestId", requestId, "-CsrDerSha256", csrDerSha256, "-TemplateOid", original.journal.templateOid]);
      assert.equal(fault.nativePendingOwnershipVerified, true); assert.equal(fault.wrongDnsName, wrongDnsName); assert.equal(String(fault.requestId), requestId); assert.equal(fault.csrDerSha256, csrDerSha256);
      command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/officer-action.ps1"), "-RequestId", requestId, "-Action", "approve", "-CommonName", domain]);
      const leaf = verifyIssuedLeaf({ native: invoke("owned-ca-request-certificate.ps1", ["-CommonName", domain, "-RequestId", requestId]), authority: owned.authority, journal: original.journal, domain, wrongDnsName });
      const scheduled = (await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({ client: fixture.pool, now: new Date(new Date(pending.next_poll_at).getTime() + 1000) })).find(item => item.enrollmentId === id); assert.ok(scheduled); continuationJobId = scheduled.jobId;
      await until(async () => { const job = (await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, continuationJobId])).rows[0]; assert.notEqual(job?.status, "succeeded"); return job?.status === "failed"; });
      const rejected = await until(async () => { const value = await row(id); return value?.state === "rejected_invalid" ? value : null; }); assert.equal(rejected.last_error_code, "ADCS_CERTIFICATE_INVALID");
      const after = readEnrollmentJournal(configDir, id); assert.equal(after.kind, "valid"); assert.equal(after.journal.state, "rejected_invalid"); assert.equal(after.journal.errorCode, "ADCS_CERTIFICATE_INVALID");
      for (const field of ["containerName", "csrSha256", "csrSpkiSha256", "snapshotSha256", "templateOid", "requestId"]) assert.ok(after.journal[field] === original.journal[field], "Rejected journal must preserve original public request and custody identity");
      assert.ok(isDeepStrictEqual(custody(previousThumbprint, previousJournal.journal.containerName), before), "Owned predecessor native custody and binding changed"); assert.equal((await served()).fingerprint256, previous.fingerprint256);
      assert.equal(ps(`$thumb='${leaf.fingerprint.replace(/:/g, "")}';@(foreach($store in @('My','WebHosting')){Get-ChildItem "Cert:\\LocalMachine\\$store"|Where-Object Thumbprint -eq $thumb}).Count`), "0");
      assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).split(/\r?\n/).map(value => value.trim()).includes(original.journal.containerName), "Exact invalid terminal key must be absent");
      assert.equal(observe().subjectRequestCount, initial.subjectRequestCount);
    } catch (error) { primary = error; }
    finally { if (requestId) try { const current = invoke("owned-request-observation.ps1", ["-CommonName", domain, "-RequestId", requestId]); const action = current.disposition === 9 ? "deny" : current.disposition === 20 ? "revoke" : null; if (action) command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/officer-action.ps1"), "-RequestId", requestId, "-Action", action, "-CommonName", domain]); const terminal = invoke("owned-request-observation.ps1", ["-CommonName", domain, "-RequestId", requestId]); assert.ok([21, 30, 31].includes(terminal.disposition), "Owned faulty CA request must be revoked or denied"); if (!primary) assert.equal(terminal.disposition, 21, "Successful wrong-SAN case must revoke its actual issued request"); } catch (error) { cleanup = error; } }
    if (primary && cleanup) throw new AggregateError([primary, cleanup], "Owned SAN refusal and CA cleanup failed"); if (primary) throw primary; if (cleanup) throw cleanup;
    const proof = { scope: SCOPE, requestId, enrollmentId: id, continuationJobId, errorCode: "ADCS_CERTIFICATE_INVALID", ...Object.fromEntries(FLAGS.map(flag => [flag, true])) }; verifyProof(proof); gate.report.nativeIssuedSanBoundary = proof;
  }, { evidenceLevel: "real-host", oracle: "actual CA-signed same-request/CSR/template wrong-SAN leaf refused by signed installed-agent continuation before accept; unchanged independently trusted predecessor and native protected custody, no CA resubmit; owned request revoked" });
}
module.exports = { SCOPE, FLAGS, REQUIRED_SCENARIOS, REQUIRED_SOURCES, verifyProof, verifyIssuedLeaf, qualifyIssuedSanBoundary };
