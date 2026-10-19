"use strict";
/* Actual per-key-profile AD CS renewals through public jobs and installed SYSTEM agent;
 * independent CA request, nonexportable CNG and trusted IIS TLS observations prove key
 * continuity. Called only by the protected disposable-forest AD CS harness; native qualification
 * requires that workflow to execute.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const tls = require("node:tls");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");

async function qualifyPositiveRenewals({ gate, fixture, api, agentRowId, issuedFixtures, ownedEnrollmentIds, ownedThumbprints, jobFinished, ps, command, tlsAuthority }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  for (const original of issuedFixtures.filter(row => row.item.id !== "rsa2048")) await gate.scenario(`adcs-real-${original.item.id}-renewed-cng-iis`, async () => {
    const { item, issuerId, authority, site, port, certificateId, observed, requestId } = original;
    const response = await fixture.request(`${api}/enrollments`, "POST", { issuerId, certificateId, agentId: agentRowId,
      target: { type: "windows-iis", reference: item.domain, store: "My", binding: { site, port, sniHost: item.domain } },
      authorizedDnsNames: [item.domain], keyAlgorithm: item.algorithm, keySize: item.size });
    assert.equal(response.status, 201); const enrollmentId = response.body.enrollmentId; ownedEnrollmentIds.push(enrollmentId);
    assert.notEqual(enrollmentId, original.enrollmentId); await jobFinished(response.body.jobId);
    const row = (await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, enrollmentId])).rows[0];
    assert.equal(row.state, "installed");
    const leaf = await new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port, servername: item.domain, ca: tlsAuthority(authority), rejectUnauthorized: true }, () => {
        try { assert.equal(socket.authorized, true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); }
        catch (error) { reject(error); } finally { socket.destroy(); }
      });
      socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Trusted AD CS profile renewal TLS oracle timed out")));
    });
    const native = JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname, "../../../infra/certops-adcs/owned-issued-request.ps1"), "-CommonName", item.domain, "-FingerprintSha256", leaf.fingerprint256.replace(/:/g, "").toLowerCase()]));
    assert.equal(native.disposition, 20); assert.equal(native.subjectRequestCount, 2, "One issuance and one renewal must create exactly two real owned CA requests"); assert.notEqual(String(native.requestId), String(requestId)); if (row.request_id != null) assert.equal(String(row.request_id), String(native.requestId));
    assert.equal(leaf.checkHost(item.domain), item.domain); assert.notEqual(leaf.fingerprint256, observed.fingerprint256); assert.notEqual(leaf.serialNumber, observed.serialNumber);
    assert.notDeepEqual(leaf.publicKey.export({ type: "spki", format: "der" }), observed.publicKey.export({ type: "spki", format: "der" }));
    assert.equal(leaf.publicKey.asymmetricKeyType, item.algorithm === "rsa" ? "rsa" : "ec");
    if (item.algorithm === "rsa") assert.equal(leaf.publicKey.asymmetricKeyDetails.modulusLength, item.size);
    else assert.equal(leaf.publicKey.asymmetricKeyDetails.namedCurve, item.size === 256 ? "prime256v1" : "secp384r1");
    const thumbprint = leaf.fingerprint.replace(/:/g, ""); ownedThumbprints.add(thumbprint);
    const getter = item.algorithm === "rsa" ? "[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)" : "[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)";
    const custody = JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;try{$k=${getter};[pscustomobject]@{name=$k.Key.KeyName;bits=$k.KeySize;exportPolicy=[string]$k.Key.ExportPolicy}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
    assert.equal(custody.name, buildEnrollmentContainerName(enrollmentId)); assert.equal(custody.bits, item.size); assert.equal(custody.exportPolicy, "None");
    assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, response.body.jobId])).rows.length);
    gate.report.nativeRenewals ??= [];
    gate.report.nativeRenewals.push({ scenario: `adcs-real-${item.id}-renewed-cng-iis`, template: item.template, templateSchema: item.schema, keyAlgorithm: item.algorithm, keySize: item.size, previousRequestId: String(requestId), requestId: String(native.requestId), requestIdSource: "native-CA-exact-leaf-fingerprint", fingerprintSha256: leaf.fingerprint256.replace(/:/g, "").toLowerCase(), trustedReplacementTls: true, nativeExportPolicy: custody.exportPolicy, renewalProtocol: "new-enrollment-for-existing-managed-certificate" });
  }, { evidenceLevel: "real-host", oracle: "public native AD CS renewal for existing identity, exactly two actual CA requests, changed serial/SPKI/fingerprint, exact nonexportable replacement CNG key and independently trusted IIS TLS" });
}
module.exports = { qualifyPositiveRenewals };
