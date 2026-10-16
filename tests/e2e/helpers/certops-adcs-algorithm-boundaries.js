"use strict";
/** Four additional incompatible key/template controls in the disposable forest.
 * Reuses actual public enrollment and installed SYSTEM execution, but binds every
 * refusal to an already genuinely issued, actively served matching-template leaf.
 * No CA/template fault, acceptance, CNG export or private material is introduced.
 * Caller must run this before renewing the original positive fixture identities. */
const assert = require("node:assert/strict"), crypto = require("node:crypto"), fs = require("node:fs"), path = require("node:path"), tls = require("node:tls");
const { buildEnrollmentContainerName, readIssuedContainerRecord } = require("../../../packages/agent/src/windows-cert-store");
const CASES = Object.freeze([
  { id: "rsa2048-below-template3072", template: "TTQualificationRSA3072", algorithm: "rsa", size: 2048, schema: 2, minimum: 3072, nativeAlgorithm: null, positiveId: "rsa3072" },
  { id: "rsa3072-below-template4096", template: "TTQualificationRSA4096", algorithm: "rsa", size: 3072, schema: 2, minimum: 4096, nativeAlgorithm: null, positiveId: "rsa4096" },
  { id: "ec256-on-p384-schema-three", template: "TTQualificationEC384Schema3", algorithm: "ecdsa", size: 256, schema: 3, minimum: 384, nativeAlgorithm: "ECDSA_P384", positiveId: "ec384schema3" },
  { id: "ec256-on-p384-schema-four", template: "TTQualificationEC384", algorithm: "ecdsa", size: 256, schema: 4, minimum: 384, nativeAlgorithm: "ECDSA_P384", positiveId: "ec384" },
]);
const FLAGS = Object.freeze(["nativeSafeTemplateObserved", "publicConfirmedIssuerUsed", "actualSignedClaimRefusal", "noCaRequestAllocated", "noKeyGenerated", "noAcceptedLeafOrJournal", "positiveNativeCustodyUnchanged", "positiveTrustedTlsUnchanged"]);
const requiredSources = Object.freeze(["tests/e2e/helpers/certops-adcs-algorithm-boundaries.js", "infra/certops-adcs/safety-cases.json", "packages/agent/src/issuers/adcs-safety.js"]);
const requiredScenarios = Object.freeze(CASES.map(item => `adcs-real-template-key-${item.id}-refused`));
function verifyDescriptor(item, expected) {
  assert.ok(expected && CASES.includes(expected));
  for (const field of ["id", "template", "algorithm", "size", "schema"]) assert.equal(item[field], expected[field], field);
  return true;
}
function verifyProof(rows) {
  assert.ok(Array.isArray(rows)); assert.equal(rows.length, CASES.length); assert.deepEqual(rows.map(row => row.caseId).sort(), CASES.map(item => item.id).sort());
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ["caseId", "positiveScenario", "positiveFingerprintSha256", "positiveRequestId", ...FLAGS].sort());
    const selected = CASES.find(item => item.id === row.caseId); assert.equal(row.positiveScenario, `adcs-real-${selected.positiveId}-issued-cng-iis`);
    assert.match(row.positiveFingerprintSha256, /^[a-f0-9]{64}$/); assert.match(row.positiveRequestId, /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(row.positiveRequestId) <= 0xffffffff);
    for (const flag of FLAGS) assert.equal(row[flag], true, flag);
  }
  assert.equal(new Set(rows.map(row => row.positiveFingerprintSha256.toLowerCase())).size, CASES.length);
  assert.equal(new Set(rows.map(row => row.positiveRequestId)).size, CASES.length);
  return true;
}
async function qualifyAlgorithmBoundaries({ gate, fixture, api, agentRowId, issuedFixtures, configDir, preflight, requireNativeRefusal, command, ps, tlsAuthority, caConfig }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1"); assert.notEqual(process.env.CERTOPS_ADCS_PENDING_ELAPSED, "1");
  assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"), "S-1-5-18");
  const root = path.resolve(__dirname, "../../.."), descriptors = require("../../../infra/certops-adcs/safety-cases.json").keyConstraintCases;
  gate.report.fixtureSources ??= [];
  for (const file of requiredSources) { const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex"), previous = gate.report.fixtureSources.find(row => row.file === file); if (previous) assert.equal(previous.sha256, sha256); else gate.report.fixtureSources.push({ file, sha256 }); }
  const proof = [];
  const positives = CASES.map(selected => issuedFixtures.find(item => item.item.id === selected.positiveId)); assert.ok(positives.every(Boolean));
  assert.equal(new Set(positives.map(item => item.observed.fingerprint256.toLowerCase())).size, CASES.length); assert.equal(new Set(positives.map(item => String(item.requestId))).size, CASES.length);
  for (const selected of CASES) await gate.scenario(`adcs-real-template-key-${selected.id}-refused`, async () => {
    const descriptor = descriptors.find(item => item.id === selected.id); verifyDescriptor(descriptor, selected);
    const original = issuedFixtures.find(item => item.item.id === selected.positiveId); assert.ok(original);
    assert.equal(original.item.template, selected.template); assert.equal(original.item.algorithm, selected.algorithm); assert.equal(original.item.size, selected.minimum);
    const positiveScenario = `adcs-real-${selected.positiveId}-issued-cng-iis`, positiveFingerprintSha256 = original.observed.fingerprint256.replaceAll(":", "").toLowerCase();
    assert.ok(gate.report.scenarios.some(item => item.id === positiveScenario && item.status === "passed"));
    const positive = gate.report.nativeCertificates.find(item => item.scenario === positiveScenario); assert.ok(positive); assert.equal(positive.fingerprintSha256, positiveFingerprintSha256); assert.equal(positive.requestId, String(original.requestId));
    const custody = () => {
      assert.match(original.thumbprint, /^[A-F0-9]{40}$/);
      const getter = selected.algorithm === "rsa" ? "[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)" : "[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)";
      const value = JSON.parse(ps(`$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${original.thumbprint}';$k=$null;try{$k=${getter};@{der=[Convert]::ToBase64String($c.RawData);name=$k.Key.KeyName;unique=$k.Key.UniqueName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;policy=[int]$k.Key.ExportPolicy;bits=$k.KeySize}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
      assert.equal(value.der, original.observed.raw.toString("base64")); assert.equal(value.name, buildEnrollmentContainerName(original.enrollmentId)); assert.ok(value.unique); assert.equal(value.provider, "Microsoft Software Key Storage Provider"); assert.equal(value.machine, true); assert.equal(value.policy, 0); assert.equal(value.bits, selected.minimum);
      return value;
    };
    const served = () => new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: original.port, servername: original.item.domain, ca: tlsAuthority(original.authority), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); const leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw); assert.equal(leaf.checkHost(original.item.domain), original.item.domain); resolve(leaf.fingerprint256.replaceAll(":", "").toLowerCase()); } catch (error) { reject(error); } finally { socket.destroy(); } });
      socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Algorithm boundary positive TLS observation timed out")));
    });
    const before = custody(); assert.equal(await served(), positiveFingerprintSha256);
    const { issuerId, result } = await preflight(selected.template); assert.equal(result.caConfig, caConfig); assert.equal(result.template, selected.template); assert.equal(result.caCheck.verdict, "safe"); assert.equal(result.templateCheck.verdict, "safe"); assert.equal(result.templateCheck.schemaVersion, selected.schema); assert.equal(result.templateCheck.minimalKeySize, selected.minimum); assert.equal(result.templateCheck.asymmetricAlgorithm, selected.nativeAlgorithm);
    assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: result.caCertificates[0].keySha256, caConfig, template: selected.template })).status, 200);
    const admitted = await requireNativeRefusal({ ...descriptor, domain: `certops-adcs-${original.item.domain.match(/^certops-adcs-([a-f0-9]+)-/)[1]}-${selected.id.replaceAll("-", "")}.example.test` }, issuerId, "ADCS_TEMPLATE_UNSAFE");
    assert.match(admitted.enrollmentId, /^[a-f0-9-]{36}$/); assert.match(admitted.jobId, /^[a-f0-9-]{36}$/);
    const job = (await fixture.pool.query("SELECT assigned_agent_id,claim_id,status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, admitted.jobId])).rows[0];
    assert.equal(job.assigned_agent_id, agentRowId); assert.ok(job.claim_id); assert.ok(["failed", "rejected"].includes(job.status)); assert.equal(job.result_metadata.enrollmentResult.state, "refused"); assert.equal(job.result_metadata.enrollmentResult.errorCode, "ADCS_TEMPLATE_UNSAFE");
    const enrollment = (await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, admitted.enrollmentId])).rows[0]; assert.equal(enrollment.state, "refused"); assert.equal(enrollment.request_id, null);
    const container = buildEnrollmentContainerName(admitted.enrollmentId); assert.ok(!command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(container));
    assert.equal(require("../../../packages/agent/src/issuers/adcs-enrollment-journal").readEnrollmentJournal(configDir, admitted.enrollmentId).kind, "not_found"); assert.equal(readIssuedContainerRecord({ stateDir: configDir, containerName: container }), null);
    assert.deepEqual(custody(), before); assert.equal(await served(), positiveFingerprintSha256);
    proof.push({ caseId: selected.id, positiveScenario, positiveFingerprintSha256, positiveRequestId: String(original.requestId), ...Object.fromEntries(FLAGS.map(flag => [flag, true])) });
  }, { evidenceLevel: "real-host", oracle: "actual positive CA-issued matching-template CNG/TLS fixture plus incompatible signed public enrollment refused before native request/key allocation; exact claim/enrollment/journal and unchanged positive custody" });
  verifyProof(proof); gate.report.nativeAlgorithmBoundaries = proof;
  return proof;
}
module.exports = { CASES, FLAGS, requiredSources, requiredScenarios, verifyDescriptor, verifyProof, qualifyAlgorithmBoundaries };
