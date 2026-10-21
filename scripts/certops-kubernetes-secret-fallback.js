/**
 * Qualification: native public Secret fallback
 *
 * controller-secret-fallback runs the actual candidate in-cluster client in a
 * production-image pod whose ServiceAccount gets only three exact Secret names in its
 * random namespace. Independently match parsed public tls.crt fingerprint and validity;
 * the destination alone owns the private key. Require actual 403 on a foreign namespace,
 * refusal of genuine malformed public data and a real 70 KiB decoded field, and
 * inability to read an unallowlisted Secret. Grant no Secret list/mutation or
 * certificate mutation. Emit only bounded passed/failed sentinel, never Secret bytes,
 * tokens or raw errors. This host case does not prove full API publication, external
 * issuers or every fallback-policy combination; parser checks are not cluster evidence.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
// Run inside the production controller image with its scoped mounted identity;
// verify the bounded public-only Secret reader and real native RBAC refusals.
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {createInClusterCertManagerClient}=require("/app/apps/k8s-controller/src/cert-manager-client");
const {createTlsCertificateFallback}=require("/app/apps/k8s-controller/src/tls-certificate-fallback");
async function main(){
 const namespace=process.env.CERTOPS_TEST_NAMESPACE,fingerprint=process.env.CERTOPS_TEST_FINGERPRINT;
 assert.match(namespace,/^certops-[a-f0-9]{16}$/);assert.match(fingerprint,/^[a-f0-9]{64}$/);
 const client=createInClusterCertManagerClient({secretFallbackEnabled:true});await client.start();
 try{
  await assert.rejects(client.readTlsCertificate({namespace:"default",secretName:"owned-tls"}),error=>Number(error.statusCode||error.response?.statusCode||error.code)===403);
  const encoded=await client.readTlsCertificate({namespace,secretName:"owned-tls"});assert.equal(typeof encoded,"string");const certificate=new crypto.X509Certificate(Buffer.from(encoded,"base64"));assert.equal(crypto.createHash("sha256").update(certificate.raw).digest("hex"),fingerprint);
  const fallback=createTlsCertificateFallback({enabled:true,kubernetesClient:client});
  const enriched=await fallback.enrichObservation({ready:true,namespace,secretName:"owned-tls"});assert.equal(enriched.publicCertificate.fingerprintSha256,fingerprint);assert.ok(Date.parse(enriched.notAfter)>Date.now());
  const output=JSON.stringify(enriched);assert.ok(!output.includes('tls.key'));assert.ok(!output.includes('PRIVATE KEY'));assert.deepEqual(Object.keys(enriched).sort(),['namespace','notAfter','notBefore','publicCertificate','ready','secretName'].sort());
  await assert.rejects(fallback.enrichObservation({ready:true,namespace,secretName:"malformed-public"}),{code:"CERTOPS_CERTIFICATE_PARSE_FAILED"});
  await assert.rejects(fallback.enrichObservation({ready:true,namespace,secretName:"oversized-public"}),{code:"CERTOPS_TLS_CRT_TOO_LARGE"});
  await assert.rejects(fallback.enrichObservation({ready:true,namespace,secretName:"not-allowed"}),{code:"CERTOPS_TLS_CRT_READ_FAILED"});
  console.log("CERTOPS_SECRET_FALLBACK_RESULT=passed");
 }finally{await client.stop();}
}
main().catch(()=>{console.error("CERTOPS_SECRET_FALLBACK_RESULT=failed");process.exitCode=1;});
