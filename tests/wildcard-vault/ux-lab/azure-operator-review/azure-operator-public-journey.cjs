"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { publishedFacts, servedFacts } = require("./azure-operator-tls-proof.cjs");

const sha256 = value => createHash("sha256").update(String(value)).digest("hex");
const providerVersion = /^[a-f0-9]{32}$/;

function providerTrace({ issuer, consumers, version }) {
  assert.match(version || "", providerVersion);
  const { interrupt, resume } = issuer;
  const first = interrupt.filter(row => row.event === "request" && row.method === "PUT");
  const restarted = resume.filter(row => row.event === "request" && row.method === "PUT");
  assert.deepEqual(first, [{ event: "request", method: "PUT", selected: "object" }]);
  assert.equal(interrupt.filter(row => row.event === "commit-lost" && row.status >= 200 && row.status < 300).length, 1);
  assert.ok(interrupt.some(row => row.event === "read-blocked"));
  assert.deepEqual(restarted, []);
  const includes = rows => rows.filter(row =>
    row.event === "response" && row.method === "GET" && row.selected === "version" && row.status === 200);
  const exact = [resume, ...consumers].map(includes);
  for (const reads of exact) {
    assert.ok(reads.length > 0, "the retained agent did not complete an exact-version read");
    assert.ok(reads.every(read => read.version === version), "agent read a different provider version");
  }
  const latest = [interrupt, resume, ...consumers].flat().filter(row =>
    row.event === "request" && row.method === "GET" && row.selected === "object");
  assert.deepEqual(latest, []);
  return {
    providerPutAttempts: first.length, providerVersion: version,
    exactVersionReads: exact.reduce((total, reads) => total + reads.length, 0),
    latestFallbacks: latest.length, restartRepublishAttempts: restarted.length,
  };
}

function mutations(output) {
  const file = path.join(output, "http-transcript.jsonl");
  assert.ok(fs.statSync(file).size <= 1024 * 1024, "bounded public HTTP transcript required");
  const http = fs.readFileSync(file, "utf8").trim().split("\n").map(row => JSON.parse(row));
  return http.filter(row => row.method !== "GET" && row.status >= 200 && row.status < 300).length;
}

async function exercise({ context, provider, broker, ports }) {
  const { state, owner, approver, api, job, terminal, wait, setup, preparePublication, bindings, customer, versions, base, root, save } = context;
  assert.equal(state.materialProvider, "azure-key-vault");
  assert.equal(state.certificateMode, "ordinary");
  assert.deepEqual(context.certificateSans, ["nginx.wildcard.test"]);
  assert.equal(state.issueJob, undefined, "fresh public operator journey required");
  await wait("owned API startup", async () => {
    try {
      return (await fetch(base + "/api/csrf-token", { signal: AbortSignal.timeout(2000) })).ok;
    } catch { return false; }
  }, 60000);
  await owner.login("owner@wildcard.test", "LabOwner-2026!Only");
  await setup();
  const requester = (await owner.request("/api/session")).user.id;
  const approverId = (await approver.request("/api/session")).user.id;
  assert.ok(requester && approverId);
  assert.notEqual(requester, approverId);
  await preparePublication();
  const allocation = await job(state.issueJob);
  assert.equal(allocation.requestedByUserId, requester);
  assert.equal(allocation.status, "pending_approval");
  const target = { workspaceId: state.workspaceId, groupId: state.groupId,
    materialVersionId: allocation.payload.publication.materialVersionId };
  const armed = await customer("azure-provider-observe", "issuer", { ...target, phase: "interrupt" });
  assert.match(armed.objectName || "", /^tt-[a-f0-9]{64}$/);
  await provider.recordOwnedObject(armed.objectName);
  await customer("start", "issuer");
  await context.approve(state.issueJob);
  const interrupted = await terminal(state.issueJob, ["failed", "orphaned_unknown_effect"]);
  assert.equal(interrupted.errorMessage, "material_publication_uncertain");
  const version = await provider.onlyCommittedVersion(armed.objectName);
  assert.match(version, providerVersion);

  await customer("azure-provider-observe", "issuer", { ...target, phase: "resume" });
  await owner.request(api() + "/distribution-jobs/" + state.issueJob + "/retry", "POST", {});
  await customer("start", "issuer");
  const recovered = await terminal(state.issueJob);
  assert.equal(recovered.approvedByUserId, approverId);
  assert.equal(recovered.payload.publication.materialVersionId, target.materialVersionId);
  const row = (await versions()).find(candidate => candidate.id === target.materialVersionId);
  assert.equal(row.state, "published");
  assert.equal(row.provider_version, version);
  assert.equal(await provider.onlyCommittedVersion(armed.objectName), version);
  state.versionId = target.materialVersionId;
  save();

  await provider.grantConsumer(armed.objectName);
  await Promise.all(["issuer", "consumer"].map(role => broker.refresh(role)));
  const { certificatePem, writeStatus } = await provider.proveConsumerAccess(armed.objectName, version);
  assert.equal(writeStatus, 403);
  await bindings({ beforeStart: name => customer("azure-provider-observe", name, { ...target, phase: "observe" }) });
  const issued = await customer("facts", "issuer");
  assert.equal(issued.orders.length, 1, "resume must not place another CA order");
  const ca = publishedFacts(certificatePem, issued.publicTrustCaPem);
  assert.equal(ca.leafSha256, row.fingerprint_sha256);
  const [nginx, haproxy] = await Promise.all(ports.map(port => servedFacts({
    port, servername: context.certificateSans[0], ca: issued.publicTrustCaPem,
  })));
  const tls = { ...ca, verifiedChain: true };
  assert.deepEqual(nginx, tls);
  assert.deepEqual(haproxy, tls);

  const rollout = await job(state.rolloutJob);
  assert.equal(rollout.requestedByUserId, requester);
  assert.equal(rollout.approvedByUserId, approverId);
  const [consumerJob, secondJob] = state.bindings.map(binding =>
    state.firstMatrix.find(item => item.binding_id === binding.id)?.latest_deployment?.jobId);
  assert.ok(consumerJob && secondJob);
  for (const id of [consumerJob, secondJob]) assert.equal((await job(id)).status, "succeeded");
  const signed = await Promise.all([
    customer("signed-job-proof", "issuer", { jobId: state.issueJob }),
    customer("signed-job-proof", "nginx", { jobId: consumerJob }),
    customer("signed-job-proof", "haproxy", { jobId: secondJob }),
  ]);
  const signer = signed[0].signerKeyIdSha256;
  assert.match(signer, /^[a-f0-9]{64}$/);
  assert.ok(signed.every(proof => proof.signerKeyIdSha256 === signer));

  const before = await customer("facts", "nginx");
  const armedRejection = await customer("transport-fault", "nginx", { mode: "signature" });
  const after = await wait("retained agent signature rejection", async () => {
    const current = await customer("facts", "nginx");
    return current.transport.injected > armedRejection.injected &&
      current.security.signatureRejected > before.security.signatureRejected ? current : false;
  }, 20000);
  assert.equal(after.certificate.modifiedAt, before.certificate.modifiedAt);
  assert.deepEqual(after.reloadEvents, before.reloadEvents);

  const issuer = await customer("azure-provider-events", "issuer");
  const consumerEvents = await Promise.all(["nginx", "haproxy"].map(name => customer("azure-provider-events", name)));
  const proof = providerTrace({ issuer, consumers: consumerEvents.map(events => events.observe), version });
  assert.equal(await provider.onlyCommittedVersion(armed.objectName), version);
  const roles = broker.observations();
  assert.ok(roles.every(role => role.tokenRenewals >= 1));
  const packageProof = await customer("package-proof", "issuer");
  return {
    packageProof,
    facts: {
      http: { mutations: mutations(root), directDatabaseInjection: false, signatureChecksBypassed: false },
      ca: { kind: "openbao-pki", fixture: false, requests: issued.orders.length, ...ca },
      tls,
      jobs: { requestedBySha256: sha256(requester), approvedBySha256: sha256(approverId), signerKeyIdSha256: signer,
        signed: signed.length, verified: signed.length, approved: 2, signatureFailureDenied: true, ...proof },
      identities: roles.map(role => ({ ...role, consumerWriteStatus: role.role === "consumer" ? writeStatus : null })),
    },
  };
}

module.exports = { exercise, providerTrace };
