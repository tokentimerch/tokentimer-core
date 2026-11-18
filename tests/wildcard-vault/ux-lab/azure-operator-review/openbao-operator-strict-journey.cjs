"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { connect } = require("node:tls");
const { caEndpoint } = require("../operator-ca.cjs");
const { Id, pin, sha256, servedCertificate } = require("./openbao-operator-observer.cjs");

async function observeTls({ root, name, servername }) {
  assert.ok(["nginx", "haproxy"].includes(name));
  const port = Number(process.env[name === "nginx" ? "TT_UX_NGINX_PORT" : "TT_UX_HAPROXY_PORT"]);
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
  const issuer = fs.readFileSync(path.join(root, "operator-ca/issuer.pem"));
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port, servername, ca: issuer, rejectUnauthorized: true });
    socket.setTimeout(5000, () => socket.destroy(new Error("Served TLS observation timed out")));
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      try {
        assert.equal(socket.authorized, true);
        resolve(servedCertificate(socket.getPeerCertificate(true), issuer));
      } catch (error) { reject(error); }
      finally { socket.destroy(); }
    });
  });
}

async function observe({ install } = {}) {
  assert.equal(process.env.TT_UX_OPERATOR_CA, "openbao-pki");
  assert.equal(process.env.TT_UX_PACKAGE_ACCEPTANCE, "1");
  const c = require("../journey.cjs").context;
  const { root, state, owner, approver, customer, api, job, terminal, wait } = c;
  assert.equal(state.materialProvider, "openbao-kv2");
  assert.equal(state.certificateMode, "ordinary");
  assert.equal(state.workspaceId, undefined, "strict evidence requires a fresh public workspace");
  await c.openSession();
  await c.setup();
  const sessionIds = (await Promise.all([owner, approver].map(actor => actor.request("/api/session"))))
    .map(({ user }) => String(user.id));
  assert.notEqual(sessionIds[0], sessionIds[1]);
  await c.preparePublication();
  const issue = await job(state.issueJob);
  assert.equal(issue.payload.caEndpoint, caEndpoint);
  assert.equal(issue.status, "pending_approval");
  assert.equal(String(issue.requestedByUserId), sessionIds[0]);
  await owner.request(api() + "/jobs/" + issue.id + "/approve", "POST", { reason: "Verify independent approval" }, [403, 409]);

  const { materialVersionId } = issue.payload.publication;
  const scope = { workspaceId: state.workspaceId, groupId: state.groupId, materialVersionId };
  const route = pin(scope.workspaceId, scope.groupId, materialVersionId);
  await customer("operator-observation-arm", "issuer", scope);
  await customer("fault");
  await c.approve(issue.id);
  await terminal(issue.id, ["failed", "orphaned_unknown_effect"]);
  await customer("stop");
  const interrupted = await customer("facts", "issuer", { certificateId: state.certificateId });
  assert.equal(interrupted.fault.path, route);
  assert.equal(interrupted.fault.droppedWrites, 1);
  assert.equal(interrupted.orders.length, 1);
  const beforeRestart = await customer("operator-observation-counters");
  assert.equal(beforeRestart.writeAttempts, 1);
  assert.equal(beforeRestart.committedWrites, 1);
  assert.equal(await c.versions().then(rows => rows.some(row => row.id === materialVersionId && row.state === "published")), false);
  await customer("clear-fault");
  await owner.request(api() + "/distribution-jobs/" + issue.id + "/retry", "POST", {});
  await customer("start");
  const recovered = await terminal(issue.id);
  assert.equal(recovered.payload.publication.materialVersionId, materialVersionId);
  assert.equal(recovered.needsOperatorReconciliation, false);
  assert.equal(String(recovered.approvedByUserId), sessionIds[1]);
  state.versionId = materialVersionId;
  c.save();

  await c.bindings();
  const rollout = await terminal(state.rolloutJob);
  assert.equal(String(rollout.requestedByUserId), sessionIds[0]);
  assert.equal(String(rollout.approvedByUserId), sessionIds[1]);
  const rows = await c.converge();
  const deployments = state.bindings.map(binding => rows.find(row => row.binding_id === binding.id));
  assert.ok(deployments.every(row => row.observed_material_version_id === materialVersionId && Id.test(row.latest_deployment?.jobId)));
  const jobs = await Promise.all(deployments.map(row => terminal(row.latest_deployment.jobId)));
  assert.ok(jobs.every(candidate => candidate.payload.materialDeployment.materialVersionId === materialVersionId));
  const selected = (await c.versions()).find(row => row.id === materialVersionId && row.state === "published");
  const measured = await customer("operator-observation-proof", "issuer", { jobIds: [issue.id, ...jobs.map(candidate => candidate.id)] });
  const { provider, orders } = measured;
  assert.equal(provider.committedWrites, 1);
  assert.ok(provider.exactReads > 0);
  assert.equal(provider.latestReads, 0);
  assert.equal(provider.version, String(selected.provider_version));
  assert.equal(orders.length, interrupted.orders.length);
  const { leafSha256, chainSha256 } = orders[0];
  assert.equal(leafSha256, selected.fingerprint_sha256);
  for (const name of ["nginx", "haproxy"]) {
    assert.deepEqual(await observeTls({ root, name, servername: c.certificateSans[0] }), { leafSha256, chainSha256 });
  }

  const before = await customer("facts", "nginx");
  const armed = await customer("transport-fault", "nginx", { mode: "signature" });
  const after = await wait("installed archive rejects invalid dispatch signature", async () => {
    const facts = await customer("facts", "nginx");
    return facts.transport.injected > armed.injected && facts.security.signatureRejected > before.security.signatureRejected && facts;
  }, 20000);
  assert.equal(after.certificate.fingerprint256, before.certificate.fingerprint256);
  assert.deepEqual(after.reloadEvents, before.reloadEvents);
  const identities = await customer("operator-role-observation", "issuer", scope);
  assert.ok(identities.every(identity => identity.tokenRenewals > 0 && identity.crossRoleDenials > 0));

  const restartRepublishAttempts = provider.writeAttempts - beforeRestart.writeAttempts;
  if (provider.writeAttempts !== 1 || restartRepublishAttempts !== 0) {
    fs.writeFileSync(path.join(root, "openbao-operator-publication-failure.json"), JSON.stringify({
      status: "failed", scenario: "interruption-resume-without-republish", expectedProviderWrites: 1,
      providerWriteAttempts: provider.writeAttempts, providerWriteStatuses: provider.writeStatuses,
      providerCommittedWrites: provider.committedWrites, exactVersionReads: provider.exactReads,
      providerVersion: provider.version, latestFallbacks: provider.latestReads, restartRepublishAttempts,
      successfulCaOrders: orders.length, independentlyVerifiedTlsConsumers: 2, distinctScopedRoles: identities.length,
    }) + "\n", { flag: "wx", mode: 0o600 });
    assert.fail("Retained agent attempted another provider write after restart");
  }
  const native = install && await c.observeNativeOpenBaoConsumer(install);
  if (native) assert.equal(native.installed.leafSha256, leafSha256);
  const afterRestart = await customer("operator-observation-proof", "issuer", { jobIds: [issue.id, ...jobs.map(candidate => candidate.id)] });
  assert.equal(afterRestart.provider.writeAttempts, provider.writeAttempts);
  assert.equal(afterRestart.provider.latestReads, 0);
  assert.deepEqual(afterRestart.orders, orders);
  const mutations = fs.readFileSync(path.join(root, "http-transcript.jsonl"), "utf8").trim().split("\n").map(JSON.parse)
    .filter(event => ["POST", "PUT", "PATCH", "DELETE"].includes(event.method) && event.status >= 200 && event.status < 300).length;
  assert.ok(mutations > 0);
  return {
    nativeService: native?.nativeService ?? null,
    facts: {
      http: { mutations, directDatabaseInjection: false, signatureChecksBypassed: false },
      ca: { kind: "openbao-pki", fixture: false, requests: orders.length, leafSha256, chainSha256 },
      tls: { leafSha256, chainSha256, verifiedChain: true },
      jobs: { requestedBySha256: sha256(sessionIds[0]), approvedBySha256: sha256(sessionIds[1]),
        signerKeyIdSha256: provider.signerKeyIdSha256, signed: provider.signed, verified: provider.verified,
        approved: [recovered, rollout].filter(candidate => String(candidate.approvedByUserId) === sessionIds[1]).length,
        signatureFailureDenied: true, providerPutAttempts: provider.writeAttempts, providerVersion: provider.version,
        exactVersionReads: afterRestart.provider.exactReads, latestFallbacks: afterRestart.provider.latestReads,
        restartRepublishAttempts },
      identities,
    },
  };
}

async function main() {
  require("./native-openbao-bootstrap.cjs").assertHosted();
  const output = process.env.TT_WILDCARD_UX_OUTPUT;
  const { packageArtifact } = JSON.parse(fs.readFileSync(path.join(output, "agent-package/harness-input.json"), "utf8"));
  const proof = await observe({ install: {
    packageArtifact, customerImage: process.env.TT_UX_CUSTOMER_IMAGE,
    apiAddress: "https://127.0.0.1:" + process.env.TT_UX_NATIVE_API_PORT,
    baoAddress: "https://127.0.0.1:" + process.env.TT_UX_NATIVE_BAO_PORT,
  } });
  assert.ok(proof.nativeService);
  fs.writeFileSync(path.join(output, "openbao-operator-observation.json"), JSON.stringify({
    sourceSha: process.env.GITHUB_SHA, runId: process.env.GITHUB_RUN_ID, packageArtifact, ...proof,
  }) + "\n", { flag: "wx", mode: 0o600 });
}

module.exports = { observe };
if (require.main === module) main().catch(error => {
  const frame = String(error.stack).split("\n").slice(1, 10).map(line => /[\\/](openbao-operator-strict-journey|openbao-operator-observer|journey|native-openbao-bootstrap)\.cjs:(\d+):\d+/.exec(line)).find(Boolean);
  console.error("OpenBao operator observation failed" + (frame ? ` (${frame[1]}:${frame[2]})` : ""));
  process.exitCode = 1;
});
