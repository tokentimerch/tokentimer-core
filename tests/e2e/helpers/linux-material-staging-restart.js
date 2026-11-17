"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { createHash, createPrivateKey, X509Certificate } = require("node:crypto");
const { createApiFixture } = require("./certops-api-fixture");
const { fixture } = require("../../helpers/distribution-lifecycle-fixture.cjs");
const operations = require("../../../apps/api/services/certops/distributionOperations");
const { activationDecision } = require("../../../packages/contracts/certops/activation-calendar.cjs");

function issueFixtureCertificate(command, stateDir, name, san, authority = false) {
  const certificate = path.join(stateDir, name + ".crt");
  const key = path.join(stateDir, name + ".key");
  command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=${name}`,
    "-addext", `basicConstraints=critical,CA:${authority ? "TRUE" : "FALSE"}`,
    "-addext", `subjectAltName=${san}`, "-keyout", key, "-out", certificate]);
  fs.chmodSync(certificate, 0o644);
  const privateKey = fs.readFileSync(key, "utf8");
  fs.unlinkSync(key);
  return { path: certificate, certificate: fs.readFileSync(certificate, "utf8"), privateKey };
}

async function startPinnedReadEndpoint(vault, tls, pinnedVersionPath) {
  const server = https.createServer({ cert: tls.certificate, key: tls.privateKey }, (request, response) => {
    if (request.method !== "GET" || request.url !== pinnedVersionPath) return response.writeHead(403).end();
    const upstream = http.request(new URL(pinnedVersionPath, vault), {
      headers: { "X-Vault-Token": request.headers["x-vault-token"] || "" }, timeout: 5000,
    }, reply => {
      response.writeHead(reply.statusCode, { "Content-Type": "application/json" });
      reply.pipe(response);
    });
    upstream.on("timeout", () => upstream.destroy());
    upstream.on("error", () => response.destroy());
    upstream.end();
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    address: `https://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    }),
  };
}

module.exports = async function qualifyStaging({
  pool, workspaceId, agentId, agentRowId, baseUrl, command, identity, mainPid, waitFor,
  stateDir, writeFixture, uid, gid, vaultFixture,
}) {
  assert.equal(process.env.TT_CLEANUP_COMPLETION_DISPOSABLE, "1");
  assert.equal(process.env.TT_CLEANUP_PROVIDER, "vault-kv2");
  const vault = process.env.TT_CLEANUP_VAULT_ADDRESS;
  assert.match(vault || "", /^http:\/\/127\.0\.0\.1:[1-9]\d*$/);
  function provider(route, method, body) {
    return fetch(new URL(route, vault), { method, signal: AbortSignal.timeout(5000), redirect: "error",
      headers: { "X-Vault-Token": "isolated-completion-fixture-only", "Content-Type": "application/json" },
      body: JSON.stringify(body) });
  }
  let endpoint, primaryError;
  try {
    const actor = await createApiFixture(baseUrl);
    vaultFixture.sessions.push(actor);
    const reviewer = await createApiFixture(baseUrl);
    vaultFixture.sessions.push(reviewer);
    await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin'),($1,$3,'workspace_manager')",
      [workspaceId, actor.userId, reviewer.userId]);

    const san = "shared.example.test";
    const leaf = issueFixtureCertificate(command, stateDir, "staged-leaf", `DNS:${san}`);
    const cert = new X509Certificate(leaf.certificate);
    const fingerprint = createHash("sha256").update(cert.raw).digest("hex");
    const f = await fixture({ fingerprint, enrolled: { workspaceId, actor: actor.userId, approver: reviewer.userId, issuer: agentRowId } });
    await pool.query("UPDATE certops_material_versions SET valid_to=$3 WHERE workspace_id=$1 AND id=$2",
      [workspaceId, f.materialVersionId, new Date(cert.validTo).toISOString()]);
    const prefix = `${workspaceId}/${f.groupId}`;
    const materialPath = `/v1/secret/data/${prefix}/bundles/${f.materialVersionId}`;
    const bundle = { schemaVersion: 1, workspaceId, groupId: f.groupId, materialVersionId: f.materialVersionId,
      certificatePem: leaf.certificate, privateKeyPem: leaf.privateKey, fingerprintSha256: fingerprint, sans: [san] };
    assert.equal((await provider(materialPath, "POST", { data: bundle })).status, 200);
    assert.equal((await provider("/v1/sys/policies/acl/installed-staging", "PUT",
      { policy: `path "${materialPath.slice(4)}" { capabilities = ["read"] }` })).status, 204);
    const createdToken = await provider("/v1/auth/token/create", "POST", { policies: ["installed-staging"], no_default_policy: true, ttl: "15m" });
    assert.equal(createdToken.status, 200);
    const token = (await createdToken.json()).auth.client_token;
    vaultFixture.revokeToken = async () => {
      assert.equal((await provider("/v1/auth/token/revoke", "POST", { token })).status, 204);
    };
    const tokenFile = path.join(stateDir, "staging-token");
    fs.writeFileSync(tokenFile, token, { flag: "wx", mode: 0o600 });
    fs.chownSync(tokenFile, uid, gid);
    const tls = issueFixtureCertificate(command, stateDir, "staging-provider", "IP:127.0.0.1", true);
    endpoint = await startPinnedReadEndpoint(vault, tls, materialPath + "?version=1");

    const api = `/api/v1/workspaces/${workspaceId}/certops`;
    const group = `${api}/distribution-groups/${f.groupId}`;
    const bindingRoute = `${group}/consumers/${f.bindingId}`;
    const binding = { ...f.binding, agentId: agentRowId, verificationPolicy: "installed" };
    const bound = await actor.request(bindingRoute, "PUT", binding);
    assert.equal(bound.status, 200);
    const now = Date.now();
    const policy = { method: "none", disruptive: false, requiresApproval: true, timezone: "UTC", windows: [],
      blackouts: [{ start: new Date(now - 60000).toISOString(), end: new Date(now + 600000).toISOString() }],
      validUntil: null, emergency: null, independentStaging: true };
    const authorization = await actor.request(`${bindingRoute}/activation-policy`, "PUT",
      { expectedAuthorizationRevision: bound.body.authorization_revision, policy });
    assert.equal(authorization.status, 200);

    const destination = writeFixture.allowed;
    const certPath = path.join(destination, "live.crt");
    const keyPath = path.join(destination, "live.key");
    const initialDirectory = fs.readdirSync(destination).sort();
    assert.ok(!fs.existsSync(certPath) && !fs.existsSync(keyPath));
    const configPath = path.join(stateDir, "config.json");
    command("systemctl", ["stop", "tokentimer-agent.service"]);
    assert.equal(mainPid(), 0);
    const stat = fs.lstatSync(configPath);
    assert.ok(stat.isFile() && stat.uid === uid && stat.gid === gid && (stat.mode & 0o777) === 0o600);
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    config.pollIntervalMs = 1000;
    config.heartbeatIntervalMs = 3000;
    config.execution = { enabled: true, dryRun: false };
    config.declaredTargetSelectors = [f.bindingId];
    config.policy = { allowedPaths: [destination] };
    config.materialStores = { customer: { provider: "vault-kv2", address: endpoint.address, caFile: tls.path,
      mount: "secret", tokenFile, groups: { [f.groupId]: { workspaceId, prefix, sans: [san], keyAlgorithm: "rsa" } } } };
    config.materialBindings = { [f.bindingId]: { workspaceId, groupId: f.groupId, agentId, materialStoreRef: "customer",
      deploymentProfileRef: binding.deploymentProfileRef, profileRevision: binding.profileRevision,
      authorizationRevision: authorization.body.authorizationRevision, verificationPolicy: "installed",
      independentStaging: true, target: { type: "endpoint", certPath, keyPath } } };
    fs.writeFileSync(configPath, JSON.stringify(config) + "\n");
    command("systemctl", ["start", "tokentimer-agent.service"]);
    const originalPid = await identity();
    await waitFor(async () => (await pool.query(`SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND id=$2
      AND supported_operations ? 'deploy-from-store' AND declared_capabilities ? 'material-consumer-staging-v1'
      AND declared_target_selectors ? $3`, [workspaceId, agentRowId, f.bindingId])).rowCount === 1, "Installed staging capability and target");

    const request = await actor.request(`${group}/rollouts`, "POST", { materialVersionId: f.materialVersionId, requiresApproval: true });
    assert.equal(request.status, 201);
    assert.equal(request.body.status, "pending_approval");
    const approved = await reviewer.request(`${api}/jobs/${request.body.id}/approve`, "POST", { reason: "Disposable staging qualification" });
    assert.equal(approved.status, 200);
    const outbox = (await pool.query(`SELECT * FROM certops_outbox WHERE workspace_id=$1
      AND event_type='distribution_approval_granted' AND dedupe_key=$2`, [workspaceId, request.body.id])).rows;
    assert.equal(outbox.length, 1);
    // Apply only this genuine public approval event using the existing worker handler.
    const expanded = await operations.transaction(client => operations.processDistributionIntent({ client, row: outbox[0], payload: outbox[0].payload }));
    assert.equal(expanded.reason, "approved_rollout_created");
    const rollout = (await pool.query("SELECT id,generation FROM certops_distribution_rollouts WHERE workspace_id=$1 AND approval_job_id=$2",
      [workspaceId, request.body.id])).rows[0];
    assert.ok(rollout);
    const advance = () => operations.transaction(client => operations.advanceRollout(client, workspaceId, f.groupId, rollout.id));
    await advance();
    const deployment = async () => (await pool.query(`SELECT d.staging_job_id,d.job_id,d.stage,d.staging_receipt,
      j.status,j.claimed_by_agent_id,j.attempt_count,j.payload FROM certops_consumer_deployments d
      JOIN certificate_jobs j ON j.workspace_id=d.workspace_id AND j.id=d.staging_job_id
      WHERE d.workspace_id=$1 AND d.rollout_id=$2 AND d.binding_id=$3`, [workspaceId, rollout.id, f.bindingId])).rows[0];
    await waitFor(async () => (await deployment())?.status === "succeeded", "Signed preparation completed by the installed agent");
    await advance();
    const staged = await deployment();
    assert.equal(staged.claimed_by_agent_id, agentRowId);
    assert.equal(staged.attempt_count, 1);
    assert.equal(staged.payload.materialDeployment.preparationOnly, true);
    assert.equal(staged.stage, "staged");
    assert.equal(staged.job_id, null);
    assert.equal(activationDecision(policy).allowed, false);
    assert.equal(staged.staging_receipt.materialVersionId, f.materialVersionId);
    assert.equal(staged.staging_receipt.fingerprintSha256, fingerprint);
    assert.equal(staged.staging_receipt.staged, true);
    for (const field of ["installed", "bound", "servedVerified", "trustValidated"]) assert.equal(staged.staging_receipt[field], false);
    const current = (await pool.query("SELECT observed_material_version_id FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2",
      [workspaceId, f.bindingId])).rows[0];
    assert.equal(current.observed_material_version_id, null);

    const directory = path.join(stateDir, "material-consumer-staging", f.bindingId, String(rollout.generation));
    const stagedBundle = path.join(directory, "bundle.json");
    const properties = fs.lstatSync(stagedBundle);
    assert.ok(properties.isFile() && properties.uid === uid && (properties.mode & 0o777) === 0o600);
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o700);
    const bytes = fs.readFileSync(stagedBundle);
    const prepared = JSON.parse(bytes);
    assert.equal(new X509Certificate(prepared.certificatePem).fingerprint256, cert.fingerprint256);
    assert.ok(cert.checkPrivateKey(createPrivateKey(prepared.privateKeyPem)));
    command("systemctl", ["restart", "tokentimer-agent.service"]);
    assert.notEqual(await identity(), originalPid);
    assert.ok(fs.readFileSync(stagedBundle).equals(bytes), "Protected stage survives actual service restart");
    assert.deepEqual(fs.readdirSync(destination).sort(), initialDirectory);
    assert.ok(!fs.existsSync(certPath) && !fs.existsSync(keyPath));
    assert.equal((await deployment()).job_id, null);
    return { provider: "vault-kv2", authenticatedAttempts: 1, stagedAcrossRestart: true, activationBlocked: true, destinationUnchanged: true };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { await endpoint?.close(); }
    catch (error) {
      if (primaryError) throw new AggregateError([primaryError, error], "Staging and its provider endpoint cleanup failed");
      throw error;
    }
  }
};
