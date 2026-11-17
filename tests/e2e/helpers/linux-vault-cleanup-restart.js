"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { createHash, randomUUID } = require("node:crypto");
const { createApiFixture } = require("./certops-api-fixture");
const { fixture, seedCleanupHistory } = require("../../helpers/distribution-lifecycle-fixture.cjs");

// The service speaks TLS to this fixture. Only the approved object's metadata
// and soft-delete routes reach the owned loopback Vault. Drop the first
// successful delete response after Vault has applied it.
async function startFaultEndpoint({ vault, cert, key, metadata, deletion }) {
  let deletes = 0;
  let responseLost = false;
  const server = https.createServer({ cert, key }, (req, res) => {
    const isDelete = req.method === "POST" && req.url === deletion;
    if (!isDelete && !(req.method === "GET" && req.url === metadata)) {
      res.writeHead(403).end();
      return;
    }
    const deleteNumber = isDelete ? ++deletes : 0;
    const upstream = http.request(new URL(req.url, vault), {
      method: req.method,
      headers: {
        "X-Vault-Token": req.headers["x-vault-token"] || "",
        "Content-Type": "application/json",
      },
      timeout: 5000,
    }, reply => {
      if (deleteNumber === 1 && reply.statusCode === 204) {
        reply.once("end", () => {
          responseLost = true;
          res.destroy();
        });
        reply.resume();
      } else {
        res.writeHead(reply.statusCode, { "Content-Type": "application/json" });
        reply.pipe(res);
      }
    });
    upstream.on("timeout", () => upstream.destroy());
    upstream.on("error", () => res.destroy());
    req.on("aborted", () => upstream.destroy());
    req.pipe(upstream);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    address: `https://127.0.0.1:${server.address().port}`,
    observe: () => ({ deletes, responseLost }),
    close: () => new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    }),
  };
}

module.exports = async function qualifyCleanupRestart({
  pool, workspaceId, agentRowId, baseUrl, command, identity, mainPid, waitFor,
  stateDir, uid, gid, vaultFixture,
}) {
  assert.equal(process.env.TT_CLEANUP_COMPLETION_DISPOSABLE, "1");
  assert.ok(process.env.TT_CLEANUP_PROVIDER);
  const { provider: materialProvider, capability } = require("../../../scripts/certops-linux-cleanup-case.cjs")(process.env.TT_CLEANUP_PROVIDER);
  assert.match(process.env.TT_CLEANUP_VAULT_ADDRESS || "", /^http:\/\/127\.0\.0\.1:[1-9]\d*$/);
  const vault = process.env.TT_CLEANUP_VAULT_ADDRESS;
  const bootstrapCredential = "isolated-completion-fixture-only";
  let endpoint, primaryError;
  async function provider(route, method = "GET", body, token = bootstrapCredential) {
    return fetch(new URL(route, vault), {
      method, signal: AbortSignal.timeout(5000), redirect: "error",
      headers: { "X-Vault-Token": token, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }
  try {
    const actor = await createApiFixture(baseUrl);
    vaultFixture.sessions.push(actor);
    const reviewer = await createApiFixture(baseUrl);
    vaultFixture.sessions.push(reviewer);
    await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin'),($1,$3,'workspace_manager')",
      [workspaceId, actor.userId, reviewer.userId]);
    const f = await fixture({ materialProvider, enrolled: { workspaceId, actor: actor.userId, approver: reviewer.userId, issuer: agentRowId } });
    const versions = await seedCleanupHistory(f);
    const materialVersionId = versions[2];
    const prefix = `${workspaceId}/${f.groupId}`;
    const object = `${prefix}/bundles/${materialVersionId}`;
    const metadata = `/v1/secret/metadata/${object}`;
    const deletion = `/v1/secret/delete/${object}`;
    const data = `/v1/secret/data/${object}`;
    for (let i = 0; i < 2; i++) {
      assert.equal((await provider(data, "POST", { data: { fixture: "disposable-cleanup-history" } })).status, 200);
    }
    const name = `cleanup-${randomUUID()}`;
    assert.equal((await provider(`/v1/sys/policies/acl/${name}`, "PUT", { policy:
      `path "secret/metadata/${object}" { capabilities = ["read"] }\npath "secret/delete/${object}" { capabilities = ["update"] }`,
    })).status, 204);
    const token = await provider("/v1/auth/token/create", "POST", { policies: [name], no_default_policy: true, ttl: "15m" });
    assert.equal(token.status, 200);
    const cleanupToken = (await token.json()).auth.client_token;
    vaultFixture.revokeToken = async () => {
      assert.equal((await provider("/v1/auth/token/revoke", "POST", { token: cleanupToken })).status, 204);
    };
    assert.equal((await provider(data, "GET", undefined, cleanupToken)).status, 403);
    assert.equal((await provider(`/v1/secret/destroy/${object}`, "POST", { versions: [1] }, cleanupToken)).status, 403);

    const certFile = path.join(stateDir, "vault-ca.pem");
    const keyFile = path.join(stateDir, "vault-key.pem");
    command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", keyFile, "-out", certFile]);
    fs.chmodSync(keyFile, 0o600);
    fs.chmodSync(certFile, 0o644);
    endpoint = await startFaultEndpoint({ vault, cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile), metadata, deletion });
    fs.unlinkSync(keyFile);

    const tokenFile = path.join(stateDir, "vault-cleanup-token");
    fs.writeFileSync(tokenFile, cleanupToken, { flag: "wx", mode: 0o600 });
    fs.chownSync(tokenFile, uid, gid);
    const configPath = path.join(stateDir, "config.json");
    const credential = path.join(stateDir, "credential");
    const hash = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    const initialCredential = hash(credential);
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    config.pollIntervalMs = 1000;
    config.heartbeatIntervalMs = 3000;
    config.execution = { enabled: true, dryRun: false };
    config.declaredTargetSelectors = [f.groupId];
    config.materialStores = { customer: { provider: materialProvider, address: endpoint.address, caFile: certFile,
      mount: "secret", tokenFile: path.join(stateDir, "unused-publication-token"), groups: {
        [f.groupId]: { workspaceId, prefix, sans: ["shared.example.test"], keyAlgorithm: "rsa",
          cleanup: { softDelete: true, profileRevision: 1, minimumSeconds: 0, tokenFile } },
      } } };
    command("systemctl", ["stop", "tokentimer-agent.service"]);
    assert.equal(mainPid(), 0);
    const configStat = fs.lstatSync(configPath);
    assert.ok(configStat.isFile() && configStat.uid === uid && configStat.gid === gid && (configStat.mode & 0o777) === 0o600);
    fs.writeFileSync(configPath, JSON.stringify(config) + "\n");
    command("systemctl", ["start", "tokentimer-agent.service"]);
    const beforePid = await identity();
    await waitFor(async () => (await pool.query(`SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND id=$2
      AND supported_operations ? 'cleanup-from-store' AND declared_capabilities ? $4
      AND declared_target_selectors ? $3`,
    [workspaceId, f.issuer, f.groupId, capability])).rowCount === 1, "installed agent advertises cleanup and its target");

    const apiRoot = `/api/v1/workspaces/${workspaceId}/certops`;
    const group = `${apiRoot}/distribution-groups/${f.groupId}`;
    const policy = structuredClone(require("../../../apps/api/services/certops/distributionLifecycle").DEFAULT_POLICY);
    Object.assign(policy.retention, { minimumSeconds: 0, minimumVersions: 2, rollbackSeconds: 0, cleanupEnabled: true, reportOnly: false });
    const saved = await actor.request(`${group}/policy`, "PUT", { policy, expectedRevision: 0 });
    assert.equal(saved.status, 200);
    const requested = await actor.request(`${group}/cleanups`, "POST", { materialVersionId, expectedRevision: saved.body.revision });
    assert.equal(requested.status, 200);
    assert.equal(requested.body.status, "pending_approval");
    const { jobId, cleanupId } = requested.body;
    const reviewed = await reviewer.request(`${apiRoot}/jobs/${jobId}/approval-review`);
    assert.equal(reviewed.status, 200);
    assert.equal(reviewed.body.jobId, jobId);
    const approved = await reviewer.request(`${apiRoot}/jobs/${jobId}/approve`, "POST",
      { reason: "disposable Vault cleanup qualification" });
    assert.equal(approved.status, 200);
    const job = async () => (await pool.query(`SELECT status, attempt_count, claim_id, claimed_by_agent_id, approved_by_user_id,
      approved_payload_hash, needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2`,
      [workspaceId, jobId])).rows[0];
    const readback = async () => (await (await provider(metadata)).json()).data.versions;
    await waitFor(async () => endpoint.observe().responseLost && (await job()).status === "orphaned_unknown_effect",
      "Vault committed the deletion and the installed agent reported uncertainty");
    const first = await readback();
    assert.ok(first["1"].deletion_time);
    assert.equal(first["1"].destroyed, false);
    assert.equal(first["2"].deletion_time, "");
    const uncertain = await job();
    assert.equal(uncertain.attempt_count, 1);
    assert.equal(uncertain.claimed_by_agent_id, f.issuer);
    assert.ok(uncertain.claim_id && uncertain.approved_payload_hash);
    assert.equal(uncertain.needs_operator_reconciliation, true);
    const journal = path.join(stateDir, "material-cleanup", cleanupId, `${jobId}.json`);
    const firstJournal = JSON.parse(fs.readFileSync(journal, "utf8"));
    assert.equal(firstJournal.uncertain, true);

    command("systemctl", ["restart", "tokentimer-agent.service"]);
    assert.notEqual(await identity(), beforePid);
    assert.equal(hash(credential), initialCredential);
    const retry = await actor.request(`${apiRoot}/distribution-jobs/${jobId}/retry`, "POST", {});
    assert.equal(retry.status, 200);
    assert.equal(retry.body.jobId, jobId);
    await waitFor(async () => (await job()).status === "succeeded", "installed agent reconciles the original cleanup");
    const final = await job();
    assert.equal(final.attempt_count, 2);
    assert.equal(final.claimed_by_agent_id, f.issuer);
    assert.ok(final.claim_id);
    assert.notEqual(final.claim_id, uncertain.claim_id);
    assert.equal(final.approved_by_user_id, reviewer.userId);
    assert.equal(final.approved_payload_hash, uncertain.approved_payload_hash);
    assert.equal(final.needs_operator_reconciliation, false);
    assert.deepEqual(await readback(), first);
    assert.deepEqual(endpoint.observe(), { deletes: 1, responseLost: true });
    const finalJournal = JSON.parse(fs.readFileSync(journal, "utf8"));
    assert.equal(finalJournal.uncertain, false);
    assert.equal(finalJournal.intentHash, firstJournal.intentHash);
    const completed = (await pool.query("SELECT state, fenced_at, receipt FROM certops_material_cleanups WHERE workspace_id=$1 AND id=$2",
      [workspaceId, cleanupId])).rows[0];
    assert.equal(completed.state, "soft_deleted");
    assert.ok(completed.fenced_at);
    assert.equal(completed.receipt.materialVersionId, materialVersionId);
    assert.equal(completed.receipt.providerVersion, 1);
    assert.equal(completed.receipt.method, `${materialProvider}-soft-delete`);
    assert.deepEqual(completed.receipt, finalJournal.receipt);
    const audit = (await pool.query("SELECT count(*)::int AS n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_MATERIAL_CLEANUP_COMPLETED'", [workspaceId])).rows[0];
    assert.equal(audit.n, 1);
    return { actualDeleteRequests: 1, authenticatedAttempts: 2 };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { await endpoint?.close(); }
    catch (error) {
      if (primaryError) throw new AggregateError([primaryError, error], "Vault cleanup and fault endpoint shutdown failed");
      throw error;
    }
  }
};
