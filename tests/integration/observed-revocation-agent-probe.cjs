"use strict";

// Invoked by the optional network test against its isolated local database.
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const express = require("node:module").createRequire(require.resolve("../../apps/api/package.json"))("express");
const { migrations } = require("../../apps/api/migrations/migrate");
const { listCertificateIdentities } = require("../../apps/api/services/certops/certificateIdentity");
const { generateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { createAgentCredentialAuth } = require("../../apps/api/middleware/agent-auth");
const { createCertOpsAgentRouter } = require("../../apps/api/routes/certops-agent");
const { createProtocolClient } = require("../../packages/agent/src/protocol");

async function main() {
  if (process.env.DB_HOST !== "127.0.0.1" || process.env.DB_NAME !== "revocation_test") throw new Error("probe requires its isolated local test database");
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const batches = JSON.parse(input);
  assert.deepEqual(batches.map(({ scenario, verdict }) => [scenario, verdict]), [
    ["good", "good"], ["leaf-crl", "revoked"], ["issuer-crl", "issuer_revoked"],
    ["leaf-ocsp", "revoked"], ["expired-crl", "unknown"], ["missing-crl", "unknown"],
  ]);
  const options = { host: process.env.DB_HOST, port: Number(process.env.DB_PORT), user: process.env.DB_USER, password: process.env.DB_PASSWORD };
  const database = `tt_revocation_probe_${process.pid}_${Date.now()}`;
  const admin = new Client({ ...options, database: process.env.DB_NAME });
  await admin.connect();
  let db, server;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    db = new Pool({ ...options, database });
    for (const migration of migrations) await db.query(migration.sql);
    const userId = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES('probe@example.test','probe@example.test','Probe','x','local') RETURNING id")).rows[0].id;
    const workspaceId = (await db.query("INSERT INTO workspaces(id,name,plan,created_by,certops_managed_identity_limit) VALUES(gen_random_uuid(),'Revocation probe','oss',$1,1) RETURNING id", [userId])).rows[0].id;
    const agentId = `probe-${randomUUID()}`;
    const credential = generateAgentCredential();
    await db.query("INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash) VALUES($1,$2,'test','1.0.0',$3,$4)", [workspaceId, agentId, credential.credentialPrefix, credential.credentialHash]);
    const app = express();
    app.use(express.json({ limit: "2mb" }));
    app.use(createCertOpsAgentRouter({ dbPool: db, credentialAuthMiddleware: createAgentCredentialAuth({ client: db }), certOpsEnabledMiddleware: (_req, _res, next) => next() }));
    server = await new Promise((resolve) => { const listener = app.listen(0, "127.0.0.1", () => resolve(listener)); });
    const client = createProtocolClient({ serverUrl: `http://127.0.0.1:${server.address().port}`, allowInsecureLocalHttp: true, agentId, protocolVersion: "1.0.0", getCredential: async () => credential.plaintextCredential });
    for (const [index, batch] of batches.entries()) {
      assert.equal(batch.items.length, 2, batch.scenario);
      // Every scan runs in a fresh process with a temporary path (and possibly
      // a new container hostname). Keep the synthetic locations stable so the
      // database sees repeat observations of the same two locations.
      const items = structuredClone(batch.items);
      for (const item of items) {
        for (const entry of item.metadata) {
          if (entry.name === "targetHost") entry.value = "revocation-probe";
          if (entry.name === "filePath") entry.value = "/synthetic/leaf.crt";
        }
        assert.doesNotMatch(JSON.stringify(item), /BEGIN CERTIFICATE|PRIVATE KEY/);
      }
      await client.reportEvidence({ evidenceItems: items });
      const grouped = await listCertificateIdentities({ workspaceId, client: db });
      assert.equal(grouped.items.length, 1, batch.scenario);
      const identity = grouped.items[0];
      assert.equal(identity.observedRevocation.verdict, batch.verdict, batch.scenario);
      assert.equal(identity.revocationObservable, true, batch.scenario);
      assert.equal(identity.locationCount, 2, batch.scenario);
      if (batch.verdict === "unknown") {
        assert.equal(identity.observedRevocation.lastVerified.verdict, "revoked", batch.scenario);
      }
      // A slot can also exist as a managed instance. Match the console's
      // identity, target and source key so it is counted only once.
      const observations = await db.query(`
        SELECT instance.source, instance.public_metadata->'observedRevocation' AS result
        FROM certificate_instances instance
        WHERE instance.workspace_id = $1 AND instance.source IN ('agent_filesystem', 'agent_windows')
          AND instance.presence_state IS DISTINCT FROM 'confirmed_absent'
        UNION ALL
        SELECT slot.source, slot.observed_revocation AS result
        FROM certops_slot_observations slot
        WHERE slot.workspace_id = $1 AND slot.source IN ('agent_filesystem', 'agent_windows')
          AND NOT EXISTS (
            SELECT 1 FROM certificate_instances instance
            WHERE instance.workspace_id = slot.workspace_id AND instance.target_id = slot.target_id
              AND instance.source = slot.source AND instance.source_ref = slot.source_ref
              AND certops_normalize_fingerprint(instance.observed_fingerprint_sha256) = slot.fingerprint_sha256
              AND instance.presence_state IS DISTINCT FROM 'confirmed_absent'
          )`, [workspaceId]);
      assert.equal(observations.rowCount, 2, batch.scenario);
      assert.deepEqual(observations.rows.map(({ source }) => source).sort(), ["agent_filesystem", "agent_windows"], batch.scenario);
      for (const { result } of observations.rows) {
        assert.equal(result.verdict, batch.verdict, batch.scenario);
        assert.ok(result.checkedAt, batch.scenario);
        if (batch.verdict !== "unknown") assert.ok(result.validUntil, batch.scenario);
        else assert.equal(result.lastVerified.verdict, "revoked", batch.scenario);
      }
      const evidence = await db.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id = $1", [workspaceId]);
      assert.equal(evidence.rows[0].count, (index + 1) * 2, batch.scenario);
    }
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (db) await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
