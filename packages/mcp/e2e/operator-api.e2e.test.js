"use strict";

// End to end: the real MCP client -> the real adapter binary over stdio -> the
// real operator routes over HTTP -> the real database. Nothing is faked.
//
// Fields that must never reach a model are seeded with sentinel strings, and
// every tool's answer is swept for them.

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("../../../apps/api/node_modules/express");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { Client } = require("@modelcontextprotocol/client");
const { StdioClientTransport } = require("@modelcontextprotocol/client/stdio");
const { pool } = require("../../../apps/api/db/database");
const connections = require("../../../apps/api/services/operator/connections");
const { guardOperatorCredentials } = require("../../../apps/api/middleware/operator-connection-auth");

const BIN = path.resolve(__dirname, "../bin/tokentimer-mcp.js");
const contractsDir = path.resolve(__dirname, "../../contracts/mcp");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(contractsDir, name), "utf8"));
const catalog = readJson("mcp-tool-catalog.json");
const readTools = readJson("mcp-read-tools.schema.json");
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(readJson("mcp-common.schema.json"));
ajv.addSchema(readTools);
const outputSchema = (name) => ajv.getSchema(`${readTools.$id}#/definitions/${name}`);

const SENTINELS = ["SENTINEL_KEY_REF", "SENTINEL_SOURCE_PATH", "SENTINEL_DEPLOY_PATH", "SENTINEL_JOB_PAYLOAD", "SENTINEL_JOB_ERROR", "SENTINEL_COMMAND_PROFILE", "SENTINEL_SELECTOR", "SENTINEL_AGENT_NAME"];

let server;
let apiUrl;
let owner;
let workspaceId;
let otherWorkspaceId;
let cert;
let otherCert;
let credential;
let sequence = 0;

async function createUser(label) {
  const result = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified) VALUES ($1, $2, 'local', 'x', TRUE) RETURNING id`,
    [`${label}-${crypto.randomUUID()}@example.test`, label],
  );
  return result.rows[0].id;
}

async function createWorkspace(createdBy) {
  const id = crypto.randomUUID();
  await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, $2, $3)", [id, `ws-${++sequence}`, createdBy]);
  return id;
}

async function seedCertificate(workspace, fingerprint, commonName) {
  const row = await pool.query(
    `INSERT INTO managed_certificates
       (workspace_id, source, source_ref, fingerprint_sha256, common_name, issuer, not_after, key_mode, key_reference, deployed_cert_path, subject_alt_names)
     VALUES ($1, 'agent_filesystem', 'file:///SENTINEL_SOURCE_PATH/x.pem', $2, $3, 'CN=Example CA', NOW() + INTERVAL '10 days',
             'external-unknown', 'vault://SENTINEL_KEY_REF', '/etc/SENTINEL_DEPLOY_PATH/cert.pem', ARRAY[$3]::text[]) RETURNING id`,
    [workspace, fingerprint, commonName],
  );
  const identity = await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id = $1 AND fingerprint_sha256 = $2", [workspace, fingerprint]);
  return { managedId: row.rows[0].id, identityId: identity.rows[0].id, fingerprint };
}

function connect(env = {}, negotiation) {
  const stderr = [];
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN],
    stderr: "pipe",
    env: { ...process.env, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL: credential, ...env },
  });
  transport.stderr?.on("data", (chunk) => stderr.push(String(chunk)));
  const client = new Client({ name: "e2e", version: "0.0.1" }, negotiation ? { versionNegotiation: negotiation } : {});
  return { client, transport, stderr };
}

async function session(options, body) {
  const s = connect(options?.env, options?.negotiation);
  try {
    await s.client.connect(s.transport);
    return await body(s);
  } finally {
    await s.client.close().catch(() => {});
  }
}

const sweep = (value, label) => {
  const text = JSON.stringify(value);
  for (const sentinel of SENTINELS) assert.ok(!text.includes(sentinel), `${label} leaked ${sentinel}`);
  for (const marker of ["vault://", "file://", "/etc/"]) assert.ok(!text.includes(marker), `${label} leaked ${marker}`);
};

describe("MCP adapter against the real operator API", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
    process.env.CERTOPS_ENABLED = "true";
    owner = await createUser("owner");
    workspaceId = await createWorkspace(owner);
    otherWorkspaceId = await createWorkspace(owner);
    cert = await seedCertificate(workspaceId, crypto.createHash("sha256").update("e2e-a").digest("hex"), "e2e.example.com");
    otherCert = await seedCertificate(otherWorkspaceId, crypto.createHash("sha256").update("e2e-other").digest("hex"), "other.example.com");
    await pool.query(
      `INSERT INTO certops_agents (workspace_id, agent_id, name, hostname, platform, agent_version, protocol_version, credential_prefix, credential_hash,
         declared_target_selectors, declared_command_profile_names, status, last_seen_at, supported_operations, declared_capabilities)
       VALUES ($1, 'e2e-agent', 'SENTINEL_AGENT_NAME', 'e2e-host', 'linux', '1.0.0', '1.0.0', $2, $3,
         '["SENTINEL_SELECTOR"]'::jsonb, '["SENTINEL_COMMAND_PROFILE"]'::jsonb, 'active', NOW(), '["renew"]'::jsonb, '[]'::jsonb)`,
      [workspaceId, `ttagent_${crypto.randomBytes(8).toString("hex")}`, crypto.randomBytes(32).toString("hex")],
    );
    await pool.query(
      `INSERT INTO certificate_jobs (workspace_id, operation, status, source, payload, subject_type, subject_id, requested_by_user_id, error_code, error_message)
       VALUES ($1, 'renew', 'failed', 'api', '{"certPath":"/SENTINEL_JOB_PAYLOAD"}'::jsonb, 'managed_certificate', $2, $3, 'WRITE_FAILED', 'wrote SENTINEL_JOB_ERROR')`,
      [workspaceId, cert.managedId, owner],
    );

    const app = express();
    app.use(express.json());
    app.use("/api", guardOperatorCredentials);
    app.use(require("../../../apps/api/routes/operator"));
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    apiUrl = `http://127.0.0.1:${server.address().port}`;

    ({ plaintextCredential: credential } = await connections.createConnection({
      workspaceId,
      userId: owner,
      name: "e2e",
      scopes: ["mcp:identity:read", "mcp:certs:read", "mcp:agents:read", "mcp:jobs:read"],
      roleCeiling: "admin",
    }));
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    delete process.env.CERTOPS_ENABLED;
    await pool.end();
  });

  for (const [label, negotiation] of [
    ["2025-era client", undefined],
    ["2026-07-28 client", { mode: { pin: "2026-07-28" } }],
  ]) {
    it(`serves every tool end to end to a ${label}, in contract and free of seeded secrets`, async () => {
      await session({ negotiation }, async ({ client, stderr }) => {
        const call = async (name, args = {}) => {
          const result = await client.callTool({ name, arguments: args });
          assert.notEqual(result.isError, true, `${name}: ${result.content?.[0]?.text}`);
          sweep(result, name);
          return result.structuredContent;
        };
        const check = (schema, body) => assert.equal(outputSchema(schema)(body), true, `${schema}: ${JSON.stringify(outputSchema(schema).errors)}`);

        const who = await call("tt_whoami");
        check("tt_whoami_output", who);
        assert.equal(who.workspace.id, workspaceId);
        assert.equal(who.certops.mcpWritesEnabled, false);

        const list = await call("tt_list_certificates", { expiresWithinDays: 30 });
        check("tt_list_certificates_output", list);
        assert.equal(list.items.length, 1);
        const id = list.items[0].id;
        assert.equal(id, cert.identityId);

        const detail = await call("tt_get_certificate", { identityId: id });
        check("tt_get_certificate_output", detail);
        const byFingerprint = await call("tt_get_certificate", { fingerprintSha256: cert.fingerprint });
        assert.deepEqual(byFingerprint, detail, "a fingerprint finds the same certificate");

        check("tt_get_certificate_observations_output", await call("tt_get_certificate_observations", { identityId: id }));
        check("tt_explain_certificate_state_output", await call("tt_explain_certificate_state", { identityId: id }));
        const agents = await call("tt_get_agent_health");
        check("tt_get_agent_health_output", agents);
        assert.equal(agents.items.length, 1);
        const jobs = await call("tt_list_jobs", { status: "failed" });
        check("tt_list_jobs_output", jobs);
        const one = await call("tt_get_job", { jobId: jobs.items[0].id });
        check("tt_get_job_output", one);
        assert.equal(one.job.errorCode, "write_failed");

        const logged = stderr.join("");
        assert.ok(!logged.includes(credential), "credential must not be logged");
      });
    });
  }

  it("keeps every answer inside the connection's workspace", async () => {
    await session({}, async ({ client }) => {
      const other = await client.callTool({ name: "tt_get_certificate", arguments: { identityId: otherCert.identityId } });
      assert.equal(other.isError, true);
      assert.equal(JSON.parse(other.content[0].text).code, "MCP_NOT_FOUND");
      const byOtherFingerprint = await client.callTool({ name: "tt_get_certificate", arguments: { fingerprintSha256: otherCert.fingerprint } });
      assert.equal(byOtherFingerprint.isError, true, "another workspace's fingerprint is not findable");
      const list = await client.callTool({ name: "tt_list_certificates", arguments: { includeRetired: true } });
      assert.ok(!JSON.stringify(list).includes(otherCert.identityId));
    });
  });

  it("stops serving the moment the connection is revoked, and says why in a stable code", async () => {
    const created = await connections.createConnection({
      workspaceId,
      userId: owner,
      name: "revoke-e2e",
      scopes: ["mcp:certs:read"],
      roleCeiling: "admin",
    });
    await session({ env: { TOKENTIMER_MCP_CREDENTIAL: created.plaintextCredential } }, async ({ client }) => {
      assert.notEqual((await client.callTool({ name: "tt_list_certificates", arguments: {} })).isError, true);
      await connections.revokeConnection({ workspaceId, connectionId: created.connection.id, revokedBy: owner });
      const after = await client.callTool({ name: "tt_list_certificates", arguments: {} });
      assert.equal(after.isError, true);
      assert.equal(JSON.parse(after.content[0].text).code, "MCP_UNAUTHENTICATED");
    });
  });

  it("refuses a tool the connection holds no scope for", async () => {
    const created = await connections.createConnection({
      workspaceId,
      userId: owner,
      name: "narrow-e2e",
      scopes: ["mcp:certs:read"],
      roleCeiling: "admin",
    });
    await session({ env: { TOKENTIMER_MCP_CREDENTIAL: created.plaintextCredential } }, async ({ client }) => {
      for (const name of ["tt_list_jobs", "tt_get_agent_health", "tt_whoami"]) {
        const result = await client.callTool({ name, arguments: {} });
        assert.equal(result.isError, true, name);
        assert.equal(JSON.parse(result.content[0].text).code, "MCP_SCOPE_DENIED", name);
      }
      assert.notEqual((await client.callTool({ name: "tt_list_certificates", arguments: {} })).isError, true);
    });
  });

  it("matches the tool set to the catalog's implemented read tools", async () => {
    await session({}, async ({ client }) => {
      const { tools } = await client.listTools();
      const expected = catalog.tools.filter((t) => t.contractStatus === "mvp" && t.routeStatus === "implemented").map((t) => t.name).sort();
      assert.deepEqual(tools.map((t) => t.name).sort(), expected);
    });
  });
});
