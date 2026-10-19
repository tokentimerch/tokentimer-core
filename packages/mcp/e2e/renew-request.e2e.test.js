"use strict";

// An assistant asks for a renewal and nothing happens until a different person
// approves it. Real MCP client -> real adapter process -> real API -> real
// database. Nothing is faked.

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const express = require("../../../apps/api/node_modules/express");
const { Client } = require("@modelcontextprotocol/client");
const { StdioClientTransport } = require("@modelcontextprotocol/client/stdio");
const { pool } = require("../../../apps/api/db/database");
const connections = require("../../../apps/api/services/operator/connections");
const approvals = require("../../../apps/api/services/certops/jobApprovals");
const { guardOperatorCredentials } = require("../../../apps/api/middleware/operator-connection-auth");

const BIN = path.resolve(__dirname, "../bin/tokentimer-mcp.js");
const SCOPES = ["mcp:identity:read", "mcp:certs:read", "mcp:jobs:read", "mcp:requests:read", "mcp:renew:request"];

let server;
let apiUrl;
let requester;
let approver;
let workspaceId;
let credential;
let identityId;

const profile = () => ({
  schemaVersion: 1, profileId: "profile-1", profileName: "web-tls",
  sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
  keyAlgorithm: "rsa", keySize: 2048, keyRotationPolicy: { rotateOnRenew: true }, preferredChain: null,
  ca: { endpoint: "https://acme-v02.api.letsencrypt.org/directory", accountRef: null, eabRef: null },
  acme: { kind: "certbot", commandRef: "acme-renew-default" }, dns: { provider: "cloudflare", zone: "example.com" },
  deploymentTargets: [{ type: "endpoint", reference: "host/web", certPath: "/etc/ssl/certs/app.pem", reloadService: "nginx" }],
  target: { type: "endpoint", reference: "host/web", certPath: "/etc/ssl/certs/app.pem" },
  verification: { host: "app.example.com", port: 443, requireMatch: true },
});

async function user(label) {
  return (
    await pool.query(
      `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified) VALUES ($1, $2, 'local', 'x', TRUE) RETURNING id`,
      [`${label}-${crypto.randomUUID()}@example.test`, label],
    )
  ).rows[0].id;
}

async function session(env, body) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN],
    stderr: "pipe",
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL: credential, ...env },
  });
  const client = new Client({ name: "renew-e2e", version: "0.0.1" });
  try {
    await client.connect(transport);
    return await body(client);
  } finally {
    await client.close().catch(() => {});
  }
}

const call = async (client, name, args = {}) => {
  const result = await client.callTool({ name, arguments: args });
  return result;
};
const data = (result) => {
  assert.notEqual(result.isError, true, result.content?.[0]?.text);
  return result.structuredContent;
};

describe("an assistant requests a renewal, a person approves it", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    process.env.CERTOPS_ENABLED = "true";
    requester = await user("requester");
    approver = await user("approver");
    workspaceId = crypto.randomUUID();
    await pool.query("INSERT INTO workspaces (id, name, created_by, operator_writes_enabled) VALUES ($1, 'Renew E2E', $2, TRUE)", [workspaceId, approver]);
    await pool.query("INSERT INTO workspace_memberships (user_id, workspace_id, role) VALUES ($1, $2, 'workspace_manager')", [requester, workspaceId]);

    const fingerprint = crypto.createHash("sha256").update("renew-e2e").digest("hex");
    const prof = await pool.query(
      `INSERT INTO certificate_profiles (workspace_id, name, status, source, source_ref, issuer_id, renew_before_days, key_mode, public_metadata, created_by)
       VALUES ($1, 'p', 'active', 'manual', 'ref:e2e', NULL, 30, 'agent-local', $2::jsonb, $3) RETURNING id`,
      [workspaceId, JSON.stringify({ renewalProfile: profile() }), approver],
    );
    await pool.query(
        `INSERT INTO managed_certificates (workspace_id, source, source_ref, fingerprint_sha256, common_name, issuer, not_after, key_mode, key_reference, subject_alt_names, profile_id)
         VALUES ($1, 'agent_filesystem', 'file:///SENTINEL/x.pem', $2, 'app.example.com', 'CN=CA', NOW() + INTERVAL '20 days', 'agent-local', 'vault://SENTINEL', ARRAY['app.example.com']::text[], $3)`,
      [workspaceId, fingerprint, prof.rows[0].id],
    );
    identityId = (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id = $1 AND fingerprint_sha256 = $2", [workspaceId, fingerprint])).rows[0].id;

    const app = express();
    app.use(express.json());
    app.use("/api", guardOperatorCredentials);
    app.use(require("../../../apps/api/routes/operator"));
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    apiUrl = `http://127.0.0.1:${server.address().port}`;
    ({ plaintextCredential: credential } = await connections.createConnection({
      workspaceId, userId: requester, name: "renew-e2e", scopes: SCOPES, roleCeiling: "workspace_manager",
    }));
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    delete process.env.MCP_OPERATOR_WRITES_ENABLED;
    delete process.env.CERTOPS_ENABLED;
    await pool.end();
  });

  for (const [label, negotiation] of [["2025-era client", undefined], ["2026-07-28 client", { mode: { pin: "2026-07-28" } }]]) {
    it(`offers only the reading tools to a ${label} unless writes are switched on`, async () => {
      const transport = new StdioClientTransport({
        command: process.execPath, args: [BIN], stderr: "pipe",
        env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL: credential },
      });
      const client = new Client({ name: "ro", version: "0.0.1" }, negotiation ? { versionNegotiation: negotiation } : {});
      try {
        await client.connect(transport);
        const names = (await client.listTools()).tools.map((t) => t.name);
        assert.equal(names.length, 8);
        assert.ok(!names.some((n) => /request|preview|cancel/.test(n)));
        const refused = await client.callTool({ name: "tt_request_renew", arguments: {} }).catch((e) => ({ rejected: String(e.message) }));
        assert.ok(refused.isError === true || refused.rejected, "an unlisted write tool cannot be called");
      } finally {
        await client.close().catch(() => {});
      }
    });
  }

  it("takes a renewal from preview to a person's approval, and nothing runs before it", async () => {
    await session({ TOKENTIMER_MCP_ENABLE_WRITES: "true" }, async (client) => {
      const tools = (await client.listTools()).tools;
      assert.equal(tools.length, 13);
      const writeTools = tools.filter((t) => t.annotations?.readOnlyHint === false).map((t) => t.name).sort();
      assert.deepEqual(writeTools, ["tt_cancel_request", "tt_preview_renew", "tt_request_renew"]);

      const who = data(await call(client, "tt_whoami"));
      assert.equal(who.certops.mcpWritesEnabled, true);

      const found = data(await call(client, "tt_list_certificates", {}));
      assert.equal(found.items[0].id, identityId);

      const plan = data(await call(client, "tt_preview_renew", { identityId }));
      assert.equal(plan.effect.issuerEffect, "contacts_issuer");
      assert.equal(plan.effect.approvalAuthority, "other_manager_or_admin");
      assert.ok(!JSON.stringify(plan).includes("SENTINEL"));
      const before = await pool.query("SELECT COUNT(*)::int AS n FROM certificate_jobs WHERE workspace_id = $1 AND operation = 'renew'", [workspaceId]);
      assert.equal(before.rows[0].n, 0, "a preview creates nothing");

      const requestId = crypto.randomUUID();
      const request = data(await call(client, "tt_request_renew", { planId: plan.planId, planHash: plan.planHash, requestId }));
      assert.equal(request.state, "pending_approval");
      assert.equal(request.replayed, false);

      const job = (await pool.query("SELECT * FROM certificate_jobs WHERE id = $1", [request.jobId])).rows[0];
      assert.equal(job.status, "pending_approval", "nothing has run");
      assert.equal(job.requested_by_user_id, requester);
      assert.ok(job.requested_by_connection_id);

      // The requester cannot approve their own request, from anywhere.
      await assert.rejects(
        approvals.approveJob({ workspaceId, jobId: request.jobId, approverUserId: requester, reason: "me" }),
        (e) => e.code === "CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN",
      );
      assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id = $1", [request.jobId])).rows[0].status, "pending_approval");

      // A retry is a replay, not a second request.
      const replay = data(await call(client, "tt_request_renew", { planId: plan.planId, planHash: plan.planHash, requestId }));
      assert.equal(replay.replayed, true);
      assert.equal(replay.requestRecordId, request.requestRecordId);

      const mine = data(await call(client, "tt_list_my_requests", {}));
      assert.equal(mine.items[0].requestRecordId, request.requestRecordId);

      // A different person approves, and only then does the job become claimable.
      await approvals.approveJob({ workspaceId, jobId: request.jobId, approverUserId: approver, reason: "reviewed" });
      const after = data(await call(client, "tt_get_action_request", { requestRecordId: request.requestRecordId }));
      assert.equal(after.state, "approved");
      assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id = $1", [request.jobId])).rows[0].status, "pending");

      // And the job is visible through the ordinary job tools, without internals.
      const viewed = data(await call(client, "tt_get_job", { jobId: request.jobId }));
      assert.equal(viewed.job.summary.operation, "renew");
      assert.equal(viewed.job.approval.state, "approved");
    });
  });

  it("lets the assistant withdraw a request, and tells it plainly when a person got there first", async () => {
    await session({ TOKENTIMER_MCP_ENABLE_WRITES: "true" }, async (client) => {
      await pool.query("UPDATE certificate_jobs SET status = 'cancelled' WHERE workspace_id = $1 AND status IN ('pending_approval','pending','approved')", [workspaceId]);
      const plan = data(await call(client, "tt_preview_renew", { identityId }));
      const first = data(await call(client, "tt_request_renew", { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() }));
      const withdrawn = data(await call(client, "tt_cancel_request", { requestRecordId: first.requestRecordId }));
      assert.equal(withdrawn.state, "cancelled");

      const second = data(await call(client, "tt_request_renew", { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() }));
      await approvals.approveJob({ workspaceId, jobId: second.jobId, approverUserId: approver, reason: "first" });
      const late = await call(client, "tt_cancel_request", { requestRecordId: second.requestRecordId });
      assert.equal(late.isError, true);
      const error = JSON.parse(late.content[0].text);
      assert.equal(error.code, "MCP_CONFLICT");
      assert.equal(error.reason, "not_cancellable");
      assert.ok(!/prevented|stopped/i.test(error.message));
    });
  });

  it("explains a refusal in stable terms, and writes stay refused when the workspace turns them off", async () => {
    await session({ TOKENTIMER_MCP_ENABLE_WRITES: "true" }, async (client) => {
      await pool.query("UPDATE workspaces SET operator_writes_enabled = FALSE WHERE id = $1", [workspaceId]);
      try {
        const refused = await call(client, "tt_preview_renew", { identityId });
        assert.equal(refused.isError, true);
        assert.equal(JSON.parse(refused.content[0].text).code, "MCP_WRITES_DISABLED");
        assert.equal(data(await call(client, "tt_whoami")).certops.mcpWritesEnabled, false);
      } finally {
        await pool.query("UPDATE workspaces SET operator_writes_enabled = TRUE WHERE id = $1", [workspaceId]);
      }
    });
  });

  it("cuts off a connection mid-conversation: revoking it ends its waiting request", async () => {
    const own = await connections.createConnection({ workspaceId, userId: requester, name: "to-revoke", scopes: SCOPES, roleCeiling: "workspace_manager" });
    await pool.query("UPDATE certificate_jobs SET status = 'cancelled' WHERE workspace_id = $1 AND status IN ('pending_approval','pending','approved')", [workspaceId]);
    await session({ TOKENTIMER_MCP_ENABLE_WRITES: "true", TOKENTIMER_MCP_CREDENTIAL: own.plaintextCredential }, async (client) => {
      const plan = data(await call(client, "tt_preview_renew", { identityId }));
      const request = data(await call(client, "tt_request_renew", { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() }));
      await connections.revokeConnection({ workspaceId, connectionId: own.connection.id, revokedBy: approver });
      assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id = $1", [request.jobId])).rows[0].status, "cancelled");
      await assert.rejects(approvals.approveJob({ workspaceId, jobId: request.jobId, approverUserId: approver, reason: "late" }));
      const after = await call(client, "tt_get_action_request", { requestRecordId: request.requestRecordId });
      assert.equal(after.isError, true);
      assert.equal(JSON.parse(after.content[0].text).code, "MCP_UNAUTHENTICATED");
    });
  });
});
