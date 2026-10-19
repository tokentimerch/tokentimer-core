"use strict";

// The whole journey with nothing faked: a person creates a grant on the real
// API, the real `tokentimer-mcp enroll` process redeems it and writes the
// credential file, and the real server process then answers a real MCP client
// using only that file.

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const express = require("../../../apps/api/node_modules/express");
const { Client } = require("@modelcontextprotocol/client");
const { StdioClientTransport } = require("@modelcontextprotocol/client/stdio");
const { pool } = require("../../../apps/api/db/database");
const enrollments = require("../../../apps/api/services/operator/enrollments");
const { guardOperatorCredentials } = require("../../../apps/api/middleware/operator-connection-auth");

const BIN = path.resolve(__dirname, "../bin/tokentimer-mcp.js");

let server;
let apiUrl;
let owner;
let workspaceId;
let tmp;
let sequence = 0;

async function createUser(label) {
  const result = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified) VALUES ($1, $2, 'local', 'x', TRUE) RETURNING id`,
    [`${label}-${crypto.randomUUID()}@example.test`, label],
  );
  return result.rows[0].id;
}

function runEnrollProcess({ input, args = [], env = {} }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, "enroll", ...args], {
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
    setTimeout(() => child.kill(), 30000).unref();
  });
}

function newGrant(overrides = {}) {
  return enrollments.createGrant({
    workspaceId,
    userId: owner,
    name: `e2e-${++sequence}`,
    scopes: ["mcp:identity:read", "mcp:certs:read", "mcp:jobs:read"],
    roleCeiling: "admin",
    ...overrides,
  });
}

describe("enroll then serve, as real processes against the real API", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
    process.env.CERTOPS_ENABLED = "true";
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tt-mcp-journey-"));
    owner = await createUser("owner");
    workspaceId = crypto.randomUUID();
    await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, 'Journey', $2)", [workspaceId, owner]);

    const app = express();
    app.use(express.json());
    app.use("/api", guardOperatorCredentials);
    app.use(require("../../../apps/api/routes/operator"));
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    apiUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    delete process.env.CERTOPS_ENABLED;
    await pool.end();
  });

  it("goes from a setup code to a working assistant using only the stored file", async () => {
    const { plaintextGrant } = await newGrant({ name: "journey" });
    const file = path.join(tmp, "journey", "credential");

    const enrolled = await runEnrollProcess({ input: `${plaintextGrant}\n`, args: ["--api-url", apiUrl, "--credential-file", file] });
    assert.equal(enrolled.code, 0, enrolled.stderr);
    assert.match(enrolled.stdout, /Connected\./);
    assert.ok(fs.existsSync(file));
    const stored = fs.readFileSync(file, "utf8").trim();
    assert.match(stored, /^ttopc_[a-f0-9]{16}_[a-f0-9]{64}$/);
    for (const text of [enrolled.stdout, enrolled.stderr]) {
      assert.ok(!text.includes(plaintextGrant) && !text.includes(stored.slice(23)), "no secret on the terminal");
    }
    if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [BIN],
      stderr: "pipe",
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL_FILE: file },
    });
    const client = new Client({ name: "journey", version: "0.0.1" });
    try {
      await client.connect(transport);
      const who = await client.callTool({ name: "tt_whoami", arguments: {} });
      assert.notEqual(who.isError, true, who.content?.[0]?.text);
      assert.equal(who.structuredContent.workspace.id, workspaceId);
      assert.deepEqual([...who.structuredContent.connection.scopes].sort(), ["mcp:certs:read", "mcp:identity:read", "mcp:jobs:read"]);
      const denied = await client.callTool({ name: "tt_get_agent_health", arguments: {} });
      assert.equal(denied.isError, true, "a scope the grant never carried stays out of reach");
      assert.equal(JSON.parse(denied.content[0].text).code, "MCP_SCOPE_DENIED");
    } finally {
      await client.close().catch(() => {});
    }
  });

  it("burns the code exactly once: a second run reports it used and writes nothing", async () => {
    const { plaintextGrant } = await newGrant({ name: "twice" });
    const first = await runEnrollProcess({ input: `${plaintextGrant}\n`, args: ["--api-url", apiUrl, "--credential-file", path.join(tmp, "a", "credential")] });
    assert.equal(first.code, 0, first.stderr);
    const second = await runEnrollProcess({ input: `${plaintextGrant}\n`, args: ["--api-url", apiUrl, "--credential-file", path.join(tmp, "b", "credential")] });
    assert.equal(second.code, 1);
    assert.match(second.stderr, /already used/);
    assert.equal(fs.existsSync(path.join(tmp, "b", "credential")), false);
  });

  it("refuses the code on the command line in a real process, before touching the network", async () => {
    const { plaintextGrant } = await newGrant({ name: "argv" });
    const result = await runEnrollProcess({ input: "", args: ["--api-url", apiUrl, plaintextGrant] });
    assert.equal(result.code, 2);
    assert.match(result.stderr, /Do not pass the setup code as an argument/);
    assert.ok(!result.stderr.includes(plaintextGrant));
    const row = await pool.query("SELECT status FROM operator_enrollment_grants WHERE grant_prefix = $1", [plaintextGrant.slice(0, 22)]);
    assert.equal(row.rows[0].status, "pending", "the refused attempt did not spend the code");
  });

  it("keeps serving with no command exactly as before, and rejects an unknown command", async () => {
    const unknown = await new Promise((resolve) => {
      const child = spawn(process.execPath, [BIN, "frobnicate"], { stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      let stdout = "";
      child.stderr.on("data", (c) => (stderr += c));
      child.stdout.on("data", (c) => (stdout += c));
      child.on("close", (code) => resolve({ code, stderr, stdout }));
    });
    assert.equal(unknown.code, 2);
    assert.match(unknown.stderr, /unknown command/);
    assert.equal(unknown.stdout, "", "nothing may reach the protocol stream");
  });
});
