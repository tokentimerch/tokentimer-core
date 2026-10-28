"use strict";

// The adapter as a real process, over real stdio, driven by the real client in
// both protocol eras, against a fake API. This is the closest a unit-level test
// gets to what an operator's MCP client experiences.

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { Client } = require("@modelcontextprotocol/client");
const { StdioClientTransport } = require("@modelcontextprotocol/client/stdio");

const BIN = path.resolve(__dirname, "../bin/tokentimer-mcp.js");
const fixtures = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/mcp/fixtures/read-tools.json"), "utf8"));
const catalog = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/mcp/mcp-tool-catalog.json"), "utf8"));
const CREDENTIAL = `ttopc_${"0123456789abcdef"}_${"a".repeat(64)}`;

let api;
let apiUrl;
let requests;
let forcedStatus;

before(async () => {
  requests = [];
  api = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, authorization: req.headers.authorization });
    if (forcedStatus) {
      res.writeHead(forcedStatus, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "SENTINEL_UPSTREAM_BODY" }));
      return;
    }
    const routes = {
      "/api/v1/operator/whoami": fixtures.tt_whoami.output.valid[0],
      "/api/v1/operator/agents": fixtures.tt_get_agent_health.output.valid[0],
      "/api/v1/operator/jobs": fixtures.tt_list_jobs.output.valid[0],
    };
    const body = routes[req.url.split("?")[0]];
    res.writeHead(body ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(body || { error: "not found" }));
  });
  await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
  apiUrl = `http://127.0.0.1:${api.address().port}`;
});

after(async () => {
  await new Promise((resolve) => api.close(resolve));
});

function open({ negotiation, env = {} } = {}) {
  const stderr = [];
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN],
    stderr: "pipe",
    env: { ...process.env, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL: CREDENTIAL, ...env },
  });
  transport.stderr?.on("data", (chunk) => stderr.push(String(chunk)));
  const client = new Client({ name: "adapter-test", version: "0.0.1" }, negotiation ? { versionNegotiation: negotiation } : {});
  return { client, transport, stderr };
}

async function withClient(options, body) {
  const session = open(options);
  try {
    await session.client.connect(session.transport);
    return await body(session);
  } finally {
    await session.client.close().catch(() => {});
  }
}

const ERAS = [
  ["2025-era handshake", undefined],
  ["2026-07-28, pinned", { mode: { pin: "2026-07-28" } }],
];

for (const [label, negotiation] of ERAS) {
  describe(`stdio server, ${label}`, () => {
    it("lists the eight read tools with the catalog's annotations and closed schemas", async () => {
      await withClient({ negotiation }, async ({ client }) => {
        const { tools } = await client.listTools();
        const expected = catalog.tools.filter((t) => t.contractStatus === "mvp").map((t) => t.name).sort();
        assert.deepEqual(tools.map((t) => t.name).sort(), expected);
        for (const tool of tools) {
          const entry = catalog.tools.find((t) => t.name === tool.name);
          assert.deepEqual(tool.annotations, entry.annotations, tool.name);
          assert.equal(tool.inputSchema.additionalProperties, false, tool.name);
          assert.equal(tool.outputSchema.additionalProperties, false, tool.name);
        }
      });
    });

    it("answers a call with structured content that equals the API's response", async () => {
      requests.length = 0;
      await withClient({ negotiation }, async ({ client }) => {
        const result = await client.callTool({ name: "tt_whoami", arguments: {} });
        assert.notEqual(result.isError, true);
        assert.deepEqual(result.structuredContent, fixtures.tt_whoami.output.valid[0]);
        assert.deepEqual(JSON.parse(result.content[0].text), fixtures.tt_whoami.output.valid[0]);
      });
      assert.equal(requests.length, 1);
      assert.equal(requests[0].method, "GET");
      assert.equal(requests[0].authorization, `Bearer ${CREDENTIAL}`);
    });

    it("passes filters through as a query string and nothing else", async () => {
      requests.length = 0;
      await withClient({ negotiation }, async ({ client }) => {
        const result = await client.callTool({ name: "tt_list_jobs", arguments: { status: "failed", limit: 5 } });
        assert.notEqual(result.isError, true);
      });
      assert.equal(requests[0].url, "/api/v1/operator/jobs?status=failed&limit=5");
    });

    it("refuses invalid and over-wide arguments without contacting the API", async () => {
      requests.length = 0;
      await withClient({ negotiation }, async ({ client }) => {
        for (const args of [{ limit: 999 }, { force: true }, { workspaceId: "x" }, { status: "stuck" }]) {
          const result = await client.callTool({ name: "tt_list_jobs", arguments: args });
          assert.equal(result.isError, true, JSON.stringify(args));
        }
        const unknown = await client.callTool({ name: "tt_request_renew", arguments: {} }).catch((error) => ({ rejected: error.message }));
        assert.ok(unknown.isError === true || unknown.rejected, "a write tool must not exist");
      });
      assert.equal(requests.length, 0, "invalid input must never leave the process");
    });

    it("reports an API refusal as a stable tool error that reveals nothing about the API", async () => {
      forcedStatus = 403;
      try {
        await withClient({ negotiation }, async ({ client }) => {
          const result = await client.callTool({ name: "tt_get_agent_health", arguments: {} });
          assert.equal(result.isError, true);
          const shaped = JSON.parse(result.content[0].text);
          assert.equal(shaped.code, "MCP_SCOPE_DENIED");
          const text = JSON.stringify(result);
          assert.ok(!text.includes("SENTINEL_UPSTREAM_BODY"));
          assert.ok(!text.includes(apiUrl));
          assert.ok(!text.includes(CREDENTIAL));
        });
      } finally {
        forcedStatus = undefined;
      }
    });

    it("never writes the credential to stderr, and stdout carries only protocol messages", async () => {
      await withClient({ negotiation }, async ({ client, stderr }) => {
        await client.callTool({ name: "tt_whoami", arguments: {} });
        await client.callTool({ name: "tt_get_agent_health", arguments: {} });
        const logged = stderr.join("");
        assert.ok(!logged.includes(CREDENTIAL));
        assert.ok(!logged.includes("0123456789abcdef"));
        assert.ok(!logged.includes(apiUrl));
      });
    });
  });
}

describe("stdio server, startup and compatibility policy", () => {
  it("serves the qualified assistant's 2025-06-18 handshake with the same tool schema enforcement", async () => {
    const child = spawn(process.execPath, [BIN], { stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL: CREDENTIAL } });
    const lines = require("node:readline").createInterface({ input: child.stdout });
    const pending = new Map();
    lines.on("line", line => { const message = JSON.parse(line); pending.get(message.id)?.(message); });
    let id = 0;
    const call = (method, params) => new Promise((resolve, reject) => {
      const requestId = ++id;
      const timer = setTimeout(() => reject(new Error("Legacy handshake timed out")), 10000);
      pending.set(requestId, value => { clearTimeout(timer); pending.delete(requestId); resolve(value); });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
    });
    try {
      const initialized = await call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "qualification-regression", version: "1" } });
      assert.equal(initialized.result.protocolVersion, "2025-06-18");
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      assert.equal((await call("tools/list", {})).result.tools.length, 8);
      const result = await call("tools/call", { name: "tt_whoami", arguments: {} });
      assert.deepEqual(result.result.structuredContent, fixtures.tt_whoami.output.valid[0]);
      const before = requests.length;
      const invalid = await call("tools/call", { name: "tt_whoami", arguments: { force: true } });
      assert.ok(invalid.error || invalid.result?.isError);
      assert.equal(requests.length, before);
    } finally { lines.close(); child.stdin.end(); child.kill(); }
  });

  it("serves a 2025-era client by default and refuses one when told to reject legacy", async () => {
    await withClient({ env: { TOKENTIMER_MCP_LEGACY: "serve" } }, async ({ client }) => {
      assert.equal((await client.listTools()).tools.length, 8);
    });
    const { client, transport } = open({ env: { TOKENTIMER_MCP_LEGACY: "reject" } });
    await assert.rejects(client.connect(transport), /Unsupported protocol version/);
    await client.close().catch(() => {});
  });

  it("still serves a client pinned to the modern revision when legacy is rejected", async () => {
    await withClient({ negotiation: { mode: { pin: "2026-07-28" } }, env: { TOKENTIMER_MCP_LEGACY: "reject" } }, async ({ client }) => {
      assert.equal((await client.listTools()).tools.length, 8);
    });
  });

  it("exits with a clear message and no secret when configuration is wrong", () => {
    const cases = [
      [{ TOKENTIMER_MCP_CREDENTIAL: "" }, /credential is required/],
      [{ TOKENTIMER_MCP_CREDENTIAL: "ttopc_not_valid_at_all" }, /expected format/],
      [{ TOKENTIMER_API_URL: "http://tokentimer.example.com" }, /https/],
      [{ TOKENTIMER_API_URL: "" }, /TOKENTIMER_API_URL is required/],
    ];
    for (const [override, pattern] of cases) {
      const run = spawnSync(process.execPath, [BIN], {
        env: { PATH: process.env.PATH, TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL: CREDENTIAL, ...override },
        encoding: "utf8",
        timeout: 15000,
      });
      assert.equal(run.status, 2, JSON.stringify(override));
      assert.match(run.stderr, pattern);
      assert.equal(run.stdout, "", "nothing may be written to the protocol stream on a configuration error");
      assert.ok(!run.stderr.includes("0123456789abcdef"));
    }
  });
});
