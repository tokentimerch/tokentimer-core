"use strict";

// Builds the tool set from the published contracts, so the catalog, the
// schemas and the adapter cannot disagree. Nothing here describes a tool's
// shape by hand: the input and output schemas, the annotations, the scope and
// the backing route all come from packages/contracts/mcp.

const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

function contractsDirectory() {
  const manifest = require.resolve("@tokentimer/contracts/package.json");
  return path.join(path.dirname(manifest), "mcp");
}

function readJson(dir, name) {
  return JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
}

// Inlines every $ref so each tool schema is self-contained, which is what an
// MCP client expects to receive from tools/list. The contract schemas have no
// reference cycles; a cycle would throw rather than loop.
function bundle(node, documents, base, seen = []) {
  if (Array.isArray(node)) return node.map((item) => bundle(item, documents, base, seen));
  if (!node || typeof node !== "object") return node;
  if (typeof node.$ref === "string") {
    const [file, pointer] = node.$ref.split("#");
    const document = file ? documents[file.split("/").pop()] : base;
    if (!document) throw new Error(`Unresolvable schema reference: ${node.$ref}`);
    const key = `${file}#${pointer}`;
    if (seen.includes(key)) throw new Error(`Cyclic schema reference: ${key}`);
    let target = document;
    for (const part of pointer.replace(/^\//, "").split("/")) target = target[part];
    return bundle(target, documents, document, [...seen, key]);
  }
  const out = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === "$comment" || key === "$id" || key === "$schema") continue;
    out[key] = bundle(value, documents, base, seen);
  }
  return out;
}

const DESCRIPTIONS = Object.freeze({
  tt_whoami:
    "Show which workspace this connection belongs to, the role it effectively holds right now, its scopes, and whether certificate operations are enabled or paused.",
  tt_list_certificates:
    "List certificates in the workspace. Filter by status, by expiry window, or by text matching names, issuer, subject alternative names or fingerprint. Returns a completeness object so you can tell no matches from a partial page.",
  tt_get_certificate:
    "Show one certificate: validity, lifecycle, management periods, renewal path and an observation summary. Give the certificate id from a list, or its SHA-256 fingerprint.",
  tt_get_certificate_observations:
    "Show where a certificate was observed and whether each location currently confirms it. Locations are reported by kind and freshness, never by path.",
  tt_get_agent_health:
    "Show agent liveness, version, compatibility and declared capabilities. Requires a manager role.",
  tt_get_job: "Show one job: status, approval state, attempt count, error code and, for a waiting job, why it is waiting.",
  tt_list_jobs: "List jobs by status, operation, certificate or recency.",
  tt_explain_certificate_state:
    "Explain why a certificate is in its current state, as stable reason codes with plain wording and the areas where evidence is missing.",
  tt_preview_renew:
    "Preview renewing one certificate. Changes nothing. Returns a plan, its hash, expiry and renewal effect, including issuer contact and whether workspace policy requires approval from someone else. Give the certificate id from a list.",
  tt_request_renew:
    "Submit a previewed renewal. Submission does not prove renewal: it queues a job under workspace CertOps job approval policy. When approval is on, a different person must approve before execution; when off, an eligible agent can claim it immediately. Pass the plan id and hash and a new random UUID as requestId. Reuse that requestId only to retry the same submission after a lost response; it returns the original outcome and never runs twice.",
  tt_get_action_request: "Show one of your requests: whether it is queued without approval, waiting for approval, approved, running, finished, rejected, withdrawn or expired.",
  tt_list_my_requests: "List your own requests, newest first.",
  tt_cancel_request:
    "Withdraw your request while waiting for approval or queued without approval. This works even when new requests are switched off. If approval or agent claim won first, it refuses rather than claiming to have stopped execution.",
});

// Write tools are only offered when the person running the adapter asks for
// them. This is a convenience for read-only setups, not a security control: the
// API refuses writes unless the instance, the workspace and the connection all
// allow them, whatever the adapter does.
function loadTools({ includeWrites = false } = {}) {
  const dir = contractsDirectory();
  const catalog = readJson(dir, "mcp-tool-catalog.json");
  const documents = {
    "mcp-common.schema.json": readJson(dir, "mcp-common.schema.json"),
    "mcp-read-tools.schema.json": readJson(dir, "mcp-read-tools.schema.json"),
    "mcp-renew-tools.schema.json": readJson(dir, "mcp-renew-tools.schema.json"),
  };

  const ajv = new Ajv({ allErrors: false, strict: false });
  addFormats(ajv);

  const wanted = (tool) =>
    tool.routeStatus === "implemented" &&
    (tool.contractStatus === "mvp" || (includeWrites && tool.contractStatus === "write"));

  return catalog.tools
    .filter(wanted)
    .map((tool) => {
      // A reference names its schema file, so each tool is read from its own.
      const documentFor = (ref) => documents[ref.split("#")[0]];
      const definition = (ref) => documentFor(ref).definitions[ref.split("/").pop()];
      const inputSchema = tool.input ? bundle(definition(tool.input), documents, documentFor(tool.input)) : { type: "object", additionalProperties: false, properties: {} };
      const outputSchema = bundle(definition(tool.output), documents, documentFor(tool.output));
      const [method, template] = tool.route.split(" ");
      if (method !== "GET" && method !== "POST") throw new Error(`${tool.name}: unsupported method ${method}`);
      return {
        name: tool.name,
        title: tool.title,
        description: DESCRIPTIONS[tool.name] || tool.title,
        scope: tool.scope,
        annotations: { ...tool.annotations },
        route: template,
        method,
        inputSchema,
        outputSchema,
        validateInput: ajv.compile(inputSchema),
        validateOutput: ajv.compile(outputSchema),
      };
    });
}

module.exports = { bundle, loadTools };
