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
});

function loadTools() {
  const dir = contractsDirectory();
  const catalog = readJson(dir, "mcp-tool-catalog.json");
  const documents = {
    "mcp-common.schema.json": readJson(dir, "mcp-common.schema.json"),
    "mcp-read-tools.schema.json": readJson(dir, "mcp-read-tools.schema.json"),
  };
  const readTools = documents["mcp-read-tools.schema.json"];

  const ajv = new Ajv({ allErrors: false, strict: false });
  addFormats(ajv);

  return catalog.tools
    .filter((tool) => tool.contractStatus === "mvp" && tool.routeStatus === "implemented")
    .map((tool) => {
      const definition = (ref) => readTools.definitions[ref.split("/").pop()];
      const inputSchema = bundle(definition(tool.input), documents, readTools);
      const outputSchema = bundle(definition(tool.output), documents, readTools);
      const [method, template] = tool.route.split(" ");
      if (method !== "GET") throw new Error(`${tool.name}: only GET routes are supported`);
      return {
        name: tool.name,
        title: tool.title,
        description: DESCRIPTIONS[tool.name] || tool.title,
        scope: tool.scope,
        annotations: { ...tool.annotations },
        route: template,
        inputSchema,
        outputSchema,
        validateInput: ajv.compile(inputSchema),
        validateOutput: ajv.compile(outputSchema),
      };
    });
}

module.exports = { bundle, loadTools };
