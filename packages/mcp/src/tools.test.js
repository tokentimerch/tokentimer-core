"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { loadTools, bundle } = require("./tools");
const { planRequest } = require("./server");

const dir = path.resolve(__dirname, "../../contracts/mcp");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
const catalog = readJson("mcp-tool-catalog.json");
const fixtures = readJson("fixtures/read-tools.json");
const tools = loadTools();
const byName = new Map(tools.map((tool) => [tool.name, tool]));

describe("adapter tool set", () => {
  it("exposes exactly the first-release read tools the catalog marks implemented", () => {
    const expected = catalog.tools
      .filter((t) => t.contractStatus === "mvp" && t.routeStatus === "implemented")
      .map((t) => t.name)
      .sort();
    assert.deepEqual([...byName.keys()].sort(), expected);
    assert.equal(expected.length, 8);
  });

  it("exposes no write, outline or draft tool, however it is named", () => {
    for (const tool of catalog.tools.filter((t) => t.contractStatus !== "mvp")) {
      assert.ok(!byName.has(tool.name), `${tool.name} must not be registered`);
    }
    for (const tool of tools) assert.match(tool.name, /^tt_(whoami|list_|get_|explain_)/);
  });

  it("carries the catalog's annotations unchanged, and every tool is read-only", () => {
    for (const tool of tools) {
      const entry = catalog.tools.find((t) => t.name === tool.name);
      assert.deepEqual(tool.annotations, entry.annotations, tool.name);
      assert.equal(tool.annotations.readOnlyHint, true, tool.name);
      assert.equal(tool.annotations.destructiveHint, false, tool.name);
      assert.equal(tool.annotations.openWorldHint, false, tool.name);
    }
  });

  it("serves every tool from a GET route inside the operator namespace", () => {
    for (const tool of tools) {
      assert.match(tool.route, /^\/api\/v1\/operator\/[a-z]/, tool.name);
      const entry = catalog.tools.find((t) => t.name === tool.name);
      assert.ok(entry.route.startsWith("GET "), tool.name);
    }
  });

  it("builds each schema from the contract, with every reference inlined and no leftovers", () => {
    const needle = "$" + "ref";
    for (const tool of tools) {
      assert.ok(!JSON.stringify(tool.inputSchema).includes(needle), `${tool.name} input`);
      assert.ok(!JSON.stringify(tool.outputSchema).includes(needle), `${tool.name} output`);
      assert.ok(!JSON.stringify(tool).includes("$comment"));
      assert.equal(tool.inputSchema.type, "object");
      assert.equal(tool.inputSchema.additionalProperties, false, `${tool.name} input must be closed`);
      assert.equal(tool.outputSchema.additionalProperties, false, `${tool.name} output must be closed`);
    }
  });

  it("accepts every valid fixture and refuses every invalid one, for input and output", () => {
    for (const tool of tools) {
      const cases = fixtures[tool.name];
      cases.input.valid.forEach((example, i) => assert.equal(tool.validateInput(example), true, `${tool.name} input valid #${i}`));
      cases.input.invalid.forEach((example, i) => assert.equal(tool.validateInput(example), false, `${tool.name} input invalid #${i}`));
      cases.output.valid.forEach((example, i) => assert.equal(tool.validateOutput(example), true, `${tool.name} output valid #${i}`));
      cases.output.invalid.forEach((example, i) => assert.equal(tool.validateOutput(example), false, `${tool.name} output invalid #${i}`));
    }
  });

  it("offers no input a caller could use to bypass a control or name a workspace", () => {
    const forbidden = new Set(catalog.forbiddenInputParameters.map((n) => n.toLowerCase()));
    const names = (node, found = new Set()) => {
      if (Array.isArray(node)) node.forEach((n) => names(n, found));
      else if (node && typeof node === "object") {
        for (const [key, value] of Object.entries(node)) {
          if (key === "properties") Object.keys(value).forEach((k) => found.add(k.toLowerCase()));
          names(value, found);
        }
      }
      return found;
    };
    for (const tool of tools) {
      for (const name of names(tool.inputSchema)) assert.ok(!forbidden.has(name), `${tool.name} accepts "${name}"`);
    }
  });

  it("describes every tool, and none of the descriptions promise more than read-only access", () => {
    for (const tool of tools) {
      assert.ok(tool.description.length > 20, tool.name);
      assert.ok(!/\b(create|delete|revoke|approve|renew|issue|modify|change|write)\b/i.test(tool.description.replace(/renewal|issuance|revocation/gi, "")), `${tool.name}: ${tool.description}`);
    }
  });

  it("refuses a reference cycle instead of looping", () => {
    const doc = { definitions: { a: { $ref: "#/definitions/b" }, b: { $ref: "#/definitions/a" } } };
    assert.throws(() => bundle({ $ref: "#/definitions/a" }, {}, doc), /Cyclic/);
    assert.throws(() => bundle({ $ref: "missing.json#/x" }, {}, doc), /Unresolvable/);
  });
});

describe("request planning", () => {
  const tool = (name) => byName.get(name);

  it("puts identifiers in the path and everything else in the query", () => {
    const id = "550e8400-e29b-41d4-a716-446655440002";
    assert.deepEqual(planRequest(tool("tt_get_certificate_observations"), { identityId: id, limit: 5 }), {
      path: `/api/v1/operator/certificates/${id}/observations`,
      query: { limit: 5 },
    });
    assert.deepEqual(planRequest(tool("tt_list_jobs"), { status: "failed" }), {
      path: "/api/v1/operator/jobs",
      query: { status: "failed" },
    });
    assert.deepEqual(planRequest(tool("tt_whoami"), {}), { path: "/api/v1/operator/whoami", query: {} });
  });

  it("encodes a path value so it cannot add a segment", () => {
    const planned = planRequest(tool("tt_get_job"), { jobId: "../workspaces/x?y=1" });
    assert.ok(!planned.path.slice("/api/v1/operator/jobs/".length).includes("/"));
    assert.ok(!planned.path.includes("?"));
  });
});
