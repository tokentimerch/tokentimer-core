import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const mcpDir = path.join(repoRoot, "packages/contracts/mcp");
const BASE_ID = "https://tokentimer.io/contracts/mcp/";

function load(relative) {
  return JSON.parse(fs.readFileSync(path.join(mcpDir, relative), "utf8"));
}

const common = load("mcp-common.schema.json");
const readTools = load("mcp-read-tools.schema.json");
const writeDraft = load("mcp-write-envelope.draft.schema.json");
const renewTools = load("mcp-renew-tools.schema.json");
const catalog = load("mcp-tool-catalog.json");
const fixtures = load("fixtures/read-tools.json");

function newAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(common);
  ajv.addSchema(readTools);
  ajv.addSchema(writeDraft);
  ajv.addSchema(renewTools);
  return ajv;
}

function validatorFor(ajv, ref) {
  const validate = ajv.getSchema(`${BASE_ID}${ref}`);
  assert.ok(validate, `schema reference does not resolve: ${ref}`);
  return validate;
}

// Visits every schema node that declares properties.
function walkObjectNodes(node, visit) {
  if (Array.isArray(node)) {
    node.forEach((item) => walkObjectNodes(item, visit));
    return;
  }
  if (!node || typeof node !== "object") return;
  if (node.properties && typeof node.properties === "object") visit(node);
  Object.values(node).forEach((value) => walkObjectNodes(value, visit));
}

function propertyNames(node) {
  const names = [];
  walkObjectNodes(node, (objectNode) => {
    names.push(...Object.keys(objectNode.properties));
  });
  return names;
}

const mvpTools = catalog.tools.filter((tool) => tool.contractStatus === "mvp");

describe("MCP tool contracts (ADR-0015)", () => {
  it("compiles every MCP schema", () => {
    const ajv = newAjv();
    for (const id of Object.keys(readTools.definitions)) {
      assert.ok(ajv.getSchema(`${readTools.$id}#/definitions/${id}`), `read definition ${id}`);
    }
    for (const id of Object.keys(writeDraft.definitions)) {
      assert.ok(ajv.getSchema(`${writeDraft.$id}#/definitions/${id}`), `draft definition ${id}`);
    }
    for (const id of Object.keys(renewTools.definitions)) {
      assert.ok(ajv.getSchema(`${renewTools.$id}#/definitions/${id}`), `renew definition ${id}`);
    }
  });

  it("keeps every object closed so fields are disclosed only deliberately", () => {
    for (const schema of [common, readTools, writeDraft, renewTools]) {
      walkObjectNodes(schema, (node) => {
        assert.strictEqual(
          node.additionalProperties,
          false,
          `${schema.$id}: object with properties ${Object.keys(node.properties).join(", ")} must set additionalProperties: false`,
        );
      });
    }
  });

  it("never names an authority-bearing or secret-bearing output field", () => {
    const forbidden = new Set(catalog.forbiddenOutputFields.map((name) => name.toLowerCase()));
    for (const schema of [common, readTools, writeDraft, renewTools]) {
      for (const name of propertyNames(schema)) {
        assert.ok(!forbidden.has(name.toLowerCase()), `${schema.$id} exposes forbidden field "${name}"`);
      }
    }
  });

  it("never accepts bypass or identity parameters as tool input", () => {
    const forbidden = new Set(catalog.forbiddenInputParameters.map((name) => name.toLowerCase()));
    const inputNodes = [
      ...Object.entries(readTools.definitions)
        .filter(([name]) => name.endsWith("_input"))
        .map(([, node]) => node),
      writeDraft.definitions.submission,
      writeDraft.definitions.withdrawal,
      ...Object.entries(renewTools.definitions)
        .filter(([name]) => name.endsWith("_input"))
        .map(([, node]) => node),
    ];
    for (const node of inputNodes) {
      for (const name of propertyNames(node)) {
        assert.ok(!forbidden.has(name.toLowerCase()), `tool input accepts forbidden parameter "${name}"`);
      }
    }
  });

  it("keeps the scope vocabulary identical in the catalog and the schemas", () => {
    const catalogScopes = catalog.scopes.map((scope) => scope.name).sort();
    assert.deepStrictEqual([...common.definitions.scope.enum].sort(), catalogScopes);
  });

  it("gives every tool a unique name, a declared scope and a matching minimum role", () => {
    const names = new Set();
    const scopes = new Map(catalog.scopes.map((scope) => [scope.name, scope]));
    for (const tool of catalog.tools) {
      assert.ok(!names.has(tool.name), `duplicate tool ${tool.name}`);
      names.add(tool.name);
      assert.ok(scopes.has(tool.scope), `${tool.name}: undeclared scope ${tool.scope}`);
      assert.strictEqual(tool.minRole, scopes.get(tool.scope).minRole, `${tool.name}: role must match its scope`);
      assert.ok(["mvp", "write", "outline", "draft"].includes(tool.contractStatus), `${tool.name}: unknown contractStatus`);
    }
  });

  it("makes the first read-only release exactly the eight reviewed read tools", () => {
    assert.deepStrictEqual(mvpTools.map((tool) => tool.name).sort(), [
      "tt_explain_certificate_state",
      "tt_get_agent_health",
      "tt_get_certificate",
      "tt_get_certificate_observations",
      "tt_get_job",
      "tt_list_certificates",
      "tt_list_jobs",
      "tt_whoami",
    ]);
    for (const tool of mvpTools) {
      assert.strictEqual(tool.annotations.readOnlyHint, true, `${tool.name} must be read-only`);
      assert.strictEqual(tool.annotations.destructiveHint, false);
      assert.ok(tool.input && tool.output && tool.route && tool.routeStatus, `${tool.name} needs schemas and a route`);
    }
  });

  it("never grants a tool looser access than the existing session route it is built on", () => {
    const rank = { viewer: 1, workspace_manager: 2, admin: 3 };
    for (const tool of mvpTools) {
      assert.ok(rank[tool.sessionRouteMinRole], `${tool.name}: record the role the session route requires`);
      assert.ok(
        rank[tool.minRole] >= rank[tool.sessionRouteMinRole],
        `${tool.name}: minRole ${tool.minRole} is looser than the session route (${tool.sessionRouteMinRole})`,
      );
    }
    const agents = mvpTools.find((tool) => tool.name === "tt_get_agent_health");
    assert.strictEqual(agents.minRole, "workspace_manager", "fleet metadata is manager-only today");
  });

  it("does not make any write contract final", () => {
    const writeTools = catalog.tools.filter((tool) => tool.annotations.readOnlyHint === false);
    assert.ok(writeTools.length > 0);
    for (const tool of writeTools) {
      assert.notStrictEqual(tool.contractStatus, "mvp", `${tool.name} is a write tool and cannot be in the read-only set`);
    }
    for (const tool of catalog.tools.filter((entry) => entry.contractStatus === "outline")) {
      assert.ok(!tool.input && !tool.output, `${tool.name}: outline tools carry no schema yet`);
    }
  });

  it("limits the pending-request withdrawal exception to tt_cancel_request", () => {
    const exceptions = catalog.tools.filter((tool) => tool.withdrawalException).map((tool) => tool.name);
    assert.deepStrictEqual(exceptions, ["tt_cancel_request"]);
  });

  it("resolves every schema reference named in the catalog", () => {
    const ajv = newAjv();
    for (const tool of catalog.tools) {
      for (const key of ["input", "output"]) {
        if (tool[key]) validatorFor(ajv, tool[key]);
      }
    }
  });

  for (const tool of mvpTools) {
    describe(tool.name, () => {
      const cases = fixtures[tool.name];

      it("has fixtures for valid and invalid input and output", () => {
        assert.ok(cases, `fixtures missing for ${tool.name}`);
        for (const side of ["input", "output"]) {
          assert.ok(cases[side].valid.length > 0, `${tool.name} ${side}: needs a valid example`);
          assert.ok(cases[side].invalid.length > 0, `${tool.name} ${side}: needs an invalid example`);
        }
      });

      for (const side of ["input", "output"]) {
        it(`accepts valid and rejects invalid ${side}`, () => {
          const validate = validatorFor(newAjv(), tool[side]);
          cases[side].valid.forEach((example, index) => {
            assert.strictEqual(
              validate(example),
              true,
              `valid ${side} #${index} rejected: ${JSON.stringify(validate.errors)}`,
            );
          });
          cases[side].invalid.forEach((example, index) => {
            assert.strictEqual(validate(example), false, `invalid ${side} #${index} was accepted`);
          });
        });
      }
    });
  }

  describe("draft write envelope", () => {
    const ajv = newAjv();
    const submission = ajv.getSchema(`${writeDraft.$id}#/definitions/submission`);
    const goodSubmission = {
      planId: "550e8400-e29b-41d4-a716-446655440010",
      planHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      requestId: "550e8400-e29b-41d4-a716-446655440011",
    };

    it("accepts exactly planId, planHash and requestId", () => {
      assert.strictEqual(submission(goodSubmission), true);
      assert.strictEqual(submission({ ...goodSubmission, force: true }), false);
      assert.strictEqual(submission({ ...goodSubmission, skipApproval: true }), false);
      assert.strictEqual(submission({ ...goodSubmission, acknowledgeUncertainty: true }), false);
      const { requestId, ...withoutRequestId } = goodSubmission;
      assert.ok(requestId);
      assert.strictEqual(submission(withoutRequestId), false);
    });

    it("keeps the JSON-RPC id out of the business identifiers", () => {
      const record = ajv.getSchema(`${writeDraft.$id}#/definitions/requestRecord`);
      const base = {
        requestRecordId: "550e8400-e29b-41d4-a716-446655440012",
        requestId: goodSubmission.requestId,
        state: "pending_approval",
        stateReason: null,
        jobId: null,
        replayed: false,
        approvalExpiresAt: "2026-10-20T12:00:00Z",
      };
      assert.strictEqual(record(base), true);
      assert.strictEqual(record({ ...base, jsonRpcId: 7 }), false);
      assert.strictEqual(record({ ...base, state: "approving" }), false);
    });

    it("states the effect of an issuance including standing renewal", () => {
      const preview = ajv.getSchema(`${writeDraft.$id}#/definitions/previewResult`);
      const valid = {
        planId: goodSubmission.planId,
        planHash: goodSubmission.planHash,
        expiresAt: "2026-10-19T12:10:00Z",
        effect: {
          operation: "issue",
          lifecycleEffect: "provisions_certificate",
          issuerEffect: "contacts_issuer",
          standingRenewal: { createsAutomaticRenewal: true, futureRenewalsNeedApproval: false },
          approvalAuthority: "other_admin",
          warnings: [],
        },
      };
      assert.strictEqual(preview(valid), true);
      const withoutRenewal = structuredClone(valid);
      delete withoutRenewal.effect.standingRenewal;
      assert.strictEqual(preview(withoutRenewal), false);
    });

    it("never lets a lifecycle-only operation claim an issuer effect in its type", () => {
      const effect = writeDraft.definitions.resolvedEffect.properties;
      assert.ok(effect.issuerEffect.enum.includes("none"));
      assert.ok(!effect.operation.enum.includes("ca_revoke"), "CA revocation is not part of the lifecycle envelope");
    });
  });
});
