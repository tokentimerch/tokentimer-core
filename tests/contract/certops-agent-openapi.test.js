/**
 * Contract Tests - CertOps agent routes vs OpenAPI / route-compat / agent-protocol
 *
 * Static assertions (no runtime API needed):
 *  1. The four /api/v1/certops/agent routes are documented in the static
 *     OpenAPI spec with the auth split frozen in
 *     packages/contracts/api/certops-route-compat.contract.json.
 *  2. The route-compat contract carries the agent-runtime version/status and keeps all
 *     four agent routes in routeAuth and stableRoutes.
 *  3. The OpenAPI request-body envelope mirrors
 *     packages/contracts/certops/agent-protocol.schema.json (required
 *     envelope fields and the messageType enum), and each operation pins the
 *     correct per-route messageType(s).
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");

const openApiYaml = fs.readFileSync(
  path.join(repoRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);
const routeCompat = JSON.parse(
  fs.readFileSync(
    path.join(
      repoRoot,
      "packages/contracts/api/certops-route-compat.contract.json",
    ),
    "utf8",
  ),
);
const agentProtocol = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "packages/contracts/certops/agent-protocol.schema.json"),
    "utf8",
  ),
);

const AGENT_ROUTES = {
  "/api/v1/certops/agent/register": "agentBootstrapTokenAuth",
  "/api/v1/certops/agent/heartbeat": "agentCredentialAuth",
  "/api/v1/certops/agent/jobs/claim": "agentCredentialAuth",
  "/api/v1/certops/agent/jobs/results": "agentCredentialAuth",
};

/**
 * Extracts the YAML block for one path entry: from the `  /path:` line up to
 * the next line that starts a sibling two-space-indented key (another path
 * or the `components:` root key).
 */
function extractPathBlock(yaml, routePath) {
  const marker = `\n  ${routePath}:`;
  const start = yaml.indexOf(marker);
  assert.ok(start !== -1, `OpenAPI is missing path: ${routePath}`);
  const bodyStart = start + marker.length;
  const rest = yaml.slice(bodyStart);
  const nextSibling = rest.search(/\n(?: {2}\/|components:)/);
  return nextSibling === -1 ? rest : rest.slice(0, nextSibling);
}

/**
 * Extracts one component schema block from `    Name:` until the next
 * four-space-indented sibling key.
 */
function extractSchemaBlock(yaml, schemaName) {
  const marker = `\n    ${schemaName}:`;
  const start = yaml.indexOf(marker);
  assert.ok(start !== -1, `OpenAPI is missing component schema: ${schemaName}`);
  const rest = yaml.slice(start + marker.length);
  const nextSibling = rest.search(/\n {4}[A-Za-z]/);
  return nextSibling === -1 ? rest : rest.slice(0, nextSibling);
}

describe("CertOps agent routes OpenAPI contract", () => {
  it("documents all four agent paths with the frozen auth split", () => {
    for (const [routePath, scheme] of Object.entries(AGENT_ROUTES)) {
      const block = extractPathBlock(openApiYaml, routePath);
      assert.ok(
        /\n    post:/.test(block),
        `${routePath} must document a POST operation`,
      );
      assert.ok(
        block.includes(`- ${scheme}: []`),
        `${routePath} must use security scheme ${scheme}`,
      );
      const otherSchemes = [
        "cookieAuth",
        "certOpsTokenAuth",
        ...Object.values(AGENT_ROUTES),
      ].filter((name) => name !== scheme);
      for (const other of otherSchemes) {
        assert.ok(
          !block.includes(`- ${other}: []`),
          `${routePath} must not additionally allow ${other}`,
        );
      }
    }
  });

  it("declares both agent bearer security schemes as non-cookie http bearer", () => {
    for (const scheme of ["agentBootstrapTokenAuth", "agentCredentialAuth"]) {
      const block = extractSchemaBlock(
        openApiYaml.slice(openApiYaml.indexOf("\n  securitySchemes:")),
        scheme,
      );
      assert.ok(
        /type: http/.test(block) && /scheme: bearer/.test(block),
        `${scheme} must be declared as http bearer`,
      );
      assert.ok(
        !/in: cookie/.test(block),
        `${scheme} must not be cookie-based`,
      );
    }
  });

  it("documents the implemented response and error surface per route", () => {
    const expectations = {
      "/api/v1/certops/agent/register": {
        success: '"201"',
        codes: [
          "CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED",
          "CERTOPS_AGENT_REGISTRATION_CONFLICT",
          "PRIVATE_KEY_MATERIAL_REJECTED",
        ],
        statuses: ['"401"', '"404"', '"409"', '"422"', '"429"'],
      },
      "/api/v1/certops/agent/heartbeat": {
        success: '"200"',
        codes: ["CERTOPS_AGENT_RETIRED", "PRIVATE_KEY_MATERIAL_REJECTED"],
        statuses: ['"401"', '"404"', '"410"', '"422"', '"429"'],
      },
      "/api/v1/certops/agent/jobs/claim": {
        success: '"200"',
        codes: [
          "CERTOPS_WORKSPACE_PAUSED",
          "CERTOPS_AGENT_RETIRED",
          "PRIVATE_KEY_MATERIAL_REJECTED",
        ],
        statuses: ['"401"', '"404"', '"409"', '"410"', '"422"', '"429"'],
      },
      "/api/v1/certops/agent/jobs/results": {
        success: '"200"',
        codes: [
          "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH",
          "CERTOPS_AGENT_RESULT_NONCE_REJECTED",
          "CERTOPS_AGENT_RETIRED",
          "PRIVATE_KEY_MATERIAL_REJECTED",
        ],
        statuses: ['"400"', '"401"', '"404"', '"409"', '"410"', '"422"', '"429"'],
      },
    };

    for (const [routePath, expected] of Object.entries(expectations)) {
      const block = extractPathBlock(openApiYaml, routePath);
      assert.ok(
        block.includes(`${expected.success}:`),
        `${routePath} must document success status ${expected.success}`,
      );
      for (const status of expected.statuses) {
        assert.ok(
          block.includes(`${status}:`),
          `${routePath} must document status ${status}`,
        );
      }
      for (const code of expected.codes) {
        assert.ok(
          block.includes(code),
          `${routePath} must reference error code ${code}`,
        );
      }
    }
  });

  it("documents register success and claim signed-job dispatch fields", () => {
    const registerResponse = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentRegisterResponse",
    );
    for (const field of [
      "agentId",
      "credential",
      "protocolVersion",
      "signingKeyId",
      "signingPublicKeyPem",
    ]) {
      assert.ok(
        registerResponse.includes(`${field}:`),
        `CertOpsAgentRegisterResponse must document ${field}`,
      );
    }

    const claimResponse = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentClaimResponse",
    );
    assert.ok(
      claimResponse.includes("jobs:"),
      "CertOpsAgentClaimResponse must wrap signed jobs in a jobs array",
    );
    for (const field of [
      "nonce",
      "issuedAt",
      "expiresAt",
      "signingKeyId",
      "signature",
    ]) {
      assert.ok(
        claimResponse.includes(`${field}:`),
        `CertOpsAgentClaimResponse signed job must document ${field}`,
      );
    }
  });
});

describe("CertOps route-compat contract (agent runtime)", () => {
  it("carries the agent-runtime version and status", () => {
    assert.strictEqual(routeCompat.version, "0.14.0");
    assert.strictEqual(routeCompat.status, "agent-runtime-stable");
  });

  it("keeps the four agent routes frozen in routeAuth with the auth split", () => {
    for (const [routePath, scheme] of Object.entries(AGENT_ROUTES)) {
      assert.strictEqual(
        routeCompat.routeAuth[routePath],
        scheme,
        `routeAuth for ${routePath} must stay ${scheme}`,
      );
    }
  });

  it("keeps the four agent routes in stableRoutes as POST", () => {
    const stable = routeCompat.guarantees.stableRoutes;
    for (const routePath of Object.keys(AGENT_ROUTES)) {
      assert.ok(
        stable.some(
          (route) => route.path === routePath && route.method === "POST",
        ),
        `stableRoutes must keep POST ${routePath}`,
      );
    }
  });

  it("keeps every stable route documented in static OpenAPI", () => {
    for (const route of routeCompat.guarantees.stableRoutes) {
      assert.ok(
        openApiYaml.includes(`${route.path}:`),
        `route-compat contains path missing in OpenAPI: ${route.path}`,
      );
    }
  });
});

describe("OpenAPI agent request bodies align with agent-protocol.schema.json", () => {
  const envelopeBlock = extractSchemaBlock(
    openApiYaml,
    "CertOpsAgentProtocolEnvelope",
  );

  it("mirrors the required envelope fields", () => {
    for (const field of agentProtocol.required) {
      assert.ok(
        new RegExp(`- ${field}\\b`).test(envelopeBlock),
        `envelope schema must require ${field} (from agent-protocol.schema.json)`,
      );
      assert.ok(
        envelopeBlock.includes(`${field}:`),
        `envelope schema must define property ${field}`,
      );
    }
  });

  it("mirrors the full messageType enum", () => {
    const schemaEnum = agentProtocol.properties.messageType.enum;
    assert.deepStrictEqual(schemaEnum, [
      "register",
      "heartbeat",
      "claim",
      "result",
      "evidence",
    ]);
    assert.ok(
      envelopeBlock.includes(`enum: [${schemaEnum.join(", ")}]`),
      "envelope messageType enum must match agent-protocol.schema.json",
    );
  });

  it("pins the per-route messageType in each request schema", () => {
    const pins = {
      CertOpsAgentRegisterRequest: "enum: [register]",
      CertOpsAgentHeartbeatRequest: "enum: [heartbeat]",
      CertOpsAgentClaimRequest: "enum: [claim]",
      CertOpsAgentResultRequest: "enum: [result, evidence]",
    };
    for (const [schemaName, pin] of Object.entries(pins)) {
      const block = extractSchemaBlock(openApiYaml, schemaName);
      assert.ok(
        block.includes(pin),
        `${schemaName} must pin messageType via ${pin}`,
      );
      assert.ok(
        block.includes("CertOpsAgentProtocolEnvelope"),
        `${schemaName} must compose the shared envelope schema`,
      );
    }
  });

  it("mirrors per-messageType required body fields", () => {
    const defs = agentProtocol.definitions;

    const registerBlock = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentRegisterRequest",
    );
    for (const field of defs.registerBody.required) {
      assert.ok(
        registerBlock.includes(field),
        `register body must include required field ${field}`,
      );
    }

    const heartbeatBlock = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentHeartbeatRequest",
    );
    for (const field of defs.heartbeatBody.required) {
      assert.ok(
        heartbeatBlock.includes(field),
        `heartbeat body must include required field ${field}`,
      );
    }

    const resultBlock = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentResultRequest",
    );
    for (const field of [
      ...defs.resultBody.required,
      ...defs.evidenceBody.required,
    ]) {
      assert.ok(
        resultBlock.includes(field),
        `results body must include required field ${field}`,
      );
    }
    const statusEnum = defs.resultBody.properties.status.enum;
    assert.ok(
      resultBlock.includes(`enum: [${statusEnum.join(", ")}]`),
      "result status enum must match agent-protocol.schema.json",
    );

    const claimBlock = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentClaimRequest",
    );
    const actionsEnum =
      defs.claimBody.properties.supportedActions.items.enum;
    assert.ok(
      claimBlock.includes(`enum: [${actionsEnum.join(", ")}]`),
      "claim supportedActions enum must match agent-protocol.schema.json",
    );
  });
});
