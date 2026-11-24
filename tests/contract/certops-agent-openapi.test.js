/**
 * Contract Tests - CertOps agent routes vs OpenAPI / route-compat / agent-protocol
 *
 * Static assertions (no runtime API needed):
 *  1. The stable /api/v1/certops/agent routes are documented in the static
 *     OpenAPI spec with the auth split frozen in
 *     packages/contracts/api/certops-route-compat.contract.json.
 *  2. The route-compat contract carries the agent-runtime version/status and keeps all
 *     documented agent routes in routeAuth and stableRoutes.
 *  3. The OpenAPI request-body envelope mirrors
 *     packages/contracts/certops/agent-protocol.schema.json (required
 *     envelope fields and the messageType enum), and each operation pins the
 *     correct per-route messageType(s).
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import addFormats from "ajv-formats";

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
  "/api/v1/certops/agent/jobs/{jobId}/lease": "agentCredentialAuth",
  "/api/v1/certops/agent/jobs/{jobId}/iis-consent": "agentCredentialAuth",
  "/api/v1/certops/agent/jobs/results": "agentCredentialAuth",
  "/api/v1/certops/agent/jobs/{jobId}/logs": "agentCredentialAuth",
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
  it("documents all agent paths with the frozen auth split", () => {
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
      "/api/v1/certops/agent/jobs/{jobId}/lease": {
        success: '"200"',
        codes: [
          "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH",
          "CERTOPS_AGENT_RETIRED",
          "PRIVATE_KEY_MATERIAL_REJECTED",
        ],
        statuses: ['"400"', '"401"', '"404"', '"409"', '"410"', '"422"', '"429"'],
      },
      "/api/v1/certops/agent/jobs/{jobId}/iis-consent": {
        success: '"200"',
        codes: [
          "CERTOPS_AGENT_MESSAGE_INVALID",
          "CERTOPS_AGENT_SEQUENCE_REGRESSION",
          "CERTOPS_AGENT_RETIRED",
          "PRIVATE_KEY_MATERIAL_REJECTED",
        ],
        statuses: ['"400"', '"401"', '"404"', '"409"', '"410"', '"422"', '"429"'],
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
      "/api/v1/certops/agent/jobs/{jobId}/logs": {
        success: '"200"',
        codes: [
          "CERTOPS_AGENT_LOG_CLAIM_INVALID",
          "CERTOPS_AGENT_LOG_PRIVATE_MATERIAL",
        ],
        statuses: [
          '"400"',
          '"401"',
          '"404"',
          '"409"',
          '"410"',
          '"413"',
          '"422"',
          '"429"',
        ],
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
    assert.strictEqual(routeCompat.version, "0.18.0");
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

  it("keeps the agent routes in stableRoutes as POST", () => {
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
      "log",
      "iis-absence-proof",
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
      CertOpsAgentResultRequest: "enum: [result, evidence, iis-absence-proof]",
      CertOpsAgentLogRequest: "enum: [log]",
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

  it("documents the authenticated IIS proof body and its runtime limits", () => {
    const apiRequire = createRequire(path.join(repoRoot, "apps/api/package.json"));
    const yaml = createRequire(apiRequire.resolve("swagger-jsdoc"))("yaml");
    const spec = yaml.parse(openApiYaml);
    const operation = spec.paths["/api/v1/certops/agent/jobs/results"].post;
    assert.deepStrictEqual(operation.security, [{ agentCredentialAuth: [] }]);
    const request = spec.components.schemas.CertOpsAgentResultRequest.allOf[1];
    const proofBranch = request.oneOf.find(branch => branch.properties.messageType.enum.includes("iis-absence-proof"));
    assert.deepStrictEqual(proofBranch.required, ["sequence"]);
    assert.strictEqual(proofBranch.properties.body.$ref, "#/components/schemas/CertOpsAgentIisAbsenceProofBody");
    const documented = spec.components.schemas.CertOpsAgentIisAbsenceProofBody;
    const protocol = agentProtocol.definitions.iisAbsenceProofBody;
    assert.strictEqual(documented.additionalProperties, false);
    assert.deepStrictEqual(documented.required, protocol.required);
    assert.strictEqual(documented.properties.proofs.minItems, protocol.properties.proofs.minItems);
    assert.strictEqual(documented.properties.proofs.maxItems, protocol.properties.proofs.maxItems);
    const docItem = documented.properties.proofs.items;
    const protocolItem = protocol.properties.proofs.items;
    assert.strictEqual(docItem.additionalProperties, false);
    assert.deepStrictEqual(docItem.required, protocolItem.required);
    assert.deepStrictEqual(Object.keys(docItem.properties).sort(), Object.keys(protocolItem.properties).sort());
    for (const [name, property] of Object.entries(protocolItem.properties)) {
      for (const key of ["type", "minLength", "maxLength", "minimum", "maximum", "pattern", "format"]) {
        if (property[key] !== undefined) assert.deepStrictEqual(docItem.properties[name][key], property[key], `${name}.${key}`);
      }
    }
    assert.strictEqual(docItem.properties.site.pattern, "^[A-Za-z0-9 _.:-]+$");
    assert.strictEqual(spec.components.schemas.CertOpsAgentProtocolEnvelope.properties.sequence.minimum, 1);

    const ajv = new Ajv({ strict: false });
    addFormats(ajv);
    const requestSchema = structuredClone(spec.components.schemas.CertOpsAgentResultRequest);
    // The shared result body includes unrelated OpenAPI-only nullable fields;
    // validate the proof branch and envelope independently of those fields.
    delete requestSchema.allOf[1].properties.body;
    const validate = ajv.compile({
      ...requestSchema,
      components: { schemas: {
        CertOpsAgentProtocolEnvelope: spec.components.schemas.CertOpsAgentProtocolEnvelope,
        CertOpsAgentIisAbsenceProofBody: documented,
      } },
    });
    const proof = { evidenceId: "proof-1", targetHost: "host.example", site: "Default Web Site", port: 443,
      address: "192.0.2.10", fingerprintSha256: "a".repeat(64), thumbprint: "b".repeat(40),
      observedAt: "2026-11-15T12:00:00Z" };
    const envelope = { schemaVersion: 1, protocolVersion: "1.0.0", messageType: "iis-absence-proof",
      agentId: "agent-1", sentAt: "2026-11-15T12:00:00Z", sequence: 1, body: { proofs: [proof] } };
    assert.strictEqual(validate(envelope), true, JSON.stringify(validate.errors));
    const { sequence, ...missingSequence } = envelope;
    assert.strictEqual(validate(missingSequence), false);
    assert.strictEqual(validate({ ...envelope, body: { proofs: [{ ...proof, unexpected: true }] } }), false);
    assert.strictEqual(validate({ ...envelope, body: { proofs: Array(17).fill(proof) } }), false);
  });

  it("mirrors per-messageType required body fields", () => {
    const defs = agentProtocol.definitions;

    const proofRequest = extractSchemaBlock(openApiYaml, "CertOpsAgentResultRequest");
    assert.ok(proofRequest.includes("required: [sequence]"));
    assert.ok(proofRequest.includes("#/components/schemas/CertOpsAgentIisAbsenceProofBody"));
    const proofBlock = extractSchemaBlock(openApiYaml, "CertOpsAgentIisAbsenceProofBody");
    const proof = defs.iisAbsenceProofBody.properties.proofs;
    assert.ok(proofBlock.includes(`minItems: ${proof.minItems}`));
    assert.ok(proofBlock.includes(`maxItems: ${proof.maxItems}`));
    assert.ok(proofBlock.includes(`required: [${proof.items.required.join(", ")}]`));
    assert.equal((proofBlock.match(/additionalProperties: false/g) || []).length, 2);

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

    const logRequestBlock = extractSchemaBlock(
      openApiYaml,
      "CertOpsAgentLogRequest",
    );
    assert.ok(
      logRequestBlock.includes("CertOpsAgentLogBody"),
      "log request must compose CertOpsAgentLogBody",
    );

    const logBodyBlock = extractSchemaBlock(openApiYaml, "CertOpsAgentLogBody");
    for (const field of defs.logBody.required) {
      assert.ok(
        logBodyBlock.includes(field),
        `log body must include required field ${field}`,
      );
    }
    assert.ok(
      logBodyBlock.includes("additionalProperties: false"),
      "log body must set additionalProperties false",
    );
    assert.ok(
      logBodyBlock.includes("maxItems: 200"),
      "log body lines must cap maxItems at 200",
    );
    assert.ok(
      logBodyBlock.includes("minItems: 1"),
      "log body must require minItems 1 on lines when final is false",
    );
    assert.ok(
      logBodyBlock.includes("CertOpsAgentLogLine"),
      "log body lines items must reference CertOpsAgentLogLine",
    );

    const logLineBlock = extractSchemaBlock(openApiYaml, "CertOpsAgentLogLine");
    for (const field of defs.logLine.required) {
      assert.ok(
        logLineBlock.includes(field),
        `log line must include required field ${field}`,
      );
    }
    assert.ok(
      logLineBlock.includes("additionalProperties: false"),
      "log line must set additionalProperties false",
    );
    const levelEnum = defs.logLine.properties.level.enum;
    assert.ok(
      logLineBlock.includes(`enum: [${levelEnum.join(", ")}]`),
      "log line level enum must match agent-protocol.schema.json",
    );
    const stepEnum = defs.logLine.properties.step.enum;
    assert.ok(
      logLineBlock.includes(`enum: [${stepEnum.join(", ")}]`),
      "log line step enum must match agent-protocol.schema.json",
    );
  });
});
