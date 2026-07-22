"use strict";

// Contract tests for the agent protocol surface:
// packages/contracts/certops/agent-protocol.schema.json plus its parity with
// the packages/agent modules (protocol client routes, policy rejection
// reasons, evidence event types / metadata name pattern), the route-compat
// contract, the OpenAPI document, and the executor schemas it is derived from.
// Follows the conventions of certops-m2-contracts.test.js.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const repoRoot = path.resolve(__dirname, "../..");

const agentProtocolSchema = require("../../packages/contracts/certops/agent-protocol.schema.json");
const evidenceSchema = require("../../packages/contracts/certops/evidence.schema.json");
const jobPayloadSchema = require("../../packages/contracts/certops/job-payload.schema.json");
const routeCompatContract = require("../../packages/contracts/api/certops-route-compat.contract.json");
const contractsManifest = require("../../contracts.manifest.json");

const {
  ROUTES,
  MESSAGE_TYPES,
  validateEnvelopeShape,
} = require("../../packages/agent/src/protocol/index.js");
const {
  REJECTION_REASONS,
} = require("../../packages/agent/src/policy/index.js");
const { EVENT_TYPES } = require("../../packages/agent/src/evidence/index.js");

const openApiSource = fs.readFileSync(
  path.join(repoRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);

const FORBIDDEN_FIELD_FRAGMENTS = [
  "privatekey",
  "privatekeypem",
  "encryptedprivatekey",
  "keymaterial",
  "pfxblob",
  "jksblob",
  "tlskey",
  "caprivatekey",
  "keystorepassword",
  "privatekeypassword",
  "keypassword",
  "password",
  "secret",
  "rawsecret",
  "rawprivatekey",
  "keypem",
];

// bootstrapTokenId and getCredential-style names are non-secret references;
// the only intentionally credential-adjacent property name in this schema.
const ALLOWED_CREDENTIAL_ADJACENT_NAMES = new Set(["bootstrapTokenId"]);

const PRIVATE_KEY_METADATA_NAMES = [
  "privateKey",
  "privateKeyPem",
  "encryptedPrivateKey",
  "keyMaterial",
  "pfxBlob",
  "jksBlob",
  "tlsKey",
  "caPrivateKey",
  "rawPrivateKey",
  "keyPem",
  "password",
  "secret",
  "credential",
];

function createAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(agentProtocolSchema);
  return ajv;
}

function collectPropertyNames(schema, names = []) {
  if (Array.isArray(schema)) {
    for (const item of schema) collectPropertyNames(item, names);
    return names;
  }
  if (!schema || typeof schema !== "object") return names;
  if (schema.properties && typeof schema.properties === "object") {
    for (const [propertyName, propertySchema] of Object.entries(
      schema.properties,
    )) {
      names.push(propertyName);
      collectPropertyNames(propertySchema, names);
    }
  }
  for (const value of Object.values(schema)) {
    collectPropertyNames(value, names);
  }
  return names;
}

function assertNoAdditionalPropertiesTrue(schema, location) {
  if (Array.isArray(schema)) {
    schema.forEach((item, index) =>
      assertNoAdditionalPropertiesTrue(item, `${location}[${index}]`),
    );
    return;
  }
  if (!schema || typeof schema !== "object") return;
  assert.notEqual(
    schema.additionalProperties,
    true,
    `${location} must not allow unconstrained extra fields`,
  );
  for (const [key, value] of Object.entries(schema)) {
    assertNoAdditionalPropertiesTrue(value, `${location}.${key}`);
  }
}

function normalizeFieldName(name) {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function envelope(messageType, body, overrides = {}) {
  return {
    schemaVersion: 1,
    protocolVersion: "1.0.0",
    messageType,
    agentId: "agent-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    sentAt: "2026-07-20T12:00:00.000Z",
    clockOffsetMs: null,
    body,
    ...overrides,
  };
}

function validRegisterBody() {
  return {
    bootstrapTokenId: "bst_abc123",
    agentVersion: "0.1.0",
    hostname: "host-1",
    platform: "linux",
    nodeVersion: "v22.0.0",
    declaredTargetSelectors: ["example.com"],
    declaredCommandProfileNames: ["nginx-reload"],
  };
}

function validHeartbeatBody() {
  return {
    agentVersion: "0.1.0",
    ntpSynced: true,
    uptimeSeconds: 3600,
    pinnedSigningKeyId: "signing-key-1",
  };
}

function validClaimBody() {
  return { maxJobs: 2, supportedActions: ["renew", "reload"] };
}

function validResultBody() {
  return {
    jobId: "job-1",
    attemptId: "attempt-1",
    status: "rejected",
    rejectionReason: "command_not_allowlisted",
    keyRotated: null,
    errorMessage: null,
  };
}

function validEvidenceBody() {
  return {
    jobId: "job-1",
    evidenceItems: [
      {
        eventType: "policy.checked",
        observedAt: "2026-07-20T12:00:00.000Z",
        summary: "Policy rejection recorded",
        metadata: [{ name: "rejectionReason", value: "command_not_allowlisted" }],
      },
    ],
  };
}

const VALID_MESSAGES = {
  register: () => envelope("register", validRegisterBody()),
  heartbeat: () => envelope("heartbeat", validHeartbeatBody(), { clockOffsetMs: -125 }),
  claim: () => envelope("claim", validClaimBody()),
  result: () => envelope("result", validResultBody(), { clockOffsetMs: 42 }),
  evidence: () => envelope("evidence", validEvidenceBody()),
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

describe("CertOps agent protocol contracts", () => {
  it("is listed in contracts.manifest.json", () => {
    const paths = new Set(
      contractsManifest.namespaces.flatMap((namespace) =>
        namespace.entries.map((entry) => entry.path),
      ),
    );
    assert.ok(
      paths.has("packages/contracts/certops/agent-protocol.schema.json"),
      "agent-protocol.schema.json must be listed in contracts.manifest.json",
    );
  });

  it("keeps the schema bounded and free of custody-shaped field names", () => {
    assert.equal(agentProtocolSchema.additionalProperties, false);
    assertNoAdditionalPropertiesTrue(
      agentProtocolSchema,
      "agent-protocol.schema.json",
    );

    for (const propertyName of collectPropertyNames(agentProtocolSchema)) {
      if (ALLOWED_CREDENTIAL_ADJACENT_NAMES.has(propertyName)) continue;
      const normalized = normalizeFieldName(propertyName);
      const hit = FORBIDDEN_FIELD_FRAGMENTS.find((fragment) =>
        normalized.includes(fragment),
      );
      assert.equal(
        hit,
        undefined,
        `agent-protocol.schema.json defines custody-shaped field ${propertyName}`,
      );
    }
  });

  it("accepts a valid envelope for every messageType", () => {
    const validate = createAjv().getSchema(agentProtocolSchema.$id);
    for (const [messageType, build] of Object.entries(VALID_MESSAGES)) {
      const message = build();
      assert.equal(
        validate(message),
        true,
        `${messageType}: ${JSON.stringify(validate.errors)}`,
      );
    }
  });

  it("rejects custody-shaped extra fields at envelope and body level", () => {
    const validate = createAjv().getSchema(agentProtocolSchema.$id);

    for (const [messageType, build] of Object.entries(VALID_MESSAGES)) {
      const withEnvelopeField = { ...build(), privateKey: "not-allowed" };
      assert.equal(
        validate(withEnvelopeField),
        false,
        `${messageType} envelope must reject custody-shaped extra fields`,
      );

      const withBodyField = build();
      withBodyField.body = { ...withBodyField.body, privateKeyPem: "not-allowed" };
      assert.equal(
        validate(withBodyField),
        false,
        `${messageType} body must reject custody-shaped extra fields`,
      );
    }
  });

  it("rejects custody-shaped metadata names in evidence items", () => {
    const validate = createAjv().getSchema(agentProtocolSchema.$id);

    for (const metadataName of PRIVATE_KEY_METADATA_NAMES) {
      const message = clone(VALID_MESSAGES.evidence());
      message.body.evidenceItems[0].metadata = [
        { name: metadataName, value: "public" },
      ];
      assert.equal(
        validate(message),
        false,
        `evidence metadata name ${metadataName} must be rejected`,
      );
    }
  });

  it("rejects malformed envelopes (missing/invalid required fields)", () => {
    const validate = createAjv().getSchema(agentProtocolSchema.$id);

    const missingAgentId = VALID_MESSAGES.heartbeat();
    delete missingAgentId.agentId;
    assert.equal(validate(missingAgentId), false);

    assert.equal(
      validate({ ...VALID_MESSAGES.heartbeat(), schemaVersion: 2 }),
      false,
      "schemaVersion must be pinned to 1",
    );
    assert.equal(
      validate({ ...VALID_MESSAGES.claim(), protocolVersion: "not-semver" }),
      false,
    );
    assert.equal(
      validate({ ...VALID_MESSAGES.claim(), messageType: "unknown" }),
      false,
    );
    assert.equal(
      validate({ ...VALID_MESSAGES.register(), agentId: "bad agent id!" }),
      false,
    );
  });

  it("enforces per-messageType body required fields", () => {
    const validate = createAjv().getSchema(agentProtocolSchema.$id);

    const registerNoToken = VALID_MESSAGES.register();
    delete registerNoToken.body.bootstrapTokenId;
    assert.equal(validate(registerNoToken), false);

    const heartbeatNoVersion = VALID_MESSAGES.heartbeat();
    delete heartbeatNoVersion.body.agentVersion;
    assert.equal(validate(heartbeatNoVersion), false);

    const resultNoAttempt = VALID_MESSAGES.result();
    delete resultNoAttempt.body.attemptId;
    assert.equal(validate(resultNoAttempt), false);

    const evidenceEmptyItems = VALID_MESSAGES.evidence();
    evidenceEmptyItems.body.evidenceItems = [];
    assert.equal(validate(evidenceEmptyItems), false);

    const evidenceTooManyItems = VALID_MESSAGES.evidence();
    evidenceTooManyItems.body.evidenceItems = Array.from(
      { length: 17 },
      () => clone(validEvidenceBody().evidenceItems[0]),
    );
    assert.equal(validate(evidenceTooManyItems), false);
  });

  it("keeps the agent module MESSAGE_TYPES and envelope check aligned with the schema", () => {
    assert.deepEqual(
      Object.values(MESSAGE_TYPES).sort(),
      [...agentProtocolSchema.properties.messageType.enum].sort(),
    );

    for (const build of Object.values(VALID_MESSAGES)) {
      assert.deepEqual(
        validateEnvelopeShape(build()),
        [],
        "protocol client envelope check must accept schema-valid envelopes",
      );
    }
    assert.ok(
      validateEnvelopeShape({ ...VALID_MESSAGES.claim(), schemaVersion: 2 })
        .length > 0,
    );
    assert.ok(
      validateEnvelopeShape({
        ...VALID_MESSAGES.claim(),
        protocolVersion: "nope",
      }).length > 0,
    );
  });

  it("keeps policy REJECTION_REASONS a subset of the schema rejectionReason enum", () => {
    const schemaReasons = new Set(
      agentProtocolSchema.definitions.resultBody.properties.rejectionReason.enum.filter(
        (value) => value !== null,
      ),
    );
    for (const reason of Object.values(REJECTION_REASONS)) {
      assert.ok(
        schemaReasons.has(reason),
        `policy rejection reason ${reason} missing from schema enum`,
      );
    }
    // The runtime-owned reasons must also stay reserved in the enum.
    for (const runtimeReason of [
      "job_integrity_failed",
      "job_replay_rejected",
      "clock_drift_suspected",
    ]) {
      assert.ok(
        schemaReasons.has(runtimeReason),
        `runtime rejection reason ${runtimeReason} missing from schema enum`,
      );
    }
  });

  it("keeps evidence EVENT_TYPES aligned across agent module, protocol schema, and evidence schema", () => {
    const protocolEventTypes =
      agentProtocolSchema.definitions.evidenceBody.properties.evidenceItems
        .items.properties.eventType.enum;
    assert.deepEqual([...EVENT_TYPES], protocolEventTypes);
    assert.deepEqual(
      protocolEventTypes,
      evidenceSchema.properties.eventType.enum,
    );
  });

  it("keeps the publicMetadataEntry name pattern identical to evidence.schema.json", () => {
    assert.equal(
      agentProtocolSchema.definitions.publicMetadataEntry.properties.name
        .pattern,
      evidenceSchema.definitions.publicMetadataEntry.properties.name.pattern,
    );
  });

  it("keeps claim supportedActions aligned with the job-payload action enum", () => {
    assert.deepEqual(
      agentProtocolSchema.definitions.claimBody.properties.supportedActions
        .items.enum,
      jobPayloadSchema.properties.action.enum,
    );
  });

  it("keeps the protocol client ROUTES aligned with route-compat and OpenAPI", () => {
    const expectedAuth = {
      [ROUTES.REGISTER]: "agentBootstrapTokenAuth",
      [ROUTES.HEARTBEAT]: "agentCredentialAuth",
      [ROUTES.CLAIM]: "agentCredentialAuth",
      [ROUTES.RESULTS]: "agentCredentialAuth",
    };

    for (const [routePath, auth] of Object.entries(expectedAuth)) {
      assert.equal(
        routeCompatContract.routeAuth[routePath],
        auth,
        `${routePath} auth mismatch with route-compat contract`,
      );
      assert.ok(
        routeCompatContract.guarantees.stableRoutes.some(
          (route) => route.path === routePath && route.method === "POST",
        ),
        `${routePath} must stay frozen in route compat`,
      );
      assert.ok(
        openApiSource.includes(`  ${routePath}:`),
        `${routePath} missing from OpenAPI`,
      );
    }
  });

  it("documents the zero-custody and outbound-only invariants in the schema description", () => {
    assert.match(agentProtocolSchema.description, /outbound-only/i);
    assert.match(agentProtocolSchema.description, /MUST NOT carry private key material/i);
    assert.match(agentProtocolSchema.description, /secretMaterial\.js/);
  });
});
