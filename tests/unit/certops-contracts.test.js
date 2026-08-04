"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const repoRoot = path.resolve(__dirname, "../..");

const routeCompatContract = require("../../packages/contracts/api/certops-route-compat.contract.json");
const contractsManifest = require("../../contracts.manifest.json");
const jobPayloadSchema = require("../../packages/contracts/certops/job-payload.schema.json");
const evidenceSchema = require("../../packages/contracts/certops/evidence.schema.json");
const executorEventSchema = require("../../packages/contracts/certops/executor-event.schema.json");
const signedDispatchPayloadSchema = require("../../packages/contracts/certops/signed-dispatch-payload.schema.json");
const signedDispatchWireV1Schema = require("../../packages/contracts/certops/signed-dispatch-wire-v1.schema.json");
const signedDispatchWireV2Schema = require("../../packages/contracts/certops/signed-dispatch-wire-v2.schema.json");
const {
  V2_MAX_ENCODED_PAYLOAD_CHARS,
} = require("../../packages/agent/src/signing/index.js");
const protocolSmokePayloadSchema = require("../../packages/contracts/certops/protocol-smoke-payload.schema.json");

const openApiSource = fs.readFileSync(
  path.join(repoRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);
const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const swaggerJsdocRequire = createRequire(apiRequire.resolve("swagger-jsdoc"));
const yaml = swaggerJsdocRequire("yaml");
const openApiDocument = yaml.parse(openApiSource);
const certOpsRoutesSource = fs.readFileSync(
  path.join(repoRoot, "apps/api/routes/certops.js"),
  "utf8",
);
const certOpsExecutorRoutesSource = fs.readFileSync(
  path.join(repoRoot, "apps/api/routes/certops-executor.js"),
  "utf8",
);
const apiIndexSource = fs.readFileSync(
  path.join(repoRoot, "apps/api/index.js"),
  "utf8",
);
const {
  JOB_STATUSES,
  LOG_STATUSES,
} = require("../../apps/api/services/certops/jobs.js");
const {
  _test: {
    EVIDENCE_SOURCES,
    EVIDENCE_STATUSES,
    RESERVED_METADATA_NAMES,
  },
} = require("../../apps/api/routes/certops-executor.js");
const { migrations } = require("../../apps/api/migrations/migrate.js");
const certOpsApiTokensSource = fs.readFileSync(
  path.join(repoRoot, "apps/api/services/certops/apiTokens.js"),
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
  "credential",
  "tokensecret",
  "apisecret",
  "rawsecret",
  "rawprivatekey",
  "keypem",
];

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
];

const SCHEMA_REJECTED_GENERIC_METADATA_NAMES = [
  "password",
  "secret",
  "credential",
  "tokenSecret",
  "apiSecret",
  "rawSecret",
];

const GENERIC_SECRET_ALIAS_METADATA_NAMES = [
  "apiToken",
  "cookieHeader",
];

const SAFE_METADATA_NAMES = [
  "issuer",
  "fingerprintSha256",
  "summary",
  "source",
  "attempt",
  "executor",
];

const CANONICAL_TOKEN_SCOPES = [
  "certops:read",
  "certops:events:write",
  "certops:jobs:read",
  "certops:evidence:write",
  "certops:observations:write",
  "certops:provision:execute",
];

const PLAN_JOB_STATUSES = [
  "pending_approval",
  "approved",
  "rejected",
  "pending",
  "claimed",
  "running",
  "succeeded",
  "failed",
  "blocked",
  "cancelled",
  // Terminal outcome for mode === "dry_run" only (B4).
  "dry_run_complete",
  // Terminal outcome when a lease was renewed but the agent never reported
  // a result: side effects are unknown and require operator reconciliation
  // instead of a silent retry (B6/H12).
  "orphaned_unknown_effect",
];

const PLAN_EXECUTOR_EVENT_STATUSES = [
  "accepted",
  "claimed",
  "running",
  "succeeded",
  "failed",
  "rejected",
  "blocked",
  "cancelled",
];

const STALE_STATUS_VALUES = ["queued", "dispatched", "canceled", "expired"];
const RFC3339_TIMESTAMP_PATTERN =
  "^(?:200[0-9]|20[1-9][0-9]|2100)-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\\.[0-9]+)?(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))$";

const certopsSchemas = {
  "job-payload.schema.json": jobPayloadSchema,
  "evidence.schema.json": evidenceSchema,
  "executor-event.schema.json": executorEventSchema,
  "protocol-smoke-payload.schema.json": protocolSmokePayloadSchema,
  "signed-dispatch-wire-v2.schema.json": signedDispatchWireV2Schema,
};

// Not part of certopsSchemas: these are partial building-block definitions
// (no top-level additionalProperties of their own; each composing schema owns
// that), so they must not be subject to the "every top-level schema is bounded"
// assertion below. They still need to be addSchema'd for $ref resolution
// whenever job-payload/protocol-smoke are validated.
//
// signed-dispatch-payload defines the SIGNED fields and deliberately has no
// signature property (a signature cannot sign itself); signed-dispatch-wire-v1
// owns that wire-only field. signed-dispatch-wire-v2 IS a bounded top-level
// wrapper schema, so it lives in certopsSchemas above instead.
const crossFileRefOnlySchemas = [
  signedDispatchPayloadSchema,
  signedDispatchWireV1Schema,
];

function manifestPaths() {
  return new Set(
    contractsManifest.namespaces.flatMap((namespace) =>
      namespace.entries.map((entry) => entry.path),
    ),
  );
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

function createAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);

  for (const schema of crossFileRefOnlySchemas) {
    ajv.addSchema(schema);
  }
  for (const schema of Object.values(certopsSchemas)) {
    ajv.addSchema(schema);
  }

  return ajv;
}

function openApiComponentSchema(componentName) {
  const schema = openApiDocument.components?.schemas?.[componentName];
  assert.ok(schema, `${componentName} missing from parsed OpenAPI`);
  return schema;
}

function createOpenApiAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv;
}

function validJobPayload() {
  return {
    schemaVersion: 1,
    jobId: "job-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    agentId: "22222222-2222-4222-8222-222222222222",
    certificateId: "cert-1",
    action: "renew",
    target: {
      type: "domain",
      reference: "example.com",
      fingerprintSha256:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    keyMode: "agent-local",
    keyReference: "external-ref-1",
    requestedAt: "2026-06-30T00:00:00.000Z",
  };
}

function validEvidence() {
  return {
    schemaVersion: 1,
    evidenceId: "evidence-1",
    jobId: "job-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    eventType: "certificate.observed",
    source: "executor",
    observedAt: "2026-06-30T00:01:00.000Z",
    fingerprintSha256:
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  };
}

function validExecutorEvent() {
  return {
    schemaVersion: 1,
    eventId: "event-1",
    jobId: "job-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    status: "running",
    eventType: "job.progress",
    occurredAt: "2026-06-30T00:02:00.000Z",
    evidence: [{ eventType: "certificate.observed" }],
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function parseOpenApiPathMethods(source) {
  const paths = new Map();
  let inPaths = false;
  let currentPath = null;

  for (const line of source.split(/\r?\n/)) {
    if (line === "paths:") {
      inPaths = true;
      continue;
    }

    if (inPaths && /^[A-Za-z][^:]*:\s*$/.test(line)) break;

    const pathMatch = line.match(/^  (\/[^:]+):\s*$/);
    if (pathMatch) {
      currentPath = pathMatch[1];
      paths.set(currentPath, new Set());
      continue;
    }

    const methodMatch = line.match(
      /^    (get|post|put|patch|delete|options|head|trace):\s*$/,
    );
    if (currentPath && methodMatch) {
      paths.get(currentPath).add(methodMatch[1].toUpperCase());
    }
  }

  return paths;
}

function openApiPathBlock(routePath) {
  const marker = `  ${routePath}:`;
  const start = openApiSource.indexOf(marker);
  assert.notEqual(start, -1, `${routePath} missing from OpenAPI`);

  const nextPath = openApiSource.indexOf("\n  /", start + marker.length);
  const components = openApiSource.indexOf("\ncomponents:", start);
  const end =
    nextPath === -1
      ? components
      : components === -1
        ? nextPath
        : Math.min(nextPath, components);

  assert.notEqual(end, -1, `${routePath} OpenAPI block end not found`);
  return openApiSource.slice(start, end);
}

function openApiComponentBlock(componentName) {
  const schemasStart = openApiSource.indexOf("\n  schemas:");
  assert.notEqual(schemasStart, -1, "OpenAPI schemas section missing");

  const marker = `    ${componentName}:`;
  const start = openApiSource.indexOf(marker, schemasStart);
  assert.notEqual(start, -1, `${componentName} missing from OpenAPI`);

  const rest = openApiSource.slice(start + marker.length);
  const nextComponent = rest.search(/\n    [A-Za-z0-9][A-Za-z0-9_]*:/);
  const end =
    nextComponent === -1
      ? openApiSource.length
      : start + marker.length + nextComponent;
  return openApiSource.slice(start, end);
}

function openApiParameterBlock(parameterName) {
  const parametersStart = openApiSource.indexOf("\n  parameters:");
  assert.notEqual(parametersStart, -1, "OpenAPI parameters section missing");

  const marker = `    ${parameterName}:`;
  const start = openApiSource.indexOf(marker, parametersStart);
  assert.notEqual(start, -1, `${parameterName} missing from OpenAPI`);

  const remainingParameters = openApiSource.slice(start + marker.length);
  const nextParameterMatch = remainingParameters.match(/\n    [^\s]/);
  const nextParameter = nextParameterMatch
    ? start + marker.length + nextParameterMatch.index
    : -1;
  const schemasStart = openApiSource.indexOf("\n  schemas:", start);
  const end = [nextParameter, schemasStart]
    .filter((index) => index !== -1)
    .sort((left, right) => left - right)[0];
  assert.notEqual(end, undefined, `${parameterName} OpenAPI block end not found`);
  return openApiSource.slice(start, end);
}

function openApiComponentEnum(componentName) {
  const block = openApiComponentBlock(componentName);
  const lines = block.split(/\r?\n/);
  const enumIndex = lines.findIndex((line) => line.trim() === "enum:");
  assert.notEqual(enumIndex, -1, `${componentName} enum missing`);

  const values = [];
  for (const line of lines.slice(enumIndex + 1)) {
    const item = line.match(/^\s+-\s+(.+?)\s*$/);
    if (item) {
      values.push(item[1]);
      continue;
    }
    if (values.length > 0 && line.trim()) break;
  }
  return values;
}

function openApiPropertyEnum(componentName, propertyName) {
  const block = openApiComponentBlock(componentName);
  const lines = block.split(/\r?\n/);
  const propertyIndex = lines.findIndex(
    (line) => line === `        ${propertyName}:`,
  );
  assert.notEqual(
    propertyIndex,
    -1,
    `${componentName}.${propertyName} missing from OpenAPI`,
  );

  const enumIndex = lines.findIndex(
    (line, index) => index > propertyIndex && line.trim() === "enum:",
  );
  assert.notEqual(
    enumIndex,
    -1,
    `${componentName}.${propertyName} enum missing`,
  );

  const values = [];
  for (const line of lines.slice(enumIndex + 1)) {
    const item = line.match(/^\s+-\s+(.+?)\s*$/);
    if (item) {
      values.push(item[1]);
      continue;
    }
    if (values.length > 0 && line.trim()) break;
  }
  return values;
}

describe("CertOps contract skeletons", () => {
  it("includes the job, executor event, and evidence schemas in the manifest", () => {
    const paths = manifestPaths();

    for (const fileName of Object.keys(certopsSchemas)) {
      assert.ok(
        paths.has(`packages/contracts/certops/${fileName}`),
        `${fileName} must be listed in contracts.manifest.json`,
      );
    }
  });

  it("keeps CertOps schemas bounded and free of private-key custody-shaped field names", () => {
    for (const [fileName, schema] of Object.entries(certopsSchemas)) {
      assert.equal(schema.additionalProperties, false);
      assertNoAdditionalPropertiesTrue(schema, fileName);

      for (const propertyName of collectPropertyNames(schema)) {
        const normalized = normalizeFieldName(propertyName);
        const hit = FORBIDDEN_FIELD_FRAGMENTS.find((fragment) =>
          normalized.includes(fragment),
        );
        assert.equal(
          hit,
          undefined,
          `${fileName} defines custody-shaped field ${propertyName}`,
        );
      }
    }
  });

  it("rejects custody-shaped fields and metadata names in CertOps schema examples", () => {
    const ajv = createAjv();
    const examples = [
      {
        schemaId: jobPayloadSchema.$id,
        example: validJobPayload(),
        withMetadataName(name) {
          return { ...validJobPayload(), metadata: [{ name, value: "public" }] };
        },
      },
      {
        schemaId: evidenceSchema.$id,
        example: validEvidence(),
        withMetadataName(name) {
          return { ...validEvidence(), metadata: [{ name, value: "public" }] };
        },
      },
      {
        schemaId: executorEventSchema.$id,
        example: validExecutorEvent(),
        withMetadataName(name) {
          return {
            ...validExecutorEvent(),
            metadata: [{ name, value: "public" }],
          };
        },
      },
      {
        schemaId: executorEventSchema.$id,
        example: validExecutorEvent(),
        withMetadataName(name) {
          return {
            ...validExecutorEvent(),
            evidence: [
              {
                eventType: "certificate.observed",
                metadata: [{ name, value: "public" }],
              },
            ],
          };
        },
      },
    ];

    for (const { schemaId, example, withMetadataName } of examples) {
      const validate = ajv.getSchema(schemaId);
      assert.ok(validate, `${schemaId} validator missing`);
      assert.equal(validate(example), true, `${schemaId} valid example failed`);

      const withExtraCustodyField = {
        ...example,
        privateKey: "not-allowed",
      };
      assert.equal(
        validate(withExtraCustodyField),
        false,
        `${schemaId} must reject custody-shaped extra fields`,
      );

      for (const metadataName of PRIVATE_KEY_METADATA_NAMES) {
        assert.equal(
          validate(withMetadataName(metadataName)),
          false,
          `${schemaId} must reject custody-shaped metadata name ${metadataName}`,
        );
      }

      for (const metadataName of SCHEMA_REJECTED_GENERIC_METADATA_NAMES) {
        assert.equal(
          validate(withMetadataName(metadataName)),
          schemaId === executorEventSchema.$id,
          `${schemaId} must ${schemaId === executorEventSchema.$id ? "accept generic secret names for executor redaction" : "reject generic secret metadata name"} ${metadataName}`,
        );
      }

      for (const metadataName of GENERIC_SECRET_ALIAS_METADATA_NAMES) {
        assert.equal(
          validate(withMetadataName(metadataName)),
          true,
          `${schemaId} must permit generic secret alias ${metadataName} for route redaction or direct-service rejection`,
        );
      }

      for (const metadataName of SAFE_METADATA_NAMES) {
        assert.equal(
          validate(withMetadataName(metadataName)),
          true,
          `${schemaId} must allow safe metadata name ${metadataName}`,
        );
      }
    }
  });

  it("uses relaxed embedded executor evidence while keeping standalone evidence strict", () => {
    const ajv = createAjv();
    const validateEvent = ajv.getSchema(executorEventSchema.$id);
    const validateStandaloneEvidence = ajv.getSchema(evidenceSchema.$id);

    const minimalEmbeddedEvidence = {
      ...validExecutorEvent(),
      evidence: [{ eventType: "certificate.observed" }],
    };
    assert.equal(validateEvent(minimalEmbeddedEvidence), true);

    const publicEmbeddedEvidence = {
      ...validExecutorEvent(),
      evidence: [
        {
          eventType: "deployment.checked",
          source: "executor",
          observedAt: "2026-06-30T00:03:00.000Z",
          fingerprintSha256:
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          summary: "Checked public deployment reference",
          metadata: [{ name: "issuer", value: "Example CA" }],
          artifactRefs: [
            {
              type: "report",
              reference: "external-report-1",
              sha256:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            },
          ],
          redactionApplied: true,
        },
      ],
    };
    assert.equal(validateEvent(publicEmbeddedEvidence), true);

    const unknownEmbeddedField = clone(publicEmbeddedEvidence);
    unknownEmbeddedField.evidence[0].unexpectedPublicField = "not allowed";
    assert.equal(validateEvent(unknownEmbeddedField), false);

    const privateKeyShapedEmbeddedField = clone(publicEmbeddedEvidence);
    privateKeyShapedEmbeddedField.evidence[0].privateKey = "not allowed";
    assert.equal(validateEvent(privateKeyShapedEmbeddedField), false);

    const boundedOutput = clone(publicEmbeddedEvidence);
    boundedOutput.evidence[0].output = "public executor output";
    assert.equal(
      validateEvent(boundedOutput),
      true,
      "embedded evidence output must be bounded and redacted before persistence",
    );

    assert.equal(
      validateStandaloneEvidence({ eventType: "certificate.observed" }),
      false,
      "standalone evidence schema must keep normalized persisted fields required",
    );
  });

  it("requires non-empty evidence only for evidence-attached executor events", () => {
    const ajv = createAjv();
    const validateEvent = ajv.getSchema(executorEventSchema.$id);

    for (const evidence of [undefined, null, []]) {
      const event = {
        ...validExecutorEvent(),
        eventType: "evidence.attached",
        status: "accepted",
      };
      if (evidence === undefined) delete event.evidence;
      else event.evidence = evidence;
      assert.equal(
        validateEvent(event),
        false,
        "evidence.attached must require a non-empty evidence array",
      );
    }

    assert.equal(
      validateEvent({
        ...validExecutorEvent(),
        eventType: "job.progress",
        status: "running",
        evidence: [],
      }),
      true,
      "lifecycle events may omit evidence or carry an empty optional array",
    );
  });

  it("documents the 65,536-byte executor output limit consistently", () => {
    const embedded = executorEventSchema.definitions.embeddedEvidenceItem;
    assert.equal(evidenceSchema.properties.output["x-maxBytes"], 65536);
    assert.equal(embedded.properties.output["x-maxBytes"], 65536);
    assert.equal(
      openApiComponentSchema("CertOpsEvidenceMetadata").properties.output[
        "x-maxBytes"
      ],
      65536,
    );
    assert.equal(
      openApiComponentSchema("CertOpsEmbeddedExecutorEvidenceItem").properties
        .output["x-maxBytes"],
      65536,
    );
  });

  it("keeps job payload signing and replay fields optional and documented as agent-protocol-reserved", () => {
    const ajv = createAjv();
    const validate = ajv.getSchema(jobPayloadSchema.$id);

    for (const agentOnlyField of [
      "issuedAt",
      "expiresAt",
      "nonce",
      "signingKeyId",
      "claimId",
      "attemptId",
      "leaseExpiresAt",
      "attemptCount",
    ]) {
      assert.equal(
        jobPayloadSchema.required.includes(agentOnlyField),
        false,
        `${agentOnlyField} must not be required today`,
      );
      assert.match(
        jobPayloadSchema.properties[agentOnlyField].description,
        /reserved for signed agent dispatch/i,
        `${agentOnlyField} must be documented as reserved for signed agent dispatch`,
      );
    }

    // "signature" is deliberately NOT in the list above. It is not a reserved
    // signed-payload field; it is a WIRE WRAPPER field, and documenting it as
    // "reserved for signed agent dispatch" alongside the others is what let an
    // earlier revision describe one shared definition as carrying both the
    // signed fields and the signature -- an impossible shape, since a signature
    // cannot sign itself (ADR-0012 decision 3). It must stay optional here, and
    // its description must say which side of the boundary it is on.
    assert.equal(jobPayloadSchema.required.includes("signature"), false);
    // "signature" is defined exactly once, on the v1 wire wrapper, and $ref'd
    // here, so the boundary documentation cannot drift between copies.
    assert.equal(
      jobPayloadSchema.properties.signature.$ref,
      `${signedDispatchWireV1Schema.$id}#/properties/signature`,
    );
    assert.match(
      signedDispatchWireV1Schema.properties.signature.description,
      /wire-only/i,
      "signature must be documented as a wire wrapper field, not a signed-payload field",
    );
    assert.equal(
      "signature" in signedDispatchPayloadSchema.properties,
      false,
      "the signed-payload schema must not define a signature property: it is the content being signed",
    );

    // The unsigned skeleton evolved: the execution fields the agent consumes
    // are now blessed as part of the executable job contract. The description
    // must record both the public-only guarantee and the signed dispatch path.
    assert.match(jobPayloadSchema.description, /unsigned planning\/reporting skeleton/i);
    assert.match(jobPayloadSchema.description, /executable job contract/i);
    assert.match(jobPayloadSchema.description, /signed dispatch/i);
    assert.equal(validate(validJobPayload()), true);
    assert.equal(validate({ ...validJobPayload(), privateKey: "nope" }), false);

    // agentDispatch.js stamps these 4 fields onto every dispatched job
    // (apps/api/services/certops/agentDispatch.js basePayload); the schema
    // must accept them so real dispatch payloads validate against the
    // published contract, not just the unsigned skeleton.
    assert.equal(
      validate({
        ...validJobPayload(),
        claimId: "claim-123",
        attemptId: "claim-123",
        leaseExpiresAt: "2030-01-01T00:00:00Z",
        attemptCount: 1,
      }),
      true,
    );
  });

  it("keeps the execution fields optional, bounded, and custody-safe", () => {
    const ajv = createAjv();
    const validate = ajv.getSchema(jobPayloadSchema.$id);

    const m5Fields = [
      "commandRef",
      "caEndpoint",
      "acmeKind",
      "keyRotation",
      "certPath",
      "reloadService",
      "verifyHost",
      "verifyPort",
      "certificatePem",
      "dnsZone",
      "dnsProvider",
    ];
    for (const field of m5Fields) {
      assert.ok(
        jobPayloadSchema.properties[field],
        `${field} must be defined in the job payload schema`,
      );
      assert.equal(
        jobPayloadSchema.required.includes(field),
        false,
        `${field} must stay optional (noop/revoke jobs never carry it)`,
      );
    }

    // certificatePem accepts only PEM certificate blocks, never key blocks.
    assert.equal(
      validate({
        ...validJobPayload(),
        certificatePem:
          "-----BEGIN CERTIFICATE-----\nRkFLRQ==\n-----END CERTIFICATE-----\n",
      }),
      true,
    );
    assert.equal(
      validate({
        ...validJobPayload(),
        certificatePem:
          "-----BEGIN RSA PRIVATE KEY-----\nRkFLRQ==\n-----END RSA PRIVATE KEY-----\n",
      }),
      false,
      "certificatePem must reject private key PEM blocks at the schema layer",
    );

    // A fully loaded renew payload validates.
    assert.equal(
      validate({
        ...validJobPayload(),
        commandRef: "acme-renew-default",
        caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
        acmeKind: "certbot",
        keyRotation: true,
        certPath: "/etc/ssl/live/example.com/cert.pem",
        reloadService: "nginx",
        verifyHost: "example.com",
        verifyPort: 443,
      }),
      true,
    );

    // Unknown ACME adapters and out-of-range ports are rejected.
    assert.equal(
      validate({ ...validJobPayload(), acmeKind: "lego" }),
      false,
    );
    assert.equal(
      validate({ ...validJobPayload(), verifyPort: 0 }),
      false,
    );
  });

  it("documents the executor event 202 response shape returned by runtime", () => {
    const schemaBlock = openApiComponentBlock(
      "CertOpsExecutorEventAcceptedResponse",
    );

    assert.match(
      schemaBlock,
      /required: \[ok, eventId, jobId, status, redactionApplied, redactionCount\]/,
    );
    assert.doesNotMatch(schemaBlock, /required: \[accepted, code\]/);
    assert.doesNotMatch(schemaBlock, /\n        accepted:/);
    assert.doesNotMatch(schemaBlock, /\n        code:/);
    assert.match(schemaBlock, /\n        ok:\r?\n          type: boolean\r?\n          enum: \[true\]/);
    assert.match(schemaBlock, /\n        eventId:\r?\n          type: string/);
    assert.match(schemaBlock, /maxLength: 128/);
    assert.match(schemaBlock, /pattern: "\^\[A-Za-z0-9_\.\:-\]\+\$"/);
    assert.match(schemaBlock, /\n        logId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(schemaBlock, /\n        jobId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(
      schemaBlock,
      /\n        status:\r?\n          type: string\r?\n          enum: \[pending_approval, approved, rejected, pending, claimed, running, succeeded, failed, blocked, cancelled\]/,
    );
    assert.match(schemaBlock, /\n        redactionApplied:\r?\n          type: boolean/);
    assert.match(
      schemaBlock,
      /\n        redactionCount:\r?\n          type: integer\r?\n          minimum: 0/,
    );
    assert.match(schemaBlock, /\n        evidenceId:\r?\n          type: string\r?\n          format: uuid\r?\n          nullable: true/);
    assert.match(schemaBlock, /\n        evidenceIds:\r?\n          type: array/);
    assert.match(schemaBlock, /\n        executorEventRecordId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(
      schemaBlock,
      /\n        duplicate:\r?\n          type: boolean\r?\n          default: false/,
    );
    assert.match(schemaBlock, /\n        idempotent:\r?\n          type: boolean/);

    const validate = createOpenApiAjv().compile(
      openApiComponentSchema("CertOpsExecutorEventAcceptedResponse"),
    );
    const response = {
      ok: true,
      eventId: "event-log-1",
      logId: "33333333-3333-4333-8333-333333333333",
      jobId: "22222222-2222-4222-8222-222222222222",
      status: "running",
      evidenceId: null,
      evidenceIds: [],
      executorEventRecordId: "44444444-4444-4444-8444-444444444444",
      redactionApplied: false,
      redactionCount: 0,
      duplicate: false,
      idempotent: false,
    };
    assert.equal(validate(response), true, JSON.stringify(validate.errors));
    delete response.redactionCount;
    assert.equal(validate(response), false);
  });

  it("keeps executor event requests closed and runtime top-level validation strict", () => {
    const schemaBlock = openApiComponentBlock("CertOpsExecutorEventRequest");

    assert.match(schemaBlock, /additionalProperties: false/);
    for (const fieldName of [
      "schemaVersion",
      "eventId",
      "jobId",
      "workspaceId",
      "certificateId",
      "executorId",
      "status",
      "eventType",
      "occurredAt",
      "message",
      "evidence",
      "metadata",
    ]) {
      assert.match(
        schemaBlock,
        new RegExp(`\\n        ${fieldName}:`),
        `${fieldName} must be documented in the executor event request schema`,
      );
      assert.match(
        certOpsExecutorRoutesSource,
        new RegExp(`"${fieldName}"`),
        `${fieldName} must be allowed by runtime top-level validation`,
      );
    }
    assert.doesNotMatch(schemaBlock, /\n        attemptId:/);
    assert.doesNotMatch(
      certOpsExecutorRoutesSource,
      /EXECUTOR_EVENT_TOP_LEVEL_FIELDS[\s\S]*?"attemptId"/,
    );

    assert.match(
      certOpsExecutorRoutesSource,
      /function rejectUnknownTopLevelFields\(body\)/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /rejectUnknownTopLevelFields\(body\);/,
    );
    assert.ok(
      certOpsExecutorRoutesSource.indexOf("rejectPrivateKeyMaterial(body);") <
        certOpsExecutorRoutesSource.indexOf("rejectUnknownTopLevelFields(body);"),
      "private-key detection must run before unknown-field rejection",
    );
  });

  it("keeps executor evidence metadata closed and runtime evidence-item validation strict", () => {
    const schemaBlock = openApiComponentBlock("CertOpsEvidenceMetadata");
    const allowedFields = [
      "schemaVersion",
      "evidenceId",
      "jobId",
      "workspaceId",
      "certificateId",
      "certificateInstanceId",
      "targetId",
      "eventType",
      "source",
      "status",
      "observedAt",
      "fingerprintSha256",
      "summary",
      "metadata",
      "artifactRefs",
      "output",
      "redactionApplied",
    ];

    assert.match(schemaBlock, /additionalProperties: false/);
    for (const fieldName of allowedFields) {
      assert.match(
        schemaBlock,
        new RegExp(`\\n        ${fieldName}:`),
        `${fieldName} must be documented in the evidence metadata schema`,
      );
      assert.match(
        certOpsExecutorRoutesSource,
        new RegExp(`"${fieldName}"`),
        `${fieldName} must be allowed by runtime evidence-item validation`,
      );
    }

    assert.match(
      certOpsExecutorRoutesSource,
      /const EVIDENCE_ITEM_FIELDS = new Set\(\[/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /function rejectUnknownEvidenceItemFields\(item\)/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /rejectUnknownEvidenceItemFields\(item\);/,
    );
    assert.ok(
      certOpsExecutorRoutesSource.indexOf("rejectPrivateKeyMaterial(item);") <
        certOpsExecutorRoutesSource.indexOf(
          "rejectUnknownEvidenceItemFields(item);",
        ),
      "private-key detection must run before evidence unknown-field rejection",
    );
    assert.doesNotMatch(
      certOpsExecutorRoutesSource,
      /item\.eventType \|\| item\.evidenceType/,
      "executor event evidence items must use the OpenAPI eventType field",
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /EVIDENCE_ITEM_FIELDS[\s\S]*?"output"/,
      "runtime must allow bounded executor output for redaction and separate storage",
    );
  });

  it("keeps embedded evidence enums and fingerprint validation aligned with schemas", () => {
    const embeddedEvidence =
      executorEventSchema.definitions.embeddedEvidenceItem.properties;
    assert.deepEqual(
      [...EVIDENCE_SOURCES],
      embeddedEvidence.source.enum.filter((value) => value !== null),
    );
    assert.deepEqual(
      [...EVIDENCE_STATUSES],
      embeddedEvidence.status.enum.filter((value) => value !== null),
    );
    assert.equal(embeddedEvidence.fingerprintSha256.pattern, "^[a-f0-9]{64}$");
    assert.match(certOpsExecutorRoutesSource, /SHA256_HEX_PATTERN = \/\^\[a-f0-9\]\{64\}\$\//);
    assert.match(certOpsExecutorRoutesSource, /optionalEvidenceEnum\(item\.source/);
    assert.match(certOpsExecutorRoutesSource, /optionalEvidenceEnum\(item\.status/);
    assert.match(certOpsExecutorRoutesSource, /optionalFingerprintSha256\(item\.fingerprintSha256\)/);
  });

  it("documents the shared executor timestamp policy and fail-closed audit response", () => {
    const embeddedEvidence =
      executorEventSchema.definitions.embeddedEvidenceItem.properties;
    assert.equal(
      executorEventSchema.properties.occurredAt.pattern,
      RFC3339_TIMESTAMP_PATTERN,
    );
    assert.equal(embeddedEvidence.observedAt.pattern, RFC3339_TIMESTAMP_PATTERN);
    assert.equal(
      evidenceSchema.properties.observedAt.pattern,
      RFC3339_TIMESTAMP_PATTERN,
    );

    for (const componentName of [
      "CertOpsEvidenceMetadata",
      "CertOpsEmbeddedExecutorEvidenceItem",
      "CertOpsExecutorEventRequest",
    ]) {
      const component = openApiComponentBlock(componentName);
      assert.match(component, /supplied RFC3339 timestamp must use a year from 2000 through 2100/i);
      assert.match(component, /normalizes accepted values to UTC milliseconds/i);
    }

    const routeBlock = openApiPathBlock("/api/v1/certops/executor/events");
    assert.match(routeBlock, /"503":/);
    assert.match(routeBlock, /CERTOPS_SECURITY_AUDIT_UNAVAILABLE/);
    assert.match(routeBlock, /fails closed/i);
    assert.match(routeBlock, /neither persisted nor echoed/i);
  });

  it("accepts the documented RFC3339 timestamp range and fractional precision", () => {
    const ajv = createAjv();
    const validateEvent = ajv.getSchema(executorEventSchema.$id);
    const validateEvidence = ajv.getSchema(evidenceSchema.$id);
    for (const timestamp of [
      "2000-01-01T00:00:00Z",
      "2026-07-12T12:00:00.123456Z",
      "2026-07-12T12:00:00.123456789+02:30",
      "2100-12-31T23:59:59.999999999-00:00",
      "2000-01-01T00:00:00+14:00",
      "2100-12-31T23:59:59-14:00",
    ]) {
      assert.equal(
        validateEvent({ ...validExecutorEvent(), occurredAt: timestamp }),
        true,
        `${timestamp} must be accepted by executor event schema`,
      );
      assert.equal(
        validateEvidence({ ...validEvidence(), observedAt: timestamp }),
        true,
        `${timestamp} must be accepted by evidence schema`,
      );
    }

    for (const timestamp of [
      "1999-12-31T23:59:59Z",
      "2101-01-01T00:00:00Z",
      "2026-13-01T00:00:00Z",
      "2026-07-12T00:00:00+14:01",
    ]) {
      assert.equal(
        validateEvent({ ...validExecutorEvent(), occurredAt: timestamp }),
        false,
        `${timestamp} must be rejected by executor event schema`,
      );
      assert.equal(
        validateEvidence({ ...validEvidence(), observedAt: timestamp }),
        false,
        `${timestamp} must be rejected by evidence schema`,
      );
    }
  });

  it("mounts the exact machine-write body boundary before the general JSON parser", () => {
    const boundaryIndex = apiIndexSource.indexOf(
      "createCertOpsMachineWritePreParserBoundary()",
    );
    const generalParserIndex = apiIndexSource.indexOf(
      'express.json({ limit: "10mb" })',
    );
    assert.notEqual(boundaryIndex, -1);
    assert.notEqual(generalParserIndex, -1);
    assert.ok(
      boundaryIndex < generalParserIndex,
      "machine-write body boundary must run before the global 10 MiB parser",
    );
  });

  it("keeps the executor event routes aligned between OpenAPI and route compat", () => {
    const routePath = "/api/v1/certops/executor/events";
    const method = "POST";
    const stableRoutes = routeCompatContract.guarantees.stableRoutes;
    const openApiPathMethods = parseOpenApiPathMethods(openApiSource);
    const routeBlock = openApiPathBlock(routePath);

    assert.ok(
      stableRoutes.some(
        (route) => route.path === routePath && route.method === method,
      ),
      "executor event route must stay frozen in route compat",
    );
    assert.equal(routeCompatContract.routeAuth[routePath], "certOpsTokenAuth");
    assert.ok(openApiPathMethods.get(routePath)?.has(method));
    assert.match(routeBlock, /certOpsTokenAuth:/);
    assert.match(routeBlock, /operationId: createCertOpsExecutorEvent/);
    assert.match(routeBlock, /idempotency key/i);
    assert.match(routeBlock, /Generic secret material[\s\S]*?redacted/i);
    assert.match(routeBlock, /CERTOPS_EXECUTOR_EVENT_CONFLICT/);
    assert.match(
      routeBlock,
      /\$ref: "#\/components\/schemas\/CertOpsExecutorEventRequest"/,
    );
    assert.match(
      routeBlock,
      /\$ref: "#\/components\/schemas\/CertOpsExecutorEventAcceptedResponse"/,
    );
    assert.match(routeBlock, /certops:events:write/);
    assert.match(routeBlock, /certops:evidence:write/);
    assert.doesNotMatch(routeBlock, /certops:executor:events/);
    assert.match(routeBlock, /"404":/);
    assert.match(routeBlock, /"409":/);
    assert.match(routeBlock, /"413":/);
    assert.match(routeBlock, /CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE/);
    assert.match(routeBlock, /CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE/);
    assert.match(routeBlock, /"429":/);
    assert.match(routeBlock, /CERTOPS_MACHINE_RATE_LIMITED/);
    assert.match(routeBlock, /Retry-After/);
    assert.match(routeBlock, /PRIVATE_KEY_MATERIAL_REJECTED/);
  });

  it("uses canonical executor scopes with feature, auth, and rate-limit guards", () => {
    assert.match(
      certOpsExecutorRoutesSource,
      /const EXECUTOR_EVENT_SCOPE = "certops:events:write"/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /const EXECUTOR_EVIDENCE_SCOPE = "certops:evidence:write"/,
    );
    assert.doesNotMatch(certOpsExecutorRoutesSource, /certops:executor:events/);
    assert.match(
      certOpsExecutorRoutesSource,
      /certOpsExecutorRouter\.post\(\s*"\/api\/v1\/certops\/executor\/events",\s*preAuthRateLimitFallback,\s*certOpsEnabledMiddleware,\s*authMiddleware,\s*rateLimitMiddleware,\s*requireExecutorRouteScope,\s*requireEvidenceItems,\s*requireExecutorEvidenceScope,\s*executorEventsHandler,/s,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /certOpsExecutorRouter\.post\(\s*"\/api\/v1\/certops\/jobs\/:jobId\/events",\s*preAuthRateLimitFallback,\s*certOpsEnabledMiddleware,\s*perJobEventAuthMiddleware,\s*rateLimitMiddleware,\s*requireExecutorRouteScope,\s*requireEvidenceItems,\s*requireExecutorEvidenceScope,/s,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      // Private-key rejection precedence (PR #61 remediation): the base route
      // scope is enforced by requireExecutorRouteScope only after private-key
      // material has been scanned and rejected, not by the auth middleware.
      /function requireExecutorRouteScope/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /CERTOPS_EXECUTOR_EVENT_CONFLICT/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH/,
    );
  });

  it("documents and keeps normalized server-owned metadata names in parity with runtime", () => {
    const expected = [...RESERVED_METADATA_NAMES].sort();
    assert.ok(
      expected.includes("redactedSecretCategories"),
      "the idempotency-only redacted secret categories must remain reserved",
    );
    const executorReserved =
      executorEventSchema.definitions.publicMetadataEntry[
        "x-certops-reservedMetadataNames"
      ];
    const evidenceReserved =
      evidenceSchema.definitions.publicMetadataEntry[
        "x-certops-reservedMetadataNames"
      ];

    assert.deepEqual([...executorReserved].sort(), expected);
    assert.deepEqual([...evidenceReserved].sort(), expected);
    const metadataComponent = openApiComponentBlock("CertOpsMetadataEntry");
    for (const name of expected) {
      assert.match(metadataComponent, new RegExp(name));
    }
    assert.match(metadataComponent, /case\/separator normalization/i);
  });

  it("uses only canonical job and executor event statuses", () => {
    assert.deepEqual(
      openApiPropertyEnum("CertOpsJob", "status"),
      PLAN_JOB_STATUSES,
    );
    assert.deepEqual(
      openApiPropertyEnum("CertOpsExecutorEventRequest", "status"),
      PLAN_EXECUTOR_EVENT_STATUSES,
    );

    const ajv = createAjv();
    const validateExecutorEvent = ajv.getSchema(executorEventSchema.$id);

    for (const status of PLAN_EXECUTOR_EVENT_STATUSES) {
      assert.equal(
        validateExecutorEvent({ ...validExecutorEvent(), status }),
        true,
        `${status} must be accepted by the executor event schema`,
      );
    }

    for (const status of STALE_STATUS_VALUES) {
      assert.equal(
        PLAN_JOB_STATUSES.includes(status),
        false,
        `${status} must not remain a CertOps job status`,
      );
      assert.equal(
        PLAN_EXECUTOR_EVENT_STATUSES.includes(status),
        false,
        `${status} must not remain a CertOps executor event status`,
      );
      assert.equal(
        validateExecutorEvent({ ...validExecutorEvent(), status }),
        false,
        `${status} must be rejected by the executor event schema`,
      );
    }
  });

  it("keeps persistence statuses aligned with the status contract", () => {
    const jobsMigration = migrations.find(
      (migration) => migration.name === "certops_jobs_evidence_schema",
    );
    assert.ok(jobsMigration, "jobs migration must exist");
    assert.deepEqual(JOB_STATUSES, PLAN_JOB_STATUSES);
    assert.deepEqual(LOG_STATUSES, PLAN_JOB_STATUSES);
    for (const stale of ["queued", "canceled"]) {
      assert.equal(JOB_STATUSES.includes(stale), false);
      assert.equal(LOG_STATUSES.includes(stale), false);
      assert.equal(
        jobsMigration.sql.includes(`'${stale}'`),
        false,
        `${stale} must not remain in jobs migration checks`,
      );
    }
  });

  it("keeps per-job executor aliases in route-compat and OpenAPI", () => {
    const stableRoutes = routeCompatContract.guarantees.stableRoutes;
    const openApiPathMethods = parseOpenApiPathMethods(openApiSource);
    for (const perJobRoute of [
      [
        "/api/v1/certops/jobs/{jobId}/events",
        "CertOpsPerJobExecutorEventRequest",
        "certops:events:write",
      ],
      [
        "/api/v1/certops/jobs/{jobId}/evidence",
        "CertOpsPerJobEvidenceRequest",
        "certops:evidence:write",
      ],
    ]) {
      const [perJobPath, schemaName, scope] = perJobRoute;
      const perJobBlock = openApiPathBlock(perJobPath);
      assert.ok(
        stableRoutes.some(
          (route) => route.path === perJobPath && route.method === "POST",
        ),
        `POST ${perJobPath} must stay frozen in route compat`,
      );
      assert.equal(routeCompatContract.routeAuth[perJobPath], "certOpsTokenAuth");
      assert.ok(openApiPathMethods.get(perJobPath)?.has("POST"));
      assert.match(perJobBlock, /certOpsTokenAuth:/);
      assert.match(perJobBlock, new RegExp(scope.replace(/:/g, ":")));
      assert.match(
        perJobBlock,
        new RegExp(`\\$ref: "#/components/schemas/${schemaName}"`),
      );
      assert.match(perJobBlock, /CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE/);
      assert.match(perJobBlock, /CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE/);
      assert.match(perJobBlock, /"404":/);
      assert.match(perJobBlock, /"503":/);
      assert.match(perJobBlock, /CERTOPS_SECURITY_AUDIT_UNAVAILABLE/);
    }
    assert.match(
      routeCompatContract.namespacePolicy.executor.notes.join(" "),
      /same idempotency, redaction, private-key rejection, dedicated pre-parser boundary, rate-limit, and audit behavior/i,
    );
  });

  it("keeps per-job request schemas aligned with the executor runtime contract", () => {
    const eventSchema = openApiComponentBlock("CertOpsPerJobExecutorEventRequest");
    const evidenceSchema = openApiComponentBlock("CertOpsPerJobEvidenceRequest");
    const authScheme = openApiSource.slice(
      openApiSource.indexOf("    certOpsTokenAuth:"),
      openApiSource.indexOf("    agentBootstrapTokenAuth:"),
    );
    const executorNotes = routeCompatContract.namespacePolicy.executor.notes.join(" ");

    assert.doesNotMatch(eventSchema, /\n        attemptId:/);
    assert.match(evidenceSchema, /status:\r?\n          type: string\r?\n          enum: \[accepted\]/);
    assert.doesNotMatch(evidenceSchema, /redacted, failed, rejected/);
    for (const schema of [eventSchema, evidenceSchema]) {
      assert.match(
        schema,
        /\$ref: "#\/components\/schemas\/CertOpsEmbeddedExecutorEvidenceItem"/,
        "per-job requests must accept relaxed embedded evidence rather than strict persisted evidence",
      );
      assert.doesNotMatch(schema, /\$ref: "#\/components\/schemas\/CertOpsEvidenceMetadata"/);
    }
    assert.match(eventSchema, /oneOf:[\s\S]*?required: \[evidence\][\s\S]*?minItems: 1/);
    assert.match(evidenceSchema, /minItems: 1/);
    assert.match(authScheme, /certops:read implies certops:jobs:read only, never a write scope/i);
    assert.match(authScheme, /Empty required-scope configuration is invalid/i);
    assert.match(executorNotes, /bearer auth only; machine routes never use cookies/i);
    assert.match(executorNotes, /empty required-scope configuration is invalid/i);
  });

  it("uses additive controller scopes without broad write implication", () => {
    const canonicalScopes = [
      "certops:read",
      "certops:events:write",
      "certops:jobs:read",
      "certops:evidence:write",
      "certops:observations:write",
      "certops:provision:execute",
    ];

    for (const scope of canonicalScopes) {
      assert.match(certOpsApiTokensSource, new RegExp(`"${scope}"`));
      assert.match(openApiSource, new RegExp(`- ${scope}`));
    }

    assert.doesNotMatch(certOpsApiTokensSource, /certops:executor:events/);
    assert.doesNotMatch(certOpsApiTokensSource, /certops:jobs:write/);
    assert.doesNotMatch(openApiSource, /certops:executor:events/);
    assert.doesNotMatch(openApiSource, /certops:jobs:write/);
  });

  it("documents token management routes with real metadata-only schemas", () => {
    const tokenListPath = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/tokens",
    );
    const tokenRevokePath = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/tokens/{tokenId}/revoke",
    );

    for (const block of [tokenListPath, tokenRevokePath]) {
      assert.doesNotMatch(block, /additionalProperties:\s+true/);
    }

    assert.match(
      tokenListPath,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenListResponse"/,
    );
    assert.match(
      tokenListPath,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenCreateRequest"/,
    );
    assert.match(
      tokenListPath,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenCreateResponse"/,
    );
    assert.match(
      tokenRevokePath,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenRevokeResponse"/,
    );

    assert.deepEqual(
      openApiComponentEnum("CertOpsApiTokenScope"),
      CANONICAL_TOKEN_SCOPES,
    );

    for (const componentName of [
      "CertOpsApiToken",
      "CertOpsApiTokenListResponse",
      "CertOpsApiTokenCreateRequest",
      "CertOpsApiTokenCreateResponse",
      "CertOpsApiTokenRevokeResponse",
    ]) {
      const block = openApiComponentBlock(componentName);
      assert.match(block, /additionalProperties:\s+false/);
      assert.doesNotMatch(block, /additionalProperties:\s+true/);
    }

    const tokenMetadataBlock = openApiComponentBlock("CertOpsApiToken");
    assert.doesNotMatch(
      tokenMetadataBlock,
      /^\s{8}(plaintextToken|tokenHash|token_hash|rawSecret|tokenSecret|apiSecret):/im,
    );
    assert.match(
      openApiComponentBlock("CertOpsApiTokenCreateResponse"),
      /^\s{8}plaintextToken:/m,
    );

    for (const oldScope of [
      "certops:executor:events",
      "certops:jobs:write",
      "certops:jobs:claim",
    ]) {
      assert.equal(
        openApiSource.includes(oldScope),
        false,
        `${oldScope} must not appear in the OpenAPI`,
      );
    }
  });

  it("documents scanner rejection, pagination, and the strict job detail shape", () => {
    const listPath = openApiPathBlock("/api/v1/workspaces/{id}/certops/jobs");
    const logPath = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/log",
    );
    const evidencePath = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/evidence",
    );
    const limitParameter = openApiParameterBlock("certOpsReadLimitParam");
    const offsetParameter = openApiParameterBlock("certOpsReadOffsetParam");
    const jobDetail = openApiComponentBlock("CertOpsJobDetail");

    for (const responseCode of ["400", "401", "403", "404", "422", "500"]) {
      assert.match(listPath, new RegExp(`\\"${responseCode}\\":`));
    }
    assert.match(
      listPath,
      /"422":\r?\n          description: A filter contained private-key or forbidden secret material\r?\n          content:\r?\n            application\/json:\r?\n              schema:\r?\n                \$ref: "#\/components\/schemas\/ErrorResponse"/,
    );
    assert.match(listPath, /PRIVATE_KEY_MATERIAL_REJECTED/);

    for (const pathBlock of [listPath, logPath, evidencePath]) {
      assert.match(
        pathBlock,
        /\$ref: "#\/components\/parameters\/certOpsReadLimitParam"/,
      );
      assert.match(
        pathBlock,
        /\$ref: "#\/components\/parameters\/certOpsReadOffsetParam"/,
      );
      assert.match(pathBlock, /pagination\.limit and\s+pagination\.offset/);
    }
    assert.match(limitParameter, /minimum: 1/);
    assert.match(limitParameter, /maximum: 100/);
    assert.match(limitParameter, /default: 50/);
    assert.match(offsetParameter, /minimum: 0/);
    assert.match(offsetParameter, /default: 0/);

    assert.doesNotMatch(jobDetail, /\ballOf:/);
    assert.match(jobDetail, /type: object/);
    assert.match(jobDetail, /additionalProperties: false/);
    for (const property of [
      "id",
      "workspaceId",
      "operation",
      "status",
      "source",
      "payload",
      "resultMetadata",
      "errorCode",
      "errorMessage",
    ]) {
      assert.match(jobDetail, new RegExp(`\\n        ${property}:`));
    }
  });

  it("documents token management alongside stable per-job aliases", () => {
    const tokenPath = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/tokens",
    );
    const revokePath = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/tokens/{tokenId}/revoke",
    );
    const createRequest = openApiComponentBlock(
      "CertOpsApiTokenCreateRequest",
    );
    const createResponse = openApiComponentBlock(
      "CertOpsApiTokenCreateResponse",
    );
    const executorNotes = routeCompatContract.namespacePolicy.executor.notes.join(
      " ",
    );

    for (const [routePath, method] of [
      ["/api/v1/workspaces/{id}/certops/tokens", "GET"],
      ["/api/v1/workspaces/{id}/certops/tokens", "POST"],
      [
        "/api/v1/workspaces/{id}/certops/tokens/{tokenId}/revoke",
        "POST",
      ],
    ]) {
      assert.ok(
        routeCompatContract.guarantees.stableRoutes.some(
          (route) => route.path === routePath && route.method === method,
        ),
        `${method} ${routePath} must stay frozen in route compat`,
      );
    }

    assert.match(tokenPath, /CertOpsApiTokenListResponse/);
    assert.match(tokenPath, /CertOpsApiTokenCreateRequest/);
    assert.match(tokenPath, /CertOpsApiTokenCreateResponse/);
    assert.match(revokePath, /CertOpsApiTokenRevokeResponse/);
    assert.match(createRequest, /Must not contain a raw CertOps token/);
    assert.match(createRequest, /bearer credential/);
    assert.match(createRequest, /token hash/);
    assert.match(createRequest, /private-key material/);
    assert.match(
      createResponse,
      /\^ttx_\[a-f0-9\]\{16\}_\[a-f0-9\]\{64\}\$/,
    );
    assert.match(createResponse, /minLength: 85/);
    assert.match(createResponse, /maxLength: 85/);
    assert.match(executorNotes, /aggregate executor ingestion route/i);
    assert.match(executorNotes, /stable path-scoped executor machine routes/i);
    assert.doesNotMatch(executorNotes, /not part of the executor surface/i);
  });

  it("keeps inventory routes free of executor and job table coupling", () => {
    // Workspace CertOps routes stay inventory/token-oriented; machine
    // executor + job/evidence tables live in certops-executor.js / services.
    assert.equal(
      certOpsRoutesSource.includes("/api/v1/certops/executor"),
      false,
    );
    assert.equal(certOpsRoutesSource.includes("certificate_jobs"), false);
    assert.equal(certOpsRoutesSource.includes("certificate_evidence"), false);
    assert.equal(certOpsRoutesSource.includes("api_tokens"), false);
  });
});

// C6: keyReference has one unified maximum length everywhere it is
// validated.
describe("keyReference maxLength parity (C6)", () => {
  const {
    KEY_REFERENCE_MAX_LENGTH,
  } = require("../../apps/api/services/certops/inventory");

  it("keeps job-payload.schema.json in parity with the runtime validator's bound", () => {
    assert.equal(jobPayloadSchema.properties.keyReference.maxLength, KEY_REFERENCE_MAX_LENGTH);
  });

  it("keeps every OpenAPI keyReference field in parity with the runtime validator's bound", () => {
    const managedCertificate = openApiComponentSchema("CertOpsManagedCertificate");
    const writeRequest = openApiComponentSchema("CertOpsCertificateWriteRequest");
    assert.equal(managedCertificate.properties.keyReference.maxLength, KEY_REFERENCE_MAX_LENGTH);
    assert.equal(writeRequest.properties.keyReference.maxLength, KEY_REFERENCE_MAX_LENGTH);
  });
});

describe("signed-dispatch payload, wire wrappers, and the action-keyed discriminated union", () => {
  const {
    CERTIFICATE_ACTIONS,
    PROTOCOL_SMOKE_ACTION,
    selectSchemaForAction,
    validateSignedJob,
  } = require("../../packages/contracts/certops/validate-signed-job.cjs");

  function baseCertificateJob(overrides = {}) {
    return {
      schemaVersion: 1,
      jobId: "job-1",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: "22222222-2222-4222-8222-222222222222",
      certificateId: "cert-1",
      action: "renew",
      target: { type: "domain", reference: "example.com" },
      keyMode: "agent-local",
      requestedAt: "2026-01-01T00:00:00.000Z",
      ...overrides,
    };
  }

  function baseSmokeJob(overrides = {}) {
    return {
      schemaVersion: 1,
      jobId: "job-smoke-1",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: "22222222-2222-4222-8222-222222222222",
      action: "protocol_smoke",
      mode: "dry_run",
      requestedAt: "2026-01-01T00:00:00.000Z",
      payload: { mode: "dry_run", echo: "hello" },
      ...overrides,
    };
  }

  it("selects job-payload.schema.json for every certificate action", () => {
    for (const action of CERTIFICATE_ACTIONS) {
      const selection = selectSchemaForAction(action);
      assert.ok(selection);
      assert.match(selection.schemaId, /job-payload\.schema\.json$/);
    }
  });

  it("selects protocol-smoke-payload.schema.json for protocol_smoke", () => {
    const selection = selectSchemaForAction(PROTOCOL_SMOKE_ACTION);
    assert.ok(selection);
    assert.match(selection.schemaId, /protocol-smoke-payload\.schema\.json$/);
  });

  it("returns null for an unrecognized or missing action", () => {
    assert.equal(selectSchemaForAction("distribute-trust"), null);
    assert.equal(selectSchemaForAction(undefined), null);
    assert.equal(selectSchemaForAction(42), null);
  });

  it("validates a well-formed certificate job against job-payload.schema.json", () => {
    const result = validateSignedJob(baseCertificateJob());
    assert.equal(result.valid, true, JSON.stringify(result.errors));
    assert.match(result.schemaId, /job-payload\.schema\.json$/);
  });

  it("validates a well-formed protocol_smoke job against protocol-smoke-payload.schema.json", () => {
    const result = validateSignedJob(baseSmokeJob());
    assert.equal(result.valid, true, JSON.stringify(result.errors));
    assert.match(result.schemaId, /protocol-smoke-payload\.schema\.json$/);
  });

  it("never validates a smoke job against the certificate schema: certificateId is not accepted", () => {
    // additionalProperties: false on protocol-smoke-payload.schema.json
    // means adding a certificate-shaped field must fail, proving the two
    // schemas are not silently compatible with each other's shape.
    const result = validateSignedJob(
      baseSmokeJob({ certificateId: "cert-should-not-be-here" }),
    );
    assert.equal(result.valid, false);
  });

  it("never validates a certificate job against the smoke schema: missing certificateId/target/keyMode fails", () => {
    const result = validateSignedJob({
      schemaVersion: 1,
      jobId: "job-2",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      action: "renew",
      requestedAt: "2026-01-01T00:00:00.000Z",
    });
    assert.equal(result.valid, false);
    assert.match(result.schemaId, /job-payload\.schema\.json$/);
  });

  it("rejects a protocol_smoke job missing the required agentId (new-client requirement, ADR-0012 decision 3)", () => {
    const job = baseSmokeJob();
    delete job.agentId;
    const result = validateSignedJob(job);
    assert.equal(result.valid, false);
  });

  it("rejects a certificate job WITHOUT agentId (required, atomic with server-side emission)", () => {
    // job-payload.schema.json now requires agentId, added in the same
    // commit as the control plane's server-side emission of the field
    // (ADR-0012 decision 3). The producer schema is never optional-then-
    // required across releases, since a schema that permits omitting the
    // field cannot catch a dispatch path that forgot it. Consumer-side
    // absence tolerance lives in the compatibility decoder gated on
    // CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID, never here.
    const job = baseCertificateJob();
    delete job.agentId;
    const result = validateSignedJob(job);
    assert.equal(result.valid, false, "expected validation to fail without agentId");
  });

  it("validates a certificate job WITH agentId identically (additive field, not a breaking one)", () => {
    const result = validateSignedJob(
      baseCertificateJob({ agentId: "22222222-2222-4222-8222-222222222222" }),
    );
    assert.equal(result.valid, true, JSON.stringify(result.errors));
  });

  it("rejects protocol_smoke's mode when it is not dry_run: there is no 'real' variant", () => {
    const job = baseSmokeJob();
    job.payload.mode = "real";
    const result = validateSignedJob(job);
    assert.equal(result.valid, false);
  });

  it("shares the signed-dispatch payload fields identically across both schemas", () => {
    const nonce = "n".repeat(20);
    const certJob = validateSignedJob(
      baseCertificateJob({
        agentId: "22222222-2222-4222-8222-222222222222",
        nonce,
        signingKeyId: "ttsk_abc123",
        signature: "s".repeat(88),
        issuedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-01T00:05:00.000Z",
        claimId: "claim-1",
        attemptId: "attempt-1",
        leaseExpiresAt: "2026-01-01T00:05:00.000Z",
        attemptCount: 1,
      }),
    );
    const smokeJob = validateSignedJob(
      baseSmokeJob({
        nonce,
        signingKeyId: "ttsk_abc123",
        signature: "s".repeat(88),
        issuedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-01T00:05:00.000Z",
        claimId: "claim-1",
        attemptId: "attempt-1",
        leaseExpiresAt: "2026-01-01T00:05:00.000Z",
        attemptCount: 1,
      }),
    );
    assert.equal(certJob.valid, true, JSON.stringify(certJob.errors));
    assert.equal(smokeJob.valid, true, JSON.stringify(smokeJob.errors));
  });

  // ---------------------------------------------------------------------
  // Payload vs wire wrapper (ADR-0012 decisions 1 and 3).
  //
  // An earlier revision had ONE shared definition named "signedDispatchEnvelope"
  // carrying both the signed fields and "signature". That cannot describe signed
  // content: the signature is computed over the payload, so it cannot be one of
  // the payload's fields. These tests pin the three-way split so the naming
  // cannot silently regress into the impossible shape again.
  // ---------------------------------------------------------------------

  it("defines no signature property on the signed payload: a signature cannot sign itself", () => {
    assert.equal("signature" in signedDispatchPayloadSchema.properties, false);
    assert.match(signedDispatchPayloadSchema.$id, /signed-dispatch-payload\.schema\.json$/);
  });

  it("defines signature exactly once, on the v1 wire wrapper, and both per-action schemas $ref it", () => {
    assert.ok(signedDispatchWireV1Schema.properties.signature);

    const expectedRef = `${signedDispatchWireV1Schema.$id}#/properties/signature`;
    assert.equal(jobPayloadSchema.properties.signature.$ref, expectedRef);
    assert.equal(protocolSmokePayloadSchema.properties.signature.$ref, expectedRef);
  });

  it("bounds the v2 wrapper to exactly four fields and no payload fields", () => {
    assert.equal(signedDispatchWireV2Schema.additionalProperties, false);
    assert.deepEqual(Object.keys(signedDispatchWireV2Schema.properties).sort(), [
      "envelopeVersion",
      "payloadB64",
      "signatureB64",
      "signingKeyId",
    ]);
    // No sibling unsigned job object and no leaked payload fields: anything not
    // inside payloadB64 is simply not part of a v2 dispatch (decision 1).
    for (const payloadOnlyField of ["jobId", "nonce", "claimId", "agentId", "action"]) {
      assert.equal(
        payloadOnlyField in signedDispatchWireV2Schema.properties,
        false,
        `v2 wrapper must not carry the payload field ${payloadOnlyField}`,
      );
    }
    assert.equal(signedDispatchWireV2Schema.properties.envelopeVersion.const, 2);
  });

  it("shares signingKeyId between payload and v2 wrapper, and only signingKeyId", () => {
    // This is the one intentional duplication: the wrapper's copy is the
    // pre-verification key-selection hint, the payload's copy is authenticated,
    // and verification requires them equal (decision 2 step 13).
    const payloadFields = new Set(Object.keys(signedDispatchPayloadSchema.properties));
    const shared = Object.keys(signedDispatchWireV2Schema.properties).filter((key) =>
      payloadFields.has(key),
    );
    assert.deepEqual(shared, ["signingKeyId"]);
  });

  it("validates a well-formed v2 wrapper and rejects malformed ones", () => {
    const ajv = createAjv();
    const validate = ajv.getSchema(signedDispatchWireV2Schema.$id);
    assert.ok(validate, "the v2 wrapper schema must be registered");

    const wellFormed = {
      envelopeVersion: 2,
      payloadB64: Buffer.from('{"jobId":"job-1"}', "utf8").toString("base64"),
      signatureB64: Buffer.alloc(64, 7).toString("base64"),
      signingKeyId: "ttsk_abc123",
    };
    assert.equal(validate(wellFormed), true, JSON.stringify(validate.errors));

    assert.equal(
      validate({ ...wellFormed, envelopeVersion: 1 }),
      false,
      "envelopeVersion must be exactly 2",
    );
    assert.equal(
      validate({ ...wellFormed, job: { jobId: "job-1" } }),
      false,
      "a sibling unsigned job object must be rejected",
    );
    assert.equal(
      validate({ ...wellFormed, signature: "s".repeat(88) }),
      false,
      "the v1 wrapper's signature field must be rejected on a v2 wrapper",
    );
    assert.equal(
      validate({ ...wellFormed, signatureB64: Buffer.alloc(63, 7).toString("base64") }),
      false,
      "a signature that is not exactly 64 decoded bytes must be rejected",
    );
    assert.match(
      signedDispatchWireV2Schema.properties.payloadB64.pattern,
      /\+\//,
      "payloadB64 must require the standard base64 alphabet, not base64url",
    );
  });

  it("bounds the v2 wrapper's payloadB64 maxLength to the same pinned encoded-char ceiling the agent verifier enforces (ADR-0012 decision 1)", () => {
    // A schema bound looser than the verifier's pinned ceiling would let a
    // wire-valid payload the verifier is guaranteed to reject slip past this
    // schema first; this test fails the moment the two numbers drift apart,
    // regardless of which side changes.
    assert.equal(
      signedDispatchWireV2Schema.properties.payloadB64.maxLength,
      V2_MAX_ENCODED_PAYLOAD_CHARS,
    );
  });

  it("rejects base64url in payloadB64 for an encoding that actually contains + and /", () => {
    const ajv = createAjv();
    const validate = ajv.getSchema(signedDispatchWireV2Schema.$id);

    // These bytes are chosen so standard base64 provably emits both + and /
    // (6-bit groups 62 and 63), making the base64url transform below a real
    // change rather than a no-op that would pass vacuously.
    const raw = Buffer.from([0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff]);
    const standard = raw.toString("base64");
    assert.ok(standard.includes("+") && standard.includes("/"), standard);

    const wrapper = {
      envelopeVersion: 2,
      payloadB64: standard,
      signatureB64: Buffer.alloc(64, 7).toString("base64"),
      signingKeyId: "ttsk_abc123",
    };
    assert.equal(validate(wrapper), true, JSON.stringify(validate.errors));

    const urlSafe = standard.replace(/\+/g, "-").replace(/\//g, "_");
    assert.notEqual(urlSafe, standard);
    assert.equal(validate({ ...wrapper, payloadB64: urlSafe }), false);
  });
});
