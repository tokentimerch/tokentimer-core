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

const CANONICAL_M2_SCOPES = [
  "certops:read",
  "certops:events:write",
  "certops:jobs:read",
  "certops:evidence:write",
];

const PLAN_M2_JOB_STATUSES = [
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
];

const PLAN_M2_EXECUTOR_EVENT_STATUSES = [
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
const M2_RFC3339_TIMESTAMP_PATTERN =
  "^(?:200[0-9]|20[1-9][0-9]|2100)-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\\.[0-9]+)?(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))$";

const m2Schemas = {
  "job-payload.schema.json": jobPayloadSchema,
  "evidence.schema.json": evidenceSchema,
  "executor-event.schema.json": executorEventSchema,
};

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

  for (const schema of Object.values(m2Schemas)) {
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

describe("CertOps M2 contract skeletons", () => {
  it("includes the M2 job, executor event, and evidence schemas in the manifest", () => {
    const paths = manifestPaths();

    for (const fileName of Object.keys(m2Schemas)) {
      assert.ok(
        paths.has(`packages/contracts/certops/${fileName}`),
        `${fileName} must be listed in contracts.manifest.json`,
      );
    }
  });

  it("keeps M2 schemas bounded and free of private-key custody-shaped field names", () => {
    for (const [fileName, schema] of Object.entries(m2Schemas)) {
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

  it("rejects custody-shaped fields and metadata names in M2 schema examples", () => {
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
      "M2-A10 embedded evidence output must be bounded and redacted before persistence",
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

  it("keeps M2 job payload signing and replay fields optional and documented as M4", () => {
    const ajv = createAjv();
    const validate = ajv.getSchema(jobPayloadSchema.$id);

    for (const m4OnlyField of [
      "issuedAt",
      "expiresAt",
      "nonce",
      "signingKeyId",
      "signature",
    ]) {
      assert.equal(
        jobPayloadSchema.required.includes(m4OnlyField),
        false,
        `${m4OnlyField} must not be required in M2-A1`,
      );
      assert.match(
        jobPayloadSchema.properties[m4OnlyField].description,
        /M4-reserved|M4/i,
        `${m4OnlyField} must be documented as M4-reserved`,
      );
    }

    assert.match(jobPayloadSchema.description, /M2-A1 public, unsigned/i);
    assert.match(jobPayloadSchema.description, /M4/i);
    assert.match(jobPayloadSchema.description, /signed job dispatch/i);
    assert.equal(validate(validJobPayload()), true);
    assert.equal(validate({ ...validJobPayload(), privateKey: "nope" }), false);
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
      "M2-A10 runtime must allow bounded executor output for redaction and separate storage",
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

  it("documents the shared M2 executor timestamp policy and fail-closed audit response", () => {
    const embeddedEvidence =
      executorEventSchema.definitions.embeddedEvidenceItem.properties;
    assert.equal(
      executorEventSchema.properties.occurredAt.pattern,
      M2_RFC3339_TIMESTAMP_PATTERN,
    );
    assert.equal(embeddedEvidence.observedAt.pattern, M2_RFC3339_TIMESTAMP_PATTERN);
    assert.equal(
      evidenceSchema.properties.observedAt.pattern,
      M2_RFC3339_TIMESTAMP_PATTERN,
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

  it("uses only v1.7 job and executor event statuses", () => {
    assert.deepEqual(
      openApiPropertyEnum("CertOpsJob", "status"),
      PLAN_M2_JOB_STATUSES,
    );
    assert.deepEqual(
      openApiPropertyEnum("CertOpsExecutorEventRequest", "status"),
      PLAN_M2_EXECUTOR_EVENT_STATUSES,
    );

    const ajv = createAjv();
    const validateExecutorEvent = ajv.getSchema(executorEventSchema.$id);

    for (const status of PLAN_M2_EXECUTOR_EVENT_STATUSES) {
      assert.equal(
        validateExecutorEvent({ ...validExecutorEvent(), status }),
        true,
        `${status} must be accepted by the executor event schema`,
      );
    }

    for (const status of STALE_STATUS_VALUES) {
      assert.equal(
        PLAN_M2_JOB_STATUSES.includes(status),
        false,
        `${status} must not remain a CertOps job status`,
      );
      assert.equal(
        PLAN_M2_EXECUTOR_EVENT_STATUSES.includes(status),
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

  it("keeps M2-A5 persistence statuses aligned with the v1.7 contract", () => {
    const jobsMigration = migrations.find(
      (migration) => migration.name === "certops_jobs_evidence_schema",
    );
    assert.ok(jobsMigration, "M2-A5 jobs migration must exist");
    assert.deepEqual(JOB_STATUSES, PLAN_M2_JOB_STATUSES);
    assert.deepEqual(LOG_STATUSES, PLAN_M2_JOB_STATUSES);
    for (const stale of ["queued", "canceled"]) {
      assert.equal(JOB_STATUSES.includes(stale), false);
      assert.equal(LOG_STATUSES.includes(stale), false);
      assert.equal(
        jobsMigration.sql.includes(`'${stale}'`),
        false,
        `${stale} must not remain in M2-A5 migration checks`,
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

  it("keeps per-job request schemas aligned with the M2 runtime contract", () => {
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

  it("uses only plan-defined M2 scopes outside migration compatibility code", () => {
    const canonicalScopes = [
      "certops:read",
      "certops:events:write",
      "certops:jobs:read",
      "certops:evidence:write",
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
      CANONICAL_M2_SCOPES,
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
        `${oldScope} must not appear in the M2-A1 OpenAPI`,
      );
    }
  });

  it("documents M2-A7 scanner rejection, pagination, and the strict job detail shape", () => {
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

  it("documents M2-A8 token management alongside stable M2-A10 aliases", () => {
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
    assert.match(executorNotes, /aggregate M2 ingestion route/i);
    assert.match(executorNotes, /stable path-scoped M2 machine routes/i);
    assert.doesNotMatch(executorNotes, /not part of M2/i);
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
