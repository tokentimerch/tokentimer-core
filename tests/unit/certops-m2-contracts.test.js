"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
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
const certOpsRoutesSource = fs.readFileSync(
  path.join(repoRoot, "apps/api/routes/certops.js"),
  "utf8",
);
const certOpsExecutorRoutesSource = fs.readFileSync(
  path.join(repoRoot, "apps/api/routes/certops-executor.js"),
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
];

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
    issuedAt: "2026-06-30T00:00:00.000Z",
    expiresAt: "2026-06-30T00:10:00.000Z",
    nonce: "nonce-1234567890123456",
    signingKeyId: "signing-key-1",
    signature:
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
    evidence: [validEvidence()],
  };
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

function openApiSchemaBlock(schemaName) {
  const marker = `    ${schemaName}:`;
  const start = openApiSource.indexOf(marker);
  assert.notEqual(start, -1, `${schemaName} missing from OpenAPI`);

  const rest = openApiSource.slice(start + marker.length);
  const nextSchemaMatch = rest.match(/\n    [A-Za-z0-9][A-Za-z0-9_]*:\r?\n/);
  const end =
    nextSchemaMatch && typeof nextSchemaMatch.index === "number"
      ? start + marker.length + nextSchemaMatch.index
      : openApiSource.length;

  return openApiSource.slice(start, end);
}

function assertStableRoute(routePath, method) {
  assert.ok(
    routeCompatContract.guarantees.stableRoutes.some(
      (route) => route.path === routePath && route.method === method,
    ),
    `${method} ${routePath} must stay frozen in route compat`,
  );
}

function changedAppFiles() {
  const diffFiles = execFileSync("git", ["diff", "--name-only", "--", "apps"], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .trim()
    .split(/\r?\n/)
    .filter(Boolean);

  const statusFiles = execFileSync(
    "git",
    ["status", "--short", "--untracked-files=all", "--", "apps"],
    {
      cwd: repoRoot,
      encoding: "utf8",
    },
  )
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => line.slice(3).trim());

  return [...new Set([...diffFiles, ...statusFiles])].sort();
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
      [jobPayloadSchema.$id, validJobPayload()],
      [evidenceSchema.$id, validEvidence()],
      [executorEventSchema.$id, validExecutorEvent()],
    ];

    for (const [schemaId, example] of examples) {
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

      const withCustodyMetadataName = {
        ...example,
        metadata: [{ name: "privateKey", value: "not-allowed" }],
      };
      assert.equal(
        validate(withCustodyMetadataName),
        false,
        `${schemaId} must reject custody-shaped metadata names`,
      );
    }
  });

  it("documents the executor event 202 response shape returned by runtime", () => {
    const schemaBlock = openApiSchemaBlock(
      "CertOpsExecutorEventAcceptedResponse",
    );

    assert.match(schemaBlock, /required: \[ok, eventId, jobId, status\]/);
    assert.doesNotMatch(schemaBlock, /required: \[accepted, code\]/);
    assert.doesNotMatch(schemaBlock, /\n        accepted:/);
    assert.doesNotMatch(schemaBlock, /\n        code:/);
    assert.match(schemaBlock, /\n        ok:\r?\n          type: boolean\r?\n          enum: \[true\]/);
    assert.match(schemaBlock, /\n        eventId:\r?\n          type: string/);
    assert.match(schemaBlock, /maxLength: 128/);
    assert.match(schemaBlock, /pattern: "\^\[A-Za-z0-9_\.\:-\]\+\$"/);
    assert.match(schemaBlock, /\n        logId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(schemaBlock, /\n        jobId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(schemaBlock, /\n        status:\r?\n          type: string\r?\n          enum: \[queued, running, succeeded, failed, canceled\]/);
    assert.match(schemaBlock, /\n        evidenceId:\r?\n          type: string\r?\n          format: uuid\r?\n          nullable: true/);
    assert.match(schemaBlock, /\n        evidenceIds:\r?\n          type: array/);
    assert.match(schemaBlock, /\n        executorEventRecordId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(schemaBlock, /\n        duplicate:\r?\n          type: boolean/);
    assert.match(schemaBlock, /\n        idempotent:\r?\n          type: boolean/);
  });

  it("keeps executor event requests closed and runtime top-level validation strict", () => {
    const schemaBlock = openApiSchemaBlock("CertOpsExecutorEventRequest");

    assert.match(schemaBlock, /additionalProperties: false/);
    for (const fieldName of [
      "schemaVersion",
      "eventId",
      "jobId",
      "workspaceId",
      "certificateId",
      "executorId",
      "attemptId",
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
    const schemaBlock = openApiSchemaBlock("CertOpsEvidenceMetadata");
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
  });

  it("keeps the executor event route aligned between OpenAPI and route compat", () => {
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
    assert.match(routeBlock, /Generic secret material.*redacted/i);
    assert.match(routeBlock, /CERTOPS_EXECUTOR_EVENT_CONFLICT/);
    assert.match(
      routeBlock,
      /\$ref: "#\/components\/schemas\/CertOpsExecutorEventRequest"/,
    );
    assert.match(
      routeBlock,
      /\$ref: "#\/components\/schemas\/CertOpsExecutorEventAcceptedResponse"/,
    );

    for (const forbiddenRoute of [
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/events",
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/evidence",
    ]) {
      assert.equal(
        stableRoutes.some(
          (route) => route.path === forbiddenRoute && route.method === "POST",
        ),
        false,
        `POST ${forbiddenRoute} is not a stable M2 executor write route`,
      );
      assert.equal(
        openApiPathMethods.get(forbiddenRoute)?.has("POST") === true,
        false,
        `POST ${forbiddenRoute} must not be introduced in OpenAPI for M2`,
      );
    }
    assert.match(
      routeCompatContract.namespacePolicy.executor.notes.join(" "),
      /single ingestion endpoint/i,
    );
  });

  it("documents token management routes with real metadata-only schemas", () => {
    const tokenRoutesBlock = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/tokens",
    );
    const revokeBlock = openApiPathBlock(
      "/api/v1/workspaces/{id}/certops/tokens/{tokenId}/revoke",
    );
    const tokenSchema = openApiSchemaBlock("CertOpsApiToken");
    const listSchema = openApiSchemaBlock("CertOpsApiTokenListResponse");
    const createRequestSchema = openApiSchemaBlock(
      "CertOpsApiTokenCreateRequest",
    );
    const createResponseSchema = openApiSchemaBlock(
      "CertOpsApiTokenCreateResponse",
    );
    const revokeResponseSchema = openApiSchemaBlock(
      "CertOpsApiTokenRevokeResponse",
    );

    assertStableRoute("/api/v1/workspaces/{id}/certops/tokens", "GET");
    assertStableRoute("/api/v1/workspaces/{id}/certops/tokens", "POST");
    assertStableRoute(
      "/api/v1/workspaces/{id}/certops/tokens/{tokenId}/revoke",
      "POST",
    );
    assertStableRoute(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}",
      "GET",
    );
    assertStableRoute(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/log",
      "GET",
    );
    assertStableRoute(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/evidence",
      "GET",
    );

    assert.match(
      tokenRoutesBlock,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenListResponse"/,
    );
    assert.match(
      tokenRoutesBlock,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenCreateRequest"/,
    );
    assert.match(
      tokenRoutesBlock,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenCreateResponse"/,
    );
    assert.match(
      revokeBlock,
      /\$ref: "#\/components\/schemas\/CertOpsApiTokenRevokeResponse"/,
    );
    assert.doesNotMatch(tokenRoutesBlock, /additionalProperties: true/);
    assert.doesNotMatch(revokeBlock, /additionalProperties: true/);

    for (const [schemaName, schemaBlock] of [
      ["CertOpsApiToken", tokenSchema],
      ["CertOpsApiTokenListResponse", listSchema],
      ["CertOpsApiTokenCreateRequest", createRequestSchema],
      ["CertOpsApiTokenRevokeResponse", revokeResponseSchema],
    ]) {
      assert.match(
        schemaBlock,
        /additionalProperties: false/,
        `${schemaName} must not remain an unconstrained skeleton`,
      );
      assert.doesNotMatch(schemaBlock, /plaintextToken/);
      assert.doesNotMatch(schemaBlock, /token_hash|tokenHash|rawSecret|apiSecret|tokenSecret/);
    }

    assert.match(createResponseSchema, /additionalProperties: false/);
    assert.match(createResponseSchema, /plaintextToken:/);
    assert.match(createResponseSchema, /\^ttx_\[A-Za-z0-9\]\+_\[A-Za-z0-9\]\+\$/);
    assert.doesNotMatch(createResponseSchema, /token_hash|tokenHash|rawSecret|apiSecret|tokenSecret/);
  });

  it("limits stacked M2 app runtime files and keeps workspace CertOps routes separate", () => {
    const allowedStackedM2Files = new Set([
      "apps/api/migrations/migrate.js",
      "apps/api/middleware/api-token-auth.js",
      "apps/api/middleware/csrf-exempt.js",
      "apps/api/middleware/machine-token-rate-limit.js",
      "apps/api/index.js",
      "apps/api/routes/certops.js",
      "apps/api/routes/certops-executor.js",
      "apps/api/services/certops/apiTokens.js",
      "apps/api/services/certops/evidence.js",
      "apps/api/services/certops/executorEvents.js",
      "apps/api/services/certops/jobs.js",
      "apps/api/utils/secretMaterial.js",
    ]);
    const unexpectedAppFiles = changedAppFiles().filter(
      (file) => !allowedStackedM2Files.has(file),
    );

    assert.deepEqual(unexpectedAppFiles, []);
    assert.equal(
      certOpsRoutesSource.includes("/api/v1/certops/executor"),
      false,
    );
    assert.equal(certOpsRoutesSource.includes("certificate_jobs"), false);
    assert.equal(certOpsRoutesSource.includes("certificate_evidence"), false);
    assert.equal(certOpsRoutesSource.includes("api_tokens"), false);
  });
});
