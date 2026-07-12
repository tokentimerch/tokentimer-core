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
const {
  JOB_STATUSES,
  LOG_STATUSES,
} = require("../../apps/api/services/certops/jobs.js");
const { migrations } = require("../../apps/api/migrations/migrate.js");

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

const FORBIDDEN_METADATA_NAMES = [
  "privateKey",
  "privateKeyPem",
  "encryptedPrivateKey",
  "keyMaterial",
  "pfxBlob",
  "jksBlob",
  "tlsKey",
  "caPrivateKey",
  "password",
  "secret",
  "credential",
  "tokenSecret",
  "apiSecret",
  "rawSecret",
  "rawPrivateKey",
  "keyPem",
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

function prChangedFiles() {
  const refs = ["feature/certops", "origin/feature/certops"];
  const errors = [];

  for (const ref of refs) {
    try {
      execFileSync("git", ["rev-parse", "--verify", ref], {
        cwd: repoRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      const output = execFileSync(
        "git",
        ["diff", "--name-only", `${ref}...HEAD`],
        {
          cwd: repoRoot,
          encoding: "utf8",
        },
      );
      return {
        ref,
        files: output
          .split(/\r?\n/)
          .map((file) => file.trim().replace(/\\/g, "/"))
          .filter(Boolean),
      };
    } catch (error) {
      errors.push(`${ref}: ${error.message}`);
    }
  }

  throw new Error(
    `Unable to compare M2-A1 PR diff against feature/certops or origin/feature/certops: ${errors.join("; ")}`,
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

      for (const metadataName of FORBIDDEN_METADATA_NAMES) {
        assert.equal(
          validate(withMetadataName(metadataName)),
          false,
          `${schemaId} must reject custody-shaped metadata name ${metadataName}`,
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
          output: "[REDACTED]",
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

    assert.equal(
      validateStandaloneEvidence({ eventType: "certificate.observed" }),
      false,
      "standalone evidence schema must keep normalized persisted fields required",
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

    assert.match(schemaBlock, /required: \[ok, eventId, jobId, status\]/);
    assert.doesNotMatch(schemaBlock, /required: \[accepted, code\]/);
    assert.doesNotMatch(schemaBlock, /\n        accepted:/);
    assert.doesNotMatch(schemaBlock, /\n        code:/);
    assert.match(schemaBlock, /\n        ok:\r?\n          type: boolean\r?\n          enum: \[true\]/);
    assert.match(schemaBlock, /\n        eventId:\r?\n          type: string/);
    assert.match(schemaBlock, /maxLength: 128/);
    assert.match(schemaBlock, /pattern: "\^\[A-Za-z0-9_\.\:-\]\+\$"/);
    assert.match(schemaBlock, /\n        jobId:\r?\n          type: string\r?\n          format: uuid/);
    assert.match(
      schemaBlock,
      /\n        status:\r?\n          type: string\r?\n          enum: \[pending_approval, approved, rejected, pending, claimed, running, succeeded, failed, blocked, cancelled\]/,
    );
    assert.match(schemaBlock, /\n        evidenceId:\r?\n          type: string\r?\n          format: uuid\r?\n          nullable: true/);
    assert.match(
      schemaBlock,
      /\n        duplicate:\r?\n          type: boolean\r?\n          default: false/,
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
      /certOpsExecutorRouter\.post\(\s*"\/api\/v1\/certops\/executor\/events",\s*preAuthRateLimitMiddleware,\s*certOpsEnabledMiddleware,\s*authMiddleware,\s*rateLimitMiddleware,\s*requireExecutorEvidenceScope,\s*executorEventsHandler,/s,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /CERTOPS_EXECUTOR_EVENT_IDEMPOTENCY_CONFLICT/,
    );
    assert.match(
      certOpsExecutorRoutesSource,
      /CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH/,
    );
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

  it("closes token OpenAPI skeletons around canonical M2 scopes", () => {
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

  it("keeps the committed M2-A1 through M2-A7 diff within the stacked scope", () => {
    const { ref, files } = prChangedFiles();
    const allowedM2Files = new Set([
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
      "tests/integration/certops-api-token-auth.test.js",
      "tests/integration/certops-api-tokens.test.js",
      "tests/integration/certops-executor-events.test.js",
      "tests/integration/certops-job-read-apis.test.js",
      "tests/integration/certops-jobs-evidence.test.js",
      "tests/integration/certops-machine-token-rate-limit.test.js",
      "tests/integration/suites/core-compatible.txt",
      "tests/integration/suites/core.txt",
      "tests/unit/certops-api-token-auth.test.js",
      "tests/unit/certops-api-tokens.test.js",
      "tests/unit/certops-evidence.test.js",
      "tests/unit/certops-jobs.test.js",
      "tests/unit/certops-machine-token-rate-limit.test.js",
      "tests/unit/certops-migration.test.js",
      "tests/unit/secretMaterial.test.js",
    ]);
    const unexpectedFiles = files.filter(
      (file) =>
        file === "contracts.manifest.json" ||
        file.startsWith("packages/contracts/") ||
        file === "tests/unit/certops-m2-contracts.test.js" ||
        file === "tests/unit/certops-routes-hardening.test.js" ||
        allowedM2Files.has(file),
    );

    assert.deepEqual(
      files.filter((file) => !unexpectedFiles.includes(file)),
      [],
      `stacked M2-A1 through M2-A7 diff against ${ref} must stay within the allowed scope`,
    );
    assert.equal(
      certOpsRoutesSource.includes("/api/v1/certops/executor"),
      false,
    );
    assert.equal(certOpsRoutesSource.includes("certificate_jobs"), false);
    assert.equal(certOpsRoutesSource.includes("certificate_evidence"), false);
    assert.equal(certOpsRoutesSource.includes("api_tokens"), false);
  });

  it("keeps local app changes within the M2-A2 through M2-A6 backend scope", () => {
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
  });
});
