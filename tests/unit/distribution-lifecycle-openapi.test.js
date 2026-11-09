"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const {
  DEFAULT_POLICY,
} = require("../../apps/api/services/certops/distributionLifecycle");
const runtime = require("../../packages/contracts/certops/distribution-lifecycle.schema.json");
const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const swaggerRequire = createRequire(apiRequire.resolve("swagger-jsdoc"));
const SwaggerParser = swaggerRequire("swagger-parser");
const yaml = swaggerRequire("yaml");
const specPath = path.resolve(
  __dirname,
  "../../packages/contracts/openapi/openapi.yaml",
);
const document = yaml.parse(fs.readFileSync(specPath, "utf8"));
const groupPath =
  "/api/v1/workspaces/{id}/certops/distribution-groups/{groupId}";
const timestamp = "2030-01-01T00:00:00Z";

test("retirement dossier OpenAPI documents all routes and unverified evidence boundaries", () => {
  const job = document.paths["/api/v1/workspaces/{id}/certops/distribution-jobs/{jobId}/retirement-dossiers"];
  const detail = document.paths["/api/v1/workspaces/{id}/certops/retirement-dossiers/{dossierId}"];
  const review = document.paths["/api/v1/workspaces/{id}/certops/retirement-dossiers/{dossierId}/review"];
  assert.ok(job.get && job.post && detail.get && review.post);
  assert.deepEqual(review.post.responses["200"].content["application/json"].schema.properties.reconciliationCleared.enum, [false]);
  assert.deepEqual(detail.get.responses["200"].content["application/json"].schema.properties.evidenceVerified.enum, [false]);
  const schema=document.components.schemas.MaterialRetirementEvidence;
  const validate=new Ajv({strict:false}).compile(schema);
  const evidence=Object.fromEntries(schema.required.map(key=>[key,`sha256:${"a".repeat(64)}`]));
  assert.equal(validate(evidence),true);
  assert.equal(validate({...evidence,writerInventory:[evidence.writerInventory]}),false);
  assert.equal(validate({...evidence,extra:"unexpected"}),false);
});

test("the complete served contract validates as OpenAPI 3.0 with resolved lifecycle schemas", async () => {
  const parsed = await SwaggerParser.validate(specPath);
  assert.equal(parsed.openapi, "3.0.3");
  const policy =
    parsed.paths[`${groupPath}/policy`].put.requestBody.content[
      "application/json"
    ].schema;
  assert.equal(
    policy.properties.policy.properties.authorizationExpiresAt.nullable,
    true,
  );
  assert.deepEqual(
    policy.properties.policy.properties.retention.properties.requiresApproval
      .enum,
    [true],
  );
  const cleanupConflict =
    parsed.paths[`${groupPath}/cleanups`].post.responses["409"];
  assert.deepEqual(Object.keys(cleanupConflict), ["description"]);
  assert.equal(
    cleanupConflict.description,
    "Disabled, unqualified, protected, stale authority or live claim; no deletion",
  );
});

const policyCases = [
  ["null expiry", () => {}, true],
  [
    "dated expiry",
    (v) => {
      v.policy.authorizationExpiresAt = timestamp;
    },
    true,
  ],
  [
    "missing expiry",
    (v) => {
      delete v.policy.authorizationExpiresAt;
    },
    false,
  ],
  [
    "invalid expiry",
    (v) => {
      v.policy.authorizationExpiresAt = "tomorrow";
    },
    false,
  ],
  [
    "non-date expiry",
    (v) => {
      v.policy.authorizationExpiresAt = 1;
    },
    false,
  ],
  [
    "negative revision",
    (v) => {
      v.expectedRevision = -1;
    },
    false,
  ],
  [
    "fractional revision",
    (v) => {
      v.expectedRevision = 0.5;
    },
    false,
  ],
  [
    "oversized revision",
    (v) => {
      v.expectedRevision = 2147483648;
    },
    false,
  ],
  [
    "missing revision",
    (v) => {
      delete v.expectedRevision;
    },
    false,
  ],
  [
    "unknown request field",
    (v) => {
      v.token = "synthetic";
    },
    false,
  ],
  [
    "unknown policy field",
    (v) => {
      v.policy.token = "synthetic";
    },
    false,
  ],
  [
    "unknown mode",
    (v) => {
      v.policy.mode = "automatic";
    },
    false,
  ],
  [
    "parallelism ceiling",
    (v) => {
      v.policy.maxParallel = 16;
    },
    true,
  ],
  [
    "excess parallelism",
    (v) => {
      v.policy.maxParallel = 17;
    },
    false,
  ],
  [
    "zero parallelism",
    (v) => {
      v.policy.maxParallel = 0;
    },
    false,
  ],
  [
    "unbounded verification",
    (v) => {
      v.policy.verification.intervalSeconds = 299;
    },
    false,
  ],
  [
    "invalid stale-job bound",
    (v) => {
      v.policy.verification.staleJobSeconds = 86401;
    },
    false,
  ],
  [
    "duplicate contact groups",
    (v) => {
      v.policy.alerts.contactGroupIds = ["ops", "ops"];
    },
    false,
  ],
  [
    "missing approval",
    (v) => {
      delete v.policy.retention.requiresApproval;
    },
    false,
  ],
  [
    "false approval",
    (v) => {
      v.policy.retention.requiresApproval = false;
    },
    false,
  ],
  [
    "null approval",
    (v) => {
      v.policy.retention.requiresApproval = null;
    },
    false,
  ],
  [
    "unknown retention field",
    (v) => {
      v.policy.retention.token = "synthetic";
    },
    false,
  ],
];
const activationPolicy = {
  method: "reload",
  disruptive: false,
  requiresApproval: true,
  timezone: "UTC",
  windows: [],
  blackouts: [],
  validUntil: null,
  emergency: null,
};
const emergency = {
  start: timestamp,
  end: "2030-01-01T01:00:00Z",
  reference: "incident_123",
};
const activationCases = [
  ["null expiry and emergency", () => {}, true],
  [
    "dated expiry",
    (v) => {
      v.policy.validUntil = timestamp;
    },
    true,
  ],
  [
    "bounded emergency",
    (v) => {
      v.policy.emergency = structuredClone(emergency);
    },
    true,
  ],
  [
    "missing expiry",
    (v) => {
      delete v.policy.validUntil;
    },
    false,
  ],
  [
    "missing emergency",
    (v) => {
      delete v.policy.emergency;
    },
    false,
  ],
  [
    "invalid expiry",
    (v) => {
      v.policy.validUntil = "tomorrow";
    },
    false,
  ],
  [
    "non-date expiry",
    (v) => {
      v.policy.validUntil = true;
    },
    false,
  ],
  [
    "invalid emergency type",
    (v) => {
      v.policy.emergency = "incident";
    },
    false,
  ],
  [
    "missing emergency reference",
    (v) => {
      v.policy.emergency = { start: timestamp, end: timestamp };
    },
    false,
  ],
  [
    "invalid emergency reference",
    (v) => {
      v.policy.emergency = { ...emergency, reference: "unsafe reference" };
    },
    false,
  ],
  [
    "emergency credentials",
    (v) => {
      v.policy.emergency = { ...emergency, token: "synthetic" };
    },
    false,
  ],
  [
    "unknown request field",
    (v) => {
      v.token = "synthetic";
    },
    false,
  ],
  [
    "unknown policy field",
    (v) => {
      v.policy.token = "synthetic";
    },
    false,
  ],
  [
    "zero authorization revision",
    (v) => {
      v.expectedAuthorizationRevision = 0;
    },
    false,
  ],
  [
    "oversized authorization revision",
    (v) => {
      v.expectedAuthorizationRevision = 2147483648;
    },
    false,
  ],
  [
    "unknown method",
    (v) => {
      v.policy.method = "shell";
    },
    false,
  ],
  [
    "duplicate weekdays",
    (v) => {
      v.policy.windows = [{ days: [1, 1], start: "01:00", end: "02:00" }];
    },
    false,
  ],
  [
    "invalid time",
    (v) => {
      v.policy.windows = [{ days: [1], start: "25:00", end: "02:00" }];
    },
    false,
  ],
  [
    "valid window",
    (v) => {
      v.policy.windows = [{ days: [0, 6], start: "01:00", end: "02:00" }];
    },
    true,
  ],
  [
    "oversized blackout list",
    (v) => {
      v.policy.blackouts = Array.from({ length: 65 }, () => ({
        start: timestamp,
        end: timestamp,
      }));
    },
    false,
  ],
];

for (const [route, method, definition, base, cases] of [
  [
    `${groupPath}/policy`,
    "put",
    "policyRequest",
    { policy: DEFAULT_POLICY, expectedRevision: 0 },
    policyCases,
  ],
  [
    `${groupPath}/consumers/{bindingId}/activation-policy`,
    "put",
    "activationRequest",
    { policy: activationPolicy, expectedAuthorizationRevision: 1 },
    activationCases,
  ],
  [
    `${groupPath}/consumers/{bindingId}/emergency`,
    "post",
    "activationRequest",
    { policy: activationPolicy, expectedAuthorizationRevision: 1 },
    activationCases,
  ],
]) {
  test(`${method.toUpperCase()} ${route} preserves runtime request validation`, () => {
    const requestSchema =
      document.paths[route][method].requestBody.content["application/json"]
        .schema;
    assert.match(
      requestSchema.$ref,
      /^#\/components\/schemas\//,
      "The served request must resolve without fetching a separate JSON Schema",
    );
    const openApiAjv = new Ajv({ strict: false });
    const runtimeAjv = new Ajv({ strict: false });
    addFormats(openApiAjv);
    addFormats(runtimeAjv);
    const documented = openApiAjv.compile({
      components: document.components,
      ...requestSchema,
    });
    const enforced = runtimeAjv.compile({
      ...runtime,
      $ref: `#/definitions/${definition}`,
    });
    for (const [name, mutate, expected] of cases) {
      const value = structuredClone(base);
      mutate(value);
      assert.equal(enforced(value), expected, `Runtime: ${name}`);
      assert.equal(documented(value), expected, `OpenAPI: ${name}`);
    }
  });
}
