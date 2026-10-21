"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);
const openApiSource = fs.readFileSync(
  path.resolve(__dirname, "../../packages/contracts/openapi/openapi.yaml"),
  "utf8",
);

function recorder() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

const currentPeriod = {
  periodId: "11111111-1111-4111-8111-111111111111",
  startedAt: "2026-10-01T00:00:00.000Z",
  managementMode: "automatic",
  automationEnabled: true,
  renewalProfile: { id: "22222222-2222-4222-8222-222222222222", name: "IIS" },
  source: "agent_filesystem",
};

describe("replace-management 409 conflict body", () => {
  for (const [code, reason] of [
    ["CERTOPS_MANAGEMENT_ALREADY_OPEN", "period_id_required"],
    ["CERTOPS_MANAGEMENT_ALREADY_OPEN", "period_id_stale"],
    ["CERTOPS_MANAGEMENT_ALREADY_OPEN", "already_managed"],
    ["CERTOPS_MANAGEMENT_PERIOD_MISMATCH", "period_id_mismatch"],
  ]) {
    it(`keeps 409 ${code} and exposes reason ${reason} with the open period`, () => {
      const res = recorder();
      const handled = certOpsRouter._test.handleCertOpsError(res, {
        code,
        message: "actionable",
        details: { reason, currentPeriod },
      });
      assert.notEqual(handled, null);
      assert.equal(res.statusCode, 409);
      assert.deepEqual(res.body, {
        error: "actionable",
        code,
        reason,
        currentPeriod,
      });
    });
  }

  it("never forwards fields the service did not put in details", () => {
    const res = recorder();
    certOpsRouter._test.handleCertOpsError(res, {
      code: "CERTOPS_MANAGEMENT_ALREADY_OPEN",
      message: "m",
      details: { reason: "period_id_required", currentPeriod, secret: "x" },
      keyReference: "vault://private",
    });
    assert.deepEqual(Object.keys(res.body).sort(), [
      "code",
      "currentPeriod",
      "error",
      "reason",
    ]);
  });

  it("returns a null currentPeriod when the service found none", () => {
    const res = recorder();
    certOpsRouter._test.handleCertOpsError(res, {
      code: "CERTOPS_MANAGEMENT_PERIOD_MISMATCH",
      message: "m",
      details: { reason: "period_id_mismatch", currentPeriod: null },
    });
    assert.equal(res.body.currentPeriod, null);
  });
});

describe("replace-management OpenAPI documents the conflict body", () => {
  it("defines the schema with the open period fields", () => {
    const block = openApiSource.split("    CertOpsManagementConflict:")[1];
    assert.ok(block, "CertOpsManagementConflict schema missing");
    const schema = block.split("\n    MaterialDistribution_uuid:")[0];
    for (const field of [
      "reason:",
      "currentPeriod:",
      "periodId:",
      "managementMode:",
      "startedAt:",
      "period_id_required",
      "period_id_stale",
    ])
      assert.ok(schema.includes(field), `schema lacks ${field}`);
  });

  it("references it from the 409 of replace-management and readd", () => {
    for (const suffix of ["replace-management", "readd"]) {
      const start = openApiSource.indexOf(
        `/certops/sources/{managedCertificateId}/${suffix}:`,
      );
      assert.ok(start > 0, `${suffix} path missing`);
      const section = openApiSource.slice(start, start + 3500);
      const conflict = section.split('"409":')[1].split('"422"')[0];
      assert.ok(
        conflict.includes("#/components/schemas/CertOpsManagementConflict"),
        `${suffix} 409 does not use the conflict schema`,
      );
    }
  });
});
