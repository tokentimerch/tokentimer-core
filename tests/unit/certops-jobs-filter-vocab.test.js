"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { describe, it } = require("node:test");

const {
  JOB_OPERATIONS,
  JOB_STATUSES,
  isTerminalJobStatus,
  TERMINAL_JOB_STATUSES,
} = require("../../apps/api/services/certops/jobs");
const { logsComplete } = require("../../apps/api/services/certops/agentJobLogs");

function extractExportArray(source, exportName) {
  const match = source.match(
    new RegExp(`export const ${exportName} = \\[([\\s\\S]*?)\\];`),
  );
  assert.ok(match, `missing export ${exportName}`);
  return match[1]
    .split("\n")
    .map((line) => {
      const quoted = line.match(/['"]([^'"]+)['"]/);
      return quoted ? quoted[1] : null;
    })
    .filter(Boolean);
}

function extractOpenApiListJobsEnum(openapiSource, paramName) {
  const jobsGet = openapiSource.match(
    /operationId: listCertOpsJobs[\s\S]*?\n    post:/,
  );
  assert.ok(jobsGet, "listCertOpsJobs GET block missing");
  const param = jobsGet[0].match(
    new RegExp(
      `name: ${paramName}\\n[\\s\\S]*?enum:\\s*(?:\\[([^\\]]+)\\]|((?:\\n\\s+- [^\\n]+)+))`,
    ),
  );
  assert.ok(param, `listCertOpsJobs query param ${paramName} enum missing`);
  const raw = param[1] || param[2];
  return raw
    .split(/[\n,]/)
    .map((part) => part.replace(/^[\s\-:]+/, "").trim())
    .filter(Boolean);
}

describe("Jobs filter vocabulary parity", () => {
  const dashboardApi = fs.readFileSync(
    path.join(
      __dirname,
      "../../apps/dashboard/src/components/certops/certopsJobsApi.js",
    ),
    "utf8",
  );
  const openapiSource = fs.readFileSync(
    path.join(__dirname, "../../packages/contracts/openapi/openapi.yaml"),
    "utf8",
  );

  it("dashboard status and operation dropdowns match the jobs service vocabulary", () => {
    assert.deepEqual(
      extractExportArray(dashboardApi, "CERTOPS_JOB_STATUSES"),
      [...JOB_STATUSES],
    );
    assert.deepEqual(
      extractExportArray(dashboardApi, "CERTOPS_JOB_OPERATIONS"),
      [...JOB_OPERATIONS],
    );
  });

  it("OpenAPI listCertOpsJobs filters match the jobs service vocabulary", () => {
    assert.deepEqual(
      extractOpenApiListJobsEnum(openapiSource, "status"),
      [...JOB_STATUSES],
    );
    assert.deepEqual(
      extractOpenApiListJobsEnum(openapiSource, "operation"),
      [...JOB_OPERATIONS],
    );
    assert.deepEqual(extractOpenApiListJobsEnum(openapiSource, "createdSince"), [
      "24h",
      "7d",
      "30d",
    ]);
    assert.match(
      openapiSource,
      /operationId: listCertOpsJobs[\s\S]*?\n\s+- in: query\n\s+name: q\n/,
    );
    assert.match(
      openapiSource,
      /CertOpsAgentLogBody:[\s\S]*?oneOf:[\s\S]*?CertOpsAgentLogLine/,
    );
  });

  it("agent-log completion uses the canonical terminal job statuses", () => {
    for (const status of JOB_STATUSES) {
      assert.equal(
        isTerminalJobStatus(status),
        TERMINAL_JOB_STATUSES.has(status),
        status,
      );
    }
    assert.equal(isTerminalJobStatus("awaiting_issuer"), true);
    assert.equal(
      logsComplete("awaiting_issuer", [{ status: "final" }]),
      true,
    );
    assert.equal(
      logsComplete("awaiting_issuer", [{ status: "streaming" }]),
      false,
    );
  });
});
