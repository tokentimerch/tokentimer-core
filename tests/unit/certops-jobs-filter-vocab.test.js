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

describe("Jobs filter vocabulary parity", () => {
  const dashboardApi = fs.readFileSync(
    path.join(
      __dirname,
      "../../apps/dashboard/src/components/certops/certopsJobsApi.js",
    ),
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
