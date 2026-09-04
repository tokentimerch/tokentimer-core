"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { listManagedCertificates } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);
const { listAgents } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentRegistry.js"),
);
const { listRenewalProfiles, listUpcomingRenewals } = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalProfileAdmin.js",
  ),
);

const WORKSPACE_ID = "11111111-1111-4111-8111-111111111111";

function recordingDb() {
  const queries = [];
  return {
    queries,
    async query(sql) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      queries.push(normalized);
      if (normalized.startsWith("SELECT COUNT(*)::int AS total")) {
        return { rows: [{ total: 0 }] };
      }
      return { rows: [] };
    },
  };
}

function assertOrderedBeforePagination(sql, expectedOrder) {
  assert.equal(typeof sql, "string", "expected a paginated list query");
  const orderIndex = sql.indexOf(expectedOrder);
  const limitIndex = sql.lastIndexOf("LIMIT");
  const offsetIndex = sql.lastIndexOf("OFFSET");
  assert.ok(orderIndex >= 0, `missing stable order in: ${sql}`);
  assert.ok(limitIndex > orderIndex, `LIMIT precedes ORDER BY in: ${sql}`);
  assert.ok(offsetIndex > limitIndex, `OFFSET precedes LIMIT in: ${sql}`);
}

describe("CertOps paginated list ordering", () => {
  it("orders certificates globally before applying limit and offset", async () => {
    const db = recordingDb();
    await listManagedCertificates({
      client: db,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
    });

    const pageQuery = db.queries.find((sql) => sql.startsWith("SELECT mc.*"));
    assertOrderedBeforePagination(
      pageQuery,
      "ORDER BY mc.not_after ASC NULLS LAST, mc.created_at DESC, mc.id ASC",
    );
  });

  it("orders agents globally before applying limit and offset", async () => {
    const db = recordingDb();
    await listAgents({
      client: db,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
    });

    const pageQuery = db.queries.find(
      (sql) => sql.includes("FROM certops_agents") && sql.includes("ORDER BY"),
    );
    assertOrderedBeforePagination(
      pageQuery,
      "ORDER BY created_at DESC, id ASC",
    );
  });

  it("orders renewal profiles globally before applying limit and offset", async () => {
    const db = recordingDb();
    await listRenewalProfiles({
      db,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
    });

    const pageQuery = db.queries.find((sql) => sql.startsWith("SELECT cp.id"));
    assertOrderedBeforePagination(pageQuery, "ORDER BY cp.name ASC");
  });

  it("orders upcoming renewals globally before applying limit and offset", async () => {
    const db = recordingDb();
    await listUpcomingRenewals({
      db,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
      thresholdDays: 30,
    });

    const pageQuery = db.queries.find(
      (sql) =>
        sql.startsWith("SELECT mc.id") &&
        sql.includes("AS last_renew_job_status"),
    );
    assertOrderedBeforePagination(
      pageQuery,
      "ORDER BY mc.not_after ASC NULLS LAST, mc.common_name ASC",
    );
  });
});
