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
const { CERTOPS_LIST_SORT_INVALID } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/listSorting.js"),
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

function pageQuery(db, prefix) {
  return db.queries.find(
    (sql) => sql.startsWith(prefix) && sql.includes("ORDER BY"),
  );
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

async function certificateQuery(sort, direction = "asc") {
  const db = recordingDb();
  await listManagedCertificates({
    client: db,
    workspaceId: WORKSPACE_ID,
    limit: 20,
    offset: 40,
    sort,
    direction,
  });
  return pageQuery(db, "SELECT mc.*");
}

async function agentQuery(sort, direction = "asc") {
  const db = recordingDb();
  await listAgents({
    client: db,
    workspaceId: WORKSPACE_ID,
    limit: 20,
    offset: 40,
    sort,
    direction,
  });
  return pageQuery(db, "SELECT id,");
}

async function profileQuery(sort, direction = "asc") {
  const db = recordingDb();
  await listRenewalProfiles({
    db,
    workspaceId: WORKSPACE_ID,
    limit: 20,
    offset: 40,
    sort,
    direction,
  });
  return pageQuery(db, "SELECT cp.id");
}

async function upcomingQuery(sort, direction = "asc") {
  const db = recordingDb();
  await listUpcomingRenewals({
    db,
    workspaceId: WORKSPACE_ID,
    limit: 20,
    offset: 40,
    thresholdDays: 30,
    sort,
    direction,
  });
  return pageQuery(db, "SELECT mc.id");
}

describe("CertOps paginated list ordering", () => {
  it("keeps stable server defaults before limit and offset", async () => {
    const certificates = recordingDb();
    await listManagedCertificates({
      client: certificates,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
    });
    assertOrderedBeforePagination(
      pageQuery(certificates, "SELECT mc.*"),
      "ORDER BY mc.not_after ASC NULLS LAST, mc.created_at DESC, mc.id ASC",
    );

    const agents = recordingDb();
    await listAgents({
      client: agents,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
    });
    assertOrderedBeforePagination(
      pageQuery(agents, "SELECT id,"),
      "ORDER BY created_at DESC, id ASC",
    );

    const profiles = recordingDb();
    await listRenewalProfiles({
      db: profiles,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
    });
    assertOrderedBeforePagination(
      pageQuery(profiles, "SELECT cp.id"),
      "ORDER BY cp.name ASC, cp.id ASC",
    );

    const upcoming = recordingDb();
    await listUpcomingRenewals({
      db: upcoming,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 40,
      thresholdDays: 30,
    });
    assertOrderedBeforePagination(
      pageQuery(upcoming, "SELECT mc.id"),
      "ORDER BY mc.not_after ASC NULLS LAST, mc.common_name ASC, mc.id ASC",
    );
  });

  it("allowlists every direct certificate sort and orders before pagination", async () => {
    const cases = {
      certificate: "COALESCE(NULLIF(mc.common_name, '')",
      status: "mc.status ASC NULLS LAST, mc.id ASC",
      expiry: "mc.not_after ASC NULLS LAST, mc.id ASC",
      keyLocality: "CASE WHEN mc.key_mode = 'external-unknown'",
      source: "CASE mc.source",
    };
    for (const [sort, expression] of Object.entries(cases)) {
      const sql = await certificateQuery(sort);
      assertOrderedBeforePagination(sql, `ORDER BY ${expression}`);
      assert.match(sql, /, mc\.id ASC LIMIT/);
    }
  });

  it("allowlists every exact agent sort and excludes derived display status", async () => {
    const cases = {
      agent: "COALESCE(NULLIF(name, '')",
      os: "CASE platform",
      version: "agent_version ASC NULLS LAST, id ASC",
      protocol: "protocol_version ASC NULLS LAST, id ASC",
      clockDrift: "clock_offset_ms ASC NULLS LAST, id ASC",
      ntp: "ntp_synced ASC NULLS LAST, id ASC",
      execution: "CASE WHEN jsonb_typeof(supported_operations)",
      signingKey: "pinned_signing_key_id ASC NULLS LAST, id ASC",
      lastHeartbeat: "last_seen_at ASC NULLS LAST, id ASC",
    };
    for (const [sort, expression] of Object.entries(cases)) {
      const sql = await agentQuery(sort);
      assertOrderedBeforePagination(sql, `ORDER BY ${expression}`);
      assert.match(sql, /, id ASC LIMIT/);
    }
    await assert.rejects(
      () => agentQuery("status"),
      (error) => error.code === CERTOPS_LIST_SORT_INVALID,
    );
  });

  it("allowlists every renewal-profile sort", async () => {
    const cases = {
      profile: "cp.name ASC NULLS LAST, cp.id ASC",
      certificates: "certificate_count ASC NULLS LAST, cp.id ASC",
      autoRenew: "CASE WHEN LOWER(COALESCE(cp.status, ''))",
      leadTime: "cp.renew_before_days ASC NULLS LAST, cp.id ASC",
      key: "CASE WHEN NULLIF(cp.public_metadata->'renewalProfile'->>'keyAlgorithm'",
    };
    for (const [sort, expression] of Object.entries(cases)) {
      const sql = await profileQuery(sort);
      assertOrderedBeforePagination(sql, `ORDER BY ${expression}`);
      assert.match(sql, /, cp\.id ASC LIMIT/);
    }
  });

  it("allowlists exact upcoming-renewal sorts and excludes derived auto-renew", async () => {
    const cases = {
      certificate: "mc.common_name ASC NULLS LAST, mc.id ASC",
      expires: "mc.not_after ASC NULLS LAST, mc.id ASC",
      renewalWindow: "mc.not_after - (COALESCE(cp.renew_before_days, $2)",
      lastAttempt: "last_renew_job_status ASC NULLS LAST, mc.id ASC",
    };
    for (const [sort, expression] of Object.entries(cases)) {
      const sql = await upcomingQuery(sort);
      assertOrderedBeforePagination(sql, `ORDER BY ${expression}`);
      assert.match(sql, /, mc\.id ASC LIMIT/);
    }
    await assert.rejects(
      () => upcomingQuery("autoRenew"),
      (error) => error.code === CERTOPS_LIST_SORT_INVALID,
    );
  });

  it("supports descending order with the same deterministic tie-breaker", async () => {
    const sql = await certificateQuery("expiry", "desc");
    assertOrderedBeforePagination(
      sql,
      "ORDER BY mc.not_after DESC NULLS LAST, mc.id ASC",
    );
  });

  it("rejects unknown keys, invalid directions, and direction without a key", async () => {
    await assert.rejects(
      () => certificateQuery("not_a_column"),
      (error) => error.code === CERTOPS_LIST_SORT_INVALID,
    );
    await assert.rejects(
      () => profileQuery("profile", "sideways"),
      (error) => error.code === CERTOPS_LIST_SORT_INVALID,
    );
    const db = recordingDb();
    await assert.rejects(
      () =>
        listUpcomingRenewals({
          db,
          workspaceId: WORKSPACE_ID,
          limit: 20,
          offset: 0,
          thresholdDays: 30,
          direction: "desc",
        }),
      (error) => error.code === CERTOPS_LIST_SORT_INVALID,
    );
  });

  it("moves a globally smallest row onto page one before slicing", async () => {
    const rows = Array.from({ length: 20 }, (_unused, index) => ({
      id: `zulu-${String(index).padStart(2, "0")}`,
      workspace_id: WORKSPACE_ID,
      common_name: `zulu-${String(index).padStart(2, "0")}.example.test`,
      subject_alt_names: [],
      status: "active",
      source: "manual",
      not_after: new Date("2027-01-01T00:00:00.000Z"),
      created_at: new Date("2026-01-01T00:00:00.000Z"),
      updated_at: new Date("2026-01-01T00:00:00.000Z"),
    }));
    rows.push({
      ...rows[0],
      id: "alpha",
      common_name: "alpha.example.test",
    });

    const db = {
      async query(sql, params = []) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        if (normalized.startsWith("SELECT COUNT(*)::int AS total")) {
          return { rows: [{ total: rows.length }] };
        }
        const ordered = rows
          .slice()
          .sort((left, right) =>
            left.common_name.localeCompare(right.common_name),
          );
        const limit = Number(params.at(-2));
        const offset = Number(params.at(-1));
        return { rows: ordered.slice(offset, offset + limit) };
      },
    };

    const firstPage = await listManagedCertificates({
      client: db,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 0,
      sort: "certificate",
      direction: "asc",
    });
    const secondPage = await listManagedCertificates({
      client: db,
      workspaceId: WORKSPACE_ID,
      limit: 20,
      offset: 20,
      sort: "certificate",
      direction: "asc",
    });

    assert.equal(firstPage.items[0].commonName, "alpha.example.test");
    assert.equal(firstPage.items.length, 20);
    assert.equal(secondPage.items[0].commonName, "zulu-19.example.test");
  });
});
