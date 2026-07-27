"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_CERTIFICATE_FILTER_INVALID,
  CERTOPS_CERTIFICATE_SOURCE_INVALID,
  CERTOPS_CERTIFICATE_STATUS_INVALID,
  listManagedCertificates,
  managedCertificateFilterSql,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function certificateRow(overrides = {}) {
  return {
    id: overrides.id || "cert-1",
    workspace_id: WORKSPACE_A,
    common_name: "example.test",
    sans: [],
    issuer: "Test CA",
    serial_number: "01",
    not_before: new Date("2026-01-01T00:00:00.000Z"),
    not_after: new Date("2026-12-31T00:00:00.000Z"),
    status: "active",
    source: "manual",
    profile_id: null,
    key_mode: null,
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

/**
 * Applies the predicates the service emitted against in-memory rows, so the
 * assertions cover the SQL the count and page queries actually share rather
 * than a hand-rolled restatement of the filter rules.
 */
function matches(where, params, row, profileStatusById) {
  const profileStatus = row.profile_id
    ? profileStatusById[row.profile_id] || null
    : null;

  return where
    .split("AND")
    .map((clause) => clause.trim())
    .filter(Boolean)
    .every((clause) => {
      if (clause.startsWith("mc.workspace_id")) {
        return row.workspace_id === params[0];
      }
      if (clause.startsWith("mc.status = $")) {
        const index = Number(clause.slice(clause.indexOf("$") + 1)) - 1;
        return row.status === params[index];
      }
      if (clause.startsWith("mc.source = $")) {
        const index = Number(clause.slice(clause.indexOf("$") + 1)) - 1;
        return row.source === params[index];
      }
      if (clause === "mc.profile_id IS NULL") return row.profile_id === null;
      if (clause === "mc.profile_id IS NOT NULL") return row.profile_id !== null;
      if (clause.startsWith("cp.status IN (")) {
        return ["disabled", "archived"].includes(profileStatus);
      }
      if (clause.startsWith("COALESCE(cp.status, '') NOT IN (")) {
        return !["disabled", "archived"].includes(profileStatus);
      }
      if (clause.startsWith("COALESCE(mc.key_mode, '') NOT IN (")) {
        return !["agent-local", "proxy-agent-local"].includes(row.key_mode);
      }
      if (clause.startsWith("mc.key_mode IN (")) {
        return ["agent-local", "proxy-agent-local"].includes(row.key_mode);
      }
      throw new Error(`Unhandled predicate in fake: ${clause}`);
    });
}

function createMemoryClient(rows, profileStatusById = {}) {
  const client = {
    queries: [],
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      client.queries.push({ sql: normalized, params });

      const whereStart = sql.indexOf("WHERE ");
      assert.ok(whereStart >= 0, `expected a WHERE clause in: ${normalized}`);
      let where = sql.slice(whereStart + "WHERE ".length);
      const orderIndex = where.indexOf("ORDER BY");
      if (orderIndex >= 0) where = where.slice(0, orderIndex);
      const limitIndex = where.indexOf("LIMIT");
      if (limitIndex >= 0) where = where.slice(0, limitIndex);

      const matching = rows.filter((row) =>
        matches(where, params, row, profileStatusById),
      );

      if (normalized.startsWith("SELECT COUNT(*)")) {
        return { rows: [{ total: matching.length }] };
      }

      const limit = Number(params[params.length - 2]);
      const offset = Number(params[params.length - 1]);
      return { rows: matching.slice(offset, offset + limit) };
    },
  };
  return client;
}

describe("CertOps managed certificate list pagination", () => {
  it("counts the whole workspace rather than the returned page", async () => {
    const rows = Array.from({ length: 30 }, (unused, index) =>
      certificateRow({ id: `cert-${index}` }),
    );
    const client = createMemoryClient(rows);

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      limit: 10,
    });

    assert.equal(listed.items.length, 10);
    assert.deepEqual(listed.pagination, { limit: 10, offset: 0, total: 30 });
  });

  it("reports a non-zero total for an offset past the end", async () => {
    const rows = Array.from({ length: 4 }, (unused, index) =>
      certificateRow({ id: `cert-${index}` }),
    );
    const client = createMemoryClient(rows);

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      limit: 25,
      offset: 400,
    });

    assert.deepEqual(listed.items, []);
    assert.equal(listed.pagination.total, 4);
  });

  it("counts through the same predicate the page query used", async () => {
    const rows = [
      ...Array.from({ length: 6 }, (unused, index) =>
        certificateRow({ id: `expiring-${index}`, status: "expiring" }),
      ),
      ...Array.from({ length: 9 }, (unused, index) =>
        certificateRow({ id: `active-${index}`, status: "active" }),
      ),
    ];
    const client = createMemoryClient(rows);

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      status: "expiring",
      limit: 2,
    });

    assert.equal(listed.items.length, 2);
    assert.equal(listed.pagination.total, 6);
    const countQuery = client.queries.find((entry) =>
      entry.sql.startsWith("SELECT COUNT(*)"),
    );
    const pageQuery = client.queries.find((entry) =>
      entry.sql.startsWith("SELECT mc.*"),
    );
    assert.ok(countQuery.sql.includes("mc.status = $2"));
    assert.ok(pageQuery.sql.includes("mc.status = $2"));
  });
});

describe("CertOps managed certificate list filters", () => {
  it("filters on status and source", async () => {
    const rows = [
      certificateRow({ id: "a", status: "expiring", source: "agent_filesystem" }),
      certificateRow({ id: "b", status: "expiring", source: "manual" }),
      certificateRow({ id: "c", status: "active", source: "agent_filesystem" }),
    ];
    const client = createMemoryClient(rows);

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      status: "expiring",
      source: "agent_filesystem",
    });

    assert.deepEqual(listed.items.map((item) => item.id), ["a"]);
    assert.equal(listed.pagination.total, 1);
  });

  it("selects certificates with no renewal profile attached", async () => {
    const rows = [
      certificateRow({ id: "unattached" }),
      certificateRow({ id: "attached", profile_id: "profile-1" }),
    ];
    const client = createMemoryClient(rows, { "profile-1": "active" });

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      noRenewalProfile: "true",
    });

    assert.deepEqual(listed.items.map((item) => item.id), ["unattached"]);
  });

  it("selects certificates whose profile has renewal switched off", async () => {
    const rows = [
      certificateRow({ id: "disabled-profile", profile_id: "profile-disabled" }),
      certificateRow({ id: "archived-profile", profile_id: "profile-archived" }),
      certificateRow({ id: "live-profile", profile_id: "profile-active" }),
      certificateRow({ id: "no-profile" }),
    ];
    const client = createMemoryClient(rows, {
      "profile-disabled": "disabled",
      "profile-archived": "archived",
      "profile-active": "active",
    });

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      renewalDisabled: "true",
    });

    assert.deepEqual(listed.items.map((item) => item.id).sort(), [
      "archived-profile",
      "disabled-profile",
    ]);
  });

  it("selects certificates whose key an agent cannot deploy, unknown custody included", async () => {
    const rows = [
      certificateRow({ id: "agent-local", key_mode: "agent-local" }),
      certificateRow({ id: "proxy", key_mode: "proxy-agent-local" }),
      certificateRow({ id: "external", key_mode: "external-managed" }),
      certificateRow({ id: "unknown", key_mode: null }),
    ];
    const client = createMemoryClient(rows);

    const listed = await listManagedCertificates({
      client,
      workspaceId: WORKSPACE_A,
      keyNotAgentDeployable: "true",
    });

    assert.deepEqual(listed.items.map((item) => item.id).sort(), [
      "external",
      "unknown",
    ]);
  });

  it("keeps the three renewal facts independent rather than one combined switch", () => {
    const noProfile = managedCertificateFilterSql({
      workspaceId: WORKSPACE_A,
      noRenewalProfile: true,
    });
    const disabled = managedCertificateFilterSql({
      workspaceId: WORKSPACE_A,
      renewalDisabled: true,
    });
    const keyBound = managedCertificateFilterSql({
      workspaceId: WORKSPACE_A,
      keyNotAgentDeployable: true,
    });

    assert.ok(noProfile.where.includes("mc.profile_id IS NULL"));
    assert.equal(noProfile.where.includes("cp.status"), false);
    assert.equal(noProfile.where.includes("key_mode"), false);

    assert.ok(disabled.where.includes("cp.status IN ('disabled', 'archived')"));
    assert.equal(disabled.where.includes("mc.profile_id IS NULL"), false);

    assert.ok(
      keyBound.where.includes("NOT IN ('agent-local', 'proxy-agent-local')"),
    );
    assert.equal(keyBound.where.includes("cp.status"), false);
  });

  it("rejects filter values outside the column constraints", () => {
    assert.throws(
      () =>
        managedCertificateFilterSql({
          workspaceId: WORKSPACE_A,
          status: "not-a-status",
        }),
      (err) => err.code === CERTOPS_CERTIFICATE_STATUS_INVALID,
    );
    assert.throws(
      () =>
        managedCertificateFilterSql({
          workspaceId: WORKSPACE_A,
          source: "not-a-source",
        }),
      (err) => err.code === CERTOPS_CERTIFICATE_SOURCE_INVALID,
    );
    assert.throws(
      () =>
        managedCertificateFilterSql({
          workspaceId: WORKSPACE_A,
          renewalDisabled: "perhaps",
        }),
      (err) => err.code === CERTOPS_CERTIFICATE_FILTER_INVALID,
    );
  });
});
