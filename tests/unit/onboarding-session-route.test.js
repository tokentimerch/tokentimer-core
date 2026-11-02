"use strict";

const { describe, it, before, after, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");
const request = require("supertest");
const { pool } = require("../../apps/api/db/database");
const router = require("../../apps/api/routes/onboarding");
const {
  createCompactPrivateMaterialFixture,
} = require("../helpers/private-material-fixtures");

const WORKSPACE_ID = "11111111-1111-4111-8111-111111111111";
const USER_ID = 42;
const SESSION_URL = `/api/v1/workspaces/${WORKSPACE_ID}/onboarding/mega`;

// A recording database interface, not a PostgreSQL substitute or integration
// claim. Keep the real Express router, guards, schema, store and audit service.
function sessionDatabaseFixture() {
  const calls = [];
  let row = null;
  return {
    calls,
    get row() { return row; },
    async query(sql, values = []) {
      const text = String(sql).replace(/\s+/g, " ").trim();
      calls.push({ text, values });
      if (text.includes("FROM workspaces w")) {
        return {
          rows: [{ id: WORKSPACE_ID, name: "Route fixture", plan: "oss", created_by: USER_ID }],
          rowCount: 1,
        };
      }
      if (text.startsWith("SELECT role FROM workspace_memberships")) {
        return { rows: [{ role: "admin" }], rowCount: 1 };
      }
      if (text.startsWith("INSERT INTO audit_events")) {
        return { rows: [], rowCount: 1 };
      }
      if (text.startsWith("INSERT INTO onboarding_sessions")) {
        if (row) return { rows: [], rowCount: 0 };
        row = {
          id: "22222222-2222-4222-8222-222222222222",
          flow: values[2],
          schema_version: 1,
          planner_version: values[3],
          status: values[4],
          intent: JSON.parse(values[5]),
          progress: JSON.parse(values[6]),
          operation_refs: JSON.parse(values[7]),
          revision: 1,
          created_at: new Date("2026-10-24T00:00:00Z"),
          updated_at: new Date("2026-10-24T00:00:00Z"),
          completed_at: null,
        };
        return { rows: [{ ...row }], rowCount: 1 };
      }
      if (text.startsWith("UPDATE onboarding_sessions SET")) {
        if (!row || row.revision !== values[3]) return { rows: [], rowCount: 0 };
        row = { ...row, revision: row.revision + 1 };
        if (values[4] !== null) row.planner_version = values[4];
        if (values[5] !== null) row.status = values[5];
        for (const [index, section] of ["intent", "progress", "operation_refs"].entries()) {
          if (values[6 + index] !== null) row[section] = JSON.parse(values[6 + index]);
        }
        return { rows: [{ ...row }], rowCount: 1 };
      }
      if (text.startsWith("SELECT") && text.includes("FROM onboarding_sessions")) {
        return { rows: row ? [{ ...row }] : [], rowCount: row ? 1 : 0 };
      }
      throw new Error("Unexpected query in onboarding route fixture");
    },
  };
}

describe("onboarding HTTP private-material boundary", () => {
  let server;
  let database;
  const originalQuery = pool.query;

  before(async () => {
    const app = express();
    app.use(express.json());
    // Session authentication is the only request fixture. Actual requireAuth,
    // workspace loading and membership guards still run on the mounted router.
    app.use((req, _res, next) => {
      const authenticated = req.get("X-Test-Session") === "member";
      req.isAuthenticated = () => authenticated;
      if (authenticated) req.user = { id: USER_ID, email_verified: true };
      next();
    });
    app.use(router);
    await new Promise((resolve, reject) => {
      server = app.listen(0, "127.0.0.1", (error) => error ? reject(error) : resolve());
      server.once("error", reject);
    });
  });

  beforeEach(() => {
    database = sessionDatabaseFixture();
    pool.query = database.query;
  });

  afterEach(() => { pool.query = originalQuery; });
  after(async () => {
    pool.query = originalQuery;
    if (server?.listening) await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  });

  function put(body) {
    return request(server).put(SESSION_URL).set("X-Test-Session", "member").send(body);
  }

  for (const expectedRevision of [0, 2]) {
    for (const section of ["intent", "progress", "operation_refs"]) {
      it(`returns 400 before session SQL for ${section} at revision ${expectedRevision}`, async () => {
        const { representations } = createCompactPrivateMaterialFixture();
        for (const value of representations) {
          const response = await put({
            expectedRevision,
            [section]: { details: [{ note: value }] },
          });
          assert.equal(response.status, 400);
          assert.equal(response.body.code, "SECRET_REJECTED");
          assert.equal(JSON.stringify(response.body).includes(value), false);
        }
        // Authorization reads are expected; no session or audit SQL may run.
        assert.equal(database.calls.some(({ text }) =>
          /onboarding_sessions|audit_events/.test(text)), false);
        assert.equal(database.row, null);
      });
    }
  }

  it("preserves create, update and conflict revisions after a rejected write", async () => {
    const created = await put({
      expectedRevision: 0,
      intent: { goal: "monitor_https" },
      progress: { note: "Initial public status" },
      operation_refs: { tokenIds: [4, 5] },
    });
    assert.equal(created.status, 200);
    assert.equal(created.body.session.revision, 1);
    assert.deepEqual(created.body.session.operationRefs.tokenIds, [4, 5]);

    const { nested } = createCompactPrivateMaterialFixture();
    const rejected = await put({
      expectedRevision: 1,
      progress: { note: nested.toString("base64url") },
    });
    assert.equal(rejected.status, 400);
    assert.equal(rejected.body.code, "SECRET_REJECTED");
    assert.equal(database.row.revision, 1);
    assert.deepEqual(database.row.progress, { note: "Initial public status" });

    const updated = await put({ expectedRevision: 1, progress: { note: "Still public" } });
    assert.equal(updated.status, 200);
    assert.equal(updated.body.session.revision, 2);
    assert.deepEqual(updated.body.session.intent, { goal: "monitor_https" });
    assert.deepEqual(updated.body.session.operationRefs.tokenIds, [4, 5]);

    const stale = await put({ expectedRevision: 1, progress: { note: "Stale" } });
    assert.equal(stale.status, 409);
    assert.equal(stale.body.code, "REVISION_CONFLICT");
    assert.equal(stale.body.current.revision, 2);
    assert.deepEqual(stale.body.current.progress, { note: "Still public" });
    assert.equal(database.row.revision, 2);
  });

  it("keeps the actual authentication guard before any database access", async () => {
    const response = await request(server).put(SESSION_URL).send({ expectedRevision: 0 });
    assert.equal(response.status, 401);
    assert.equal(database.calls.length, 0);
  });
});
