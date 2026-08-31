"use strict";

/**
 * HTTP-route-layer regression coverage for the import-cleanup contract.
 *
 * tests/integration/import-cleanup-scan-lifecycle.test.js drives
 * cleanupObsoleteTokens() directly and covers the deletion engine's safety
 * properties. It never goes through the actual route handler, so it cannot
 * catch a request-shape mismatch between a real caller (like the auto-sync
 * worker) and what the route accepts. These tests post to the real HTTP
 * routes with a body shaped exactly like a real caller sends, so a
 * contract mismatch at the route boundary shows up here even if the
 * cleanup engine itself is perfectly correct.
 */

const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { request, expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const Token = require("../../apps/api/db/models/Token");
const { persistScan } = require("../../apps/api/services/integrationScans");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Import cleanup contract at the HTTP route layer", function () {
  this.timeout(60000);

  let adminUser;
  let adminSession;
  let workspaceId;

  before(async () => {
    await runMigrations();
    adminUser = await TestUtils.createVerifiedTestUser();
    adminSession = await TestUtils.loginTestUser(
      adminUser.email,
      "SecureTest123!@#",
    );
    const ws = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [adminUser.id],
    );
    workspaceId = ws.rows[0].id;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(adminUser.email, adminSession.cookie);
  });

  async function createProvenanceToken({
    name,
    provider,
    instance,
    ownerKey,
    kind,
    objectId,
  }) {
    return Token.create({
      userId: adminUser.id,
      workspaceId,
      created_by: adminUser.id,
      name,
      expiration: "2099-12-31",
      type: "secret",
      category: "key_secret",
      location: `${provider}:${objectId}`,
      imported_at: new Date(),
      source_provider: provider,
      source_instance: instance,
      source_owner_key: ownerKey,
      source_owner_display: ownerKey,
      source_kind: kind,
      source_dimensions: {},
      source_object_id: objectId,
    });
  }

  async function tokenStillExists(id) {
    const res = await TestUtils.execQuery(
      "SELECT id FROM tokens WHERE id = $1",
      [id],
    );
    return res.rows.length > 0;
  }

  async function makeCompleteScan(provider, kind) {
    const instance = `${provider}-route-${crypto.randomUUID()}.example.com`;
    return persistScan({
      workspaceId,
      provider,
      identityContext: { host: instance, address: instance, ownerKey: instance },
      items: [],
      subScopes: [{ sourceKind: kind, dimensions: {}, complete: true }],
    }).then((scan) => ({ scan, instance }));
  }

  it("accepts the exact empty-items + camelCase-scanId payload the auto-sync worker sends and runs cleanup", async () => {
    const { scan, instance } = await makeCompleteScan("github", "github-ssh-key");
    const obsolete = await createProvenanceToken({
      name: "route-github-key-gone",
      provider: "github",
      instance,
      ownerKey: instance,
      kind: "github-ssh-key",
      objectId: `route-${crypto.randomUUID()}`,
    });

    // This is exactly the shape apps/worker/src/auto-sync-worker.js builds:
    // an empty items array (the scan legitimately found nothing new) plus
    // a `cleanup` object carrying `scanId` (camelCase) and
    // reason: "auto_sync_cleanup".
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [],
        cleanup: {
          enabled: true,
          provider: "github",
          scanId: scan.scanId,
          reason: "auto_sync_cleanup",
        },
      });

    expect(res.status).to.equal(201);
    expect(res.body.created_count).to.equal(0);
    expect(res.body.deleted_count).to.equal(1);
    expect(res.body.deleted.map((d) => d.id)).to.include(obsolete.id);
    expect(await tokenStillExists(obsolete.id)).to.equal(false);
  });

  it("normalizes a nested snake_case cleanup.scan_id as a defense-in-depth fallback", async () => {
    const { scan, instance } = await makeCompleteScan("gitlab", "gitlab-pat");
    const obsolete = await createProvenanceToken({
      name: "route-gitlab-pat-gone",
      provider: "gitlab",
      instance,
      ownerKey: instance,
      kind: "gitlab-pat",
      objectId: `route-${crypto.randomUUID()}`,
    });

    // A caller that mirrors the request body's own snake_case convention
    // when building the nested `cleanup` object (the exact shape that used
    // to reject the whole import request with a 400) must still work.
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [],
        cleanup: {
          enabled: true,
          provider: "gitlab",
          scan_id: scan.scanId,
          reason: "auto_sync_cleanup",
        },
      });

    expect(res.status).to.equal(201);
    expect(res.body.deleted_count).to.equal(1);
    expect(res.body.deleted.map((d) => d.id)).to.include(obsolete.id);
    expect(await tokenStillExists(obsolete.id)).to.equal(false);
  });

  it("rejects empty items with no cleanup requested (no regression)", async () => {
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({ items: [] });

    expect(res.status).to.equal(400);
    expect(res.body.error).to.match(/items array required/);
  });

  it("rejects empty items when cleanup is present but disabled (no regression)", async () => {
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({ items: [], cleanup: { enabled: false, provider: "github" } });

    expect(res.status).to.equal(400);
    expect(res.body.error).to.match(/items array required/);
  });

  it("Vault import route: accepts empty items + enabled cleanup with a valid scan_id and runs cleanup", async () => {
    const instance = `vault-route-${crypto.randomUUID()}.example.com`;
    const scan = await persistScan({
      workspaceId,
      provider: "vault",
      identityContext: { address: instance },
      items: [],
      subScopes: [{ sourceKind: "vault-kv", dimensions: {}, complete: true }],
    });
    const obsolete = await createProvenanceToken({
      name: "route-vault-secret-gone",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: `secret/data/route-${crypto.randomUUID()}`,
    });

    const res = await request(BASE)
      .post(`/api/v1/integrations/vault/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [],
        cleanup: {
          enabled: true,
          provider: "vault",
          scanId: scan.scanId,
          reason: "import_cleanup",
        },
      });

    expect(res.status).to.equal(201);
    expect(res.body.deleted_count).to.equal(1);
    expect(res.body.deleted.map((d) => d.id)).to.include(obsolete.id);
    expect(await tokenStillExists(obsolete.id)).to.equal(false);
  });

  it("Vault import route: attributes a newly imported item to the scan that discovered it", async () => {
    // Regression for a route-layer bug found during live UI verification:
    // both import routes destructured a bare top-level `scan_id` for
    // item-scan binding instead of the resolved `effectiveCleanup.scanId`,
    // so a request shaped exactly like the real dashboard form (which only
    // ever nests the id as `cleanup.scanId`) silently bound zero items.
    // Every freshly imported token stayed unattributed ("legacy") and was
    // therefore permanently excluded from cleanup, regardless of the
    // checkbox -- this is the one test in this file that actually imports
    // a non-empty item and checks its resulting provenance, rather than
    // only exercising cleanup's empty-items branch.
    const objectId = `secret/data/route-bound-${crypto.randomUUID()}`;
    const scan = await persistScan({
      workspaceId,
      provider: "vault",
      identityContext: { address: "https://vault.route-bound.example.com" },
      items: [{ sourceKind: "vault-kv", sourceObjectId: objectId, dimensions: {} }],
      subScopes: [{ sourceKind: "vault-kv", dimensions: {}, complete: true }],
    });
    const name = `route-bound-item-${crypto.randomUUID()}`;

    const res = await request(BASE)
      .post(`/api/v1/integrations/vault/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [
          {
            name,
            location: `vault:${objectId}`,
            category: "key_secret",
            type: "secret",
            sourceKind: "vault-kv",
          },
        ],
        cleanup: {
          enabled: true,
          provider: "vault",
          scanId: scan.scanId,
        },
      });

    expect(res.status).to.equal(201);
    expect(res.body.created_count).to.equal(1);

    const row = await TestUtils.execQuery(
      `SELECT source_provider, source_instance, source_owner_key, source_kind, source_object_id
       FROM tokens WHERE workspace_id = $1 AND name = $2`,
      [workspaceId, name],
    );
    expect(row.rows.length).to.equal(1);
    expect(row.rows[0].source_provider).to.equal("vault");
    expect(row.rows[0].source_instance).to.equal(scan.instance);
    expect(row.rows[0].source_kind).to.equal("vault-kv");
    expect(row.rows[0].source_object_id).to.equal(objectId);
  });

  it("Vault import route: rejects empty items with no cleanup requested (no regression)", async () => {
    const res = await request(BASE)
      .post(`/api/v1/integrations/vault/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({ items: [] });

    expect(res.status).to.equal(400);
    expect(res.body.error).to.match(/items array required/);
  });
});
