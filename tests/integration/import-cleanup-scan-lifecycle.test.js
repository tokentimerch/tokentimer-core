"use strict";

/**
 * DB-backed destructive test matrix for the scan-backed cleanup engine.
 * Unlike tests/unit/import-cleanup.unit.test.js (pure-function coverage for
 * validateCleanupRequest/buildDimensionFilterSql), these tests drive real
 * PostgreSQL transactions through persistScan()/cleanupObsoleteTokens() to
 * verify the actual safety properties: per-instance/per-owner scoping,
 * per-sub-scope completeness gating, the anti-join against recorded scan
 * items, the observation fence, and the single-use scan claim.
 */

const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const { pool } = require("../../apps/api/db/database");
const Token = require("../../apps/api/db/models/Token");
const { persistScan, getScan } = require("../../apps/api/services/integrationScans");
const { cleanupObsoleteTokens } = require("../../apps/api/services/importCleanup");

describe("Import cleanup scan lifecycle (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();

    const email = `cleanup-scan-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Cleanup Scan Test', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;

    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Cleanup Scan WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery(
        "DELETE FROM audit_events WHERE workspace_id = $1",
        [workspaceId],
      );
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [
        workspaceId,
      ]);
    }
    if (ownerId) {
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  /**
   * Creates a provenance-attributed token directly (bypassing the import
   * route, since these tests exercise cleanupObsoleteTokens() directly).
   */
  async function createProvenanceToken({
    name,
    provider,
    instance,
    ownerKey,
    kind,
    objectId,
    dimensions = {},
    observedAt = null,
  }) {
    return Token.create({
      userId: ownerId,
      workspaceId,
      created_by: ownerId,
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
      source_dimensions: dimensions,
      source_object_id: objectId,
      source_observed_at: observedAt,
    });
  }

  async function tokenStillExists(id) {
    const res = await TestUtils.execQuery(
      "SELECT id FROM tokens WHERE id = $1",
      [id],
    );
    return res.rows.length > 0;
  }

  it("deletes a not-rediscovered token in a scope the scan reported complete", async () => {
    const instance = `vault-${crypto.randomUUID()}.example.com`;
    const survivor = await createProvenanceToken({
      name: "kept-secret",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: "secret/data/kept",
      dimensions: { mount: "secret/", path: "kept", category: "generic" },
    });
    const obsolete = await createProvenanceToken({
      name: "obsolete-secret",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: "secret/data/gone",
      dimensions: { mount: "secret/", path: "gone", category: "generic" },
    });

    const scan = await persistScan({
      workspaceId,
      provider: "vault",
      identityContext: { address: instance },
      items: [
        {
          sourceKind: "vault-kv",
          sourceObjectId: "secret/data/kept",
          dimensions: { mount: "secret/", path: "kept", category: "generic" },
        },
      ],
      subScopes: [
        {
          sourceKind: "vault-kv",
          dimensions: { mount: "secret/" },
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "vault", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(obsolete.id);
    expect(deleted.map((d) => d.id)).to.not.include(survivor.id);
    expect(await tokenStillExists(survivor.id)).to.equal(true);
    expect(await tokenStillExists(obsolete.id)).to.equal(false);
  });

  it("never touches a different instance of the same provider, even with colliding owner keys", async () => {
    const ownerKey = "42";
    const instanceA = `github-a-${crypto.randomUUID()}.example.com`;
    const instanceB = `github-b-${crypto.randomUUID()}.example.com`;

    const tokenA = await createProvenanceToken({
      name: "instance-a-key",
      provider: "github",
      instance: instanceA,
      ownerKey,
      kind: "github-ssh-key",
      objectId: "111",
    });
    const tokenB = await createProvenanceToken({
      name: "instance-b-key",
      provider: "github",
      instance: instanceB,
      ownerKey,
      kind: "github-ssh-key",
      objectId: "222",
    });

    // A scan of instance A, discovering nothing, must never delete
    // instance B's token even though both share the same numeric owner key.
    const scan = await persistScan({
      workspaceId,
      provider: "github",
      identityContext: { host: instanceA, ownerKey },
      items: [],
      subScopes: [
        { sourceKind: "github-ssh-key", dimensions: {}, complete: true },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "github", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(tokenA.id);
    expect(deleted.map((d) => d.id)).to.not.include(tokenB.id);
    expect(await tokenStillExists(tokenB.id)).to.equal(true);
  });

  it("never deletes anything from a sub-scope the scan reported incomplete", async () => {
    const instance = `aws-${crypto.randomUUID()}`;
    const obsolete = await createProvenanceToken({
      name: "aws-secret-truncated-region",
      provider: "aws",
      instance,
      ownerKey: instance,
      kind: "aws-secrets-manager",
      objectId: "arn:aws:secretsmanager:us-east-1:123:secret:x",
      dimensions: { region: "us-east-1", service: "secretsmanager" },
    });

    const scan = await persistScan({
      workspaceId,
      provider: "aws",
      identityContext: { accountId: instance },
      items: [],
      subScopes: [
        {
          sourceKind: "aws-secrets-manager",
          dimensions: { region: "us-east-1", service: "secretsmanager" },
          complete: false,
          reason: "describe_failures",
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "aws", scanId: scan.scanId },
    });

    expect(deleted).to.have.length(0);
    expect(await tokenStillExists(obsolete.id)).to.equal(true);
  });

  it("deletes everything in a scope when a fully complete scan legitimately finds zero items", async () => {
    const instance = `gcp-${crypto.randomUUID()}`;
    const obsolete = await createProvenanceToken({
      name: "gcp-secret-now-gone",
      provider: "gcp",
      instance,
      ownerKey: instance,
      kind: "gcp-secret-manager",
      objectId: "projects/x/secrets/gone",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "gcp",
      identityContext: { projectId: instance },
      items: [],
      subScopes: [
        { sourceKind: "gcp-secret-manager", dimensions: {}, complete: true },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gcp", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(obsolete.id);
    expect(await tokenStillExists(obsolete.id)).to.equal(false);
  });

  it("refuses to replay a scan_id for a second destructive cleanup", async () => {
    const instance = `gitlab-${crypto.randomUUID()}.example.com`;
    const obsolete = await createProvenanceToken({
      name: "gitlab-pat-gone",
      provider: "gitlab",
      instance,
      ownerKey: "7",
      kind: "gitlab-pat",
      objectId: "555",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "gitlab",
      identityContext: { host: instance, ownerKey: "7" },
      items: [],
      subScopes: [{ sourceKind: "gitlab-pat", dimensions: {}, complete: true }],
    });

    const first = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gitlab", scanId: scan.scanId },
    });
    expect(first.deleted.map((d) => d.id)).to.include(obsolete.id);

    // A second token that would otherwise be a valid cleanup candidate
    // must NOT be deleted by replaying the already-consumed scan_id.
    const secondObsolete = await createProvenanceToken({
      name: "gitlab-pat-also-gone",
      provider: "gitlab",
      instance,
      ownerKey: "7",
      kind: "gitlab-pat",
      objectId: "556",
    });

    const replay = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gitlab", scanId: scan.scanId },
    });
    expect(replay.deleted).to.have.length(0);
    expect(await tokenStillExists(secondObsolete.id)).to.equal(true);

    const scanRow = await getScan({
      scanId: scan.scanId,
      workspaceId,
      provider: "gitlab",
    });
    expect(scanRow.cleanup_consumed_at).to.not.equal(null);
  });

  it("observation fence: never deletes a token observed after the cleanup-driving scan started", async () => {
    const instance = `azure-${crypto.randomUUID()}.vault.azure.net`;
    const obsolete = await createProvenanceToken({
      name: "kv-secret-recently-rediscovered",
      provider: "azure",
      instance,
      ownerKey: instance,
      kind: "azure-key-vault-secret",
      objectId: "https://kv.example/secrets/rediscovered",
    });

    // Simulate a slower, older scan (started_at in the past) that never
    // saw this token, racing against a newer concurrent scan that just
    // (re)discovered it. Set source_observed_at to "now" (newer than the
    // older scan's started_at) to model that race deterministically.
    await TestUtils.execQuery(
      "UPDATE tokens SET source_observed_at = NOW() WHERE id = $1",
      [obsolete.id],
    );

    const olderScanRes = await TestUtils.execQuery(
      `INSERT INTO integration_scans (workspace_id, provider, source_instance, source_owner_key, started_at, completed_at, cleanup_scope)
       VALUES ($1, 'azure', $2, $2, NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '9 minutes', $3::jsonb)
       RETURNING id`,
      [
        workspaceId,
        instance,
        JSON.stringify({
          subScopes: [
            {
              sourceKind: "azure-key-vault-secret",
              dimensions: {},
              complete: true,
            },
          ],
        }),
      ],
    );
    const olderScanId = olderScanRes.rows[0].id;

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "azure", scanId: olderScanId },
    });

    expect(deleted.map((d) => d.id)).to.not.include(obsolete.id);
    expect(await tokenStillExists(obsolete.id)).to.equal(true);
  });

  it("never touches legacy tokens with no provenance attribution", async () => {
    const legacy = await Token.create({
      userId: ownerId,
      workspaceId,
      created_by: ownerId,
      name: "legacy-ambiguous-token",
      expiration: "2099-12-31",
      type: "secret",
      category: "key_secret",
      location: "vault/legacy/path",
      imported_at: new Date(),
    });

    const instance = `vault-legacy-${crypto.randomUUID()}.example.com`;
    const scan = await persistScan({
      workspaceId,
      provider: "vault",
      identityContext: { address: instance },
      items: [],
      subScopes: [{ sourceKind: "vault-kv", dimensions: {}, complete: true }],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "vault", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.not.include(legacy.id);
    expect(await tokenStillExists(legacy.id)).to.equal(true);
  });

  it("narrows Vault cleanup to the scanned mount, sparing an unscanned mount", async () => {
    const instance = `vault-narrow-${crypto.randomUUID()}.example.com`;
    const scannedMountObsolete = await createProvenanceToken({
      name: "secret-mount-gone",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: "secret/data/gone",
      dimensions: { mount: "secret/", path: "gone", category: "generic" },
    });
    const otherMountToken = await createProvenanceToken({
      name: "kv2-mount-untouched",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: "kv2/data/untouched",
      dimensions: { mount: "kv2/", path: "untouched", category: "generic" },
    });

    const scan = await persistScan({
      workspaceId,
      provider: "vault",
      identityContext: { address: instance },
      items: [],
      subScopes: [
        {
          sourceKind: "vault-kv",
          dimensions: { mount: "secret/" },
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "vault", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(scannedMountObsolete.id);
    expect(deleted.map((d) => d.id)).to.not.include(otherMountToken.id);
    expect(await tokenStillExists(otherMountToken.id)).to.equal(true);
  });

  it("does not confuse a KV secret at a PKI-shaped path with an actual PKI certificate", async () => {
    // A KV secret stored at a path that merely looks PKI-shaped (e.g.
    // "kv/data/cert/my-app") must be scoped by its real source_kind
    // (vault-kv), never inferred from the path string.
    const instance = `vault-kvpki-${crypto.randomUUID()}.example.com`;
    const kvSecretAtCertLikePath = await createProvenanceToken({
      name: "kv-secret-cert-shaped-path",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: "secret/data/cert/my-app",
      dimensions: { mount: "secret/", path: "cert/my-app", category: "generic" },
    });

    // A scan that only completed the PKI sub-scope (not KV) must never
    // delete the KV-kind token, even though its path looks PKI-shaped.
    const scan = await persistScan({
      workspaceId,
      provider: "vault",
      identityContext: { address: instance },
      items: [],
      subScopes: [
        { sourceKind: "vault-pki", dimensions: { mount: "pki/" }, complete: true },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "vault", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.not.include(kvSecretAtCertLikePath.id);
    expect(await tokenStillExists(kvSecretAtCertLikePath.id)).to.equal(true);
  });
});
