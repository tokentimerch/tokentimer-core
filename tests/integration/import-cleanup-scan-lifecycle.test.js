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
const {
  persistScan,
  getScan,
  createScan,
  recordScanItems,
  finalizeScan,
} = require("../../apps/api/services/integrationScans");
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

  it("All-Regions AWS scan only deletes the missing region's token", async () => {
    const accountId = `aws-${crypto.randomUUID()}`;
    const goneEast = await createProvenanceToken({
      name: "secret-us-east-1-deleted",
      provider: "aws",
      instance: accountId,
      ownerKey: accountId,
      kind: "aws-secrets-manager",
      objectId: "arn:aws:secretsmanager:us-east-1:123:secret:gone",
      dimensions: { region: "us-east-1", service: "secretsmanager" },
    });
    const keptWest = await createProvenanceToken({
      name: "secret-eu-west-1-kept",
      provider: "aws",
      instance: accountId,
      ownerKey: accountId,
      kind: "aws-secrets-manager",
      objectId: "arn:aws:secretsmanager:eu-west-1:123:secret:kept",
      dimensions: { region: "eu-west-1", service: "secretsmanager" },
    });

    const scan = await persistScan({
      workspaceId,
      provider: "aws",
      identityContext: { accountId },
      items: [
        {
          sourceKind: "aws-secrets-manager",
          sourceObjectId: "arn:aws:secretsmanager:eu-west-1:123:secret:kept",
          dimensions: { region: "eu-west-1", service: "secretsmanager" },
        },
      ],
      subScopes: [
        {
          sourceKind: "aws-secrets-manager",
          dimensions: { region: "us-east-1", service: "secretsmanager" },
          complete: true,
        },
        {
          sourceKind: "aws-secrets-manager",
          dimensions: { region: "eu-west-1", service: "secretsmanager" },
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "aws", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(goneEast.id);
    expect(deleted.map((d) => d.id)).to.not.include(keptWest.id);
    expect(await tokenStillExists(keptWest.id)).to.equal(true);
    expect(await tokenStillExists(goneEast.id)).to.equal(false);
  });

  it("never touches a different Azure Key Vault when cleaning vault A", async () => {
    const vaultA = `https://vault-a-${crypto.randomUUID()}.vault.azure.net`;
    const vaultB = `https://vault-b-${crypto.randomUUID()}.vault.azure.net`;
    const goneA = await createProvenanceToken({
      name: "vault-a-secret-gone",
      provider: "azure",
      instance: vaultA,
      ownerKey: vaultA,
      kind: "azure-key-vault-secret",
      objectId: `${vaultA}/secrets/gone`,
    });
    const keptB = await createProvenanceToken({
      name: "vault-b-secret-kept",
      provider: "azure",
      instance: vaultB,
      ownerKey: vaultB,
      kind: "azure-key-vault-secret",
      objectId: `${vaultB}/secrets/kept`,
    });

    const scan = await persistScan({
      workspaceId,
      provider: "azure",
      identityContext: { vaultUrl: vaultA },
      items: [],
      subScopes: [
        {
          sourceKind: "azure-key-vault-secret",
          dimensions: {},
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "azure", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(goneA.id);
    expect(deleted.map((d) => d.id)).to.not.include(keptB.id);
    expect(await tokenStillExists(keptB.id)).to.equal(true);
  });

  it("cleans complete Azure KV types while leaving an incomplete type untouched", async () => {
    const vaultUrl = `https://kv-mixed-${crypto.randomUUID()}.vault.azure.net`;
    const goneSecret = await createProvenanceToken({
      name: "kv-secret-gone",
      provider: "azure",
      instance: vaultUrl,
      ownerKey: vaultUrl,
      kind: "azure-key-vault-secret",
      objectId: `${vaultUrl}/secrets/gone`,
    });
    const keptSecret = await createProvenanceToken({
      name: "kv-secret-kept",
      provider: "azure",
      instance: vaultUrl,
      ownerKey: vaultUrl,
      kind: "azure-key-vault-secret",
      objectId: `${vaultUrl}/secrets/kept`,
    });
    const unscannedCert = await createProvenanceToken({
      name: "kv-cert-permission-denied",
      provider: "azure",
      instance: vaultUrl,
      ownerKey: vaultUrl,
      kind: "azure-key-vault-certificate",
      objectId: `${vaultUrl}/certificates/unseen`,
    });

    const scan = await persistScan({
      workspaceId,
      provider: "azure",
      identityContext: { vaultUrl },
      items: [
        {
          sourceKind: "azure-key-vault-secret",
          sourceObjectId: `${vaultUrl}/secrets/kept`,
        },
      ],
      subScopes: [
        {
          sourceKind: "azure-key-vault-secret",
          dimensions: {},
          complete: true,
        },
        {
          sourceKind: "azure-key-vault-certificate",
          dimensions: {},
          complete: false,
          reason: "list_forbidden",
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "azure", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(goneSecret.id);
    expect(deleted.map((d) => d.id)).to.not.include(keptSecret.id);
    expect(deleted.map((d) => d.id)).to.not.include(unscannedCert.id);
    expect(await tokenStillExists(keptSecret.id)).to.equal(true);
    expect(await tokenStillExists(unscannedCert.id)).to.equal(true);
  });

  it("Azure AD cleanup only removes the deleted app secret, not another app's", async () => {
    const tenantId = `tenant-${crypto.randomUUID()}`;
    const gone = await createProvenanceToken({
      name: "app-a-secret-gone",
      provider: "azure-ad",
      instance: tenantId,
      ownerKey: tenantId,
      kind: "azure-ad-client-secret",
      objectId: "app-a-secret-1",
    });
    const kept = await createProvenanceToken({
      name: "app-b-secret-kept",
      provider: "azure-ad",
      instance: tenantId,
      ownerKey: tenantId,
      kind: "azure-ad-client-secret",
      objectId: "app-b-secret-1",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "azure-ad",
      identityContext: { tenantId },
      items: [
        {
          sourceKind: "azure-ad-client-secret",
          sourceObjectId: "app-b-secret-1",
        },
      ],
      subScopes: [
        {
          sourceKind: "azure-ad-client-secret",
          dimensions: {},
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "azure-ad", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(gone.id);
    expect(deleted.map((d) => d.id)).to.not.include(kept.id);
    expect(await tokenStillExists(kept.id)).to.equal(true);
  });

  it("GCP incomplete secrets kind skips cleanup even for a secret missing from the scan", async () => {
    const projectId = `gcp-${crypto.randomUUID()}`;
    const listed = await createProvenanceToken({
      name: "gcp-secret-listed-but-describe-failed",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-secret-manager",
      objectId: "projects/x/secrets/listed",
    });
    const missing = await createProvenanceToken({
      name: "gcp-secret-actually-deleted",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-secret-manager",
      objectId: "projects/x/secrets/gone",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "gcp",
      identityContext: { projectId },
      items: [
        {
          sourceKind: "gcp-secret-manager",
          sourceObjectId: "projects/x/secrets/listed",
        },
      ],
      subScopes: [
        {
          sourceKind: "gcp-secret-manager",
          dimensions: {},
          complete: false,
          reason: "describe_failures",
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gcp", scanId: scan.scanId },
    });

    expect(deleted).to.have.length(0);
    expect(await tokenStillExists(listed.id)).to.equal(true);
    expect(await tokenStillExists(missing.id)).to.equal(true);
  });

  it("GCP complete scan still deletes a missing secret when a listed one had a version-lookup failure", async () => {
    const projectId = `gcp-${crypto.randomUUID()}`;
    const listed = await createProvenanceToken({
      name: "gcp-secret-listed-without-expiration",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-secret-manager",
      objectId: "projects/x/secrets/listed",
    });
    const missing = await createProvenanceToken({
      name: "gcp-secret-actually-deleted",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-secret-manager",
      objectId: "projects/x/secrets/gone",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "gcp",
      identityContext: { projectId },
      items: [
        {
          sourceKind: "gcp-secret-manager",
          sourceObjectId: "projects/x/secrets/listed",
        },
      ],
      subScopes: [
        {
          sourceKind: "gcp-secret-manager",
          dimensions: {},
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gcp", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(missing.id);
    expect(deleted.map((d) => d.id)).to.not.include(listed.id);
    expect(await tokenStillExists(listed.id)).to.equal(true);
    expect(await tokenStillExists(missing.id)).to.equal(false);
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

  it("GCP certificate sub-scope cleanup only touches the certificate kind, scoped by location dimension", async () => {
    const projectId = `gcp-${crypto.randomUUID()}`;
    const goneCert = await createProvenanceToken({
      name: "gcp-cert-now-gone",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-certificate-manager-cert",
      objectId: "gone-cert",
      dimensions: { location: "global" },
    });
    const untouchedSecret = await createProvenanceToken({
      name: "gcp-secret-untouched-by-cert-cleanup",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-secret-manager",
      objectId: "projects/x/secrets/still-there",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "gcp",
      identityContext: { projectId },
      items: [],
      subScopes: [
        {
          sourceKind: "gcp-certificate-manager-cert",
          dimensions: { location: "global" },
          complete: true,
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gcp", scanId: scan.scanId },
    });

    expect(deleted.map((d) => d.id)).to.include(goneCert.id);
    expect(deleted.map((d) => d.id)).to.not.include(untouchedSecret.id);
    expect(await tokenStillExists(goneCert.id)).to.equal(false);
    expect(await tokenStillExists(untouchedSecret.id)).to.equal(true);
  });

  it("GCP compute SSL cert cleanup skips an incomplete sub-scope", async () => {
    const projectId = `gcp-${crypto.randomUUID()}`;
    const kept = await createProvenanceToken({
      name: "gcp-compute-ssl-cert-not-rediscovered",
      provider: "gcp",
      instance: projectId,
      ownerKey: projectId,
      kind: "gcp-compute-ssl-cert",
      objectId: "lb-ssl-cert",
    });

    const scan = await persistScan({
      workspaceId,
      provider: "gcp",
      identityContext: { projectId },
      items: [],
      subScopes: [
        {
          sourceKind: "gcp-compute-ssl-cert",
          dimensions: {},
          complete: false,
          reason: "error",
        },
      ],
    });

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "gcp", scanId: scan.scanId },
    });

    expect(deleted).to.have.length(0);
    expect(await tokenStillExists(kept.id)).to.equal(true);
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

  it("survives a rediscovery race: an older scan's cleanup must not delete a token a newer, concurrent scan just rediscovered", async () => {
    // Regression test for the observation-fence race: recordScanItems() must
    // bump source_observed_at on rediscovery immediately (at scan time), not
    // only later via a separate import step, or an older/slower scan's
    // cleanup could win the race and delete a token a newer scan just saw.
    const instance = `vault-race-${crypto.randomUUID()}.example.com`;
    const objectId = "secret/data/racy";
    const token = await createProvenanceToken({
      name: "racy-secret",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId,
      dimensions: { mount: "secret/", path: "racy", category: "generic" },
      // Simulate a token whose last observation predates both scans below.
      observedAt: new Date(Date.now() - 60 * 60 * 1000),
    });
    // Control: a second, genuinely obsolete token in the same scope that no
    // scan ever rediscovers. It must still be deleted by scan A's cleanup,
    // proving the assertions below aren't a vacuous "cleanup did nothing".
    const genuinelyObsolete = await createProvenanceToken({
      name: "genuinely-obsolete-secret",
      provider: "vault",
      instance,
      ownerKey: instance,
      kind: "vault-kv",
      objectId: "secret/data/actually-gone",
      dimensions: { mount: "secret/", path: "actually-gone", category: "generic" },
      observedAt: new Date(Date.now() - 60 * 60 * 1000),
    });

    // Scan A starts first (older / slower) and discovers nothing -- it will
    // want to delete the token as obsolete.
    const scanA = await createScan({
      workspaceId,
      provider: "vault",
      instance,
      ownerKey: instance,
    });
    // Postgres timestamptz can collapse two back-to-back NOW() inserts to
    // the same tick, which would make B's rediscovery look simultaneous
    // with A and defeat the observation fence. Pin A firmly in the past.
    await TestUtils.execQuery(
      "UPDATE integration_scans SET started_at = NOW() - INTERVAL '2 seconds' WHERE id = $1",
      [scanA.id],
    );

    // Scan B starts after A, rediscovers the token (item recorded ->
    // source_observed_at bumped immediately), and finishes before A's
    // cleanup runs -- even though B's own import step hasn't run yet.
    const scanB = await createScan({
      workspaceId,
      provider: "vault",
      instance,
      ownerKey: instance,
    });
    await recordScanItems(
      scanB.id,
      [
        {
          sourceKind: "vault-kv",
          sourceObjectId: objectId,
          dimensions: { mount: "secret/", path: "racy", category: "generic" },
        },
      ],
      {
        workspaceId,
        provider: "vault",
        instance,
        ownerKey: instance,
        observedAt: scanB.startedAt,
      },
    );
    await finalizeScan(scanB.id, [
      { sourceKind: "vault-kv", dimensions: { mount: "secret/" }, complete: true },
    ]);

    // Scan A finalizes (still having recorded zero items) and its cleanup
    // runs after B's rediscovery was already persisted.
    await recordScanItems(scanA.id, [], {
      workspaceId,
      provider: "vault",
      instance,
      ownerKey: instance,
      observedAt: scanA.startedAt,
    });
    await finalizeScan(scanA.id, [
      { sourceKind: "vault-kv", dimensions: { mount: "secret/" }, complete: true },
    ]);

    const { deleted } = await cleanupObsoleteTokens({
      workspaceId,
      actorUserId: ownerId,
      cleanup: { enabled: true, provider: "vault", scanId: scanA.id },
    });

    expect(deleted.map((d) => d.id)).to.not.include(token.id);
    expect(await tokenStillExists(token.id)).to.equal(true);
    expect(deleted.map((d) => d.id)).to.include(genuinelyObsolete.id);
    expect(await tokenStillExists(genuinelyObsolete.id)).to.equal(false);
  });
});
