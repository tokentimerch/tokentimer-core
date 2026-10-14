const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  getRenewalProfile,
  updateRenewalProfile,
} = require("../../apps/api/services/certops/renewalProfileAdmin");

const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const KEY = "ab".repeat(32);
const REFERENCE = "app.example.com";

const target = {
  type: "windows-iis",
  reference: REFERENCE,
  store: "WebHosting",
  binding: { site: "Shop", port: 443 },
};

// ACME-shaped on purpose: this is what a profile looks like before it is moved
// to an AD CS issuer.
const acmeShapedProfile = {
  schemaVersion: 1,
  profileName: `Derived: ${REFERENCE}`,
  sanPolicy: { mode: "exact", sans: [REFERENCE], allowWildcards: false },
  keyAlgorithm: "ecdsa",
  keySize: 256,
  keyRotationPolicy: { rotateOnRenew: true },
  preferredChain: null,
  ca: {
    endpoint: "https://acme-v02.api.letsencrypt.org/directory",
    accountRef: "le-prod",
    eabRef: null,
  },
  acme: { kind: "certbot", commandRef: "issue.dns" },
  dns: { provider: "route53", zone: "example.com", credentialRef: "r53" },
  deploymentTargets: [target],
  target,
  verification: { host: null, port: null, requireMatch: false },
};

describe("AD CS issuer switch on an ACME-shaped profile (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;
  let issuerId;

  before(async () => {
    await runMigrations();
    const email = `adcs-switch-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'AD CS Switch', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;
    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'AD CS Switch WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
    const issuer = await TestUtils.execQuery(
      `INSERT INTO certificate_issuers (workspace_id, kind, name, current_version, revalidation_required)
       VALUES ($1, 'adcs', 'Issuing CA switch', 1, false)
       RETURNING id`,
      [workspaceId],
    );
    issuerId = issuer.rows[0].id;
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 1, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, TEMPLATE, KEY],
    );
  });

  after(async () => {
    await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
  });

  async function insertAcmeShapedProfile() {
    const row = await TestUtils.execQuery(
      `INSERT INTO certificate_profiles (
         workspace_id, name, description, status, source, source_ref,
         issuer_id, renew_before_days, key_mode, public_metadata, created_by
       ) VALUES ($1, $2, NULL, 'active', 'manual', $3, NULL, 30, 'os-store-managed', $4::jsonb, $5)
       RETURNING id`,
      [
        workspaceId,
        `switch-${crypto.randomUUID()}`,
        `adcs-profile:${REFERENCE}`,
        JSON.stringify({ renewalProfile: acmeShapedProfile }),
        ownerId,
      ],
    );
    return row.rows[0].id;
  }

  const audit = async () => {};

  it("applies AD CS edit rules after an ACME-shaped Windows/IIS profile is moved to an AD CS issuer", async () => {
    const profileId = await insertAcmeShapedProfile();

    await updateRenewalProfile({
      dbPool: pool,
      workspaceId,
      profileId,
      issuerId,
      actorUserId: ownerId,
      auditWriter: audit,
    });

    const onAdcs = await getRenewalProfile({ db: pool, workspaceId, profileId });
    expect(onAdcs.issuerId).to.equal(issuerId);
    expect(onAdcs.editableFields).to.deep.equal(["sanPolicy", "keyAlgorithm", "keySize"]);

    let refused = null;
    try {
      await updateRenewalProfile({
        dbPool: pool,
        workspaceId,
        profileId,
        renewalProfile: { verification: { host: REFERENCE, port: 443, requireMatch: true } },
        actorUserId: ownerId,
        auditWriter: audit,
      });
    } catch (error) {
      refused = error;
    }
    expect(refused?.code).to.equal("CERTOPS_PROFILE_INVALID");

    await updateRenewalProfile({
      dbPool: pool,
      workspaceId,
      profileId,
      renewalProfile: { keyAlgorithm: "rsa", keySize: 2048 },
      actorUserId: ownerId,
      auditWriter: audit,
    });
    const after = await getRenewalProfile({ db: pool, workspaceId, profileId });
    expect(after.renewalProfile.keyAlgorithm).to.equal("rsa");
    expect(after.renewalProfile.keySize).to.equal(2048);
  });
});
