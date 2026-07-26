const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const {
  createCertificateIssuanceJob,
} = require("../../apps/api/services/certops/issuance");
const { pool } = require("../../apps/api/db/database");

/**
 * Issuance identity resolution is a read-then-insert: look for an existing
 * certificate under the idempotency key, create one if absent. Whether that is
 * safe depends entirely on real lock behaviour, so a mocked client cannot test
 * it. The workspace kill-switch lock a caller already holds is FOR SHARE, which
 * two concurrent issuance requests both acquire without conflicting, so before
 * the advisory lock both could read "no certificate" and both insert. One won,
 * the other got a raw 23505 unique violation surfaced as an opaque 500, when the
 * correct answer was the job the first request had already created.
 *
 * These tests drive two genuinely concurrent transactions against real
 * PostgreSQL.
 */
describe("CertOps issuance concurrency (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();

    const email = `issue-race-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Issue Race', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;

    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Issue Race WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [
        workspaceId,
      ]);
    }
    if (ownerId) {
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  function issueOptions(idempotencyKey, commonName) {
    return {
      workspaceId,
      idempotencyKey,
      payload: {
        target: { type: "domain", reference: commonName },
        certPath: `/etc/ssl/tokentimer/${commonName}.pem`,
        caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
        commandRef: "certbot-dns-cloudflare",
        dnsProvider: "cloudflare",
        dnsZone: "example.com",
      },
    };
  }

  /**
   * Runs one issuance in its own transaction, pausing after the identity has
   * been resolved so the caller can interleave a second attempt. Mirrors the
   * real call shape: the route holds a transaction-bound client.
   */
  async function issueInTransaction(idempotencyKey, commonName) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const outcome = await createCertificateIssuanceJob({
        ...issueOptions(idempotencyKey, commonName),
        client,
        requestedByUserId: ownerId,
        mode: "real",
      });
      await client.query("COMMIT");
      return outcome;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  it("returns one certificate and one job when two requests race on a key", async () => {
    const key = `race-${crypto.randomUUID()}`;
    const commonName = `race-${Date.now()}.example.com`;

    // Genuinely concurrent: both transactions are open and contending before
    // either commits.
    const [first, second] = await Promise.all([
      issueInTransaction(key, commonName),
      issueInTransaction(key, commonName),
    ]);

    const jobIds = new Set([
      String(first.job?.id || first.id),
      String(second.job?.id || second.id),
    ]);
    expect(jobIds.size).to.equal(
      1,
      "both requests must resolve to the same job",
    );

    const certificates = await TestUtils.execQuery(
      `SELECT id, status, source FROM managed_certificates
        WHERE workspace_id = $1 AND source = 'agent_issuance' AND source_ref = $2`,
      [workspaceId, key],
    );
    expect(certificates.rows.length).to.equal(
      1,
      "a raced retry must not create a second certificate identity",
    );
    expect(certificates.rows[0].status).to.equal("provisioning");

    const jobs = await TestUtils.execQuery(
      `SELECT id FROM certificate_jobs
        WHERE workspace_id = $1 AND idempotency_key = $2`,
      [workspaceId, key],
    );
    expect(jobs.rows.length).to.equal(
      1,
      "a raced retry must not create a second ACME order",
    );

    // Exactly one of the two callers is the creator; the other is a replay.
    const createdFlags = [first.created, second.created].filter(
      (value) => value === true,
    );
    expect(createdFlags.length).to.equal(1);
  });

  it("does not leave an orphan certificate when the job insert conflicts", async () => {
    // A key already taken by a non-issuance job must not mint an identity: the
    // honest answer is the idempotency conflict, and a certificate created
    // before that error surfaced would be an unreferenced provisioning row.
    const key = `borrowed-${crypto.randomUUID()}`;
    await TestUtils.execQuery(
      `INSERT INTO certificate_jobs (
         workspace_id, operation, executor_kind, mode, status, source,
         idempotency_key, payload, requested_by_user_id
       ) VALUES ($1, 'reload', 'agent', 'real', 'pending', 'api', $2, '{}'::jsonb, $3)`,
      [workspaceId, key, ownerId],
    );

    const before = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM managed_certificates WHERE workspace_id = $1",
      [workspaceId],
    );

    let failed = false;
    try {
      await issueInTransaction(key, `borrowed-${Date.now()}.example.com`);
    } catch (_) {
      failed = true;
    }

    const after = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM managed_certificates WHERE workspace_id = $1",
      [workspaceId],
    );
    expect(after.rows[0].n).to.equal(
      before.rows[0].n,
      "no certificate identity may be created for a conflicting key",
    );
    expect(failed).to.equal(true, "the conflict must be reported to the caller");
  });

  it("keeps distinct keys independent under contention", async () => {
    // The lock is scoped to one identity, not the workspace, so unrelated
    // issuance must still proceed in parallel rather than serialize.
    const keys = Array.from(
      { length: 4 },
      () => `indep-${crypto.randomUUID()}`,
    );
    const outcomes = await Promise.all(
      keys.map((key, index) =>
        issueInTransaction(key, `indep-${index}-${Date.now()}.example.com`),
      ),
    );

    const jobIds = new Set(
      outcomes.map((outcome) => String(outcome.job?.id || outcome.id)),
    );
    expect(jobIds.size).to.equal(keys.length, "each key gets its own job");

    const certificates = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS n FROM managed_certificates
        WHERE workspace_id = $1 AND source_ref = ANY($2::text[])`,
      [workspaceId, keys],
    );
    expect(certificates.rows[0].n).to.equal(keys.length);
  });
});
