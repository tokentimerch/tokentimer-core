const { expect } = require("chai");
const { Pool } = require("pg");
const crypto = require("crypto");

const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || "tokentimer",
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
  max: 10,
};

const pool = new Pool(dbConfig);

// Mirrors the delivery worker's per-row re-check + claim renewal UPDATE
// (apps/worker/src/delivery-worker.js). The predicate must match the claim
// SELECT's status set so a row that another worker meanwhile finished
// (sent/blocked) fails the recheck atomically, and it is owner-scoped on
// delivery_claim_id so a superseded worker's renewal no-ops.
const DELIVERY_RECHECK_SQL = `
  UPDATE alert_queue
     SET next_attempt_at = NOW() + ($2 * INTERVAL '1 millisecond'),
         updated_at = NOW()
   WHERE id = $1
     AND delivery_claim_id = $3
     AND status IN ('pending', 'failed', 'partial')
 RETURNING id`;

// Mirrors the delivery worker's batch claim UPDATE: marks the row via
// next_attempt_at and stamps the run's owner identity.
const DELIVERY_CLAIM_SQL = `
  UPDATE alert_queue
     SET next_attempt_at = NOW() + ($2 * INTERVAL '1 millisecond'),
         delivery_claim_id = $3,
         updated_at = NOW()
   WHERE id = $1`;

// Mirrors the delivery worker's terminal write for a sent alert: conditional
// on still owning the claim, and clears the owner id.
const DELIVERY_TERMINAL_SENT_SQL = `
  UPDATE alert_queue
     SET status = 'sent', last_attempt = NOW(), next_attempt_at = NULL,
         delivery_claim_id = NULL, updated_at = NOW()
   WHERE id = $1 AND delivery_claim_id = $2`;

// Mirrors the endpoint check worker's claim SELECT + lease UPDATE
// (apps/worker/src/endpoint-check-worker.js): only rows with a free or
// expired check_claimed_until lease are claimable.
const ENDPOINT_CLAIM_SELECT_SQL = `
  SELECT id FROM domain_monitors
   WHERE (check_claimed_until IS NULL OR check_claimed_until < NOW())
     AND (
       (check_interval = '1min' AND (last_health_check_at IS NULL OR last_health_check_at < NOW() - INTERVAL '1 minute'))
     )
     AND workspace_id = $1
   ORDER BY last_health_check_at ASC NULLS FIRST
   LIMIT 50
   FOR UPDATE SKIP LOCKED`;

// Mirrors the endpoint check worker's batch claim UPDATE: takes the lease and
// stamps the run's owner identity (overwriting any stale claim id).
const ENDPOINT_CLAIM_UPDATE_SQL = `
  UPDATE domain_monitors
     SET check_claimed_until = NOW() + ($2 * INTERVAL '1 millisecond'),
         check_claim_id = $3,
         updated_at = NOW()
   WHERE id = $1`;

// Mirrors the endpoint check worker's owner-scoped finally release.
const ENDPOINT_RELEASE_SQL = `
  UPDATE domain_monitors
     SET last_health_check_at = NOW(),
         check_claimed_until = NULL,
         check_claim_id = NULL,
         updated_at = NOW()
   WHERE id = $1
     AND check_claim_id = $2`;

describe("Worker claim leases", function () {
  this.timeout(30000);

  let userId, tokenId, workspaceId;
  const monitorIds = [];

  before(async () => {
    const userRes = await pool.query(
      `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
       VALUES ($1, $2, $3, $4, true)
       RETURNING id`,
      [
        `claim-lease-test-${Date.now()}@example.com`,
        "Claim Lease Test User",
        "local",
        "hash",
      ],
    );
    userId = userRes.rows[0].id;

    const wsRes = await pool.query(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, $2, $3, 'oss')
       RETURNING id`,
      [crypto.randomUUID(), `Claim Lease WS ${Date.now()}`, userId],
    );
    workspaceId = wsRes.rows[0].id;

    const tokenRes = await pool.query(
      `INSERT INTO tokens (user_id, workspace_id, name, type, expiration, created_by)
       VALUES ($1, $2, $3, $4, CURRENT_DATE + INTERVAL '5 days', $5)
       RETURNING id`,
      [userId, workspaceId, "Claim Lease Token", "ssl_cert", userId],
    );
    tokenId = tokenRes.rows[0].id;
  });

  after(async () => {
    if (monitorIds.length > 0) {
      await pool.query("DELETE FROM domain_monitors WHERE id = ANY($1::uuid[])", [
        monitorIds,
      ]);
    }
    if (tokenId) {
      await pool.query("DELETE FROM alert_queue WHERE token_id = $1", [tokenId]);
      await pool.query("DELETE FROM tokens WHERE id = $1", [tokenId]);
    }
    if (workspaceId) {
      await pool.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    }
    if (userId) {
      await pool.query("DELETE FROM audit_events WHERE subject_user_id = $1", [
        userId,
      ]);
      await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    }
    await pool.end();
  });

  describe("delivery worker per-row recheck", () => {
    async function insertAlert(suffix) {
      const res = await pool.query(
        `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
         VALUES ($1, $2, $3, 7, CURRENT_DATE, $4, 'pending')
         RETURNING id`,
        [
          userId,
          tokenId,
          `claim_lease_${suffix}_${Date.now()}`,
          JSON.stringify(["email"]),
        ],
      );
      return res.rows[0].id;
    }

    it("skips a row that another worker marked sent after the claim snapshot", async () => {
      const alertId = await insertAlert("sent_race");
      const claimA = crypto.randomUUID();

      // Worker A claims the row (batch claim marker + owner id).
      await pool.query(
        `UPDATE alert_queue
            SET next_attempt_at = NOW() + INTERVAL '15 minutes',
                delivery_claim_id = $2, updated_at = NOW()
          WHERE id = $1`,
        [alertId, claimA],
      );

      // Worker B (lease expired for it) processes and sends the alert.
      await pool.query(
        `UPDATE alert_queue
            SET status = 'sent', delivery_claim_id = NULL,
                last_attempt = NOW(), updated_at = NOW()
          WHERE id = $1`,
        [alertId],
      );

      // Worker A reaches the row late; the per-row recheck must not match
      // (row left the claimable status set and A's owner id was cleared).
      const recheck = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
        claimA,
      ]);
      expect(recheck.rows).to.have.length(0);

      const row = await pool.query(
        "SELECT status FROM alert_queue WHERE id = $1",
        [alertId],
      );
      expect(row.rows[0].status).to.equal("sent");
    });

    it("skips a row that another worker blocked after the claim snapshot", async () => {
      const alertId = await insertAlert("blocked_race");
      const claimA = crypto.randomUUID();

      await pool.query(
        `UPDATE alert_queue
            SET delivery_claim_id = $2, updated_at = NOW()
          WHERE id = $1`,
        [alertId, claimA],
      );
      await pool.query(
        `UPDATE alert_queue
            SET status = 'blocked', updated_at = NOW()
          WHERE id = $1`,
        [alertId],
      );

      const recheck = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
        claimA,
      ]);
      expect(recheck.rows).to.have.length(0);
    });

    it("renews the claim marker for a row that is still pending and owned", async () => {
      const alertId = await insertAlert("still_pending");
      const claimId = crypto.randomUUID();

      // Simulate a nearly-expired batch claim marker owned by this worker.
      await pool.query(
        `UPDATE alert_queue
            SET next_attempt_at = NOW() + INTERVAL '1 second',
                delivery_claim_id = $2, updated_at = NOW()
          WHERE id = $1`,
        [alertId, claimId],
      );

      const recheck = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
        claimId,
      ]);
      expect(recheck.rows).to.have.length(1);
      expect(recheck.rows[0].id).to.equal(alertId);

      // The lease was pushed out well beyond the old near-expiry marker.
      const row = await pool.query(
        `SELECT (next_attempt_at > NOW() + INTERVAL '10 minutes') AS renewed
           FROM alert_queue WHERE id = $1`,
        [alertId],
      );
      expect(row.rows[0].renewed).to.equal(true);
    });

    it("no-ops a superseded owner's renewal and terminal write after takeover", async () => {
      const alertId = await insertAlert("owner_overlap");
      const claimA = crypto.randomUUID();
      const claimB = crypto.randomUUID();

      // Worker A claimed the row, but its marker has expired mid-batch
      // (external sends on earlier rows outlived the batch-wide marker).
      await pool.query(
        `UPDATE alert_queue
            SET next_attempt_at = NOW() - INTERVAL '1 second',
                delivery_claim_id = $2, updated_at = NOW()
          WHERE id = $1`,
        [alertId, claimA],
      );

      // Worker B's batch claim takes over the expired row (the production
      // gating clause admits rows with next_attempt_at <= NOW()), stamping
      // its own claim id over A's.
      const bClaim = await pool.query(DELIVERY_CLAIM_SQL, [
        alertId,
        15 * 60 * 1000,
        claimB,
      ]);
      expect(bClaim.rowCount).to.equal(1);

      // A reaches the row late; its owner-scoped renewal must affect 0 rows.
      const aRenewal = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
        claimA,
      ]);
      expect(aRenewal.rows).to.have.length(0);

      // B processes and delivers the alert (owner-scoped terminal write).
      const bTerminal = await pool.query(DELIVERY_TERMINAL_SENT_SQL, [
        alertId,
        claimB,
      ]);
      expect(bTerminal.rowCount).to.equal(1);

      // A's terminal write must also no-op: wrong owner AND already sent.
      const aTerminal = await pool.query(DELIVERY_TERMINAL_SENT_SQL, [
        alertId,
        claimA,
      ]);
      expect(aTerminal.rowCount).to.equal(0);

      // Final state is B's: sent, claim released.
      const row = await pool.query(
        `SELECT status, delivery_claim_id, next_attempt_at
           FROM alert_queue WHERE id = $1`,
        [alertId],
      );
      expect(row.rows[0].status).to.equal("sent");
      expect(row.rows[0].delivery_claim_id).to.equal(null);
      expect(row.rows[0].next_attempt_at).to.equal(null);
    });
  });

  describe("endpoint check worker claim lease", () => {
    async function insertMonitor() {
      const res = await pool.query(
        `INSERT INTO domain_monitors
           (workspace_id, url, token_id, health_check_enabled, check_interval,
            last_health_status, last_health_check_at, consecutive_failures,
            alert_after_failures, created_by)
         VALUES ($1, 'http://127.0.0.1:9', $2, TRUE, '1min',
                 'healthy', NOW() - INTERVAL '10 minutes', 0, 2, $3)
         RETURNING id`,
        [workspaceId, tokenId, userId],
      );
      monitorIds.push(res.rows[0].id);
      return res.rows[0].id;
    }

    it("does not re-claim a monitor whose lease is still active", async () => {
      const monitorId = await insertMonitor();
      const claimA = crypto.randomUUID();

      // First claim pass takes the lease and stamps the owner id.
      const first = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(first.rows.map((r) => r.id)).to.include(monitorId);
      await pool.query(ENDPOINT_CLAIM_UPDATE_SQL, [
        monitorId,
        10 * 60 * 1000,
        claimA,
      ]);

      // A second worker's claim pass must skip it even though it is still
      // "due" by last_health_check_at (10 minutes > 1 minute interval).
      const second = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(second.rows.map((r) => r.id)).to.not.include(monitorId);
    });

    it("re-claims a monitor whose lease has expired (crash recovery)", async () => {
      const monitorId = await insertMonitor();

      // Expired lease with a stale owner id left by a crashed worker: the
      // claim predicate ignores the stale check_claim_id.
      await pool.query(
        `UPDATE domain_monitors
            SET check_claimed_until = NOW() - INTERVAL '1 second',
                check_claim_id = $2, updated_at = NOW()
          WHERE id = $1`,
        [monitorId, crypto.randomUUID()],
      );

      const claim = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(claim.rows.map((r) => r.id)).to.include(monitorId);
    });

    it("makes a monitor claimable again once the lease is cleared after completion", async () => {
      const monitorId = await insertMonitor();
      const claimA = crypto.randomUUID();

      // Claimed and processing.
      await pool.query(ENDPOINT_CLAIM_UPDATE_SQL, [
        monitorId,
        10 * 60 * 1000,
        claimA,
      ]);
      const during = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(during.rows.map((r) => r.id)).to.not.include(monitorId);

      // Completion: schedule advances, lease clears owner-scoped (as the
      // worker's finally block does).
      const release = await pool.query(ENDPOINT_RELEASE_SQL, [
        monitorId,
        claimA,
      ]);
      expect(release.rowCount).to.equal(1);

      // Not claimable right away (not due yet)...
      const fresh = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(fresh.rows.map((r) => r.id)).to.not.include(monitorId);

      // ...but claimable once the schedule makes it due again.
      await pool.query(
        `UPDATE domain_monitors
            SET last_health_check_at = NOW() - INTERVAL '2 minutes'
          WHERE id = $1`,
        [monitorId],
      );
      const due = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(due.rows.map((r) => r.id)).to.include(monitorId);
    });

    it("no-ops a superseded owner's release after another worker takes over the expired lease", async () => {
      const monitorId = await insertMonitor();
      const claimA = crypto.randomUUID();
      const claimB = crypto.randomUUID();

      // Worker A holds the monitor but its lease has expired mid-batch.
      await pool.query(
        `UPDATE domain_monitors
            SET check_claimed_until = NOW() - INTERVAL '1 second',
                check_claim_id = $2, updated_at = NOW()
          WHERE id = $1`,
        [monitorId, claimA],
      );

      // Worker B's claim pass takes over, overwriting A's stale lease.
      const bSelect = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [
        workspaceId,
      ]);
      expect(bSelect.rows.map((r) => r.id)).to.include(monitorId);
      await pool.query(ENDPOINT_CLAIM_UPDATE_SQL, [
        monitorId,
        10 * 60 * 1000,
        claimB,
      ]);

      // A's per-row renewal (owner-scoped) must affect 0 rows.
      const aRenewal = await pool.query(
        `UPDATE domain_monitors
            SET check_claimed_until = NOW() + ($3 * INTERVAL '1 millisecond'),
                updated_at = NOW()
          WHERE id = $1
            AND check_claim_id = $2
        RETURNING id`,
        [monitorId, claimA, 10 * 60 * 1000],
      );
      expect(aRenewal.rows).to.have.length(0);

      // A's finally release (owner-scoped) must also affect 0 rows and must
      // not clear B's lease.
      const aRelease = await pool.query(ENDPOINT_RELEASE_SQL, [
        monitorId,
        claimA,
      ]);
      expect(aRelease.rowCount).to.equal(0);

      const row = await pool.query(
        `SELECT check_claim_id,
                (check_claimed_until > NOW()) AS lease_active
           FROM domain_monitors WHERE id = $1`,
        [monitorId],
      );
      expect(row.rows[0].check_claim_id).to.equal(claimB);
      expect(row.rows[0].lease_active).to.equal(true);

      // B's own release works and frees the monitor.
      const bRelease = await pool.query(ENDPOINT_RELEASE_SQL, [
        monitorId,
        claimB,
      ]);
      expect(bRelease.rowCount).to.equal(1);
      const final = await pool.query(
        `SELECT check_claim_id, check_claimed_until
           FROM domain_monitors WHERE id = $1`,
        [monitorId],
      );
      expect(final.rows[0].check_claim_id).to.equal(null);
      expect(final.rows[0].check_claimed_until).to.equal(null);
    });
  });
});
