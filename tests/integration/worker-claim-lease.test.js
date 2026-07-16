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
// (sent/blocked) fails the recheck atomically.
const DELIVERY_RECHECK_SQL = `
  UPDATE alert_queue
     SET next_attempt_at = NOW() + ($2 * INTERVAL '1 millisecond'),
         updated_at = NOW()
   WHERE id = $1
     AND status IN ('pending', 'failed', 'partial')
 RETURNING id`;

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

      // Worker A claims the row (batch claim marker).
      await pool.query(
        `UPDATE alert_queue
            SET next_attempt_at = NOW() + INTERVAL '15 minutes', updated_at = NOW()
          WHERE id = $1`,
        [alertId],
      );

      // Worker B (lease expired for it) processes and sends the alert.
      await pool.query(
        `UPDATE alert_queue
            SET status = 'sent', last_attempt = NOW(), updated_at = NOW()
          WHERE id = $1`,
        [alertId],
      );

      // Worker A reaches the row late; the per-row recheck must not match.
      const recheck = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
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

      await pool.query(
        `UPDATE alert_queue
            SET status = 'blocked', updated_at = NOW()
          WHERE id = $1`,
        [alertId],
      );

      const recheck = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
      ]);
      expect(recheck.rows).to.have.length(0);
    });

    it("renews the claim marker for a row that is still pending", async () => {
      const alertId = await insertAlert("still_pending");

      // Simulate a nearly-expired batch claim marker.
      await pool.query(
        `UPDATE alert_queue
            SET next_attempt_at = NOW() + INTERVAL '1 second', updated_at = NOW()
          WHERE id = $1`,
        [alertId],
      );

      const recheck = await pool.query(DELIVERY_RECHECK_SQL, [
        alertId,
        15 * 60 * 1000,
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

      // First claim pass takes the lease.
      const first = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(first.rows.map((r) => r.id)).to.include(monitorId);
      await pool.query(
        `UPDATE domain_monitors
            SET check_claimed_until = NOW() + INTERVAL '10 minutes', updated_at = NOW()
          WHERE id = $1`,
        [monitorId],
      );

      // A second worker's claim pass must skip it even though it is still
      // "due" by last_health_check_at (10 minutes > 1 minute interval).
      const second = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(second.rows.map((r) => r.id)).to.not.include(monitorId);
    });

    it("re-claims a monitor whose lease has expired (crash recovery)", async () => {
      const monitorId = await insertMonitor();

      await pool.query(
        `UPDATE domain_monitors
            SET check_claimed_until = NOW() - INTERVAL '1 second', updated_at = NOW()
          WHERE id = $1`,
        [monitorId],
      );

      const claim = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(claim.rows.map((r) => r.id)).to.include(monitorId);
    });

    it("makes a monitor claimable again once the lease is cleared after completion", async () => {
      const monitorId = await insertMonitor();

      // Claimed and processing.
      await pool.query(
        `UPDATE domain_monitors
            SET check_claimed_until = NOW() + INTERVAL '10 minutes', updated_at = NOW()
          WHERE id = $1`,
        [monitorId],
      );
      const during = await pool.query(ENDPOINT_CLAIM_SELECT_SQL, [workspaceId]);
      expect(during.rows.map((r) => r.id)).to.not.include(monitorId);

      // Completion: schedule advances, lease clears (as the worker does).
      await pool.query(
        `UPDATE domain_monitors
            SET last_health_check_at = NOW(), check_claimed_until = NULL, updated_at = NOW()
          WHERE id = $1`,
        [monitorId],
      );

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
  });
});
