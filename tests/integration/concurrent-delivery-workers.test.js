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

describe("Concurrent Delivery Workers", function () {
  this.timeout(30000);

  let userId, tokenId, workspaceId;

  before(async () => {
    // Create test user
    const userRes = await pool.query(
      `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified) 
       VALUES ($1, $2, $3, $4, true) 
       RETURNING id`,
      [
        `concurrent-test-${Date.now()}@example.com`,
        "Test User",
        "local",
        "hash",
      ],
    );
    userId = userRes.rows[0].id;

    // Create workspace
    const wsId = crypto.randomUUID();
    const wsRes = await pool.query(
      `INSERT INTO workspaces (id, name, created_by, plan) 
       VALUES ($1, $2, $3, 'oss') 
       RETURNING id`,
      [wsId, `Test Workspace ${Date.now()}`, userId],
    );
    workspaceId = wsRes.rows[0].id;

    // Create workspace settings with email contact
    const contactId = crypto.randomUUID();
    await pool.query(
      `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled, contact_groups, default_contact_group_id)
       VALUES ($1, true, $2::jsonb, $3)`,
      [
        workspaceId,
        JSON.stringify([
          {
            id: "default",
            name: "Default",
            email_contact_ids: [contactId],
          },
        ]),
        "default",
      ],
    );

    // Create workspace contact
    await pool.query(
      `INSERT INTO workspace_contacts (id, workspace_id, first_name, last_name, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        contactId,
        workspaceId,
        "Test",
        "User",
        JSON.stringify({ email: "test@example.com" }),
      ],
    );

    // Create token
    const tokenRes = await pool.query(
      `INSERT INTO tokens (user_id, workspace_id, name, type, expiration, created_by)
       VALUES ($1, $2, $3, $4, CURRENT_DATE + INTERVAL '5 days', $5)
       RETURNING id`,
      [userId, workspaceId, "Test Token", "ssl_cert", userId],
    );
    tokenId = tokenRes.rows[0].id;

    // Create multiple alert queue entries for testing
    for (let i = 0; i < 5; i++) {
      await pool.query(
        `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
         VALUES ($1, $2, $3, $4, CURRENT_DATE, $5, 'pending')`,
        [
          userId,
          tokenId,
          `test_alert_${i}_${Date.now()}`,
          7,
          JSON.stringify(["email"]),
        ],
      );
    }
  });

  after(async () => {
    // Cleanup
    if (tokenId) {
      await pool.query("DELETE FROM alert_queue WHERE token_id = $1", [
        tokenId,
      ]);
      await pool.query("DELETE FROM alert_delivery_log WHERE token_id = $1", [
        tokenId,
      ]);
      await pool.query("DELETE FROM tokens WHERE id = $1", [tokenId]);
    }
    if (workspaceId) {
      await pool.query(
        "DELETE FROM workspace_contacts WHERE workspace_id = $1",
        [workspaceId],
      );
      await pool.query(
        "DELETE FROM workspace_settings WHERE workspace_id = $1",
        [workspaceId],
      );
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

  it("should prevent duplicate email deliveries when running concurrent workers", async () => {
    const client1 = await pool.connect();
    const client2 = await pool.connect();

    try {
      await client1.query("BEGIN");
      const worker1Rows = await client1.query(
        `SELECT aq.id
         FROM alert_queue aq
         JOIN tokens t ON t.id = aq.token_id
         WHERE aq.status IN ('pending', 'failed', 'partial') 
           AND aq.due_date <= CURRENT_DATE
           AND aq.token_id = $1
         ORDER BY aq.due_date ASC, aq.created_at ASC
         LIMIT 1000
         FOR UPDATE OF aq SKIP LOCKED`,
        [tokenId],
      );

      await client2.query("BEGIN");
      const worker2Rows = await client2.query(
        `SELECT aq.id
         FROM alert_queue aq
         JOIN tokens t ON t.id = aq.token_id
         WHERE aq.status IN ('pending', 'failed', 'partial') 
           AND aq.due_date <= CURRENT_DATE
           AND aq.token_id = $1
         ORDER BY aq.due_date ASC, aq.created_at ASC
         LIMIT 1000
         FOR UPDATE OF aq SKIP LOCKED`,
        [tokenId],
      );

      const worker1Ids = new Set(worker1Rows.rows.map((r) => r.id));
      const worker2Ids = new Set(worker2Rows.rows.map((r) => r.id));
      const overlap = [...worker1Ids].filter((id) => worker2Ids.has(id));

      expect(overlap.length).to.equal(0);
      expect(worker1Rows.rows.length + worker2Rows.rows.length).to.equal(5);

      await client1.query("COMMIT");
      await client2.query("COMMIT");
    } catch (err) {
      await client1.query("ROLLBACK").catch(() => {});
      await client2.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client1.release();
      client2.release();
    }
  });

  it("should distribute alerts evenly between concurrent workers", async () => {
    // Reset alerts to pending
    await pool.query(
      "UPDATE alert_queue SET status = 'pending' WHERE token_id = $1",
      [tokenId],
    );

    // Simulate concurrent workers processing alerts
    const processAlerts = async (workerName) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query(
          `SELECT aq.id
           FROM alert_queue aq
           JOIN tokens t ON t.id = aq.token_id
           WHERE aq.status IN ('pending', 'failed', 'partial') 
             AND aq.due_date <= CURRENT_DATE
             AND aq.token_id = $1
           ORDER BY aq.due_date ASC, aq.created_at ASC
           LIMIT 1000
           FOR UPDATE OF aq SKIP LOCKED`,
          [tokenId],
        );

        // Mark as processed
        for (const row of result.rows) {
          await client.query(
            "UPDATE alert_queue SET status = 'sent', last_attempt = NOW() WHERE id = $1",
            [row.id],
          );
        }

        await client.query("COMMIT");
        return { worker: workerName, count: result.rows.length };
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      } finally {
        client.release();
      }
    };

    const results = await Promise.all([
      processAlerts("worker1"),
      processAlerts("worker2"),
      processAlerts("worker3"),
    ]);

    const totalProcessed = results.reduce((sum, r) => sum + r.count, 0);
    expect(totalProcessed).to.equal(5);

    // Verify no duplicates in delivery
    const sentAlerts = await pool.query(
      "SELECT COUNT(*) as count FROM alert_queue WHERE token_id = $1 AND status = 'sent'",
      [tokenId],
    );
    expect(Number(sentAlerts.rows[0].count)).to.equal(5);
  });

  it("should handle worker failures gracefully without duplicates", async () => {
    // Reset alerts to pending
    await pool.query(
      "UPDATE alert_queue SET status = 'pending' WHERE token_id = $1",
      [tokenId],
    );

    const processAlertsWithFailure = async (shouldFail) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query(
          `SELECT aq.id
           FROM alert_queue aq
           JOIN tokens t ON t.id = aq.token_id
           WHERE aq.status IN ('pending', 'failed', 'partial') 
             AND aq.due_date <= CURRENT_DATE
             AND aq.token_id = $1
           ORDER BY aq.due_date ASC, aq.created_at ASC
           LIMIT 2
           FOR UPDATE OF aq SKIP LOCKED`,
          [tokenId],
        );

        if (shouldFail) {
          // Simulate failure - rollback without processing
          await client.query("ROLLBACK");
          return { success: false, count: 0 };
        }

        // Mark as processed
        for (const row of result.rows) {
          await client.query(
            "UPDATE alert_queue SET status = 'sent', last_attempt = NOW() WHERE id = $1",
            [row.id],
          );
        }

        await client.query("COMMIT");
        return { success: true, count: result.rows.length };
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      } finally {
        client.release();
      }
    };

    // Run workers where one fails
    const [result1, result2, result3] = await Promise.all([
      processAlertsWithFailure(false),
      processAlertsWithFailure(true), // This one fails
      processAlertsWithFailure(false),
    ]);

    // Failed worker should release locks, allowing other workers to process
    expect(result2.success).to.equal(false);

    // Re-run to pick up what the failed worker didn't process
    const result4 = await processAlertsWithFailure(false);

    const totalProcessed = result1.count + result3.count + result4.count;
    expect(totalProcessed).to.equal(5);

    // Verify all alerts are now sent
    const sentAlerts = await pool.query(
      "SELECT COUNT(*) as count FROM alert_queue WHERE token_id = $1 AND status = 'sent'",
      [tokenId],
    );
    expect(Number(sentAlerts.rows[0].count)).to.equal(5);
  });
});
