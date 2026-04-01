const crypto = require("crypto");
const { TestUtils, expect } = require("./setup");

function encryptCredentials(plaintext, secret) {
  const key = crypto.createHash("sha256").update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted}`;
}

describe("Auto-sync worker integration", function () {
  this.timeout(90000);

  let testUser;
  let workspaceId;
  const workerSecret = "integration-worker-secret";

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    const ws = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [testUser.id],
    );
    workspaceId = ws.rows[0].id;
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery(
        "DELETE FROM auto_sync_configs WHERE workspace_id = $1",
        [workspaceId],
      );
    }
  });

  it("skips disabled and schedule-miss configs", async () => {
    const creds = encryptCredentials(
      JSON.stringify({ token: "x", baseUrl: "https://api.github.com" }),
      workerSecret,
    );

    await TestUtils.execQuery(
      `INSERT INTO auto_sync_configs
         (workspace_id, provider, credentials_encrypted, frequency, schedule_time, schedule_tz, enabled, next_sync_at, created_by)
       VALUES
         ($1, 'github', $2, 'daily', '09:00', 'UTC', FALSE, NOW() - INTERVAL '1 hour', $3),
         ($1, 'gitlab', $2, 'daily', '09:00', 'UTC', TRUE, NOW() + INTERVAL '6 hours', $3)`,
      [workspaceId, creds, testUser.id],
    );

    await TestUtils.runNode(
      "node",
      ["src/auto-sync-worker.js"],
      "apps/worker",
      {
        ...process.env,
        SESSION_SECRET: workerSecret,
        API_URL: process.env.TEST_API_URL || "http://localhost:4000",
      },
    );

    const result = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS processed
       FROM auto_sync_configs
       WHERE workspace_id = $1 AND last_sync_at IS NOT NULL`,
      [workspaceId],
    );
    expect(result.rows[0].processed).to.equal(0);
  });

  it("handles provider failure and keeps idempotency across repeated runs", async () => {
    await TestUtils.execQuery(
      "DELETE FROM auto_sync_configs WHERE workspace_id = $1",
      [workspaceId],
    );
    const creds = encryptCredentials(
      JSON.stringify({
        token: "invalid-token",
        baseUrl: "https://api.github.com",
      }),
      workerSecret,
    );

    const inserted = await TestUtils.execQuery(
      `INSERT INTO auto_sync_configs
         (workspace_id, provider, credentials_encrypted, frequency, schedule_time, schedule_tz, enabled, next_sync_at, created_by)
       VALUES
         ($1, 'github', $2, 'daily', '00:01', 'UTC', TRUE, NOW() - INTERVAL '5 minutes', $3)
       RETURNING id`,
      [workspaceId, creds, testUser.id],
    );
    const configId = inserted.rows[0].id;

    await TestUtils.runNode(
      "node",
      ["src/auto-sync-worker.js"],
      "apps/worker",
      {
        ...process.env,
        SESSION_SECRET: workerSecret,
        API_URL: process.env.TEST_API_URL || "http://localhost:4000",
      },
    );

    const first = await TestUtils.execQuery(
      `SELECT last_sync_status, last_sync_error, last_sync_at, next_sync_at
       FROM auto_sync_configs WHERE id = $1`,
      [configId],
    );
    expect(first.rows[0].last_sync_status).to.equal("failed");
    expect(
      String(first.rows[0].last_sync_error || "").length,
    ).to.be.greaterThan(0);
    const firstSyncAt = String(first.rows[0].last_sync_at);

    await TestUtils.runNode(
      "node",
      ["src/auto-sync-worker.js"],
      "apps/worker",
      {
        ...process.env,
        SESSION_SECRET: workerSecret,
        API_URL: process.env.TEST_API_URL || "http://localhost:4000",
      },
    );

    const second = await TestUtils.execQuery(
      `SELECT last_sync_at, next_sync_at
       FROM auto_sync_configs WHERE id = $1`,
      [configId],
    );
    expect(String(second.rows[0].last_sync_at)).to.equal(firstSyncAt);
    expect(new Date(second.rows[0].next_sync_at).getTime()).to.be.greaterThan(
      Date.now() - 60000,
    );
  });
});
