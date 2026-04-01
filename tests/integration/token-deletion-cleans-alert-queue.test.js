const { expect, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const request = require("supertest");

const TEST_API_URL = process.env.TEST_API_URL || "http://localhost:4000";

describe("Token Deletion - Alert Queue Cleanup", function () {
  this.timeout(60000);

  let client;
  let user1; // Token creator
  let user2; // Workspace owner (subscription owner)
  let workspaceId;
  let tokenId;
  let cookie1;
  let cookie2;

  before(async () => {
    await TestEnvironment.setup();
    client = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    await client.connect();

    // Create two users
    user1 = await TestUtils.createAuthenticatedUser();
    user2 = await TestUtils.createAuthenticatedUser();
    cookie1 = user1.cookie;
    cookie2 = user2.cookie;

    // Create a workspace owned by user2
    const crypto = require("crypto");
    workspaceId = crypto.randomUUID();
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, $2, 'oss', $3)`,
      [workspaceId, "Token Delete Test Workspace", user2.user.id],
    );

    // Add user2 as admin
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1, $2, 'admin', $1)`,
      [user2.user.id, workspaceId],
    );

    // Add user1 as a workspace_manager to the workspace
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1, $2, 'workspace_manager', $3)`,
      [user1.user.id, workspaceId, user2.user.id],
    );

    // Create a token in the workspace (user1 creates it)
    const exp = new Date();
    exp.setDate(exp.getDate() + 25);
    const expiration = exp.toISOString().slice(0, 10);

    const tokenRes = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, $3, $4, 'api_key', 'general') RETURNING id`,
      [user1.user.id, workspaceId, "Test Token for Alert Queue", expiration],
    );
    tokenId = tokenRes.rows[0].id;
  });

  after(async () => {
    try {
      // Cleanup
      if (tokenId) {
        await client.query("DELETE FROM alert_queue WHERE token_id = $1", [
          tokenId,
        ]);
        await client.query("DELETE FROM tokens WHERE id = $1", [tokenId]);
      }
      if (workspaceId) {
        await client.query("DELETE FROM workspaces WHERE id = $1", [
          workspaceId,
        ]);
      }
      await TestUtils.cleanupTestUser(user1.email, cookie1);
      await TestUtils.cleanupTestUser(user2.email, cookie2);
    } catch (_) {}
    await client.end();
  });

  it("should delete all alert_queue entries when token is deleted, regardless of user_id", async () => {
    // Simulate alert queue discovery job creating alerts for different users
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 25);
    const dueDateStr = dueDate.toISOString().slice(0, 10);

    // Alert for user1 (token creator)
    await client.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
       VALUES ($1, $2, $3, 30, $4, '["email"]'::jsonb, 'pending')`,
      [user1.user.id, tokenId, `token-${tokenId}-30-${dueDateStr}`, dueDateStr],
    );

    // Alert for user2 (workspace owner - subscription owner)
    await client.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
       VALUES ($1, $2, $3, 14, $4, '["email"]'::jsonb, 'pending')`,
      [user2.user.id, tokenId, `token-${tokenId}-14-${dueDateStr}`, dueDateStr],
    );

    // Verify both alerts exist
    const beforeDelete = await client.query(
      "SELECT user_id FROM alert_queue WHERE token_id = $1 ORDER BY user_id",
      [tokenId],
    );
    expect(beforeDelete.rows).to.have.lengthOf(2);
    expect(beforeDelete.rows[0].user_id).to.equal(user1.user.id);
    expect(beforeDelete.rows[1].user_id).to.equal(user2.user.id);

    // Delete the token via API (user1 has permission as workspace_manager)
    const deleteResponse = await request(TEST_API_URL)
      .delete(`/api/tokens/${tokenId}`)
      .set("Cookie", cookie1);

    expect(deleteResponse.status).to.equal(200);

    // Verify ALL alerts for this token are deleted, regardless of user_id
    const afterDelete = await client.query(
      "SELECT * FROM alert_queue WHERE token_id = $1",
      [tokenId],
    );
    expect(afterDelete.rows).to.have.lengthOf(0);

    // Verify the token itself is deleted
    const tokenCheck = await client.query(
      "SELECT * FROM tokens WHERE id = $1",
      [tokenId],
    );
    expect(tokenCheck.rows).to.have.lengthOf(0);

    // Mark as deleted to prevent double cleanup in after hook
    tokenId = null;
  });
});
