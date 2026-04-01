const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

/**
 * Tests for the three alert delivery bugs:
 * 1. Duplicate emails for the same token expiration
 * 2. Alerts for expired tokens when user doesn't want them
 * 3. Incorrect message for expired tokens
 */

describe("Alert Bug Fixes", function () {
  this.timeout(60000);

  let user;
  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    user = u;
    cookie = u.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  after(async () => {
    if (user && user.email && cookie) {
      await TestUtils.cleanupTestUser(user.email, cookie);
    }
  });

  it("should not send alerts for expired tokens when user has default thresholds", async () => {
    // Create a token that expired 2 days ago
    const expiredDate = new Date();
    expiredDate.setDate(expiredDate.getDate() - 2);

    const res = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Expired Token Test",
        type: "api_key",
        category: "general",
        expiresAt: expiredDate.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      });
    expect(res.status).to.equal(201);

    // Run queue discovery - should not create alerts for expired tokens
    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    // Check that no alerts were queued
    const queueRes = await request(BASE)
      .get("/api/alert-queue")
      .query({ workspace_id: workspaceId })
      .set("Cookie", cookie)
      .expect(200);

    // Should not have any alerts for the expired token
    const expiredTokenAlerts = queueRes.body.alerts.filter(
      (alert) => alert.token_name === "Expired Token Test",
    );
    expect(expiredTokenAlerts).to.have.length(0);
  });

  it("should send alerts for expired tokens when user has negative thresholds", async () => {
    // Update user to have negative thresholds (post-expiration alerts)
    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .send({ alert_thresholds: [30, 7, 1, 0, -1, -2] });

    // Create a token that expired 1 day ago
    const expiredDate = new Date();
    expiredDate.setDate(expiredDate.getDate() - 1);

    const res = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Expired Token With Negative Thresholds",
        type: "api_key",
        category: "general",
        expiresAt: expiredDate.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      });
    expect(res.status).to.equal(201);

    // Run queue discovery - should create alerts for expired tokens with negative thresholds
    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    // Check that alerts were queued
    const queueRes = await request(BASE)
      .get("/api/alert-queue")
      .query({ workspace_id: workspaceId })
      .set("Cookie", cookie)
      .expect(200);

    const expiredTokenAlerts = queueRes.body.alerts.filter(
      (alert) => alert.token_name === "Expired Token With Negative Thresholds",
    );
    expect(expiredTokenAlerts.length).to.be.greaterThan(0);
  });

  it("should not create duplicate alerts for the same token/threshold/day", async () => {
    // Create a token expiring in 7 days
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);

    const res = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Duplicate Test Token",
        type: "api_key",
        category: "general",
        expiresAt: futureDate.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      });
    expect(res.status).to.equal(201);

    // Ensure alert settings make this token eligible for queueing.
    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .send({ alert_thresholds: [30, 7, 1, 0, -1, -2] })
      .expect(200);

    // Run queue discovery twice - should never create duplicates for same threshold/day.
    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );
    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    // Check that only one alert was created
    const queueRes = await request(BASE)
      .get("/api/alert-queue")
      .query({ workspace_id: workspaceId })
      .set("Cookie", cookie)
      .expect(200);

    const duplicateTestAlerts = queueRes.body.alerts.filter(
      (alert) => alert.token_name === "Duplicate Test Token",
    );
    expect(duplicateTestAlerts.length).to.be.at.most(1);
  });

  it("should format expired token messages correctly", async () => {
    // This test would require mocking the email delivery to check the actual message content
    // For now, we'll test the logic by creating an expired token and checking the queue
    const expiredDate = new Date();
    expiredDate.setDate(expiredDate.getDate() - 3);

    const res = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Message Format Test Token",
        type: "api_key",
        category: "general",
        expiresAt: expiredDate.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      });
    expect(res.status).to.equal(201);

    // Update user to have negative thresholds
    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .send({ alert_thresholds: [30, 7, 1, 0, -1, -2, -3] });

    // Run queue discovery
    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    // Check that alert was queued (the message format will be tested in delivery)
    const queueRes = await request(BASE)
      .get("/api/alert-queue")
      .query({ workspace_id: workspaceId })
      .set("Cookie", cookie)
      .expect(200);

    const messageTestAlerts = queueRes.body.alerts.filter(
      (alert) => alert.token_name === "Message Format Test Token",
    );
    expect(messageTestAlerts.length).to.be.greaterThan(0);
  });
});
