/**
 * Endpoint (SSL) Monitor Integration Tests
 *
 * Tests for:
 * - CRUD operations on domain_monitors via workspace endpoints
 * - Manual health-check trigger
 * - Token listing enriched with monitor health data
 * - check_interval DB constraint validation
 */

const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { logger } = require("./logger");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

// ---------------------------------------------------------------------------
// 1. Endpoint Monitor CRUD
// ---------------------------------------------------------------------------
describe("Endpoint Monitor CRUD", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;
  let domainId;

  before(async () => {
    await TestEnvironment.setup();
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    const wsList = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie);
    workspaceId = wsList?.body?.items?.[0]?.id;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(testUser.email, session.cookie);
  });

  // --- POST create ---

  it("POST /domains - should create an endpoint monitor", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domains`)
      .set("Cookie", session.cookie)
      .send({ url: "https://example.com" })
      .expect(201);

    expect(res.body).to.have.property("id");
    expect(res.body).to.have.property("url");
    expect(res.body.url).to.include("example.com");
    expect(res.body).to.have.property("health_check_enabled");
    expect(res.body).to.have.property("check_interval");

    // Store for subsequent tests
    domainId = res.body.id;
  });

  it("POST /domains - should reject without url (400)", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domains`)
      .set("Cookie", session.cookie)
      .send({})
      .expect(400);

    expect(res.body).to.have.property("error");
    expect(res.body.error).to.include("url");
  });

  it("POST /domains - should reject without auth (401)", async () => {
    await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domains`)
      .send({ url: "https://example.com" })
      .expect(401);
  });

  // --- GET list ---

  it("GET /domains - should return the created monitor", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/domains`)
      .set("Cookie", session.cookie)
      .expect(200);

    expect(res.body).to.have.property("items").that.is.an("array");
    expect(res.body.items.length).to.be.at.least(1);

    const monitor = res.body.items.find((m) => m.id === domainId);
    expect(monitor).to.exist;
    expect(monitor).to.have.property("url");
    expect(monitor).to.have.property("check_interval");
    expect(monitor).to.have.property("health_check_enabled");
  });

  // --- PUT update ---

  it("PUT /domains/:domainId - should update check_interval to 5min", async () => {
    const res = await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/domains/${domainId}`)
      .set("Cookie", session.cookie)
      .send({ check_interval: "5min" })
      .expect(200);

    expect(res.body).to.have.property("id", domainId);
    expect(res.body).to.have.property("check_interval", "5min");
  });

  // --- POST manual health check ---

  it("POST /domains/:domainId/check - should perform a health check", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domains/${domainId}/check`)
      .set("Cookie", session.cookie)
      .expect(200);

    expect(res.body).to.have.property("status");
    expect(res.body).to.have.property("statusCode");
    expect(res.body).to.have.property("responseMs");
    // example.com should be reachable
    expect(res.body.status).to.equal("healthy");
    expect(res.body.statusCode).to.be.a("number");
    expect(res.body.responseMs).to.be.a("number");
  });

  // --- DELETE ---

  it("DELETE /domains/:domainId - should delete the monitor", async () => {
    const res = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/domains/${domainId}`)
      .set("Cookie", session.cookie)
      .expect(200);

    expect(res.body).to.have.property("success", true);
  });

  it("GET /domains - list should be empty after delete", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/domains`)
      .set("Cookie", session.cookie)
      .expect(200);

    const remaining = res.body.items.filter((m) => m.id === domainId);
    expect(remaining).to.have.length(0);
  });
});

// ---------------------------------------------------------------------------
// 2. Token listing with health data
// ---------------------------------------------------------------------------
describe("Token listing with endpoint-monitor health data", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;
  let tokenId;
  let monitorId;

  before(async () => {
    await TestEnvironment.setup();
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    const wsList = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie);
    workspaceId = wsList?.body?.items?.[0]?.id;

    // Create a token directly in the DB
    const tokenRes = await TestUtils.execQuery(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, 'Monitor Test Token', '2099-01-01', 'api_key', 'key_secret')
       RETURNING id`,
      [testUser.id, workspaceId],
    );
    tokenId = tokenRes.rows[0].id;

    // Create a domain_monitors row linked to the token with health data
    const monitorRes = await TestUtils.execQuery(
      `INSERT INTO domain_monitors
         (workspace_id, url, health_check_enabled, check_interval,
          last_health_status, last_health_response_ms, token_id, created_by)
       VALUES ($1, 'https://example.com', TRUE, 'hourly', 'healthy', 42, $2, $3)
       RETURNING id`,
      [workspaceId, tokenId, testUser.id],
    );
    monitorId = monitorRes.rows[0].id;
  });

  after(async () => {
    // Cleanup created rows
    if (monitorId) {
      await TestUtils.execQuery("DELETE FROM domain_monitors WHERE id = $1", [
        monitorId,
      ]);
    }
    if (tokenId) {
      await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [tokenId]);
    }
    await TestUtils.cleanupTestUser(testUser.email, session.cookie);
  });

  it("GET /api/tokens should include monitor health fields for linked token", async () => {
    const res = await request(BASE)
      .get(`/api/tokens?workspace_id=${workspaceId}`)
      .set("Cookie", session.cookie);

    if (res.status !== 200) {
      logger.info("Token listing failed with status:", res.status);
      logger.info("Response body:", JSON.stringify(res.body));
      logger.info("Workspace ID used:", workspaceId);
      logger.info("Test user ID:", testUser.id);
    }
    expect(res.status).to.equal(200);

    // Find our specific token
    const items = res.body.items || res.body;
    const token = (Array.isArray(items) ? items : []).find(
      (t) => t.id === tokenId,
    );
    expect(token).to.exist;
    expect(token).to.have.property("monitor_health_status", "healthy");
    expect(token).to.have.property("monitor_response_ms");
    expect(Number(token.monitor_response_ms)).to.equal(42);
    expect(token).to.have.property("monitor_url", "https://example.com");
  });

  it("Tokens without a monitor should have null health fields", async () => {
    // Create an unlinked token
    const unlRes = await TestUtils.execQuery(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, 'No Monitor Token', '2099-01-01', 'api_key', 'key_secret')
       RETURNING id`,
      [testUser.id, workspaceId],
    );
    const unlinkedId = unlRes.rows[0].id;

    try {
      const res = await request(BASE)
        .get(`/api/tokens?workspace_id=${workspaceId}`)
        .set("Cookie", session.cookie)
        .expect(200);

      const items = res.body.items || res.body;
      const token = (Array.isArray(items) ? items : []).find(
        (t) => t.id === unlinkedId,
      );
      expect(token).to.exist;
      expect(token.monitor_health_status).to.be.null;
      expect(token.monitor_response_ms).to.be.null;
      expect(token.monitor_url).to.be.null;
    } finally {
      await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [
        unlinkedId,
      ]);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Check interval validation
// ---------------------------------------------------------------------------
describe("Endpoint Monitor - check_interval validation", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    const wsList = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie);
    workspaceId = wsList?.body?.items?.[0]?.id;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(testUser.email, session.cookie);
  });

  const validIntervals = ["1min", "5min", "30min", "hourly", "daily"];

  validIntervals.forEach((interval) => {
    it(`should accept check_interval '${interval}'`, async () => {
      const createRes = await request(BASE)
        .post(`/api/v1/workspaces/${workspaceId}/domains`)
        .set("Cookie", session.cookie)
        .send({ url: "https://example.com", check_interval: interval })
        .expect(201);

      const id = createRes.body.id;
      expect(createRes.body).to.have.property("check_interval", interval);

      // Cleanup
      await request(BASE)
        .delete(`/api/v1/workspaces/${workspaceId}/domains/${id}`)
        .set("Cookie", session.cookie)
        .expect(200);
    });
  });

  it("should reject an invalid check_interval", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/domains`)
      .set("Cookie", session.cookie)
      .send({ url: "https://example.com", check_interval: "every_2_seconds" });

    // The DB constraint should cause a 500 or specific validation error
    expect(res.status).to.be.oneOf([400, 500]);
    expect(res.body).to.have.property("error");
  });
});
