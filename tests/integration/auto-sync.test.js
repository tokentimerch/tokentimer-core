/**
 * Auto-Sync Integration Tests
 *
 * Tests for:
 * - CRUD operations on auto_sync_configs via workspace endpoints
 * - Enable/disable toggle
 * - Schedule validation (frequency, schedule_time, schedule_tz)
 * - Manual trigger endpoint
 */

const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

// ---------------------------------------------------------------------------
// 1. Auto-Sync CRUD
// ---------------------------------------------------------------------------
describe("Auto-Sync CRUD", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;
  let configId;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    const wsList = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie);
    workspaceId = wsList?.body?.items?.[0]?.id;
    logger.info("Auto-Sync CRUD - workspaceId:", workspaceId);
  });

  after(async () => {
    await TestUtils.cleanupTestUser(testUser.email, session.cookie);
  });

  // --- POST create ---

  it("POST /auto-sync - should create an auto-sync config", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .send({
        provider: "github",
        credentials: { token: "fake-gh-token" },
        frequency: "daily",
        schedule_time: "09:00",
        schedule_tz: "UTC",
      })
      .expect(201);

    // Store configId first so subsequent tests can use it even if an assertion fails
    configId = res.body.id;
    logger.info("Created auto-sync config:", configId);

    expect(res.body).to.have.property("id");
    // workspace_id is implicit from the URL; the RETURNING clause may not include it
    expect(res.body).to.have.property("provider", "github");
    expect(res.body).to.have.property("frequency", "daily");
    expect(res.body).to.have.property("schedule_time", "09:00");
    expect(res.body).to.have.property("schedule_tz", "UTC");
    expect(res.body).to.have.property("enabled");
  });

  it("POST /auto-sync - should reject without provider (400)", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .send({
        credentials: { token: "fake" },
        frequency: "daily",
      })
      .expect(400);

    expect(res.body).to.have.property("error");
  });

  it("POST /auto-sync - should reject without auth (401)", async () => {
    await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .send({
        provider: "github",
        credentials: { token: "fake" },
        frequency: "daily",
      })
      .expect(401);
  });

  // --- GET list ---

  it("GET /auto-sync - should return the created config", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .expect(200);

    const items = res.body.items || res.body;
    expect(items).to.be.an("array");
    expect(items.length).to.be.at.least(1);

    const config = (Array.isArray(items) ? items : []).find(
      (c) => c.id === configId,
    );
    expect(config).to.exist;
    expect(config).to.have.property("provider", "github");
    expect(config).to.have.property("frequency", "daily");
  });

  it("GET /auto-sync - credentials should NOT be returned in clear text", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .expect(200);

    const items = res.body.items || res.body;
    const config = (Array.isArray(items) ? items : []).find(
      (c) => c.id === configId,
    );
    expect(config).to.exist;

    // Credentials should either be omitted, masked, or not contain the raw token
    if (config.credentials) {
      const creds =
        typeof config.credentials === "string"
          ? config.credentials
          : JSON.stringify(config.credentials);
      expect(creds).to.not.include("fake-gh-token");
    }
    // If credentials is null/undefined that's also acceptable (redacted)
  });

  // --- PUT update ---

  it("PUT /auto-sync/:id - should update frequency to weekly", async () => {
    const res = await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/auto-sync/${configId}`)
      .set("Cookie", session.cookie)
      .send({ frequency: "weekly" })
      .expect(200);

    expect(res.body).to.have.property("id", configId);
    expect(res.body).to.have.property("frequency", "weekly");
  });

  // --- POST manual trigger ---

  it("POST /auto-sync/:id/run - should trigger a manual sync", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync/${configId}/run`)
      .set("Cookie", session.cookie)
      .expect(200);

    // Should acknowledge the trigger (exact shape depends on implementation)
    expect(res.body).to.have.property("success", true);
  });

  // --- DELETE ---

  it("DELETE /auto-sync/:id - should delete the config", async () => {
    const res = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/auto-sync/${configId}`)
      .set("Cookie", session.cookie)
      .expect(200);

    expect(res.body).to.have.property("success", true);
  });

  it("GET /auto-sync - list should be empty after delete", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .expect(200);

    const items = res.body.items || res.body;
    const remaining = (Array.isArray(items) ? items : []).filter(
      (c) => c.id === configId,
    );
    expect(remaining).to.have.length(0);
  });
});

// ---------------------------------------------------------------------------
// 2. Auto-Sync enable/disable
// ---------------------------------------------------------------------------
describe("Auto-Sync enable/disable", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;
  let configId;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    const wsList = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie);
    workspaceId = wsList?.body?.items?.[0]?.id;
  });

  after(async () => {
    // Cleanup config if it still exists
    if (configId) {
      try {
        await request(BASE)
          .delete(`/api/v1/workspaces/${workspaceId}/auto-sync/${configId}`)
          .set("Cookie", session.cookie);
      } catch (_) {
        // ignore cleanup errors
      }
    }
    await TestUtils.cleanupTestUser(testUser.email, session.cookie);
  });

  it("should create a config with enabled=true", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .send({
        provider: "gitlab",
        credentials: { token: "fake-gl-token" },
        frequency: "daily",
        schedule_time: "08:00",
        schedule_tz: "UTC",
        enabled: true,
      })
      .expect(201);

    expect(res.body).to.have.property("id");
    expect(res.body).to.have.property("enabled", true);
    configId = res.body.id;
  });

  it("should disable the config via PUT", async () => {
    const res = await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/auto-sync/${configId}`)
      .set("Cookie", session.cookie)
      .send({ enabled: false })
      .expect(200);

    expect(res.body).to.have.property("id", configId);
    expect(res.body).to.have.property("enabled", false);
  });

  it("should verify the config is disabled in the list", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .expect(200);

    const items = res.body.items || res.body;
    const config = (Array.isArray(items) ? items : []).find(
      (c) => c.id === configId,
    );
    expect(config).to.exist;
    expect(config).to.have.property("enabled", false);
  });
});

// ---------------------------------------------------------------------------
// 3. Schedule validation
// ---------------------------------------------------------------------------
describe("Auto-Sync schedule validation", function () {
  this.timeout(60000);

  let testUser;
  let session;
  let workspaceId;

  before(async () => {
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

  const validFrequencies = ["daily", "weekly", "monthly"];

  validFrequencies.forEach((freq) => {
    it(`should accept frequency '${freq}'`, async () => {
      const createRes = await request(BASE)
        .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
        .set("Cookie", session.cookie)
        .send({
          provider: "github",
          credentials: { token: "fake" },
          frequency: freq,
          schedule_time: "10:00",
          schedule_tz: "UTC",
        })
        .expect(201);

      const id = createRes.body.id;
      expect(createRes.body).to.have.property("frequency", freq);

      // Cleanup
      await request(BASE)
        .delete(`/api/v1/workspaces/${workspaceId}/auto-sync/${id}`)
        .set("Cookie", session.cookie)
        .expect(200);
    });
  });

  it("should store schedule_time and schedule_tz correctly", async () => {
    const createRes = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .send({
        provider: "github",
        credentials: { token: "fake" },
        frequency: "daily",
        schedule_time: "14:30",
        schedule_tz: "Europe/Zurich",
      })
      .expect(201);

    const id = createRes.body.id;
    expect(createRes.body).to.have.property("schedule_time", "14:30");
    expect(createRes.body).to.have.property("schedule_tz", "Europe/Zurich");

    // Cleanup
    await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/auto-sync/${id}`)
      .set("Cookie", session.cookie)
      .expect(200);
  });

  it("should compute and store next_sync_at", async () => {
    const createRes = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .send({
        provider: "github",
        credentials: { token: "fake" },
        frequency: "daily",
        schedule_time: "09:00",
        schedule_tz: "UTC",
        enabled: true,
      })
      .expect(201);

    const id = createRes.body.id;
    expect(createRes.body).to.have.property("next_sync_at");
    expect(createRes.body.next_sync_at).to.not.be.null;

    // next_sync_at should be a valid date in the future
    const nextSync = new Date(createRes.body.next_sync_at);
    expect(nextSync.getTime()).to.be.greaterThan(Date.now() - 60000); // allow 1 min tolerance

    // Cleanup
    await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/auto-sync/${id}`)
      .set("Cookie", session.cookie)
      .expect(200);
  });

  it("should reject an invalid frequency", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/auto-sync`)
      .set("Cookie", session.cookie)
      .send({
        provider: "github",
        credentials: { token: "fake" },
        frequency: "every_2_seconds",
        schedule_time: "09:00",
        schedule_tz: "UTC",
      });

    // Should be rejected by validation or DB constraint
    expect(res.status).to.be.oneOf([400, 500]);
    expect(res.body).to.have.property("error");
  });
});
