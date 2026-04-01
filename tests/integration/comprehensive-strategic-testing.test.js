const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");
const strategicManager = require("./strategic-test-data-manager");

// Use the existing Docker Compose server
const TEST_SERVER_URL = process.env.TEST_API_URL || "http://localhost:4000";

// Helper function to generate future dates for test tokens
function getFutureDate(daysInFuture = 90) {
  return new Date(Date.now() + daysInFuture * 24 * 60 * 60 * 1000)
    .toISOString()
    .split("T")[0];
}

describe("Comprehensive Strategic Token Testing", () => {
  let testUser;
  let session;
  let workspaceId;

  beforeEach(async () => {
    testUser = await TestUtils.createTestUser();
    logger.info(`Strategic test user created: ${testUser.email}`);
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    logger.info("Strategic test user logged in successfully");
    workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);

    if (!workspaceId) {
      throw new Error("Failed to initialize workspaceId in beforeEach");
    }
    logger.info(`Workspace initialized: ${workspaceId}`);
  });

  afterEach(async () => {
    if (testUser && testUser.email && session && session.cookie) {
      await TestUtils.cleanupTestUser(testUser.email, session.cookie);
    }
  });

  describe("1. Smart Field Grouping Implementation", () => {
    it("should test logically grouped fields together", async () => {
      const fieldGroups = strategicManager.SMART_FIELD_GROUPS;

      // Test certificate identity group
      const certIdentityToken = {
        name: "Certificate Identity Test",
        type: "ssl_cert",
        category: "cert",
        expiresAt: getFutureDate(90),
        ...fieldGroups.cert_identity,
      };

      const response1 = await request(TEST_SERVER_URL)
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...certIdentityToken, workspace_id: workspaceId });

      expect(response1.status).to.equal(201);
      expect(response1.body.domains).to.deep.equal(
        fieldGroups.cert_identity.domains,
      );
      expect(response1.body.subject).to.equal(
        fieldGroups.cert_identity.subject,
      );
      expect(response1.body.issuer).to.equal(fieldGroups.cert_identity.issuer);

      // Test license business group
      const licenseBizToken = {
        name: "License Business Test",
        type: "software_license",
        category: "license",
        expiresAt: getFutureDate(90),
        ...fieldGroups.license_business,
      };

      const response2 = await request(TEST_SERVER_URL)
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...licenseBizToken, workspace_id: workspaceId });

      expect(response2.status).to.equal(201);
      expect(response2.body.vendor).to.equal(
        fieldGroups.license_business.vendor,
      );
      expect(response2.body.license_type).to.equal(
        fieldGroups.license_business.license_type,
      );
      expect(parseFloat(response2.body.cost)).to.equal(
        fieldGroups.license_business.cost,
      );
    });
  });

  describe("2. Strategic Test Data Management", () => {
    it("should generate and run a representative test suite", async () => {
      // Create a dataset with 2 tokens per category to keep test fast but representative
      const dataset = await strategicManager.createStrategicTestDataset(
        "Representative Suite",
        { maxTokensPerCategory: 2 },
      );

      expect(dataset.scenarios.length).to.be.greaterThan(0);

      const results = await strategicManager.runStrategicTestSuite(
        dataset,
        session.cookie,
        { workspaceId },
      );

      const report = strategicManager.generateSummaryReport(results);

      logger.info("Strategic Test Report Overview:", report.overview);
      if (report.mismatches.length > 0) {
        logger.warn("Strategic Test Mismatches:", report.mismatches);
      }

      expect(report.overview.accuracyRate).to.equal(100);
    });
  });
});
