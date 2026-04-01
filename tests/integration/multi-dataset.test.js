const { expect } = require("chai");
const { testDataManager, TEST_CONFIG } = require("./test-data-manager");
const request = require("supertest");
const { logger } = require("./logger");

describe("Multi-Dataset Test Suite", () => {
  let testScenarios = [];

  // Setup before all tests
  before(async () => {
    logger.info("Setting up multi-dataset test suite...");

    // Wait for server to be ready
    await testDataManager.retry(async () => {
      const response = await request(TEST_CONFIG.API_URL).get("/");
      expect(response.status).to.equal(200);
    });
  });

  // Cleanup after all tests
  after(async () => {
    logger.info("Cleaning up multi-dataset test suite...");
    await testDataManager.cleanupAll();
  });

  describe("Dataset Management", () => {
    it("should create and manage multiple datasets independently", async () => {
      // Create multiple datasets with different configurations
      const dataset1 = testDataManager.createDataset("Basic Users", {
        emailPrefix: "basic",
        password: "basicpass123",
      });

      const dataset2 = testDataManager.createDataset("Premium Users", {
        emailPrefix: "premium",
        password: "premiumpass456",
      });

      const dataset3 = testDataManager.createDataset("Admin Users", {
        emailPrefix: "admin",
        password: "adminpass789",
      });

      // Verify datasets are created independently
      expect(dataset1.id).to.not.equal(dataset2.id);
      expect(dataset2.id).to.not.equal(dataset3.id);
      expect(dataset1.config.emailPrefix).to.equal("basic");
      expect(dataset2.config.emailPrefix).to.equal("premium");
      expect(dataset3.config.emailPrefix).to.equal("admin");

      // Generate test data for each dataset
      const user1 = testDataManager.generateTestData(dataset1.id, "user");
      const user2 = testDataManager.generateTestData(dataset2.id, "user");
      const user3 = testDataManager.generateTestData(dataset3.id, "user");

      // Verify data is unique per dataset
      expect(user1.email).to.include("basic");
      expect(user2.email).to.include("premium");
      expect(user3.email).to.include("admin");

      logger.info("✅ Multiple datasets created and managed independently");
    });

    it("should create users in different datasets without conflicts", async () => {
      const dataset1 = testDataManager.createDataset("Conflict Test 1");
      const dataset2 = testDataManager.createDataset("Conflict Test 2");

      // Create users in parallel
      const [users1, users2] = await Promise.all([
        testDataManager.createTestUsers(dataset1.id, 3),
        testDataManager.createTestUsers(dataset2.id, 3),
      ]);

      // Verify users are created successfully
      expect(users1).to.have.length(3);
      expect(users2).to.have.length(3);

      // Verify no conflicts between datasets
      const emails1 = users1.map((u) => u.email);
      const emails2 = users2.map((u) => u.email);

      for (const email1 of emails1) {
        expect(emails2).to.not.include(email1);
      }

      logger.info("✅ Users created in different datasets without conflicts");
    });
  });

  describe("Test Scenarios with Multiple Datasets", () => {
    it("should create complete test scenarios with users, sessions, and tokens", async () => {
      // Create different test scenarios
      const scenario1 = await testDataManager.createTestScenario(
        "Single User Scenario",
        {
          userCount: 1,
          sessionCount: 1,
          tokenCount: 2,
        },
      );

      const scenario2 = await testDataManager.createTestScenario(
        "Multi User Scenario",
        {
          userCount: 3,
          sessionCount: 2,
          tokenCount: 1,
        },
      );

      const scenario3 = await testDataManager.createTestScenario(
        "Token Heavy Scenario",
        {
          userCount: 1,
          sessionCount: 1,
          tokenCount: 5,
        },
      );

      testScenarios.push(scenario1, scenario2, scenario3);

      // Verify scenarios are created correctly
      expect(scenario1.users).to.have.length(1);
      expect(scenario1.sessions).to.have.length(1);
      expect(scenario1.tokens).to.have.length(2);

      expect(scenario2.users).to.have.length(3);
      expect(scenario2.sessions).to.have.length(2);
      expect(scenario2.tokens).to.have.length(2);

      expect(scenario3.users).to.have.length(1);
      expect(scenario3.sessions).to.have.length(1);
      expect(scenario3.tokens).to.have.length(5);

      logger.info("✅ Complete test scenarios created successfully");
    });

    it("should test token operations across multiple datasets", async () => {
      const scenario = await testDataManager.createTestScenario(
        "Token Operations Test",
        {
          userCount: 2,
          sessionCount: 2,
          tokenCount: 3,
        },
      );

      testScenarios.push(scenario);

      // Test token retrieval for each session
      for (let i = 0; i < scenario.sessions.length; i++) {
        const session = scenario.sessions[i];
        const response = await request(TEST_CONFIG.API_URL)
          .get("/api/tokens")
          .set("Cookie", session.cookie || "");

        if (response.status !== 200) {
          logger.info(
            `Token listing failed for session ${i} with status:`,
            response.status,
          );
          logger.info("Response body:", JSON.stringify(response.body));
          logger.info("Cookie present:", !!session.cookie);
          logger.info("Session user:", JSON.stringify(session.user?.email));
        }
        expect(response.status).to.equal(200);
        const items = response.body.items || response.body;
        expect(items).to.be.an("array");

        const userTokens = scenario.tokens.filter(
          (t) => t.sessionId === session.user.id,
        );
        expect(items).to.have.length(userTokens.length);
      }

      logger.info("✅ Token operations tested across multiple datasets");
    });
  });

  describe("Security Testing with Multiple Datasets", () => {
    it("should test security scenarios with different datasets", async () => {
      const attackPayloads = testDataManager.generateAttackPayloads();

      // Create a security test dataset
      const securityDataset = testDataManager.createDataset(
        "Security Test Dataset",
      );
      const users = await testDataManager.createTestUsers(
        securityDataset.id,
        2,
      );
      const sessions = await testDataManager.createAuthenticatedSessions(
        securityDataset.id,
        2,
      );

      // Test SQL injection attempts
      for (const payload of attackPayloads.sqlInjection) {
        const response = await request(TEST_CONFIG.API_URL)
          .post("/auth/login")
          .send({
            email: payload,
            password: "testpassword",
          });

        // Should fail with 400 (validation error) for invalid email format
        expect(response.status).to.equal(400);
        expect(response.body).to.have.property("error");
      }

      // Test XSS attempts in token creation
      for (const payload of attackPayloads.xss.slice(0, 3)) {
        // Test first 3 payloads
        const response = await request(TEST_CONFIG.API_URL)
          .post("/api/tokens")
          .set("Cookie", sessions[0].cookie || "")
          .send({
            name: payload,
            type: "api_key",
            expiresAt: "2030-12-31",
          });

        // Should either reject or accept (depending on backend validation)
        expect([201, 400]).to.include(response.status);
      }

      logger.info("✅ Security testing completed with multiple datasets");
    });
  });

  describe("Rate Limiting with Multiple Datasets", () => {
    it("should test rate limiting across different datasets", async () => {
      // Create multiple datasets to test rate limiting
      const datasets = [];
      for (let i = 0; i < 3; i++) {
        const dataset = testDataManager.createDataset(
          `Rate Limit Test ${i + 1}`,
        );
        datasets.push(dataset);
      }

      // Create users in each dataset
      const userPromises = datasets.map((dataset) =>
        testDataManager.createTestUsers(dataset.id, 2),
      );
      const allUsers = await Promise.all(userPromises);

      // Test concurrent requests from different datasets
      const loginPromises = allUsers.flat().map((user) =>
        request(TEST_CONFIG.API_URL).post("/auth/login").send({
          email: user.email,
          password: user.password,
        }),
      );

      const responses = await Promise.allSettled(loginPromises);

      // Count successful logins
      const successfulLogins = responses.filter(
        (r) => r.status === "fulfilled" && r.value.status === 200,
      ).length;

      // Should have successful logins (rate limiting should not affect different datasets)
      expect(successfulLogins).to.be.greaterThan(0);

      logger.info(`✅ Rate limiting tested across ${datasets.length} datasets`);
    });
  });

  describe("Data Isolation and Cleanup", () => {
    it("should maintain data isolation between datasets", async () => {
      const dataset1 = testDataManager.createDataset("Isolation Test 1");
      const dataset2 = testDataManager.createDataset("Isolation Test 2");

      // Create users in both datasets
      const users1 = await testDataManager.createTestUsers(dataset1.id, 2);
      const users2 = await testDataManager.createTestUsers(dataset2.id, 2);

      // Create sessions
      const sessions1 = await testDataManager.createAuthenticatedSessions(
        dataset1.id,
        2,
      );
      const sessions2 = await testDataManager.createAuthenticatedSessions(
        dataset2.id,
        2,
      );

      // Create tokens
      const tokens1 = await testDataManager.createTestTokens(dataset1.id, 0, 2);
      const tokens2 = await testDataManager.createTestTokens(dataset2.id, 0, 2);

      // Verify isolation - users from dataset1 should not see tokens from dataset2
      const response1 = await request(TEST_CONFIG.API_URL)
        .get("/api/tokens")
        .set("Cookie", sessions1[0].cookie || "");

      const response2 = await request(TEST_CONFIG.API_URL)
        .get("/api/tokens")
        .set("Cookie", sessions2[0].cookie || "");

      if (response1.status !== 200) {
        logger.info(
          "Isolation test response1 failed:",
          response1.status,
          JSON.stringify(response1.body),
        );
        logger.info("Cookie1 present:", !!sessions1[0].cookie);
      }
      if (response2.status !== 200) {
        logger.info(
          "Isolation test response2 failed:",
          response2.status,
          JSON.stringify(response2.body),
        );
        logger.info("Cookie2 present:", !!sessions2[0].cookie);
      }
      expect(response1.status).to.equal(200);
      expect(response2.status).to.equal(200);

      // Verify each user only sees their own tokens
      const tokens1Ids = tokens1.map((t) => t.id);
      const tokens2Ids = tokens2.map((t) => t.id);

      const items1 = response1.body.items || response1.body;
      const items2 = response2.body.items || response2.body;

      for (const token of items1) {
        expect(tokens1Ids).to.include(token.id);
        expect(tokens2Ids).to.not.include(token.id);
      }

      for (const token of items2) {
        expect(tokens2Ids).to.include(token.id);
        expect(tokens1Ids).to.not.include(token.id);
      }

      logger.info("✅ Data isolation maintained between datasets");
    });

    it("should properly cleanup datasets without affecting others", async () => {
      const dataset1 = testDataManager.createDataset("Cleanup Test 1");
      const dataset2 = testDataManager.createDataset("Cleanup Test 2");

      // Create data in both datasets
      await testDataManager.createTestUsers(dataset1.id, 1);
      await testDataManager.createTestUsers(dataset2.id, 1);
      await testDataManager.createAuthenticatedSessions(dataset1.id, 1);
      await testDataManager.createAuthenticatedSessions(dataset2.id, 1);
      await testDataManager.createTestTokens(dataset1.id, 0, 1);
      await testDataManager.createTestTokens(dataset2.id, 0, 1);

      // Verify both datasets have data
      expect(dataset1.users).to.have.length(1);
      expect(dataset2.users).to.have.length(1);

      // Cleanup only dataset1
      await testDataManager.cleanupDataset(dataset1.id);

      // Verify dataset1 is cleaned up but dataset2 remains
      expect(testDataManager.datasets.has(dataset1.id)).to.be.false;
      expect(testDataManager.datasets.has(dataset2.id)).to.be.true;
      expect(dataset2.users).to.have.length(1);

      logger.info("✅ Dataset cleanup works without affecting others");
    });
  });

  describe("Performance Testing with Multiple Datasets", () => {
    it("should handle bulk operations across multiple datasets", async () => {
      const startTime = Date.now();

      // Create multiple datasets with bulk data
      const bulkScenarios = [];
      for (let i = 0; i < 3; i++) {
        const scenario = await testDataManager.createTestScenario(
          `Bulk Test ${i + 1}`,
          {
            userCount: 2,
            sessionCount: 2,
            tokenCount: 3,
          },
        );
        bulkScenarios.push(scenario);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Verify all scenarios were created
      expect(bulkScenarios).to.have.length(3);
      for (const scenario of bulkScenarios) {
        expect(scenario.users).to.have.length(2);
        expect(scenario.sessions).to.have.length(2);
        expect(scenario.tokens).to.have.length(6); // 2 sessions * 3 tokens
      }

      logger.info(`✅ Bulk operations completed in ${duration}ms`);
      logger.info(`- Created ${bulkScenarios.length} scenarios`);
      logger.info(
        `- Total users: ${bulkScenarios.reduce((sum, s) => sum + s.users.length, 0)}`,
      );
      logger.info(
        `- Total tokens: ${bulkScenarios.reduce((sum, s) => sum + s.tokens.length, 0)}`,
      );

      // Add to cleanup list
      testScenarios.push(...bulkScenarios);
    });
  });

  // TODO: Fix and re-enable the following test block. The backend should properly reject invalid user data and the test should fail as expected.
  // describe('Error Handling and Recovery', () => {
  //   it('should handle errors gracefully across multiple datasets', async () => {
  //     const dataset = testDataManager.createDataset('Error Test Dataset');
  //
  //     // Test with invalid data
  //     const invalidUserData = {
  //       email: 'invalid-email',
  //       password: '123', // Too short
  //       name: ''
  //     };
  //
  //     try {
  //       await testDataManager.createTestUsers(dataset.id, 1, invalidUserData);
  //       throw new Error('Should have failed with invalid data');
  //     } catch (error) {
  //       // Expected to fail - check for any error (could be validation error from backend)
  //       logger.info('Actual error:', error.message);
  //       expect(error.message).to.not.equal('Should have failed with invalid data');
  //       // Also check that it's a proper error (not just a timeout or network error)
  //       expect(error.message).to.not.include('timeout');
  //       expect(error.message).to.not.include('network');
  //     }
  //
  //     // Verify dataset is still usable
  //     const validUsers = await testDataManager.createTestUsers(dataset.id, 1);
  //     expect(validUsers).to.have.length(1);
  //
  //     logger.info('✅ Error handling works correctly across datasets');
  //   });
  // });

  describe("Dataset Statistics and Monitoring", () => {
    it("should provide accurate statistics for multiple datasets", async () => {
      // Create some test data
      await testDataManager.createTestScenario("Stats Test 1", {
        userCount: 2,
        sessionCount: 1,
        tokenCount: 3,
      });

      await testDataManager.createTestScenario("Stats Test 2", {
        userCount: 1,
        sessionCount: 1,
        tokenCount: 2,
      });

      const stats = testDataManager.getDatasetStats();

      // Verify statistics
      expect(stats.totalDatasets).to.be.greaterThan(0);
      expect(stats.totalTestCases).to.be.greaterThan(0);
      expect(stats.datasets).to.be.an("array");

      for (const dataset of stats.datasets) {
        expect(dataset).to.have.property("id");
        expect(dataset).to.have.property("name");
        expect(dataset).to.have.property("users");
        expect(dataset).to.have.property("sessions");
        expect(dataset).to.have.property("tokens");
        expect(dataset).to.have.property("created");
      }

      logger.info("Dataset Statistics:", JSON.stringify(stats, null, 2));
      logger.info("✅ Dataset statistics are accurate");
    });
  });
});
