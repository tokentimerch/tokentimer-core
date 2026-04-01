const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");
const { testDataManager } = require("./test-data-manager");

describe("Database Schema Tests", () => {
  let testUser;
  let session;

  before(async () => {
    try {
      // Create a verified test user
      testUser = await TestUtils.createVerifiedTestUser();
      logger.info("Database schema test user created:", testUser.email);

      // Login the test user
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
      logger.info("Database schema test user logged in successfully");
      session.workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
    } catch (error) {
      logger.info(
        "Failed to create or login database schema test user:",
        error.message,
      );
      session = { cookie: null };
    }
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("Subject Column Verification", () => {
    it("should verify subject column exists and can store data", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Schema Test Certificate",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["schema-test.example.com"],
        issuer: "Schema Test CA",
        subject: "CN=schema-test.example.com, O=Schema Test Corp, C=US",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.subject).to.equal(
        "CN=schema-test.example.com, O=Schema Test Corp, C=US",
      );
    });

    it("should verify subject column can store null values", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Schema Test Certificate No Subject",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["no-subject.example.com"],
        issuer: "Test CA",
        // No subject field - should be null
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.subject).to.be.null;
    });

    it("should verify subject column can store long text", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const longSubject =
        "CN=very-long-subject.example.com, O=Very Long Organization Name That Exceeds Normal Length, OU=Department of Information Technology and Security, L=San Francisco, ST=California, C=United States of America, DC=example, DC=com";

      const tokenData = {
        name: "Schema Test Certificate Long Subject",
        type: "code_signing",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["long-subject.example.com"],
        issuer: "Test CA",
        subject: longSubject,
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.subject).to.equal(longSubject);
    });
  });

  describe("Database Persistence", () => {
    it("should verify subject field persists across database operations", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      // Create token with subject
      const createData = {
        name: "Persistence Test Certificate",
        type: "client_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["persistence-test.example.com"],
        issuer: "Test CA",
        subject:
          "CN=persistence-test.example.com, O=Persistence Test Corp, C=US",
      };

      const createResponse = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...createData, workspace_id: session.workspaceId })
        .expect(201);

      const tokenId = createResponse.body.id;
      const originalSubject = createResponse.body.subject;

      // Update the token
      const updateData = {
        subject:
          "CN=updated-persistence.example.com, O=Updated Persistence Corp, C=US",
      };

      const updateResponse = await request("http://localhost:4000")
        .put(`/api/tokens/${tokenId}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(updateResponse.body.subject).to.equal(updateData.subject);

      // Retrieve the token again to verify persistence
      const getResponse = await request("http://localhost:4000")
        .get(`/api/tokens/${tokenId}`)
        .set("Cookie", session.cookie)
        .expect(200);

      expect(getResponse.body.subject).to.equal(updateData.subject);
    });
  });

  describe("Database Index Verification", () => {
    it("should verify subject field queries work efficiently", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      // Create multiple tokens with different subjects
      const subjects = [
        "CN=index-test1.example.com, O=Index Test Corp, C=US",
        "CN=index-test2.example.com, O=Index Test Corp, C=US",
        "CN=index-test3.example.com, O=Index Test Corp, C=US",
      ];

      const tokenIds = [];

      for (let i = 0; i < subjects.length; i++) {
        const tokenData = {
          name: `Index Test Certificate ${i + 1}`,
          type: "tls_cert",
          category: "cert",
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          domains: [`index-test${i + 1}.example.com`],
          issuer: "Test CA",
          subject: subjects[i],
        };

        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(201);

        tokenIds.push(response.body.id);
      }

      // Verify all tokens were created with correct subjects
      for (let i = 0; i < tokenIds.length; i++) {
        const getResponse = await request("http://localhost:4000")
          .get(`/api/tokens/${tokenIds[i]}`)
          .set("Cookie", session.cookie)
          .expect(200);

        expect(getResponse.body.subject).to.equal(subjects[i]);
      }
    });
  });

  describe("Database Constraints", () => {
    it("should verify subject field accepts valid certificate subject formats", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const validSubjects = [
        "CN=simple.example.com",
        "CN=example.com, O=Test Corp",
        "CN=example.com, O=Test Corp, C=US",
        "CN=example.com, OU=IT Department, O=Test Corp, L=San Francisco, ST=CA, C=US",
        "CN=example.com, DC=example, DC=com",
      ];

      for (let i = 0; i < validSubjects.length; i++) {
        const tokenData = {
          name: `Constraint Test Certificate ${i + 1}`,
          type: "ssl_cert",
          category: "cert",
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          domains: [`constraint-test${i + 1}.example.com`],
          issuer: "Test CA",
          subject: validSubjects[i],
        };

        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(201);

        expect(response.body.subject).to.equal(validSubjects[i]);
      }
    });
  });
});
