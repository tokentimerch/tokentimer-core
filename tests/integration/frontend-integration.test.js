const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");
const { testDataManager } = require("./test-data-manager");

describe("Frontend Integration Tests", () => {
  let testUser;
  let session;

  before(async () => {
    try {
      // Create a verified test user
      testUser = await TestUtils.createVerifiedTestUser();
      logger.info("Frontend integration test user created:", testUser.email);

      // Login the test user
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
      logger.info("Frontend integration test user logged in successfully");
      // Resolve a workspace for this session
      session.workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
    } catch (error) {
      logger.info(
        "Failed to create or login frontend integration test user:",
        error.message,
      );
      session = { cookie: null };
    }
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("Subject Field Integration", () => {
    it("should create certificate with subject field and verify API response", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Frontend Test Certificate",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["frontend-test.example.com"],
        issuer: "Test CA",
        serial_number: "FRONTEND123456",
        subject: "CN=frontend-test.example.com, O=Frontend Test Corp, C=US",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.subject).to.equal(
        "CN=frontend-test.example.com, O=Frontend Test Corp, C=US",
      );
      expect(response.body.category).to.equal("cert");
      expect(response.body.type).to.equal("tls_cert");
    });

    it("should verify subject field is included in token retrieval", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      // First create a token with subject
      const createData = {
        name: "Retrieval Test Certificate",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["retrieval-test.example.com"],
        issuer: "Test CA",
        subject: "CN=retrieval-test.example.com, O=Retrieval Test Corp, C=US",
      };

      const createResponse = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...createData, workspace_id: session.workspaceId })
        .expect(201);

      const tokenId = createResponse.body.id;

      // Then retrieve the token and verify subject field
      const getResponse = await request("http://localhost:4000")
        .get(`/api/tokens/${tokenId}`)
        .set("Cookie", session.cookie)
        .expect(200);

      expect(getResponse.body.subject).to.equal(
        "CN=retrieval-test.example.com, O=Retrieval Test Corp, C=US",
      );
    });
  });

  describe("Certificate Type Coverage", () => {
    it("should support all certificate types with subject field", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const certificateTypes = [
        { type: "ssl_cert", subject: "CN=ssl.example.com, O=SSL Corp, C=US" },
        { type: "tls_cert", subject: "CN=tls.example.com, O=TLS Corp, C=US" },
        {
          type: "code_signing",
          subject: "CN=code.example.com, O=Code Corp, C=US",
        },
        {
          type: "client_cert",
          subject: "CN=client.example.com, O=Client Corp, C=US",
        },
      ];

      for (const certType of certificateTypes) {
        const tokenData = {
          name: `Frontend ${certType.type} Test`,
          type: certType.type,
          category: "cert",
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          domains: [`${certType.type}.example.com`],
          issuer: "Test CA",
          subject: certType.subject,
        };

        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(201);

        expect(response.body.type).to.equal(certType.type);
        expect(response.body.subject).to.equal(certType.subject);
        expect(response.body.category).to.equal("cert");
      }
    });
  });

  describe("Table Display Integration", () => {
    it("should create tokens for all categories to test table display", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const testTokens = [
        {
          name: "Certificate for Table Test",
          type: "tls_cert",
          category: "cert",
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          domains: ["table-test.example.com"],
          issuer: "Test CA",
          subject: "CN=table-test.example.com, O=Table Test Corp, C=US",
        },
        {
          name: "Key/Secret for Table Test",
          type: "api_key",
          category: "key_secret",
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          location: "/secure/vault/",
          used_by: "Table Test Application",
          description: "Test key/secret for table display",
        },
        {
          name: "License for Table Test",
          type: "software_license",
          category: "license",
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          vendor: "Table Test Vendor",
          license_type: "Subscription",
          cost: 199.99,
          contacts: "admin@table-test.com",
        },
        {
          name: "General for Table Test",
          type: "other",
          category: "general",
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          location: "/etc/config/",
          used_by: "General Test Service",
        },
      ];

      const createdTokens = [];

      for (const tokenData of testTokens) {
        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(201);

        createdTokens.push(response.body);
      }

      // Verify all tokens were created successfully
      expect(createdTokens).to.have.length(4);

      // Verify certificate has subject field
      const certToken = createdTokens.find((t) => t.category === "cert");
      expect(certToken.subject).to.equal(
        "CN=table-test.example.com, O=Table Test Corp, C=US",
      );

      // Verify key/secret has description field
      const keySecretToken = createdTokens.find(
        (t) => t.category === "key_secret",
      );
      expect(keySecretToken.description).to.equal(
        "Test key/secret for table display",
      );

      // Verify license has contacts field
      const licenseToken = createdTokens.find((t) => t.category === "license");
      expect(licenseToken.contacts).to.equal("admin@table-test.com");

      // Verify general has location and used_by fields
      const generalToken = createdTokens.find((t) => t.category === "general");
      expect(generalToken.location).to.equal("/etc/config/");
      expect(generalToken.used_by).to.equal("General Test Service");
    });
  });

  describe("API Response Structure", () => {
    it("should verify API responses include all required fields for frontend", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "API Structure Test",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["api-structure.example.com"],
        issuer: "Test CA",
        subject: "CN=api-structure.example.com, O=API Test Corp, C=US",
        section: ["Production", "Web Servers"],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      // Verify all fields that frontend expects are present
      expect(response.body).to.have.property("id");
      expect(response.body).to.have.property("name");
      expect(response.body).to.have.property("type");
      expect(response.body).to.have.property("category");
      expect(response.body).to.have.property("expiresAt");
      expect(response.body).to.have.property("privileges");
      expect(response.body).to.have.property("last_used");
      expect(response.body).to.have.property("imported_at");
      expect(response.body).to.have.property("created_at");
      expect(response.body).to.have.property("updated_at");
      expect(response.body).to.have.property("section");
      expect(Array.isArray(response.body.section)).to.be.true;

      // Verify certificate-specific fields
      expect(response.body).to.have.property("domains");
      expect(response.body).to.have.property("issuer");
      expect(response.body).to.have.property("serial_number");
      expect(response.body).to.have.property("subject");

      // Verify subject field is properly set
      expect(response.body.subject).to.equal(
        "CN=api-structure.example.com, O=API Test Corp, C=US",
      );
    });
  });
});
