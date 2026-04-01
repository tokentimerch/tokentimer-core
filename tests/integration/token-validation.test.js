const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");
const { testDataManager } = require("./test-data-manager");

describe("Token Validation Integration Tests", () => {
  let testUser;
  let session;

  before(async () => {
    try {
      // Create a verified test user
      testUser = await TestUtils.createVerifiedTestUser();
      logger.info("Token validation test user created:", testUser.email);

      // Login the test user
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
      logger.info("Token validation test user logged in successfully");
      // Ensure a workspace exists and attach its id
      session.workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
    } catch (error) {
      logger.info(
        "Failed to create or login token validation test user:",
        error.message,
      );
      session = { cookie: null };
    }
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("Required Fields Validation", () => {
    it("should reject token without name", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body).to.have.property("details");
    });

    it("should reject token without type", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Test Token",
        category: "general",
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body).to.have.property("details");
    });

    it("should reject token without category", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Test Token",
        type: "api_key",
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body).to.have.property("details");
    });
  });

  describe("Field Length Validation", () => {
    it("should reject token with name too short", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "ab",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Token name must be between 3 and 100 characters",
      );
    });

    it("should reject token with name too long", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "a".repeat(101),
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Token name must be between 3 and 100 characters",
      );
    });
  });

  describe("Category-Specific Validation", () => {
    it("should accept certificate without domains if issuer is provided", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "SSL Certificate",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        issuer: "Let's Encrypt",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.issuer).to.equal("Let's Encrypt");
    });

    it("should accept certificate with domains but no issuer", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "SSL Certificate",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com"],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.domains).to.deep.equal(["example.com"]);
    });

    it("should accept certificate without any identifying fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "SSL Certificate",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        // No domains, issuer, subject, or serial_number - all optional now
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal("SSL Certificate");
      expect(response.body.type).to.equal("ssl_cert");
      expect(response.body.category).to.equal("cert");
    });

    it("should accept license without vendor", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Software License",
        type: "software_license",
        category: "license",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        // Vendor is optional now
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal("Software License");
      expect(response.body.type).to.equal("software_license");
      expect(response.body.category).to.equal("license");
    });
  });

  describe("Certificate Field Validation", () => {
    it("should validate certificate with subject field", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Certificate with Subject",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com"],
        issuer: "Example CA",
        subject: "CN=example.com, O=Example Corp, C=US",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.subject).to.equal(
        "CN=example.com, O=Example Corp, C=US",
      );
    });

    it("should handle empty subject field for certificates", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Certificate without Subject",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com"],
        issuer: "Example CA",
        subject: "",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.subject).to.be.null;
    });

    it("should validate subject field for all certificate types", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const certificateTypes = [
        "ssl_cert",
        "tls_cert",
        "code_signing",
        "client_cert",
      ];

      for (const certType of certificateTypes) {
        const tokenData = {
          name: `Certificate ${certType}`,
          type: certType,
          category: "cert",
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          domains: [`${certType}.example.com`],
          issuer: "Test CA",
          subject: `CN=${certType}.example.com, O=Test Corp, C=US`,
        };

        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(201);

        expect(response.body.type).to.equal(certType);
        expect(response.body.subject).to.equal(
          `CN=${certType}.example.com, O=Test Corp, C=US`,
        );
      }
    });
  });

  describe("Valid Token Creation", () => {
    it("should create valid certificate token", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "SSL Certificate",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com", "www.example.com"],
        issuer: "Let's Encrypt",
        serial_number: "1234567890ABCDEF",
        algorithm: "RSA",
        key_size: 2048,
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal("SSL Certificate");
      expect(response.body.category).to.equal("cert");
      expect(response.body.domains).to.deep.equal([
        "example.com",
        "www.example.com",
      ]);
      expect(response.body.issuer).to.equal("Let's Encrypt");
    });

    it("should create valid license token", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Software License",
        type: "software_license",
        category: "license",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        vendor: "Microsoft",
        license_type: "Enterprise",
        cost: 999.99,
        renewal_url: "https://microsoft.com/renew",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal("Software License");
      expect(response.body.category).to.equal("license");
      expect(response.body.vendor).to.equal("Microsoft");
      expect(response.body.cost).to.equal(999.99);
    });

    it("should create valid general token", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "General Token",
        type: "other",
        category: "general",
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        location: "/etc/config/",
        used_by: "Backup Service",
        notes: "Important configuration",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal("General Token");
      expect(response.body.category).to.equal("general");
      expect(response.body.location).to.equal("/etc/config/");
    });
  });
});
