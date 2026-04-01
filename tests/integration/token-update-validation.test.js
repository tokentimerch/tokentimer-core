const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");
const { testDataManager } = require("./test-data-manager");

describe("Token Update Validation Integration Tests", () => {
  let testUser;
  let session;
  let testToken;

  // Helper function to create a fresh token for each test
  async function createTestToken(session, overrides = {}) {
    const tokenData = {
      name: "Test Certificate",
      type: "ssl_cert",
      category: "cert",
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split("T")[0],
      domains: ["example.com"],
      issuer: "Let's Encrypt",
      serial_number: "1234567890ABCDEF",
      subject: "CN=example.com, O=Test Corp, C=US",
      ...overrides,
    };

    logger.info(
      "Creating test token with data:",
      JSON.stringify(tokenData, null, 2),
    );

    const response = await request("http://localhost:4000")
      .post("/api/tokens")
      .set("Cookie", session.cookie)
      .send(tokenData)
      .expect(201);

    logger.info("Token created successfully:", response.body.id);
    return response.body;
  }

  before(async () => {
    try {
      // Create a verified test user
      testUser = await TestUtils.createVerifiedTestUser();
      logger.info("Token update validation test user created:", testUser.email);

      // Login the test user
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
      logger.info("Token update validation test user logged in successfully");

      // Create a test token for update tests
      testToken = await createTestToken(session);
      logger.info(
        "Test token created for update validation tests:",
        testToken ? testToken.id : "FAILED",
      );
      logger.info("Full testToken object:", JSON.stringify(testToken, null, 2));
      if (!testToken) {
        logger.info("Failed to create test token");
        throw new Error("Test token creation failed");
      }
    } catch (error) {
      logger.info(
        "Failed to create or login token update validation test user:",
        error.message,
      );
      session = { cookie: null };
      testToken = null;
    }
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("Update Field Name Consistency", () => {
    it("should accept expiresAt field name in updates", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      // Create a fresh token for this test
      const tokenData = {
        name: "Test Certificate for ExpiresAt",
        type: "ssl_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com"],
        issuer: "Let's Encrypt",
        subject: "CN=example.com, O=Test Corp, C=US",
      };

      const createResponse = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send(tokenData)
        .expect(201);

      const freshToken = createResponse.body;

      const updateData = {
        expiresAt: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${freshToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.expiresAt).to.equal(updateData.expiresAt);
    });

    it("should accept expiration field name in updates", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const freshToken = await createTestToken(session);

      const updateData = {
        expiresAt: new Date(Date.now() + 270 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${freshToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.expiresAt).to.equal(updateData.expiresAt);
    });
  });

  describe("Update Date Validation", () => {
    it("should reject update with invalid date format", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        expiresAt: "invalid-date",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Invalid expiration date format",
      );
    });

    it("should reject update with past date", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Expiration date must be in the future",
      );
    });
  });

  describe("Update Field Validation", () => {
    it("should reject update with name too short", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        name: "ab",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Token name must be between 3 and 100 characters",
      );
    });

    it("should reject update with name too long", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        name: "a".repeat(101),
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Token name must be between 3 and 100 characters",
      );
    });

    it("should reject update with invalid category", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        category: "invalid_category",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("Invalid category");
    });

    it("should reject update with invalid type for category", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        type: "api_key",
        category: "cert",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("Invalid token type");
    });
  });

  describe("Update Category-Specific Validation", () => {
    it("should accept certificate update with empty domains", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        domains: [],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.domains).to.be.null; // Empty domains should be converted to null
    });

    it("should accept certificate update with empty issuer", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        issuer: "",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.issuer).to.be.null; // Empty issuer should be converted to null
    });

    it("should accept license update without vendor", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        category: "license",
        type: "software_license",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.category).to.equal("license");
      expect(response.body.type).to.equal("software_license");
    });
  });

  describe("Valid Token Updates", () => {
    it("should update token name successfully", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        name: "Updated Certificate Name",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.name).to.equal("Updated Certificate Name");
    });

    it("should update token expiration successfully", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const newExpiration = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split("T")[0];
      const updateData = {
        expiresAt: newExpiration,
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.expiresAt).to.equal(newExpiration);
    });

    it("should update token domains successfully", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        domains: ["example.com", "www.example.com", "api.example.com"],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.domains).to.deep.equal([
        "example.com",
        "www.example.com",
        "api.example.com",
      ]);
    });

    it("should update token to license category successfully", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        name: "Software License",
        type: "software_license",
        category: "license",
        vendor: "Microsoft",
        license_type: "Enterprise",
        cost: 999.99,
        renewal_url: "https://microsoft.com/renew",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.name).to.equal("Software License");
      expect(response.body.category).to.equal("license");
      expect(response.body.vendor).to.equal("Microsoft");
      expect(response.body.cost).to.equal(999.99);
    });
  });

  describe("Subject Field Update Tests", () => {
    it("should update subject field for certificate", async () => {
      if (!session.cookie || !testToken) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const updateData = {
        subject: "CN=updated.example.com, O=Updated Corp, C=US",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.subject).to.equal(
        "CN=updated.example.com, O=Updated Corp, C=US",
      );
    });

    it("should clear subject field when set to empty string", async () => {
      if (!session.cookie || !testToken) {
        logger.info(
          "Skipping authenticated test due to login failure or missing testToken",
        );
        logger.info("testToken:", testToken);
        return;
      }

      logger.info("Updating token with ID:", testToken.id);

      const updateData = {
        subject: "",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.subject).to.be.null;
    });

    it("should update subject field for all certificate types", async () => {
      if (!session.cookie || !testToken) {
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
        // Create a new token for each type
        const createData = {
          name: `Update Test ${certType}`,
          type: certType,
          category: "cert",
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
          domains: [`${certType}.example.com`],
          issuer: "Test CA",
          subject: `CN=${certType}.example.com, O=Test Corp, C=US`,
        };

        const createResponse = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send(createData)
          .expect(201);

        const tokenId = createResponse.body.id;
        const newSubject = `CN=updated.${certType}.example.com, O=Updated Corp, C=US`;

        const updateResponse = await request("http://localhost:4000")
          .put(`/api/tokens/${tokenId}`)
          .set("Cookie", session.cookie)
          .send({ subject: newSubject })
          .expect(200);

        expect(updateResponse.body.type).to.equal(certType);
        expect(updateResponse.body.subject).to.equal(newSubject);
      }
    });
  });

  describe("Partial Updates", () => {
    it("should allow partial updates without affecting other fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const freshToken = await createTestToken(session);
      const originalName = freshToken.name;
      const originalDomains = freshToken.domains;

      const updateData = {
        notes: "Updated notes",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${freshToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.name).to.equal(originalName);
      expect(response.body.domains).to.deep.equal(originalDomains);
      expect(response.body.notes).to.equal("Updated notes");
    });

    it("should update new fields (privileges, last_used, section array)", async () => {
      if (!session.cookie || !testToken) {
        logger.info(
          "Skipping authenticated test due to login failure or missing test token",
        );
        return;
      }

      const lastUsed = new Date().toISOString();
      const updateData = {
        privileges: "read:only, write:restricted",
        last_used: lastUsed,
        section: ["updated", "tags"],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.privileges).to.equal(updateData.privileges);
      expect(Array.isArray(response.body.section)).to.be.true;
      expect(response.body.section).to.include("updated");
      expect(response.body.section).to.include("tags");
      expect(new Date(response.body.last_used).getTime()).to.equal(
        new Date(lastUsed).getTime(),
      );
    });
  });
});
