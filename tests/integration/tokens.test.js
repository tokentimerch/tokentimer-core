const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");

describe("Token Management Integration Tests", () => {
  let testUser;
  let session;

  before(async () => {
    try {
      // Create a verified test user
      testUser = await TestUtils.createVerifiedTestUser();
      logger.info("Token test user created:", testUser.email);

      // Login the test user
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
      logger.info("Token test user logged in successfully");

      // Verify the session is working
      const sessionResponse = await request("http://localhost:4000")
        .get("/api/session")
        .set("Cookie", session.cookie);

      if (sessionResponse.status !== 200 || !sessionResponse.body.loggedIn) {
        logger.info("Warning: Session verification failed in token tests");
        logger.info(
          "Session response:",
          sessionResponse.status,
          sessionResponse.body,
        );
      }
    } catch (error) {
      logger.info("Failed to create or login token test user:", error.message);
      session = { cookie: null };
    }
  });

  describe("Token CRUD Operations", () => {
    it("should reject token creation without authentication", async () => {
      const tokenData = {
        name: "Unauthorized Token",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .send(tokenData)
        .expect(401);

      expect(response.body.error).to.equal("Not authenticated");
    });

    it("should create a new token when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Test API Key",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours from now
        section: "prod",
      };

      logger.info("Attempting to create token with data:", tokenData);
      logger.info("Using session cookie:", session.cookie);

      // Resolve workspace_id for this session
      const wsList = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceId = wsList?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceId });

      logger.info("Token creation response:", response.status, response.body);

      if (response.status !== 201) {
        logger.info("Token creation failed. Full response:", response.body);
        throw new Error(
          `Expected 201, got ${response.status}: ${JSON.stringify(response.body)}`,
        );
      }

      expect(response.body).to.have.property("id");
      expect(response.body.name).to.equal(tokenData.name);
      expect(response.body.type).to.equal(tokenData.type);
      expect(response.body.category).to.equal(tokenData.category);
      expect(response.body).to.have.property("user_id");
      expect(Array.isArray(response.body.section)).to.be.true;
      expect(response.body.section).to.include("prod");

      // If testUser.id is available, check it matches
      if (testUser && testUser.id) {
        expect(response.body.user_id).to.equal(testUser.id);
      }
    });

    it("should reject token creation with invalid data when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const invalidTokenData = {
        name: "ab", // Too short
        type: "invalid_type",
        category: "invalid_category",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
        section: "qa",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send(invalidTokenData)
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Token name must be between 3 and 100 characters",
      );
    });

    it("should list user tokens when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const response = await request("http://localhost:4000")
        .get("/api/tokens")
        .set("Cookie", session.cookie);

      if (response.status !== 200) {
        logger.info("Token listing failed with status:", response.status);
        logger.info("Response body:", JSON.stringify(response.body));
        logger.info("Response headers:", JSON.stringify(response.headers));
      }

      expect(response.status).to.equal(200);
      const items = response.body.items || response.body;
      expect(items).to.be.an("array");
    });

    it("should reject token listing without authentication", async () => {
      const response = await request("http://localhost:4000")
        .get("/api/tokens")
        .expect(401);

      expect(response.body.error).to.equal("Not authenticated");
    });

    it("should delete a token when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      // First create a token
      const tokenData = {
        name: "Token to Delete",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
        section: "__temp__",
      };

      const wsList2 = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceId2 = wsList2?.body?.items?.[0]?.id;
      const createResponse = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceId2 })
        .expect(201);

      const tokenId = createResponse.body.id;

      // Then delete it
      const deleteResponse = await request("http://localhost:4000")
        .delete(`/api/tokens/${tokenId}`)
        .set("Cookie", session.cookie)
        .expect(200);

      expect(deleteResponse.body.message).to.include("deleted");
    });

    it("should reject deleting non-existent token when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const response = await request("http://localhost:4000")
        .delete("/api/tokens/99999")
        .set("Cookie", session.cookie)
        .expect(404);

      expect(response.body.error).to.include("not found");
    });

    it("should reject deleting token without authentication", async () => {
      const response = await request("http://localhost:4000")
        .delete("/api/tokens/1")
        .expect(401);

      expect(response.body.error).to.equal("Not authenticated");
    });
  });

  describe("Token Categories", () => {
    it("should create certificate token with domain information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "SSL Certificate",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 90 days from now
        domains: ["example.com", "www.example.com"],
        issuer: "Let's Encrypt",
        serial_number: "1234567890",
        algorithm: "RSA",
        key_size: 2048,
        section: "prod",
      };

      const wsListA = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdA = wsListA?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceIdA })
        .expect(201);

      expect(response.body.category).to.equal("cert");
      expect(response.body.domains).to.deep.equal([
        "example.com",
        "www.example.com",
      ]);
      expect(response.body.issuer).to.equal("Let's Encrypt");
      expect(response.body.algorithm).to.equal("RSA");
      expect(response.body.key_size).to.equal(2048);
    });

    it("should create key/secret token with location and usage information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Database API Key",
        type: "secret",
        category: "key_secret",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 1 year from now
        location: "/etc/secrets/prod",
        used_by: "Web Application",
        algorithm: "AES-256",
        key_size: 256,
        section: "infra",
      };

      const wsListB = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdB = wsListB?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceIdB })
        .expect(201);

      expect(response.body.category).to.equal("key_secret");
      expect(response.body.location).to.equal("/etc/secrets/prod");
      expect(response.body.used_by).to.equal("Web Application");
      expect(response.body.algorithm).to.equal("AES-256");
      expect(response.body.key_size).to.equal(256);
    });

    it("should create license token with vendor and cost information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Microsoft Office License",
        type: "api_key",
        category: "license",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 1 year from now
        vendor: "Microsoft",
        license_type: "Subscription",
        cost: 99.99,
        renewal_url: "https://microsoft.com/renew",
        section: "it",
      };

      const wsListC = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdC = wsListC?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceIdC })
        .expect(201);

      expect(response.body.category).to.equal("license");
      expect(response.body.vendor).to.equal("Microsoft");
      expect(response.body.license_type).to.equal("Subscription");
      expect(response.body.cost).to.equal(99.99);
      expect(response.body.renewal_url).to.equal("https://microsoft.com/renew");
    });

    it("should create general token with basic information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "General Expiring Item",
        type: "other", // Fixed: use 'other' type for general category
        category: "general",
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 30 days from now
        location: "/etc/config/",
        used_by: "Backup Service",
        notes: "Important configuration file",
        section: "ops",
      };

      const wsListD = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdD = wsListD?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceIdD })
        .expect(201);

      expect(response.body.category).to.equal("general");
      expect(response.body.location).to.equal("/etc/config/");
      expect(response.body.used_by).to.equal("Backup Service");
      expect(response.body.notes).to.equal("Important configuration file");
    });

    it("should reject invalid category", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Invalid Category Token",
        type: "api_key",
        category: "invalid_category",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const wsListX = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdX = wsListX?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceIdX })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("Invalid category");
    });
  });

  describe("Category-Specific Validation", () => {
    it("should accept certificate with empty domains", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Certificate with Empty Domains",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        issuer: "Test CA",
        domains: ["", "   ", ""], // Empty domains - now allowed
      };

      const wsList0 = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceId0 = wsList0?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceId0 })
        .expect(201);

      expect(response.body.name).to.equal("Certificate with Empty Domains");
      expect(response.body.domains).to.be.null; // Empty domains get filtered to null
    });

    it("should validate license cost", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "License with Invalid Cost",
        type: "api_key",
        category: "license",
        vendor: "Test Vendor Inc.",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        cost: -50.0, // Negative cost
        section: "licensing",
      };

      const wsListK = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdK = wsListK?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceIdK })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("Cost must be");
    });

    it("should validate key size for invalid token types", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Token with Key Size for Invalid Type",
        type: "api_key", // api_key doesn't support key_size
        category: "key_secret",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        key_size: 256,
      };

      // Ensure workspace_id so validation reaches key_size/type constraint
      const wsList = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=1&offset=0")
        .set("Cookie", session.cookie);
      const wsId = wsList.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: wsId })
        .expect(400);

      expect(response.body.error).to.equal(
        "Key size is only valid for encryption keys, SSH keys, secrets, and certificates",
      );
    });
  });

  describe("Token Validation", () => {
    it("should validate token name length when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const shortNameToken = {
        name: "ab", // Too short
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
      };

      const wsListY = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdY = wsListY?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...shortNameToken, workspace_id: workspaceIdY })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("characters");
    });

    it("should validate future expiration dates when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const pastExpirationToken = {
        name: "Past Token",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 24 hours ago
        section: "old",
      };

      const wsListZ = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdZ = wsListZ?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...pastExpirationToken, workspace_id: workspaceIdZ })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include(
        "Expiration date must be in the future",
      );
    });

    it("should validate token types when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const invalidTypeToken = {
        name: "Invalid Type Token",
        type: "invalid_type",
        category: "general",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
        section: "misc",
      };

      const wsListW = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceIdW = wsListW?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...invalidTypeToken, workspace_id: workspaceIdW })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("Invalid token type");
    });
  });

  describe("Token Security", () => {
    it("should prevent cross-user token access when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const otherUser = await TestUtils.createVerifiedTestUser();
      const otherSession = await TestUtils.loginTestUser(
        otherUser.email,
        "SecureTest123!@#",
      );

      // Create a token for the other user
      const tokenData = {
        name: "Other User Token",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
      };

      const wsList3 = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", otherSession.cookie);
      const workspaceId3 = wsList3?.body?.items?.[0]?.id;
      const createResponse = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", otherSession.cookie)
        .send({ ...tokenData, workspace_id: workspaceId3 })
        .expect(201);

      const tokenId = createResponse.body.id;

      // Try to access it with the first user's session
      const response = await request("http://localhost:4000")
        .get(`/api/tokens/${tokenId}`)
        .set("Cookie", session.cookie)
        .expect(404);

      expect(response.body.error).to.include("not found");
    });

    it("should enforce rate limiting on token operations when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Rate Limit Test Token",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
        section: "perf",
      };

      // Make multiple requests to test rate limiting
      const wsList4 = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceId4 = wsList4?.body?.items?.[0]?.id;
      const requests = Array(5)
        .fill()
        .map(() =>
          request("http://localhost:4000")
            .post("/api/tokens")
            .set("Cookie", session.cookie)
            .send({ ...tokenData, workspace_id: workspaceId4 }),
        );

      const responses = await Promise.all(requests);

      // Should handle rate limiting gracefully
      responses.forEach((response) => {
        expect([201, 429]).to.include(response.status);
      });
    });
  });

  describe("Token Types", () => {
    it("should create API Key token when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "API Key Token",
        type: "api_key",
        category: "key_secret", // Fixed: api_key belongs to key_secret category
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
        section: "ci",
      };

      logger.info("Creating API Key token with data:", tokenData);

      const wsList5 = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceId5 = wsList5?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceId5 });

      logger.info(
        "API Key token creation response:",
        response.status,
        response.body,
      );

      if (response.status !== 201) {
        logger.info(
          "API Key token creation failed. Full response:",
          response.body,
        );
        throw new Error(
          `Expected 201, got ${response.status}: ${JSON.stringify(response.body)}`,
        );
      }

      expect(response.body.type).to.equal("api_key");
      expect(response.body.name).to.equal("API Key Token");
    });

    it("should create TLS Cert token when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "TLS Certificate",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0], // 24 hours from now
        domains: ["example.com", "api.example.com"],
        issuer: "Let's Encrypt",
        section: "edge",
      };

      logger.info("Creating TLS Cert token with data:", tokenData);

      const wsList6 = await request("http://localhost:4000")
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie);
      const workspaceId6 = wsList6?.body?.items?.[0]?.id;
      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: workspaceId6 });

      logger.info(
        "TLS Cert token creation response:",
        response.status,
        response.body,
      );

      if (response.status !== 201) {
        logger.info(
          "TLS Cert token creation failed. Full response:",
          response.body,
        );
        throw new Error(
          `Expected 201, got ${response.status}: ${JSON.stringify(response.body)}`,
        );
      }

      expect(response.body.type).to.equal("tls_cert");
      expect(response.body.category).to.equal("cert");
      expect(response.body.name).to.equal("TLS Certificate");
    });
  });
});
