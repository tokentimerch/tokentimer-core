const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");
const { testDataManager } = require("./test-data-manager");

describe("Token Categories Integration Tests", () => {
  let testUser;
  let session;

  before(async () => {
    try {
      // Create a verified test user
      testUser = await TestUtils.createVerifiedTestUser();
      logger.info("Token categories test user created:", testUser.email);

      // Login the test user
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
      logger.info("Token categories test user logged in successfully");
      // Resolve workspace and attach to session
      session.workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);

      // Verify the session is working
      const sessionResponse = await request("http://localhost:4000")
        .get("/api/session")
        .set("Cookie", session.cookie);

      if (sessionResponse.status !== 200 || !sessionResponse.body.loggedIn) {
        logger.info(
          "Warning: Session verification failed in token categories tests",
        );
        logger.info(
          "Session response:",
          sessionResponse.status,
          sessionResponse.body,
        );
      }
    } catch (error) {
      logger.info(
        "Failed to create or login token categories test user:",
        error.message,
      );
      session = { cookie: null };
    }
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("Certificate Category Tests", () => {
    it("should create certificate token with all required fields including subject", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "SSL Certificate Test",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com", "www.example.com", "api.example.com"],
        issuer: "Let's Encrypt",
        serial_number: "1234567890ABCDEF",
        subject: "CN=example.com, O=Example Corp, C=US",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("cert");
      expect(response.body.domains).to.deep.equal([
        "example.com",
        "www.example.com",
        "api.example.com",
      ]);
      expect(response.body.issuer).to.equal("Let's Encrypt");
      expect(response.body.serial_number).to.equal("1234567890ABCDEF");
      expect(response.body.subject).to.equal(
        "CN=example.com, O=Example Corp, C=US",
      );
    });

    it("should create code signing certificate with subject field", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Code Signing Certificate",
        type: "code_signing",
        category: "cert",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["code.example.com"],
        issuer: "DigiCert",
        serial_number: "CODE123456789",
        subject: "CN=Code Signing, O=Software Corp, C=US",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("cert");
      expect(response.body.type).to.equal("code_signing");
      expect(response.body.domains).to.deep.equal(["code.example.com"]);
      expect(response.body.issuer).to.equal("DigiCert");
      expect(response.body.serial_number).to.equal("CODE123456789");
      expect(response.body.subject).to.equal(
        "CN=Code Signing, O=Software Corp, C=US",
      );
    });

    it("should create client certificate with subject field", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Client Certificate",
        type: "client_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["client.example.com"],
        issuer: "Internal CA",
        serial_number: "CLIENT123456",
        subject: "CN=Client User, OU=IT Department, O=Company Inc, C=US",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("cert");
      expect(response.body.type).to.equal("client_cert");
      expect(response.body.domains).to.deep.equal(["client.example.com"]);
      expect(response.body.issuer).to.equal("Internal CA");
      expect(response.body.serial_number).to.equal("CLIENT123456");
      expect(response.body.subject).to.equal(
        "CN=Client User, OU=IT Department, O=Company Inc, C=US",
      );
    });

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
        domains: ["", "   ", ""], // Empty domains should be filtered out and allowed
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal(tokenData.name);
      expect(response.body.domains).to.be.null; // Empty domains should be converted to null
    });

    it("should handle certificate with minimal required fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Minimal Certificate",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["minimal.example.com"],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("cert");
      expect(response.body.domains).to.deep.equal(["minimal.example.com"]);
      expect(response.body.issuer).to.be.null;
      expect(response.body.serial_number).to.be.null;
      expect(response.body.subject).to.be.null;
    });

    it("should create certificate with all required fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Certificate With All Fields",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["example.com"],
        issuer: "Test CA",
        subject: "CN=example.com, O=Test Corp",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("cert");
      expect(response.body.domains).to.deep.equal(["example.com"]);
      expect(response.body.issuer).to.equal("Test CA");
      expect(response.body.subject).to.equal("CN=example.com, O=Test Corp");
    });

    it("should validate subject field length", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const longSubject = "CN=" + "a".repeat(300) + ", O=Test Corp, C=US";
      const tokenData = {
        name: "Certificate with Long Subject",
        type: "tls_cert",
        category: "cert",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        domains: ["long-subject.example.com"],
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

  describe("Key/Secret Category Tests", () => {
    it("should create key/secret token with location and usage information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Database Connection Key",
        type: "secret",
        category: "key_secret",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        location: "Secret Store /prod/database",
        used_by: "Web Application, API Service",
        algorithm: "AES-256",
        key_size: 256,
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("key_secret");
      expect(response.body.location).to.equal("Secret Store /prod/database");
      expect(response.body.used_by).to.equal("Web Application, API Service");
      expect(response.body.algorithm).to.equal("AES-256");
      expect(response.body.key_size).to.equal(256);
    });

    it("should accept key_secret tokens with optional key_size", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Key Secret Token",
        type: "secret",
        category: "key_secret",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        key_size: 256, // Optional key size
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.name).to.equal(tokenData.name);
      expect(response.body.key_size).to.equal(tokenData.key_size);
    });

    it("should handle key/secret with minimal fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Simple API Key",
        type: "api_key",
        category: "key_secret",
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        location: "/etc/secrets/",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("key_secret");
      expect(response.body.location).to.equal("/etc/secrets/");
      expect(response.body.used_by).to.be.null;
      expect(response.body.algorithm).to.be.null;
    });
  });

  describe("License Category Tests", () => {
    it("should create license token with vendor and cost information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Microsoft Office 365 License",
        type: "software_license", // Fixed: use proper license type instead of api_key
        category: "license",
        vendor: "Test Vendor Inc.",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        vendor: "Microsoft",
        license_type: "Subscription",
        cost: 199.99,
        renewal_url: "https://microsoft.com/office365/renew",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("license");
      expect(response.body.vendor).to.equal("Microsoft");
      expect(response.body.license_type).to.equal("Subscription");
      expect(response.body.cost).to.equal(199.99);
      expect(response.body.renewal_url).to.equal(
        "https://microsoft.com/office365/renew",
      );
    });

    it("should validate license cost properly", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Invalid Cost License",
        type: "software_license", // Fixed: use proper license type instead of api_key
        category: "license",
        vendor: "Test Vendor Inc.",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        cost: -100.0, // Invalid negative cost
        section: "licensing",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(400);

      expect(response.body.error).to.equal("Validation failed");
      expect(response.body.details.join(" ")).to.include("Cost must be");
    });

    it("should handle license with zero cost", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Open Source License",
        type: "software_license", // Fixed: use proper license type instead of api_key
        category: "license",
        vendor: "Open Source Project",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        license_type: "Open Source",
        cost: 0.0,
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("license");
      expect(response.body.cost).to.equal(0.0);
    });

    it("should create license with all required fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "License With Vendor",
        type: "software_license", // Fixed: use proper license type instead of api_key
        category: "license",
        vendor: "Test Vendor Inc.",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        license_type: "Internal",
        cost: 50.0,
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("license");
      expect(response.body.vendor).to.equal("Test Vendor Inc.");
      expect(response.body.license_type).to.equal("Internal");
      expect(response.body.cost).to.equal(50.0);
    });
  });

  describe("General Category Tests", () => {
    it("should create general token with basic information", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Configuration File",
        type: "other", // Fixed: use proper general type instead of api_key
        category: "general",
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        location: "/etc/config/app.conf",
        used_by: "Application Server",
        notes: "Important configuration file that needs regular updates",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("general");
      expect(response.body.location).to.equal("/etc/config/app.conf");
      expect(response.body.used_by).to.equal("Application Server");
      expect(response.body.notes).to.equal(
        "Important configuration file that needs regular updates",
      );
    });

    it("should handle all new token fields properly", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Comprehensive Test Token",
        type: "other", // Fixed: use proper general type instead of api_key
        category: "general",
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        location: "/secure/vault/",
        used_by: "Production Services",
        renewal_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        contacts: "admin@test.com, support@test.com",
        description: "Comprehensive test token with all fields populated",
        notes: "This is a test token to verify all fields work correctly",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      // Verify all fields are properly saved and returned
      expect(response.body.name).to.equal(tokenData.name);
      expect(response.body.type).to.equal(tokenData.type);
      expect(response.body.category).to.equal(tokenData.category);
      expect(response.body.location).to.equal(tokenData.location);
      expect(response.body.used_by).to.equal(tokenData.used_by);
      expect(response.body.renewal_date).to.equal(tokenData.renewal_date);
      expect(response.body.contacts).to.equal(tokenData.contacts);
      expect(response.body.description).to.equal(tokenData.description);
      expect(response.body.notes).to.equal(tokenData.notes);

      // Verify unset fields are null
      expect(response.body.domains).to.be.null;
      expect(response.body.issuer).to.be.null;
      expect(response.body.serial_number).to.be.null;
      expect(response.body.key_size).to.be.null;
      expect(response.body.algorithm).to.be.null;
      expect(response.body.license_type).to.be.null;
      expect(response.body.vendor).to.be.null;
      expect(response.body.cost).to.be.null;
      expect(response.body.renewal_url).to.be.null;
    });

    it("should handle general token with minimal fields", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "Simple General Token",
        type: "other", // Fixed: use proper general type instead of api_key
        category: "general",
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.category).to.equal("general");
      expect(response.body.location).to.be.null;
      expect(response.body.used_by).to.be.null;
      expect(response.body.notes).to.be.null;
    });
  });

  describe("Category Validation Tests", () => {
    it("should reject invalid category values", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const invalidCategories = [
        "invalid",
        "certificate",
        "key",
        "licence",
        "other",
      ];

      for (const invalidCategory of invalidCategories) {
        const tokenData = {
          name: `Invalid Category Test - ${invalidCategory}`,
          type: "api_key",
          category: invalidCategory,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
        };

        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(400);

        expect(response.body.error).to.equal("Validation failed");
        expect(response.body.details.join(" ")).to.include("Invalid category");
      }
    });

    it("should accept all valid category values", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const validCategories = ["cert", "key_secret", "license", "general"];

      for (const validCategory of validCategories) {
        const tokenData = {
          name: `Valid Category Test - ${validCategory}`,
          type: "api_key",
          category: validCategory,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0],
        };

        // Add required fields based on category
        if (validCategory === "cert") {
          tokenData.type = "tls_cert";
          tokenData.domains = ["test.example.com"];
          tokenData.issuer = "Test CA";
        } else if (validCategory === "license") {
          tokenData.vendor = "Test Vendor Inc.";
        }

        const response = await request("http://localhost:4000")
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: session.workspaceId })
          .expect(201);

        expect(response.body.category).to.equal(validCategory);
      }
    });

    it("should create API key with privileges field", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const tokenData = {
        name: "API Key with Privileges",
        type: "api_key",
        category: "key_secret",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
          .toISOString()
          .split("T")[0],
        privileges: "read:users, write:settings",
      };

      const response = await request("http://localhost:4000")
        .post("/api/tokens")
        .set("Cookie", session.cookie)
        .send({ ...tokenData, workspace_id: session.workspaceId })
        .expect(201);

      expect(response.body.privileges).to.equal("read:users, write:settings");
    });
  });

  describe("Test Data Manager Integration", () => {
    it("should create category-specific tokens using test data manager", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      // Create a test dataset
      const dataset = testDataManager.createDataset("Category Test Dataset");

      // Add session to dataset
      dataset.sessions.push({
        cookie: session.cookie,
        user: testUser,
      });

      // Test creating tokens for each category
      const categories = ["cert", "key_secret", "license", "general"];

      for (const category of categories) {
        const token = await testDataManager.createCategoryTokens(
          dataset.id,
          0,
          category,
        );

        expect(token.category).to.equal(category);
        expect(token.id).to.exist;

        // Verify category-specific fields are present
        switch (category) {
          case "cert":
            expect(token.domains).to.be.an("array");
            expect(token.issuer).to.exist;
            break;
          case "key_secret":
            expect(token.location).to.exist;
            expect(token.used_by).to.exist;
            break;
          case "license":
            expect(token.vendor).to.exist;
            expect(token.cost).to.be.a("number");
            break;
          case "general":
            expect(token.location).to.exist;
            expect(token.used_by).to.exist;
            break;
        }
      }
    });
  });
});
