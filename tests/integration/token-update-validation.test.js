const { TestUtils, request, expect } = require("./test-server");
const { testDataManager } = require("./test-data-manager");

describe("Token Update Validation Integration Tests", () => {
  let testUser;
  let session;
  let testToken;

  async function createTestToken(session, overrides = {}) {
    const tokenData = {
      name: `Test Certificate ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
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

    const response = await request("http://localhost:4000")
      .post("/api/tokens")
      .set("Cookie", session.cookie)
      .send({ ...tokenData, workspace_id: session.workspaceId })
      .expect(201);

    return response.body;
  }

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(
      testUser.email,
      "SecureTest123!@#",
    );
    session.workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
    testToken = await createTestToken(session);
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("Update Field Name Consistency", () => {
    it("should accept expiresAt field name in updates", async () => {
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
        .send({ ...tokenData, workspace_id: session.workspaceId })
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

    it("should preserve date-only expiresAt updates without timezone drift", async () => {
      const freshToken = await createTestToken(session, {
        name: "Timezone Stable Date Token",
      });
      const updateData = { expiresAt: "2030-06-14" };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${freshToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.expiresAt).to.equal("2030-06-14");
    });
  });

  describe("Update Date Validation", () => {
    it("should reject update with invalid date format", async () => {
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

    it("should allow editing an expired token when its expiration date is unchanged", async () => {
      const workspaceResult = await TestUtils.execQuery(
        `SELECT workspace_id FROM workspace_memberships WHERE user_id = $1 LIMIT 1`,
        [testUser.id],
      );
      const workspaceId = workspaceResult.rows[0]?.workspace_id || null;
      const expiredDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split("T")[0];

      const insertResult = await TestUtils.execQuery(
        `INSERT INTO tokens (
          user_id, workspace_id, created_by, name, expiration, type, category
        )
        VALUES ($1, $2, $1, $3, $4, 'api_key', 'general')
        RETURNING id`,
        [testUser.id, workspaceId, "Expired Editable Token", expiredDate],
      );
      const expiredTokenId = insertResult.rows[0].id;

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${expiredTokenId}`)
        .set("Cookie", session.cookie)
        .send({
          expiresAt: expiredDate,
          notes: "Updated notes on an expired asset",
        })
        .expect(200);

      expect(response.body.expiresAt).to.equal(expiredDate);
      expect(response.body.notes).to.equal("Updated notes on an expired asset");
    });
  });

  describe("Update Field Validation", () => {
    it("should reject update with name too short", async () => {
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
      const updateData = {
        domains: [],
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.domains).to.be.null;
    });

    it("should accept certificate update with empty issuer", async () => {
      const updateData = {
        issuer: "",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${testToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.issuer).to.be.null;
    });

    it("should accept license update without vendor", async () => {
      const licenseToken = await createTestToken(session, {
        name: "License Without Vendor",
      });
      const updateData = {
        category: "license",
        type: "software_license",
      };

      const response = await request("http://localhost:4000")
        .put(`/api/tokens/${licenseToken.id}`)
        .set("Cookie", session.cookie)
        .send(updateData)
        .expect(200);

      expect(response.body.category).to.equal("license");
      expect(response.body.type).to.equal("software_license");
    });
  });

  describe("Valid Token Updates", () => {
    it("should update token name successfully", async () => {
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
      const licenseToken = await createTestToken(session, {
        name: "Software License Source",
      });
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
        .put(`/api/tokens/${licenseToken.id}`)
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
      const certificateTypes = [
        "ssl_cert",
        "tls_cert",
        "code_signing",
        "client_cert",
      ];

      for (const certType of certificateTypes) {
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
          .send({ ...createData, workspace_id: session.workspaceId })
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
      expect(response.body.expiresAt).to.equal(freshToken.expiresAt);
      expect(response.body.notes).to.equal("Updated notes");
    });

    it("should update new fields (privileges, last_used, section array)", async () => {
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
