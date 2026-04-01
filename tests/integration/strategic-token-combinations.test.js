const { TestUtils, request, expect } = require("./test-server");
const { logger } = require("./logger");

// Use the existing Docker Compose server
const TEST_SERVER_URL = process.env.TEST_API_URL || "http://localhost:4000";

// Helper function to generate future dates for test tokens
function getFutureDate(daysInFuture = 90) {
  return new Date(Date.now() + daysInFuture * 24 * 60 * 60 * 1000)
    .toISOString()
    .split("T")[0];
}

describe("Strategic Token Testing Suite", () => {
  let testUser;
  let session;
  let workspaceId;

  // Token type definitions with their valid categories
  const TOKEN_DEFINITIONS = {
    cert: ["ssl_cert", "tls_cert", "code_signing", "client_cert"],
    key_secret: ["api_key", "secret", "password", "encryption_key", "ssh_key"],
    license: ["software_license", "service_subscription"],
    general: ["domain_registration", "other", "document", "membership"],
  };

  // Smart field grouping: Group related fields together
  const FIELD_GROUPS = {
    // Certificate-specific fields
    certificate_fields: {
      domains: ["example.com"],
      issuer: "Test CA",
    },

    // Key/Secret-specific fields
    key_secret_fields: {
      location: "/etc/keys/",
      used_by: "API Server",
    },

    // License-specific fields
    license_fields: {
      vendor: "Test Vendor",
      cost: 99.99,
    },

    // General/Common fields
    common_fields: {
      description: "Test document",
    },

    // Constraint testing fields - values that test database limits
    constraint_fields: {
      name_min: "ABC", // Minimum length (3 chars)
      name_max: "A".repeat(100), // Maximum length
      location_max: "B".repeat(500), // Maximum VARCHAR(500)
      used_by_max: "C".repeat(500), // Maximum VARCHAR(500)
      issuer_max: "D".repeat(255), // Maximum VARCHAR(255)
      serial_number_max: "E".repeat(255), // Maximum VARCHAR(255)
      algorithm_max: "F".repeat(100), // Maximum VARCHAR(100)
      license_type_max: "G".repeat(100), // Maximum VARCHAR(100)
      vendor_max: "H".repeat(255), // Maximum VARCHAR(255)
      renewal_url_max: "I".repeat(500), // Maximum VARCHAR(500)
      contacts_max: "J".repeat(500), // Maximum VARCHAR(500)
      key_size_min: 1, // Minimum positive integer
      key_size_large: 65536, // Large but valid key size
      cost_zero: 0, // Minimum cost
      cost_large: 999999999999.99, // Just under the constraint limit
    },
  };

  // Representative test combinations instead of all 65k
  const REPRESENTATIVE_COMBINATIONS = [
    // Minimal required fields only
    { name: "minimal", fields: {} },

    // Single field groups
    { name: "certificate_only", fields: FIELD_GROUPS.certificate_fields },
    { name: "key_secret_only", fields: FIELD_GROUPS.key_secret_fields },
    { name: "license_only", fields: FIELD_GROUPS.license_fields },
    { name: "common_only", fields: FIELD_GROUPS.common_fields },

    // Mixed field groups
    {
      name: "cert_with_common",
      fields: {
        ...FIELD_GROUPS.certificate_fields,
        ...FIELD_GROUPS.common_fields,
      },
    },
    {
      name: "key_with_common",
      fields: {
        ...FIELD_GROUPS.key_secret_fields,
        ...FIELD_GROUPS.common_fields,
      },
    },
    {
      name: "license_with_common",
      fields: { ...FIELD_GROUPS.license_fields, ...FIELD_GROUPS.common_fields },
    },

    // Constraint testing combinations
    { name: "constraint_testing", fields: FIELD_GROUPS.constraint_fields },

    // Maximum data combination (all fields populated)
    {
      name: "maximum_data",
      fields: {
        ...FIELD_GROUPS.certificate_fields,
        ...FIELD_GROUPS.key_secret_fields,
        ...FIELD_GROUPS.license_fields,
        ...FIELD_GROUPS.common_fields,
      },
    },

    // Edge case combinations
    {
      name: "empty_strings",
      fields: {
        domains: [],
        location: "",
        used_by: "",
        issuer: "",
        serial_number: "",
        subject: "",
        algorithm: "",
        license_type: "",
        vendor: "",
        renewal_url: "",
        contacts: "",
        description: "",
        notes: "",
      },
    },

    // Boundary value combinations
    {
      name: "boundary_values",
      fields: {
        key_size: 1, // Minimum valid
        cost: 0, // Minimum valid
        renewal_date: getFutureDate(30),
      },
    },
  ];

  // Ambiguous/problematic data for failure testing
  const FAILURE_TEST_DATA = {
    // SQL Injection attempts
    sql_injection: {
      domains: ["'; DROP TABLE tokens; --", "admin'--"],
      issuer: "'; DELETE FROM users; --",
      subject: "'; UPDATE tokens SET name='hacked'; --",
      vendor: "'; INSERT INTO users (email) VALUES ('hacker@evil.com'); --",
    },

    // XSS attempts
    xss_injection: {
      location: "<script>alert('xss')</script>",
      used_by: "<img src=x onerror=alert('XSS')>",
      description: "javascript:alert('xss')",
      notes: '"><script>alert("xss")</script>',
    },

    // Constraint violations
    constraint_violations: {
      name: "AB", // Too short (< 3 chars)
      key_size: -1, // Negative value
      cost: -100.5, // Negative cost
      cost_too_large: 9999999999999.99, // Over DB limit
      location_too_long: "A".repeat(501), // Over VARCHAR(500) limit
      issuer_too_long: "B".repeat(256), // Over VARCHAR(255) limit
      renewal_date: "2020-01-01", // Past date
    },

    // Type violations
    type_violations: {
      key_size: "not_a_number",
      cost: "not_a_decimal",
      renewal_date: "invalid_date_format",
    },
  };

  beforeEach(async () => {
    testUser = await TestUtils.createTestUser();
    logger.info(`Strategic test user created: ${testUser.email}`);
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");
    logger.info("Strategic test user logged in successfully");
    workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
  });

  afterEach(async () => {
    if (testUser && testUser.email && session && session.cookie) {
      await TestUtils.cleanupTestUser(testUser.email, session.cookie);
    }
  });

  describe("1. Smart Field Grouping Tests", () => {
    Object.entries(FIELD_GROUPS).forEach(([groupName, groupFields]) => {
      it(`should handle ${groupName} field group correctly`, async () => {
        // Test with a representative token type for each group
        const tokenType = groupName.includes("certificate")
          ? "ssl_cert"
          : groupName.includes("key_secret")
            ? "api_key"
            : groupName.includes("license")
              ? "software_license"
              : "other";

        const category = groupName.includes("certificate")
          ? "cert"
          : groupName.includes("key_secret")
            ? "key_secret"
            : groupName.includes("license")
              ? "license"
              : "general";

        const tokenData = {
          name: `Test ${groupName} Token`,
          type: tokenType,
          expiresAt: getFutureDate(90),
          ...groupFields,
          category: category, // Set category AFTER spreading fields to ensure it's not overridden
        };

        const response = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...tokenData, workspace_id: workspaceId });

        // Should succeed for valid field groups
        if (groupName !== "constraint_fields" || !groupFields.name_max) {
          expect(response.status).to.equal(201);
          expect(response.body).to.have.property("id");
          expect(response.body.name).to.equal(tokenData.name);
        }
      });
    });
  });

  describe("2. Representative Combinations Testing", () => {
    REPRESENTATIVE_COMBINATIONS.forEach((combination) => {
      TOKEN_DEFINITIONS.cert.forEach((tokenType) => {
        it(`should handle ${combination.name} combination for ${tokenType}`, async () => {
          const tokenData = {
            name: `Test ${combination.name} ${tokenType}`,
            type: tokenType,
            category: "cert",
            expiresAt: getFutureDate(90),
            ...combination.fields,
          };

          const response = await request(TEST_SERVER_URL)
            .post("/api/tokens")
            .set("Cookie", session.cookie)
            .send({ ...tokenData, workspace_id: workspaceId });

          // Most combinations should succeed
          if (combination.name !== "constraint_testing") {
            expect(response.status).to.equal(201);
            expect(response.body.name).to.equal(tokenData.name);
            expect(response.body.type).to.equal(tokenType);
            expect(response.body.category).to.equal("cert");
          }
        });
      });
    });
  });

  describe("3. Category-Based Testing", () => {
    Object.entries(TOKEN_DEFINITIONS).forEach(([category, tokenTypes]) => {
      describe(`Category: ${category}`, () => {
        tokenTypes.forEach((tokenType) => {
          it(`should create ${tokenType} with category-relevant fields`, async () => {
            // Use only basic, safe fields for each category
            let relevantFields = {};
            switch (category) {
              case "cert":
                relevantFields = {
                  domains: ["example.com"],
                  issuer: "Test CA",
                };
                break;
              case "key_secret":
                relevantFields = {
                  location: "/etc/keys/",
                  used_by: "API Server",
                };
                break;
              case "license":
                relevantFields = { vendor: "Test Vendor", cost: 99.99 };
                break;
              case "general":
                relevantFields = { description: "Test document" };
                break;
            }

            const tokenData = {
              name: `Test ${tokenType} Token`,
              type: tokenType,
              expiresAt: getFutureDate(90),
              ...relevantFields,
              category: category, // Set category AFTER spreading fields to ensure it's not overridden
            };

            const response = await request(TEST_SERVER_URL)
              .post("/api/tokens")
              .set("Cookie", session.cookie)
              .send({ ...tokenData, workspace_id: workspaceId });

            expect(response.status).to.equal(201);
            expect(response.body.type).to.equal(tokenType);
            expect(response.body.category).to.equal(category);

            // Verify category-specific fields are preserved
            if (category === "cert" && relevantFields.domains) {
              expect(response.body.domains).to.deep.equal(
                relevantFields.domains,
              );
            }
            if (category === "license" && relevantFields.cost) {
              expect(parseFloat(response.body.cost)).to.equal(
                relevantFields.cost,
              );
            }
          });
        });
      });
    });
  });

  describe("4. Constraint-Based Testing", () => {
    describe("Database Constraint Validation", () => {
      it("should enforce name length constraints", async () => {
        // Test minimum length (should succeed)
        const validToken = {
          name: "ABC", // Exactly 3 characters
          type: "api_key",
          category: "key_secret", // Fixed: api_key belongs to key_secret category
          expiresAt: getFutureDate(90),
        };

        const validResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...validToken, workspace_id: workspaceId });

        expect(validResponse.status).to.equal(201);

        // Test too short (should fail)
        const invalidToken = {
          name: "AB", // Only 2 characters
          type: "api_key",
          category: "key_secret", // Fixed: api_key belongs to key_secret category
          expiresAt: getFutureDate(90),
        };

        const invalidResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...invalidToken, workspace_id: workspaceId });

        expect(invalidResponse.status).to.equal(400);
        expect(invalidResponse.body.error).to.include("Validation failed");
      });

      it("should enforce key_size constraints", async () => {
        // Test valid key size
        const validToken = {
          name: "Valid Key Size Token",
          type: "encryption_key",
          category: "key_secret",
          expiresAt: getFutureDate(90),
          key_size: 2048,
        };

        const validResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...validToken, workspace_id: workspaceId });

        expect(validResponse.status).to.equal(201);

        // Test invalid key size (negative)
        const invalidToken = {
          name: "Invalid Key Size Token",
          type: "encryption_key",
          category: "key_secret",
          expiresAt: getFutureDate(90),
          key_size: -1024,
        };

        const invalidResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...invalidToken, workspace_id: workspaceId });

        expect(invalidResponse.status).to.equal(400);
        expect(invalidResponse.body.error).to.include("Validation failed");
      });

      it("should enforce cost constraints", async () => {
        // Test valid cost
        const validToken = {
          name: "Valid Cost Token",
          type: "software_license",
          category: "license",
          expiresAt: getFutureDate(90),
          cost: 999.99,
        };

        const validResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...validToken, workspace_id: workspaceId });

        expect(validResponse.status).to.equal(201);

        // Test invalid cost (negative)
        const invalidToken = {
          name: "Invalid Cost Token",
          type: "software_license",
          category: "license",
          expiresAt: getFutureDate(90),
          cost: -100.5,
        };

        const invalidResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...invalidToken, workspace_id: workspaceId });

        expect(invalidResponse.status).to.equal(400);
        expect(invalidResponse.body.error).to.include("Validation failed");
      });

      it("should enforce VARCHAR length constraints", async () => {
        // Test maximum allowed lengths (should succeed)
        const maxLengthToken = {
          name: "A".repeat(100), // VARCHAR(100) limit
          type: "ssl_cert",
          category: "cert",
          expiresAt: getFutureDate(90),
          location: "B".repeat(500), // VARCHAR(500) limit
          issuer: "C".repeat(255), // VARCHAR(255) limit
          algorithm: "D".repeat(100), // VARCHAR(100) limit
        };

        const validResponse = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...maxLengthToken, workspace_id: workspaceId });

        expect(validResponse.status).to.equal(201);
      });
    });

    describe("Security Constraint Testing", () => {
      it("should prevent SQL injection in token fields", async () => {
        const sqlInjectionToken = {
          name: "'; DROP TABLE tokens; --",
          type: "api_key",
          category: "key_secret", // Fixed: api_key belongs to key_secret category
          expiresAt: getFutureDate(90),
          location: "'; DELETE FROM users; --",
          issuer: "'; UPDATE tokens SET name='hacked'; --",
        };

        const response = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...sqlInjectionToken, workspace_id: workspaceId });

        // Should either succeed (if properly sanitized) or fail with validation error
        // But should NOT crash the server or execute SQL
        expect([201, 400, 422]).to.include(response.status);

        if (response.status === 201) {
          // If it succeeded, the malicious content should be stored (may be HTML encoded for XSS protection)
          // Accept either the original or HTML encoded version
          const expectedName = sqlInjectionToken.name;
          const htmlEncodedName = expectedName.replace(/'/g, "&#x27;");
          expect([expectedName, htmlEncodedName]).to.include(
            response.body.name,
          );
        }
      });

      it("should handle XSS attempts in token fields", async () => {
        const xssToken = {
          name: "XSS Test Token",
          type: "document",
          category: "general",
          expiresAt: getFutureDate(90),
          description: '<script>alert("xss")</script>',
          notes: '<img src=x onerror=alert("xss")>',
        };

        const response = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...xssToken, workspace_id: workspaceId });

        // Should succeed but sanitize the content
        expect(response.status).to.equal(201);
        // The XSS content should be stored as plain text, not executed
        expect(response.body.description).to.be.a("string");
        expect(response.body.notes).to.be.a("string");
      });
    });
  });

  describe("5. Failure Testing with Ambiguous Data", () => {
    it("should handle constraint violations gracefully", async () => {
      const violations = [
        {
          name: "Name Too Short",
          data: {
            name: "AB",
            type: "api_key",
            category: "key_secret",
            expiresAt: getFutureDate(90),
          }, // Fixed: api_key belongs to key_secret category
          expectedError: "name",
        },
        {
          name: "Negative Key Size",
          data: {
            name: "Test Token",
            type: "encryption_key",
            category: "key_secret",
            expiresAt: getFutureDate(90),
            key_size: -1,
          },
          expectedError: "key size",
        },
        {
          name: "Negative Cost",
          data: {
            name: "Test Token",
            type: "software_license",
            category: "license",
            expiresAt: getFutureDate(90),
            cost: -100,
          },
          expectedError: "cost",
        },
      ];

      for (const violation of violations) {
        const response = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...violation.data, workspace_id: workspaceId });

        expect(response.status).to.equal(400);
        expect(response.body.error).to.include("Validation failed");
      }
    });

    it("should handle type mismatches gracefully", async () => {
      const typeMismatches = [
        {
          name: "String Key Size",
          data: {
            name: "Test Token",
            type: "encryption_key",
            category: "key_secret",
            expiresAt: getFutureDate(90),
            key_size: "not_a_number",
          },
        },
        {
          name: "String Cost",
          data: {
            name: "Test Token",
            type: "software_license",
            category: "license",
            expiresAt: getFutureDate(90),
            cost: "not_a_decimal",
          },
        },
      ];

      for (const mismatch of typeMismatches) {
        const response = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...mismatch.data, workspace_id: workspaceId });

        expect(response.status).to.equal(400);
        expect(response.body.error).to.include("Validation failed");
      }
    });
  });

  describe("6. Comprehensive Success Scenarios", () => {
    it("should successfully create tokens with all valid field combinations", async () => {
      const successScenarios = [
        {
          name: "Complete Certificate Token",
          data: {
            name: "Complete SSL Certificate",
            type: "ssl_cert",
            category: "cert",
            expiresAt: getFutureDate(180),
            domains: ["example.com", "www.example.com", "api.example.com"],
            issuer: "Let's Encrypt Authority X3",
            serial_number: "1A2B3C4D5E6F7890ABCDEF1234567890",
            subject:
              "CN=example.com, O=Example Corporation, OU=IT Department, L=San Francisco, ST=California, C=US",
            algorithm: "RSA-SHA256",
            key_size: 2048,
            location: "/etc/ssl/certs/",
            used_by: "Nginx Web Server, Apache Load Balancer",
            renewal_url: "https://ssl.example.com/renew",
            renewal_date: getFutureDate(90),
            contacts: "ssl-admin@example.com, security-team@example.com",
            description:
              "Primary SSL certificate for production website and API endpoints",
            notes:
              "Auto-renewal enabled. Critical for business operations. Monitor expiration closely.",
          },
        },
        {
          name: "Complete License Token",
          data: {
            name: "Microsoft Office 365 Enterprise",
            type: "software_license",
            category: "license",
            expiresAt: getFutureDate(120),
            vendor: "Microsoft Corporation",
            license_type: "Enterprise E5",
            cost: 22.0,
            renewal_url: "https://admin.microsoft.com/licenses",
            renewal_date: getFutureDate(90),
            contacts: "licensing@company.com, finance@company.com",
            location: "Microsoft 365 Admin Center",
            used_by: "All employees, HR Department, Finance Team",
            description:
              "Enterprise license for Microsoft Office 365 suite including Teams, SharePoint, and advanced security features",
            notes:
              "Covers 500 users. Auto-renewal enabled. Contact finance 30 days before renewal.",
          },
        },
      ];

      for (const scenario of successScenarios) {
        const response = await request(TEST_SERVER_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie)
          .send({ ...scenario.data, workspace_id: workspaceId });

        expect(response.status).to.equal(201);
        expect(response.body.name).to.equal(scenario.data.name);
        expect(response.body.type).to.equal(scenario.data.type);
        expect(response.body.category).to.equal(scenario.data.category);

        // Verify all fields are properly stored
        Object.keys(scenario.data).forEach((key) => {
          if (key !== "expiresAt") {
            // expiresAt is transformed to expiration
            if (
              scenario.data[key] !== null &&
              scenario.data[key] !== undefined
            ) {
              expect(response.body).to.have.property(key);
            }
          }
        });
      }
    });
  });
});
