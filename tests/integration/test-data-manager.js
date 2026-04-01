const { expect } = require("chai");
const { logger } = require("./logger");
const request = require("supertest");
const { request: supertestRequest } = require("./test-server");

// Test configuration
const TEST_CONFIG = {
  API_URL: process.env.TEST_API_URL || "http://localhost:4000",
  TEST_TIMEOUT: 30000,
  CLEANUP_DELAY: 1000,
  MAX_RETRIES: 3,
  DATASET_CLEANUP_TIMEOUT: 5000,
};

/**
 * Comprehensive Test Data Manager
 * Handles multiple datasets and test cases with proper isolation
 */
class TestDataManager {
  constructor() {
    this.datasets = new Map();
    this.testCases = new Map();
    this.cleanupQueue = [];
    this.datasetCounter = 0;
    this.testCaseCounter = 0;
  }

  /**
   * Create a new dataset with unique identifiers
   */
  createDataset(name = null, config = {}) {
    const datasetId = `dataset_${++this.datasetCounter}_${Date.now()}`;
    const datasetName = name || `Test Dataset ${this.datasetCounter}`;

    const dataset = {
      id: datasetId,
      name: datasetName,
      config: {
        emailPrefix: `test-${datasetId}`,
        password: "SecureTest123!@#",
        tokenPrefix: `token-${datasetId}`,
        ...config,
      },
      users: [],
      tokens: [],
      sessions: [],
      created: Date.now(),
      metadata: {},
    };

    this.datasets.set(datasetId, dataset);
    logger.info(`Created dataset: ${datasetName} (${datasetId})`);

    return dataset;
  }

  /**
   * Generate test data for a specific dataset
   */
  generateTestData(datasetId, type = "user", overrides = {}) {
    const dataset = this.datasets.get(datasetId);
    if (!dataset) {
      throw new Error(`Dataset ${datasetId} not found`);
    }

    const baseConfig = dataset.config;
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);

    switch (type) {
      case "user":
        const validNames = [
          "Test User Alpha",
          "Test User Beta",
          "Test User Gamma",
          "Test User Delta",
          "Test User Epsilon",
          "Test User Zeta",
          "Test User Eta",
          "Test User Theta",
          "Test User Iota",
          "Test User Kappa",
        ];
        const nameIndex = Math.floor(timestamp / 1000) % validNames.length;
        return {
          email: `${baseConfig.emailPrefix}-user-${timestamp}-${random}@example.com`,
          password: baseConfig.password,
          name: validNames[nameIndex],
          ...overrides,
        };

      case "token":
        const futureDate = new Date();
        futureDate.setFullYear(futureDate.getFullYear() + 1);

        return {
          name: `${baseConfig.tokenPrefix}-${timestamp}`,
          expiresAt: futureDate.toISOString().split("T")[0],
          type: "api_key",
          category: "key_secret", // Fixed: api_key belongs to key_secret category
          ...overrides,
        };

      case "session":
        const sessionValidNames = [
          "Session User Alpha",
          "Session User Beta",
          "Session User Gamma",
          "Session User Delta",
          "Session User Epsilon",
        ];
        const sessionNameIndex =
          Math.floor(timestamp / 1000) % sessionValidNames.length;
        return {
          email: `${baseConfig.emailPrefix}-session-${timestamp}-${random}@example.com`,
          password: baseConfig.password,
          name: sessionValidNames[sessionNameIndex],
          ...overrides,
        };

      default:
        throw new Error(`Unknown test data type: ${type}`);
    }
  }

  /**
   * Create multiple test users for a dataset
   */
  async createTestUsers(datasetId, count = 1, overrides = {}) {
    const dataset = this.datasets.get(datasetId);
    if (!dataset) {
      throw new Error(`Dataset ${datasetId} not found`);
    }

    const users = [];

    for (let i = 0; i < count; i++) {
      const userData = this.generateTestData(datasetId, "user", overrides);

      try {
        const response = await request(TEST_CONFIG.API_URL)
          .post("/auth/register")
          .send(userData);

        let userId = response.body?.user?.id;

        // Core does not expose /auth/register in all builds.
        // Fall back to direct DB insertion when it returns 404 or no user id.
        if (response.status === 404 || !userId) {
          const { Client } = require("pg");
          const bcrypt = require("bcryptjs");
          const pgClient = new Client({
            user: process.env.DB_USER || "tokentimer",
            host: process.env.DB_HOST || "localhost",
            database: process.env.DB_NAME || "tokentimer",
            password: process.env.DB_PASSWORD || "password",
            port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
            ssl: false,
          });
          await pgClient.connect();
          try {
            const hash = await bcrypt.hash(
              userData.password || "SecureTest123!@#",
              10,
            );
            const inserted = await pgClient.query(
              `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
               VALUES ($1, $2, $3, $4, 'local', TRUE)
               RETURNING id`,
              [
                (userData.email || "").toLowerCase(),
                userData.email,
                userData.name || "Test User",
                hash,
              ],
            );
            userId = inserted.rows[0].id;
          } finally {
            await pgClient.end();
          }
        }

        const user = {
          ...userData,
          id: userId,
          response: response,
          datasetId: datasetId,
          created: Date.now(),
        };

        users.push(user);
        dataset.users.push(user);

        logger.info(
          `Created test user: ${user.email} in dataset ${dataset.name}`,
        );
      } catch (error) {
        logger.error(`Failed to create test user: ${error.message}`);
        throw error;
      }
    }

    return users;
  }

  /**
   * Create authenticated sessions for users
   */
  async createAuthenticatedSessions(datasetId, userCount = 1) {
    const dataset = this.datasets.get(datasetId);
    if (!dataset) {
      throw new Error(`Dataset ${datasetId} not found`);
    }

    // Create users if they don't exist
    if (dataset.users.length === 0) {
      await this.createTestUsers(datasetId, userCount);
    }

    const sessions = [];

    for (const user of dataset.users.slice(0, userCount)) {
      try {
        const response = await request(TEST_CONFIG.API_URL)
          .post("/auth/login")
          .send({
            email: user.email,
            password: user.password,
          });

        if (response.status !== 200) {
          throw new Error(
            `Login failed with status ${response.status}: ${JSON.stringify(response.body)}`,
          );
        }

        const cookie = response.headers["set-cookie"];
        if (!cookie) {
          throw new Error("No session cookie received from login");
        }

        const session = {
          user: user,
          cookie: cookie,
          userData: response.body?.user,
          response: response,
          datasetId: datasetId,
          created: Date.now(),
        };

        sessions.push(session);
        dataset.sessions.push(session);

        logger.info(`Created authenticated session for: ${user.email}`);
      } catch (error) {
        logger.error(
          `Failed to create session for ${user.email}: ${error.message}`,
        );
        throw error;
      }
    }

    return sessions;
  }

  /**
   * Create test tokens for authenticated users
   */
  async createTestTokens(
    datasetId,
    sessionIndex = 0,
    tokenCount = 1,
    overrides = {},
  ) {
    const dataset = this.datasets.get(datasetId);
    if (!dataset) {
      throw new Error(`Dataset ${datasetId} not found`);
    }

    if (dataset.sessions.length === 0) {
      throw new Error(`No sessions available in dataset ${datasetId}`);
    }

    const session = dataset.sessions[sessionIndex];
    if (!session) {
      throw new Error(
        `Session ${sessionIndex} not found in dataset ${datasetId}`,
      );
    }

    const tokens = [];

    // Resolve workspace_id for the session once
    let workspaceId = null;
    try {
      const base = TEST_CONFIG.API_URL;
      const list = await request(base)
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie || "");
      workspaceId = list?.body?.items?.[0]?.id || null;
      if (!workspaceId) {
        const create = await request(base)
          .post("/api/v1/workspaces")
          .set("Cookie", session.cookie || "")
          .send({ name: `Test WS ${Date.now()}` });
        workspaceId =
          create.body.id || create.body?.workspace?.id || create.body?.id;
      }
    } catch (_) {}

    for (let i = 0; i < tokenCount; i++) {
      const tokenData = this.generateTestData(datasetId, "token", {
        ...overrides,
      });

      try {
        const response = await request(TEST_CONFIG.API_URL)
          .post("/api/tokens")
          .set("Cookie", session.cookie || "")
          .send({ ...tokenData, workspace_id: workspaceId });

        const token = {
          ...tokenData,
          id: response.body?.id,
          response: response,
          datasetId: datasetId,
          sessionId: session.user.id,
          created: Date.now(),
        };

        tokens.push(token);
        dataset.tokens.push(token);

        logger.info(
          `Created test token: ${token.name} in dataset ${dataset.name}`,
        );
      } catch (error) {
        logger.error(`Failed to create test token: ${error.message}`);
        throw error;
      }
    }

    return tokens;
  }

  /**
   * Create category-specific test tokens
   */
  async createCategoryTokens(
    datasetId,
    sessionIndex = 0,
    category = "general",
    overrides = {},
  ) {
    const dataset = this.datasets.get(datasetId);
    if (!dataset) {
      throw new Error(`Dataset ${datasetId} not found`);
    }

    if (dataset.sessions.length === 0) {
      throw new Error(`No sessions available in dataset ${datasetId}`);
    }

    const session = dataset.sessions[sessionIndex];
    if (!session) {
      throw new Error(
        `Session ${sessionIndex} not found in dataset ${datasetId}`,
      );
    }

    // Generate category-specific token data
    const baseTokenData = this.generateTestData(datasetId, "token", {
      category,
      ...overrides,
    });

    // Add category-specific fields based on category
    let categorySpecificData = {};

    switch (category) {
      case "cert":
        categorySpecificData = {
          type: "tls_cert", // Ensure certificate tokens have proper type
          domains: ["test-domain.com", "www.test-domain.com"],
          issuer: "Test CA",
          subject: "CN=test-domain.com, O=Test Corp, C=US",
        };
        break;
      case "key_secret":
        categorySpecificData = {
          type: "secret", // Ensure key_secret tokens have proper type
          location: "Test Location",
          used_by: "Test Application",
          algorithm: "AES-256",
          key_size: 256,
        };
        break;
      case "license":
        categorySpecificData = {
          type: "software_license", // Ensure license tokens have proper type
          vendor: "Test Vendor",
          license_type: "Subscription",
          cost: 99.99,
          renewal_url: "https://test-vendor.com/renew",
        };
        break;
      case "general":
      default:
        categorySpecificData = {
          location: "Test Location",
          used_by: "Test Application",
        };
        break;
    }

    // Resolve workspace_id for the session
    let workspaceId = null;
    try {
      const base = TEST_CONFIG.API_URL;
      const list = await request(base)
        .get("/api/v1/workspaces?limit=50&offset=0")
        .set("Cookie", session.cookie || "");
      workspaceId = list?.body?.items?.[0]?.id || null;
      if (!workspaceId) {
        const create = await request(base)
          .post("/api/v1/workspaces")
          .set("Cookie", session.cookie || "")
          .send({ name: `Test WS ${Date.now()}` });
        workspaceId =
          create.body.id || create.body?.workspace?.id || create.body?.id;
      }
    } catch (_) {}

    const tokenData = {
      ...baseTokenData,
      ...categorySpecificData,
    };

    try {
      const response = await request(TEST_CONFIG.API_URL)
        .post("/api/tokens")
        .set("Cookie", session.cookie || "")
        .send({ ...tokenData, workspace_id: workspaceId });

      const token = {
        ...tokenData,
        id: response.body?.id,
        response: response,
        datasetId: datasetId,
        sessionId: session.user.id,
        created: Date.now(),
      };

      dataset.tokens.push(token);
      logger.info(
        `Created ${category} test token: ${token.name} in dataset ${dataset.name}`,
      );

      return token;
    } catch (error) {
      logger.error(`Failed to create ${category} test token: ${error.message}`);
      throw error;
    }
  }

  /**
   * Create a complete test scenario with users, sessions, and tokens
   */
  async createTestScenario(scenarioName, config = {}) {
    const {
      userCount = 1,
      sessionCount = 1,
      tokenCount = 1,
      datasetConfig = {},
      tokenOverrides = {},
    } = config;

    const dataset = this.createDataset(scenarioName, datasetConfig);

    logger.info(`Creating test scenario: ${scenarioName}`);
    logger.info(`- Users: ${userCount}`);
    logger.info(`- Sessions: ${sessionCount}`);
    logger.info(`- Tokens per session: ${tokenCount}`);

    // Create users
    const users = await this.createTestUsers(dataset.id, userCount);

    // Create sessions
    const sessions = await this.createAuthenticatedSessions(
      dataset.id,
      sessionCount,
    );

    // Create tokens for each session
    const allTokens = [];
    for (let i = 0; i < Math.min(sessionCount, sessions.length); i++) {
      const tokens = await this.createTestTokens(
        dataset.id,
        i,
        tokenCount,
        tokenOverrides,
      );
      allTokens.push(...tokens);
    }

    const scenario = {
      name: scenarioName,
      dataset: dataset,
      users: users,
      sessions: sessions,
      tokens: allTokens,
      created: Date.now(),
    };

    this.testCases.set(scenarioName, scenario);
    logger.info(`✅ Test scenario created: ${scenarioName}`);

    return scenario;
  }

  /**
   * Generate attack payloads for security testing
   */
  generateAttackPayloads() {
    return {
      sqlInjection: [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users VALUES (1, 'hacker', 'hacker@evil.com'); --",
        "admin'--",
        "' UNION SELECT * FROM users--",
        "'; UPDATE users SET password='hacked'; --",
      ],

      xss: [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src="x" onerror="alert(\'xss\')">',
        '"><script>alert("xss")</script>',
        '";alert("xss");//',
        "<iframe src=\"javascript:alert('xss')\"></iframe>",
      ],

      weakPasswords: [
        "123",
        "abc",
        "password",
        "qwerty",
        "123456",
        "password123",
        "admin",
        "test",
      ],

      invalidEmails: [
        "test",
        "test@",
        "@example.com",
        "test@example",
        "test..test@example.com",
        "test@.com",
        "test@example..com",
      ],

      largePayloads: [
        { size: 1000, description: "Small large payload" },
        { size: 10000, description: "Medium large payload" },
        { size: 100000, description: "Large payload" },
      ],
    };
  }

  /**
   * Clean up a specific dataset
   */
  async cleanupDataset(datasetId) {
    const dataset = this.datasets.get(datasetId);
    if (!dataset) {
      logger.warn(`Dataset ${datasetId} not found for cleanup`);
      return;
    }

    logger.info(`Cleaning up dataset: ${dataset.name} (${datasetId})`);

    // Clean up tokens
    for (const token of dataset.tokens) {
      try {
        await request(TEST_CONFIG.API_URL)
          .delete(`/api/tokens/${token.id}`)
          .set("Cookie", dataset.sessions[0]?.cookie || "");
      } catch (error) {
        logger.warn(`Failed to cleanup token ${token.id}: ${error.message}`);
      }
    }

    // Clean up users (delete accounts)
    for (const session of dataset.sessions) {
      try {
        await request(TEST_CONFIG.API_URL)
          .delete("/api/account")
          .set("Cookie", session.cookie || "");
      } catch (error) {
        logger.warn(
          `Failed to cleanup user ${session.user.email}: ${error.message}`,
        );
      }
    }

    // Remove from datasets map
    this.datasets.delete(datasetId);
    logger.info(`✅ Dataset cleaned up: ${dataset.name}`);
  }

  /**
   * Clean up all datasets
   */
  async cleanupAll() {
    logger.info("Cleaning up all test datasets...");

    const cleanupPromises = Array.from(this.datasets.keys()).map((datasetId) =>
      this.cleanupDataset(datasetId),
    );

    await Promise.allSettled(cleanupPromises);

    // Clear maps
    this.datasets.clear();
    this.testCases.clear();
    this.cleanupQueue = [];

    logger.info("✅ All test datasets cleaned up");
  }

  /**
   * Get dataset statistics
   */
  getDatasetStats() {
    const stats = {
      totalDatasets: this.datasets.size,
      totalTestCases: this.testCases.size,
      datasets: [],
    };

    for (const [datasetId, dataset] of this.datasets) {
      stats.datasets.push({
        id: datasetId,
        name: dataset.name,
        users: dataset.users.length,
        sessions: dataset.sessions.length,
        tokens: dataset.tokens.length,
        created: dataset.created,
      });
    }

    return stats;
  }

  /**
   * Wait for async operations
   */
  wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Retry function with exponential backoff
   */
  async retry(fn, maxRetries = TEST_CONFIG.MAX_RETRIES) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        if (i === maxRetries - 1) throw error;
        await this.wait(Math.pow(2, i) * 1000);
      }
    }
  }
}

// Create singleton instance
const testDataManager = new TestDataManager();

// Export for use in tests
module.exports = {
  TestDataManager,
  testDataManager,
  TEST_CONFIG,
};
