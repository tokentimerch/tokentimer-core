const { expect } = require("chai");
const supertest = require("supertest");
const { spawn } = require("child_process");
const { Client } = require("pg");
const { logger } = require("./logger");

// Test configuration
const TEST_CONFIG = {
  API_URL: process.env.TEST_API_URL || "http://localhost:4000",
  TEST_TIMEOUT: 30000, // 30 seconds
  CLEANUP_DELAY: 1000, // 1 second
  MAX_RETRIES: 10,
};

if (
  process.env.DB_PORT &&
  process.env.TT_TEST_DB_PORT &&
  String(process.env.DB_PORT) !== String(process.env.TT_TEST_DB_PORT)
) {
  throw new Error(
    `DB port mismatch in test setup: DB_PORT=${process.env.DB_PORT} but TT_TEST_DB_PORT=${process.env.TT_TEST_DB_PORT}`,
  );
}

const RESOLVED_DB_HOST = process.env.DB_HOST || "localhost";
const RESOLVED_DB_PORT = Number(
  process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432,
);
process.env.DB_HOST = RESOLVED_DB_HOST;
process.env.DB_PORT = String(RESOLVED_DB_PORT);
if (!process.env.TT_TEST_DB_PORT) {
  process.env.TT_TEST_DB_PORT = String(RESOLVED_DB_PORT);
}

function isTransientDbError(error) {
  const msg = String(error?.message || "");
  return (
    msg.includes("ECONNREFUSED") ||
    msg.includes("ECONNRESET") ||
    msg.includes("Connection terminated") ||
    msg.includes("terminating connection due to administrator command") ||
    msg.includes("Client has encountered a connection error") ||
    msg.includes("Connection terminated unexpectedly")
  );
}

function normalizeBaseUrl(target) {
  if (!target) return TEST_CONFIG.API_URL;
  if (target === "http://localhost:4000") return TEST_CONFIG.API_URL;
  return target;
}

const request = function requestWithBase(target) {
  return supertest(normalizeBaseUrl(target));
};
request.agent = function requestAgentWithBase(target) {
  return supertest.agent(normalizeBaseUrl(target));
};

const normalizeWorkspacePlan = (plan) => {
  if (plan === "enterprise") return "enterprise";
  return "oss";
};

// Test utilities
const TestUtils = {
  // Generate unique test email
  generateTestEmail: (prefix = "test") => {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`;
  },

  // Generate unique test name
  generateTestName: (prefix = "Test User") => {
    const validNames = [
      "Alpha",
      "Beta",
      "Gamma",
      "Delta",
      "Epsilon",
      "Zeta",
      "Eta",
      "Theta",
      "Iota",
      "Kappa",
    ];
    const timestamp = Date.now();
    const nameIndex = Math.floor(timestamp / 1000) % validNames.length;
    return `${prefix} ${validNames[nameIndex]}`;
  },

  // Create test user and return credentials
  createTestUser: async (
    email = null,
    password = "SecureTest123!@#",
    name = null,
  ) => {
    const testEmail = email || TestUtils.generateTestEmail();
    const testName = name || TestUtils.generateTestName();

    const response = await request(TEST_CONFIG.API_URL)
      .post("/auth/register")
      .send({
        email: testEmail,
        password: password,
        name: testName,
      });

    // Fall back to DB insertion when public registration is unavailable or invite-gated.
    if (
      response.status === 404 ||
      response.status === 400 ||
      response.status === 409 ||
      !response.body?.user?.id
    ) {
      const bcrypt = require("bcryptjs");
      const hash = await bcrypt.hash(password, 10);
      const inserted = await TestUtils.execQuery(
        `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
         VALUES ($1, $2, $3, $4, 'local', TRUE)
         RETURNING id`,
        [testEmail.toLowerCase(), testEmail, testName, hash],
      );
      if (!inserted.rows || !inserted.rows[0] || !inserted.rows[0].id) {
        throw new Error(
          `Failed to create test user via DB insertion: no user ID returned`,
        );
      }
      return {
        email: testEmail,
        password: password,
        name: testName,
        id: inserted.rows[0].id,
        response: response,
      };
    }

    // Registration endpoint exists - check for success status codes.
    if (response.status !== 200 && response.status !== 201) {
      throw new Error(
        `User registration failed with status ${response.status}: ${JSON.stringify(response.body)}`,
      );
    }

    if (!response.body?.user?.id) {
      throw new Error(
        `User registration succeeded but no user ID in response: ${JSON.stringify(response.body)}`,
      );
    }

    return {
      email: testEmail,
      password: password,
      name: testName,
      id: response.body.user.id,
      response: response,
    };
  },

  // Create verified test user (bypasses email verification)
  createVerifiedTestUser: async (
    email = null,
    password = "SecureTest123!@#",
    name = null,
    plan = "oss",
  ) => {
    const user = await TestUtils.createTestUser(email, password, name);
    // Mark email as verified directly in DB for test speed/stability
    try {
      await TestUtils.execQuery(
        `UPDATE users SET email_verified = TRUE WHERE LOWER(email) = LOWER($1)`,
        [user.email],
      );

      // Create a workspace for the user if one doesn't exist
      let workspaceId;
      const workspaceResult = await TestUtils.execQuery(
        `SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1`,
        [user.id],
      );

      if (workspaceResult.rows.length > 0) {
        workspaceId = workspaceResult.rows[0].id;
      } else {
        // Create a workspace
        const crypto = require("crypto");
        workspaceId = crypto.randomUUID();
        await TestUtils.execQuery(
          `INSERT INTO workspaces (id, name, created_by, plan) VALUES ($1, $2, $3, $4)`,
          [
            workspaceId,
            `Test Workspace ${Date.now()}`,
            user.id,
            normalizeWorkspacePlan(plan),
          ],
        );

        // Create workspace membership with admin role (required for requireAnyWorkspaceAdmin middleware)
        await TestUtils.execQuery(
          `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) 
           VALUES ($1, $2, 'admin', $1)
           ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'admin'`,
          [user.id, workspaceId],
        );
      }

      // Update the workspace plan if needed
      if (plan) {
        await TestUtils.execQuery(
          `UPDATE workspaces SET plan = $1 WHERE id = $2`,
          [normalizeWorkspacePlan(plan), workspaceId],
        );
      }

      // Ensure workspace membership exists even for existing workspaces
      await TestUtils.execQuery(
        `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) 
         VALUES ($1, $2, 'admin', $1)
         ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'admin'`,
        [user.id, workspaceId],
      );

      // Also update the user's plan when the users.plan column exists.
      // Some schema variants do not have this column, which produced noisy warnings.
      if (plan) {
        const planColumnCheck = await TestUtils.execQuery(
          `SELECT 1
             FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'plan'
            LIMIT 1`,
        );
        if (planColumnCheck.rowCount > 0) {
          await TestUtils.execQuery(
            `UPDATE users SET plan = $1 WHERE id = $2`,
            [normalizeWorkspacePlan(plan), user.id],
          );
        }
      }
    } catch (e) {
      logger.warn(
        "Failed to set email_verified or plan in test setup:",
        e.message,
      );
    }
    return user;
  },

  // Login test user and return session cookie
  loginTestUser: async (email, password) => {
    const response = await request(TEST_CONFIG.API_URL)
      .post("/auth/login")
      .send({
        email: email,
        password: password,
      });

    // Login must succeed with 200 status
    if (response.status !== 200) {
      throw new Error(
        `User login failed with status ${response.status}: ${JSON.stringify(response.body)}`,
      );
    }

    if (!response.body?.user) {
      throw new Error(
        `User login succeeded but no user object in response: ${JSON.stringify(response.body)}`,
      );
    }

    if (!response.headers["set-cookie"]) {
      throw new Error(
        `User login succeeded but no session cookie set in response headers`,
      );
    }

    return {
      cookie: response.headers["set-cookie"],
      user: response.body.user,
      response: response,
    };
  },

  // Create authenticated test user
  createAuthenticatedUser: async () => {
    const user = await TestUtils.createTestUser();
    if (!user || !user.id) {
      throw new Error(`createTestUser failed: user object is invalid`);
    }

    const session = await TestUtils.loginTestUser(user.email, user.password);
    if (!session || !session.user || !session.cookie) {
      throw new Error(`loginTestUser failed: session object is invalid`);
    }

    return {
      ...user,
      ...session,
    };
  },

  // Ensure a test workspace exists and return its id
  ensureTestWorkspace: async (cookie) => {
    const base = TEST_CONFIG.API_URL;
    // Try list first
    try {
      const list = await request(base)
        .get("/api/v1/workspaces?limit=1&offset=0")
        .set("Cookie", cookie);
      const existing = list?.body?.items?.[0]?.id;
      if (existing) return existing;
    } catch (_) {}
    // Create one on demand
    const create = await request(base)
      .post("/api/v1/workspaces")
      .set("Cookie", cookie)
      .send({ name: `Test WS ${Date.now()}` });
    return create.body.id || create.body?.workspace?.id || create.body?.id;
  },

  // Supertest agent for session-bound flows
  newAgent: async () => {
    return request.agent(TEST_CONFIG.API_URL);
  },

  // Clean up test user
  cleanupTestUser: async (email, cookie = null) => {
    try {
      if (cookie) {
        await request(TEST_CONFIG.API_URL)
          .delete("/api/account")
          .set("Cookie", cookie);
      }
    } catch (error) {
      logger.warn("Cleanup failed:", error.message);
    }
  },

  // Wait for async operations
  wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),

  // Retry function with exponential backoff
  retry: async (fn, maxRetries = TEST_CONFIG.MAX_RETRIES) => {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        if (i === maxRetries - 1) throw error;
        await TestUtils.wait(Math.pow(2, i) * 1000);
      }
    }
  },

  // Execute a SQL query against the test database
  execQuery: async (sql, params = []) => {
    let lastError;
    for (let attempt = 0; attempt < 10; attempt++) {
      const client = new Client({
        user: process.env.DB_USER || "tokentimer",
        host: RESOLVED_DB_HOST,
        database: process.env.DB_NAME || "tokentimer",
        password: process.env.DB_PASSWORD || "password",
        port: RESOLVED_DB_PORT,
        ssl: false,
      });

      try {
        await client.connect();
        return await client.query(sql, params);
      } catch (error) {
        lastError = error;
        if (!isTransientDbError(error) || attempt === 9) {
          throw error;
        }
        await TestUtils.wait(300 * (attempt + 1));
      } finally {
        try {
          await client.end();
        } catch (_) {}
      }
    }
    throw lastError;
  },

  // Run a node script in a given working directory
  runNode: (
    cmd,
    args,
    cwd = process.cwd(),
    env = process.env,
    options = {},
  ) => {
    return new Promise((resolve, reject) => {
      const argsText = Array.isArray(args)
        ? args.join(" ")
        : String(args || "");
      const isWorkerScript =
        argsText.includes("src/queue-manager.js") ||
        argsText.includes("src/delivery-worker.js");
      const allowExitCodes = Array.isArray(options.allowExitCodes)
        ? options.allowExitCodes
        : isWorkerScript
          ? [0, 1]
          : [0];
      const mergedEnv = {
        ...process.env,
        ...(env || {}),
        DB_HOST: RESOLVED_DB_HOST,
        DB_PORT: String(RESOLVED_DB_PORT),
        TT_TEST_DB_PORT: String(RESOLVED_DB_PORT),
      };
      const p = spawn(cmd, args, { stdio: "inherit", cwd, env: mergedEnv });
      p.on("close", (code) => {
        if (allowExitCodes.includes(code)) {
          resolve({ code });
          return;
        }
        reject(new Error(`${cmd} ${args.join(" ")} exited ${code}`));
      });
      p.on("error", reject);
    });
  },

  // Validate response structure
  validateResponse: (response, expectedStatus = 200) => {
    expect(response.status).to.equal(expectedStatus);
    expect(response.body).to.be.an("object");
    return response;
  },

  // Validate error response
  validateErrorResponse: (response, expectedStatus = 400) => {
    expect(response.status).to.equal(expectedStatus);
    expect(response.body).to.have.property("error");
    expect(response.body.error).to.be.a("string");
    return response;
  },

  // Validate authentication response
  validateAuthResponse: (response, expectedStatus = 200) => {
    TestUtils.validateResponse(response, expectedStatus);
    expect(response.body).to.have.property("message");
    expect(response.body).to.have.property("user");
    expect(response.body.user).to.have.property("email");
    expect(response.body.user).to.have.property("displayName");
    return response;
  },

  // Validate token response
  validateTokenResponse: (response, expectedStatus = 201) => {
    TestUtils.validateResponse(response, expectedStatus);
    expect(response.body).to.have.property("id");
    expect(response.body).to.have.property("name");
    expect(response.body).to.have.property("type");
    expect(response.body).to.have.property("expiresAt");
    expect(response.body).to.have.property("createdAt");
    return response;
  },

  // Validate session response
  validateSessionResponse: (response, expectedLoggedIn = true) => {
    TestUtils.validateResponse(response, 200);
    expect(response.body).to.have.property("loggedIn", expectedLoggedIn);
    if (expectedLoggedIn) {
      expect(response.body).to.have.property("user");
      expect(response.body.user).to.have.property("email");
      expect(response.body.user).to.have.property("displayName");
      expect(response.body.user).to.have.property("authMethod");
    }
    return response;
  },
};

// Test data generators
const TestData = {
  // Generate valid token data
  generateTokenData: (overrides = {}) => {
    const futureDate = new Date();
    futureDate.setFullYear(futureDate.getFullYear() + 1);

    return {
      name: `Test Token ${Date.now()}`,
      expiresAt: futureDate.toISOString().split("T")[0],
      type: "api_key",
      ...overrides,
    };
  },

  // Generate invalid token data
  generateInvalidTokenData: () => ({
    name: "", // Empty name
    expiresAt: "2020-01-01", // Past date
    type: "invalid_type",
  }),

  // Generate SQL injection payloads
  sqlInjectionPayloads: [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "'; INSERT INTO users VALUES (1, 'hacker', 'hacker@evil.com'); --",
    "admin'--",
    "' UNION SELECT * FROM users--",
  ],

  // Generate XSS payloads
  xssPayloads: [
    '<script>alert("xss")</script>',
    'javascript:alert("xss")',
    '<img src="x" onerror="alert(\'xss\')">',
    '"><script>alert("xss")</script>',
    '";alert("xss");//',
  ],

  // Generate weak passwords
  weakPasswords: ["123", "abc", "password", "qwerty", "123456"],

  // Generate large payloads
  generateLargePayload: (size = 10000) => ({
    email: "a".repeat(size) + "@example.com",
    password: "a".repeat(size),
    name: "a".repeat(size),
  }),
};

// Test environment setup
const TestEnvironment = {
  // Setup test environment
  setup: async () => {
    logger.info("Setting up test environment...");

    // Set test timeout
    if (process.env.NODE_ENV !== "development") {
      process.env.NODE_ENV = "test";
    }

    // Wait for server to be ready
    await TestUtils.retry(async () => {
      const response = await request(TEST_CONFIG.API_URL).get("/");
      expect(response.status).to.equal(200);
    });

    logger.info("Test environment ready");
  },

  // Cleanup test environment
  cleanup: async () => {
    logger.info("Cleaning up test environment...");
    // Add any cleanup logic here
  },

  resetDatabase: async () => {
    try {
      await TestUtils.execQuery(`
        DELETE FROM alert_delivery_log WHERE 1=1;
        DELETE FROM alert_queue WHERE 1=1;
        DELETE FROM domain_monitors WHERE 1=1;
        DELETE FROM contact_opt_ins WHERE 1=1;
        DELETE FROM tokens WHERE 1=1;
        DELETE FROM workspace_contacts WHERE 1=1;
        DELETE FROM workspace_settings WHERE 1=1;
        DELETE FROM workspace_memberships WHERE 1=1;
        DELETE FROM workspaces WHERE 1=1;
        DELETE FROM session WHERE 1=1;
        DELETE FROM users WHERE 1=1;
      `);
      logger.info("Database reset complete");
    } catch (err) {
      logger.warn("Database reset failed (non-fatal)", { error: err.message });
    }
  },
};

// Export utilities for use in tests
module.exports = {
  TEST_CONFIG,
  TestUtils,
  TestData,
  TestEnvironment,
  expect,
  request,
};
