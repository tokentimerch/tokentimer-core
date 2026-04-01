#!/usr/bin/env node

// Orchestrates alert queue integration flow in docker-compose:
// 1) Injects test data directly into DB
// 2) Runs discovery job (node apps/worker/src/queue-manager.js)
// 3) Runs delivery job (node apps/worker/src/delivery-worker.js)
// 4) Then runs mocha tests for queue visibility and stats

const { Client } = require("pg");
const { spawn } = require("child_process");
const { logger } = require("./logger");

async function injectTestData() {
  const client = new Client({
    user: process.env.DB_USER || "tokentimer",
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "tokentimer",
    password: process.env.DB_PASSWORD || "password",
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
    ssl: false,
  });

  await client.connect();
  try {
    // Create a user and a token expiring in 7 days directly
    const userRes = await client.query(
      `INSERT INTO users (email, display_name, auth_method, password_hash, plan)
       VALUES ($1, $2, 'local', 'x', 'pro') RETURNING id, email`,
      [
        `compose-test-${Date.now()}@example.com`,
        `Compose Test User ${Date.now()}`,
      ],
    );
    const userId = userRes.rows[0].id;

    const exp = new Date();
    exp.setDate(exp.getDate() + 7);
    await client.query(
      `INSERT INTO tokens (user_id, name, expiration, type, category)
       VALUES ($1, $2, $3, 'api_key', 'general')`,
      [userId, "Compose Alert Token", exp.toISOString().slice(0, 10)],
    );

    logger.info(`Injected user ${userId} and one token expiring in 7 days.`);
  } finally {
    await client.end();
  }
}

function runNode(cmd, args, cwd = process.cwd(), env = process.env) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: "inherit", cwd, env });
    p.on("close", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`${cmd} ${args.join(" ")} exited ${code}`)),
    );
    p.on("error", reject);
  });
}

async function main() {
  await injectTestData();

  // Run discovery then delivery sequentially
  await runNode("node", ["src/queue-manager.js"], "apps/worker");
  await runNode("node", ["src/delivery-worker.js"], "apps/worker");

  // Run the alert queue tests afterwards
  await runNode("pnpm", [
    "exec",
    "mocha",
    "tests/integration/alert-queue.test.js",
    "--timeout",
    "30000",
  ]);
  await runNode("pnpm", [
    "exec",
    "mocha",
    "tests/integration/alert-notifications.test.js",
    "--timeout",
    "30000",
  ]);
  await runNode("pnpm", [
    "exec",
    "mocha",
    "tests/integration/plan-limits.test.js",
    "--timeout",
    "30000",
  ]);
}

main().catch((err) => {
  logger.error("Runner failed:", err);
  process.exit(1);
});

// Test runner that ensures rate limit security tests run last
process.env.NODE_ENV = "test";

// Get the test file from command line arguments
const testFile = process.argv[2];

if (!testFile) {
  logger.info("Usage: node run-tests-with-security-last.js <test-file>");
  logger.info("Example: node run-tests-with-security-last.js account.test.js");
  process.exit(1);
}

logger.info(`Running test: ${testFile} with NODE_ENV=test`);
logger.info(
  "Note: Rate limit security tests will run last to avoid interference",
);

// Run the test with mocha
const mocha = spawn(
  "pnpm",
  ["exec", "mocha", `tests/integration/${testFile}`, "--timeout", "15000"],
  {
    stdio: "inherit",
    env: { ...process.env, NODE_ENV: "test" },
  },
);

mocha.on("close", (code) => {
  logger.info(`Test completed with exit code: ${code}`);
  process.exit(code);
});

mocha.on("error", (error) => {
  logger.error("Failed to start test:", error);
  process.exit(1);
});
