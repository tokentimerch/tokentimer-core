#!/usr/bin/env node

// Test runner script that sets proper environment variables
process.env.NODE_ENV = "test";

const { spawn } = require("child_process");
const { logger } = require("./logger");

// Test files to run
const testFiles = [
  "basic.test.js",
  "auth.test.js",
  "account.test.js",
  "tokens.test.js",
  "token-categories.test.js",
  "token-validation.test.js",
  "token-update-validation.test.js",
  "tokens-extended.test.js",
  "frontend-integration.test.js",
  "database-schema.test.js",
  "security.test.js",
  "rate-limit-security.test.js",
  "account-settings-display.test.js",
];

// Get the test file from command line arguments
const testFile = process.argv[2];

if (!testFile) {
  logger.info("Usage: node run-tests.js <test-file>");
  logger.info("Example: node run-tests.js account.test.js");
  process.exit(1);
}

logger.info(`Running test: ${testFile} with NODE_ENV=test`);

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
