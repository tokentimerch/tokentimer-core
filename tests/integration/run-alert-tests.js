#!/usr/bin/env node

/**
 * Test runner for alert system integration tests
 * Validates channel-specific failures, retries, and usage calculations
 */

const { spawn } = require("child_process");
const path = require("path");
const { logger } = require("./logger");

const TEST_FILES = [
  "alert-delivery-channel-failures.test.js",
  "alert-monthly-usage-calculation.test.js",
  "alert-queue.test.js",
  "alert-notifications.test.js",
  "webhooks-delivery.test.js",
];

async function runTest(testFile) {
  return new Promise((resolve, reject) => {
    logger.info(`\n🧪 Running ${testFile}...`);
    logger.info("=".repeat(60));

    const mocha = spawn(
      "pnpm",
      ["exec", "mocha", testFile, "--timeout", "120000"],
      {
        stdio: "inherit",
        cwd: __dirname,
        env: {
          ...process.env,
          NODE_ENV: "test",
        },
      },
    );

    mocha.on("close", (code) => {
      if (code === 0) {
        logger.info(`✅ ${testFile} passed`);
        resolve();
      } else {
        logger.info(`❌ ${testFile} failed with code ${code}`);
        reject(new Error(`${testFile} failed with code ${code}`));
      }
    });

    mocha.on("error", (err) => {
      logger.info(`❌ ${testFile} error:`, err.message);
      reject(err);
    });
  });
}

async function runAllTests() {
  logger.info("🚀 Starting Alert System Integration Tests");
  logger.info("=".repeat(60));
  logger.info("This will test:");
  logger.info("• Channel-specific failures and retries");
  logger.info("• Monthly usage calculation fixes");
  logger.info("• Alert queue behavior");
  logger.info("• Webhook delivery validation");
  logger.info("• Teams webhook host validation");
  logger.info("");

  const results = {
    passed: [],
    failed: [],
  };

  for (const testFile of TEST_FILES) {
    try {
      await runTest(testFile);
      results.passed.push(testFile);
    } catch (error) {
      results.failed.push(testFile);
      logger.info(`\n⚠️  Continuing with remaining tests...`);
    }
  }

  // Summary
  logger.info("\n" + "=".repeat(60));
  logger.info("📊 TEST SUMMARY");
  logger.info("=".repeat(60));

  if (results.passed.length > 0) {
    logger.info("\n✅ PASSED TESTS:");
    results.passed.forEach((test) => logger.info(`  • ${test}`));
  }

  if (results.failed.length > 0) {
    logger.info("\n❌ FAILED TESTS:");
    results.failed.forEach((test) => logger.info(`  • ${test}`));
  }

  logger.info(
    `\n📈 Results: ${results.passed.length} passed, ${results.failed.length} failed`,
  );

  if (results.failed.length === 0) {
    logger.info("\n🎉 All alert system tests passed!");
    process.exit(0);
  } else {
    logger.info("\n💥 Some tests failed. Check the output above for details.");
    process.exit(1);
  }
}

// Handle command line arguments
const args = process.argv.slice(2);
if (args.length > 0) {
  const testFile = args[0];
  if (TEST_FILES.includes(testFile)) {
    runTest(testFile)
      .then(() => {
        logger.info("\n✅ Test completed successfully");
        process.exit(0);
      })
      .catch((error) => {
        logger.info("\n❌ Test failed:", error.message);
        process.exit(1);
      });
  } else {
    logger.info(`❌ Unknown test file: ${testFile}`);
    logger.info(`Available tests: ${TEST_FILES.join(", ")}`);
    process.exit(1);
  }
} else {
  runAllTests().catch((error) => {
    logger.error("💥 Test runner failed:", error.message);
    process.exit(1);
  });
}
