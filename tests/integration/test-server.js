/**
 * Compatibility layer: re-exports from setup.js.
 * New tests should import from "./setup" directly.
 */
const {
  TEST_CONFIG,
  TestUtils,
  TestEnvironment,
  expect,
  request,
} = require("./setup");

const TEST_SERVER_URL = TEST_CONFIG.API_URL;
const execQuery = TestUtils.execQuery;

async function initializeTestEnvironment() {
  await TestEnvironment.setup();
  return TEST_SERVER_URL;
}

async function cleanupTestEnvironment() {
  await TestEnvironment.cleanup();
}

module.exports = {
  initializeTestEnvironment,
  cleanupTestEnvironment,
  getTestServerUrl: () => TEST_SERVER_URL,
  TestUtils,
  request,
  expect,
  execQuery,
};
