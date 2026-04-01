// Test configuration that relaxes rate limiting for testing
process.env.NODE_ENV = "test";
process.env.TEST_MODE = "true";

// Override rate limiting for tests
const originalRateLimit = require("express-rate-limit");

// Create a more permissive rate limiter for tests
function createTestRateLimiter(options = {}) {
  return originalRateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 1000, // Much higher limit for tests
    message: "Test rate limit exceeded",
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
    ...options,
  });
}

// Export test configuration
module.exports = {
  createTestRateLimiter,
  TEST_CONFIG: {
    API_URL: process.env.TEST_API_URL || "http://localhost:4000",
    TEST_TIMEOUT: 30000,
    CLEANUP_DELAY: 100, // milliseconds
    RATE_LIMIT_DELAY: 2000, // milliseconds to wait when rate limited
    MAX_RETRIES: 3,
  },
};
