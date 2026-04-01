const { Pool } = require("pg");
const fs = require("fs");
const client = require("prom-client");
const { logger } = require("../utils/logger.js");

// Database connection configuration
const caPath = process.env.PGSSLROOTCERT;
const sslMode = process.env.DB_SSL;
const hasCA = !!caPath;
const sslConfig =
  sslMode === "verify" || hasCA
    ? {
        ca: hasCA ? fs.readFileSync(caPath, "utf8") : undefined,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
      }
    : sslMode === "require"
      ? { rejectUnauthorized: false, minVersion: "TLSv1.3" }
      : false;

const dbConfig = {
  user: process.env.DB_USER || "tokentimer",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "tokentimer",
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  ssl: sslConfig,
  // Optimized connection pool settings
  max: 10, // Reduced from 20 - sufficient for small to medium apps
  min: 2, // Minimum connections to maintain
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 30000, // Increased from 5s to 30s for production stability
  acquireTimeoutMillis: 60000, // Time to wait for connection from pool
  // Connection retry settings
  maxUses: 7500, // Maximum uses before connection is recycled
  allowExitOnIdle: true, // Allow process to exit when all connections are idle
};

// Database connection pool
const pool = new Pool(dbConfig);

// Metrics: connection pool and query durations
const dbActiveConnections = new client.Gauge({
  name: "tokentimer_api_db_connections_active",
  help: "Active database connections",
});
const dbIdleConnections = new client.Gauge({
  name: "tokentimer_api_db_connections_idle",
  help: "Idle database connections",
});
const dbWaitingCount = new client.Gauge({
  name: "tokentimer_api_db_connections_waiting",
  help: "Waiting requests for a DB connection",
});
const dbQueryDuration = new client.Histogram({
  name: "tokentimer_api_db_query_duration_seconds",
  help: "DB query duration by operation",
  labelNames: ["operation"],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2],
});
const dbErrors = new client.Counter({
  name: "tokentimer_api_db_errors_total",
  help: "Database errors",
  labelNames: ["kind"],
});

function observePool() {
  try {
    const total = pool.totalCount || 0;
    const idle = pool.idleCount || 0;
    const waiting = pool.waitingCount || 0;
    dbActiveConnections.set(Math.max(total - idle, 0));
    dbIdleConnections.set(idle);
    dbWaitingCount.set(waiting);
  } catch (e) {
    logger.warn("Pool observation failed", { error: e.message });
  }
}
setInterval(observePool, 5000).unref();

function isConnectionError(err) {
  const code = err.code || "";
  const msg = (err.message || "").toLowerCase();
  if (["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "ETIMEDOUT"].includes(code)) return true;
  if (typeof code === "string" && code.startsWith("08")) return true;
  if (msg.includes("connection terminated") || msg.includes("could not connect")) return true;
  return false;
}

// Wrap pool.query to observe duration and crash on connection-level errors
const originalQuery = pool.query.bind(pool);
pool.query = async function (...args) {
  const end = dbQueryDuration.labels("generic").startTimer();
  try {
    return await originalQuery(...args);
  } catch (e) {
    try {
      dbErrors.labels("query").inc();
    } catch (_) {}
    if (isConnectionError(e)) {
      logger.error("Database connection lost, exiting", { error: e.message, code: e.code });
      process.exit(1);
    }
    throw e;
  } finally {
    try {
      end();
    } catch (_) {}
  }
};

pool.on("connect", () => {
  logger.info("Connected to PostgreSQL database");
});

pool.on("error", (err) => {
  logger.error("Database connection error, exiting", {
    error: err.message,
    code: err.code,
  });
  try {
    dbErrors.labels("pool").inc();
  } catch (_) {}
  process.exit(1);
});

// Enhanced connection test function
async function testConnection() {
  try {
    const client = await pool.connect();
    await client.query("SELECT 1");
    client.release();
    logger.info("Database connection test successful");
    return true;
  } catch (error) {
    logger.error("Database connection test failed", {
      error: error.message,
      code: error.code,
      host: dbConfig.host,
      port: dbConfig.port,
      database: dbConfig.database,
      user: dbConfig.user,
    });
    try {
      dbErrors.labels("test").inc();
    } catch (_) {}
    return false;
  }
}

// Wait for database to be ready
async function waitForDatabase(maxAttempts = 90, delayMs = 2000) {
  logger.info("Waiting for database to be ready...", {
    host: dbConfig.host,
    port: dbConfig.port,
    database: dbConfig.database,
    user: dbConfig.user,
  });

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    logger.info(`Database connection attempt ${attempt}/${maxAttempts}`);

    if (await testConnection()) {
      logger.info("Database is ready!");
      return true;
    }

    if (attempt < maxAttempts) {
      logger.info(`Waiting ${delayMs}ms before next attempt...`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  logger.error(`Database connection failed after ${maxAttempts} attempts`);
  return false;
}

module.exports = { pool, testConnection, waitForDatabase };
