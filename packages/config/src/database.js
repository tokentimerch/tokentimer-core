/**
 * Database configuration for TokenTimer
 */

import { readFileSync, existsSync } from "fs";

/**
 * Get database configuration
 * @returns {Object} Database configuration object with connection settings, SSL config, and pool settings
 */
export function getDatabaseConfig() {
  const sslMode = process.env.DB_SSL;
  const caPath = process.env.PGSSLROOTCERT;

  // Build SSL config
  let ssl = false;
  if (sslMode === "verify" || caPath) {
    ssl = {
      ca:
        caPath && existsSync(caPath) ? readFileSync(caPath, "utf8") : undefined,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    };
  } else if (sslMode === "require") {
    ssl = { rejectUnauthorized: false, minVersion: "TLSv1.3" };
  }

  return {
    host: process.env.DB_HOST || "localhost",
    port: parseInt(process.env.DB_PORT || "5432", 10),
    database: process.env.DB_NAME || "tokentimer",
    user: process.env.DB_USER || "tokentimer",
    password: process.env.DB_PASSWORD,
    ssl,

    // Pool settings
    poolMax: parseInt(process.env.DB_POOL_MAX || "10", 10),
    poolMin: parseInt(process.env.DB_POOL_MIN || "2", 10),
    poolIdleTimeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || "30000", 10),
    connectionTimeout: parseInt(
      process.env.DB_CONNECTION_TIMEOUT || "5000",
      10,
    ),
  };
}

/**
 * Get connection string
 * @returns {string} PostgreSQL connection string
 */
export function getConnectionString() {
  const config = getDatabaseConfig();
  const auth = config.password
    ? `${config.user}:${config.password}@`
    : `${config.user}@`;
  const sslParam = config.ssl ? "?sslmode=require" : "";
  return `postgresql://${auth}${config.host}:${config.port}/${config.database}${sslParam}`;
}
