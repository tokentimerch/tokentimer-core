const winston = require("winston");
const client = require("prom-client");

// Environment detection
const isDev =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";
const isStaging = process.env.NODE_ENV === "staging";

// Safe JSON serialization that handles circular references
const safeJsonFormat = winston.format((info) => {
  // Iterate through all properties and replace circular ones
  for (const key in info) {
    if (info[key] !== null && typeof info[key] === "object") {
      try {
        // Test if the value can be JSON stringified
        JSON.stringify(info[key]);
      } catch (_e) {
        // If circular reference, extract only safe properties
        if (info[key] instanceof Error) {
          info[key] = {
            message: info[key].message,
            stack: info[key].stack,
            name: info[key].name,
            code: info[key].code,
          };
        } else {
          info[key] = "[Circular or Non-Serializable]";
        }
      }
    }
  }
  return info;
});

// Create Winston logger
const logger = winston.createLogger({
  level: isDev ? "debug" : "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    safeJsonFormat(),
  ),
  defaultMeta: { service: "tokentimer-core-api" },
  transports: [],
});

// Add transports based on environment
if (isDev) {
  // Development: Console transport with colors
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
      ),
    }),
  );
} else if (isStaging) {
  // Staging: Console transport with timestamps (goes to stdout/stderr)
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          let metaStr = "";
          if (Object.keys(meta).length) {
            try {
              metaStr = JSON.stringify(meta);
            } catch (e) {
              // Handle circular references or other JSON serialization errors
              metaStr = JSON.stringify({
                error: "Failed to serialize metadata",
                reason: e.message,
              });
            }
          }
          return `[${timestamp}] [${level.toUpperCase()}] ${message} ${metaStr}`;
        }),
      ),
    }),
  );
} else {
  // Production: Console transport (will go to stdout/stderr)
  logger.add(
    new winston.transports.Console({
      format: winston.format.json(),
    }),
  );
}

// Metrics: centralized error counter
let cLogError;
try {
  cLogError = new client.Counter({
    name: "app_log_errors_total",
    help: "Count of error-level log events by service",
    labelNames: ["service"],
  });
} catch (_) {
  /* intentionally empty: ignore duplicate registration in dev/hot reload */
}

const origError = logger.error.bind(logger);
logger.error = (...args) => {
  try {
    if (cLogError) cLogError.labels("tokentimer-core-api").inc();
  } catch (_) {}
  return origError(...args);
};

module.exports = { logger };
