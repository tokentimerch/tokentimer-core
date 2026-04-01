import winston from "winston";
import { cLogError } from "./metrics.js";

const isDev =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";
const isStaging = process.env.NODE_ENV === "staging";

// Create Winston logger
const logger = winston.createLogger({
  level: isDev ? "debug" : "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  defaultMeta: { service: "tokentimer-worker" },
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
          return `[${timestamp}] [${level.toUpperCase()}] ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ""}`;
        }),
      ),
    }),
  );
} else {
  // Production: Console transport (will go to stdout/stderr)
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
    }),
  );
}

// Hook: increment error metric on any error-level log
const origError = logger.error.bind(logger);
logger.error = (...args) => {
  try {
    cLogError.labels("tokentimer-worker").inc();
  } catch (_) {}
  return origError(...args);
};

export { logger };
