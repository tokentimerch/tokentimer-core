"use strict";

const { sanitizeLogRecord } = require("@tokentimer/log-scrub");

const SERVICE = "tokentimer-k8s-controller";

function createControllerLogger({
  now = () => new Date().toISOString(),
  write = (line) => process.stdout.write(line),
} = {}) {
  function log(level, message, metadata = {}) {
    const record = sanitizeLogRecord({
      level,
      message,
      service: SERVICE,
      timestamp: now(),
      ...metadata,
    });
    write(`${JSON.stringify(record)}\n`);
  }

  return {
    debug(message, metadata) {
      log("debug", message, metadata);
    },
    error(message, metadata) {
      log("error", message, metadata);
    },
    info(message, metadata) {
      log("info", message, metadata);
    },
    warn(message, metadata) {
      log("warn", message, metadata);
    },
  };
}

module.exports = {
  SERVICE,
  createControllerLogger,
};
