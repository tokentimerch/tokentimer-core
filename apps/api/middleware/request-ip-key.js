"use strict";

const { ipKeyGenerator } = require("express-rate-limit");

// Express resolves req.ip only through its configured trust-proxy policy.
function requestIpKey(req) {
  return ipKeyGenerator(req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || "unknown");
}

module.exports = { requestIpKey };
