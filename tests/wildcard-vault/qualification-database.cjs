"use strict";
const assert = require("node:assert/strict");
// Explicit random qualification databases can use a free loopback port. Legacy
// fixture addresses remain unchanged. The controller creates and owns the server.
module.exports = function qualificationPort(prefix, legacyPort) {
  if (process.env.TT_CERTOPS_DISTRIBUTION_DISPOSABLE !== "1") return legacyPort;
  assert.match(
    process.env.DB_NAME || "",
    new RegExp("^" + prefix + "_qualification_[a-f0-9]{32}$"),
  );
  assert.match(
    process.env.TT_CERTOPS_DISTRIBUTION_DB_PORT || "",
    /^[1-9][0-9]{3,4}$/,
  );
  assert.ok(Number(process.env.TT_CERTOPS_DISTRIBUTION_DB_PORT) <= 65535);
  return process.env.TT_CERTOPS_DISTRIBUTION_DB_PORT;
};
