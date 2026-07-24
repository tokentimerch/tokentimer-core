"use strict";

// Compatibility seam for existing API imports. The shared package owns the
// canonical detector so lower-level logging/controller code never imports API
// implementation files.
module.exports = require("../../../packages/log-scrub/secret-material");
