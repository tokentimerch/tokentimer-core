"use strict";
// Variants may add billing/freeze checks here. Receipt ingestion deliberately
// does not call this gate: safe continuing results remain reconcilable.
module.exports.assertDistributionPolicy = require("./workspaceKillSwitch").lockWorkspaceForCertOpsSideEffect;
