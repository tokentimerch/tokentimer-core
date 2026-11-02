"use strict";

/** Supporting contract CLI; its scope-specific failure projection stays explicit. */
const {createPendingCli} = require("./certops-qualification-report");
const contract = require("../tests/e2e/helpers/certops-fs-symlink-rollback");

const main = createPendingCli(contract, ["status","qualified","followedSymlink","hostCapabilityAbsentIsPass"], { status: "failed", qualified: false });

if (require.main === module) main();

module.exports = { main };
