/**
 * Require an explicit qualified environment for every mandatory certificate suite.
 * This schema guard prevents newly added suites from silently escaping full release collection. */
"use strict";
const { validateMatrix } = require("../certops-release-qualification");
const errors = validateMatrix();
if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
else console.log("certops-release-matrix: every mandatory suite has an explicit qualification environment");
