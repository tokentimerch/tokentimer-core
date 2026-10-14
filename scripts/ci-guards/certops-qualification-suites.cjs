/**
 * Validate unique mandatory scenarios, capability prerequisites and evidence levels.
 * Source metadata is a contract; passing this guard does not establish test execution. */
"use strict";
const { validateSuites } = require("../certops-qualification-suites");
const errors = validateSuites(require("../../docs/certops/qualification-suites.json"));
if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
else console.log("certops-qualification-suites: mandatory evidence contract valid");
