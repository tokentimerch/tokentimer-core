"use strict";
// Parse privileged qualification harnesses before a costly environment is provisioned.
const errors = require("../certops-harness-source").validateHarnessSources();
if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
else console.log("certops-harness-source: scenario registrations valid");
