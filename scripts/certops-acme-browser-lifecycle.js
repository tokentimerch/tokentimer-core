"use strict";
/** Trusted manual native-browser journey; shared host ownership and cleanup. */
const runner = require("./certops-native-browser-runner").createRunner("lifecycle");
module.exports = runner;
if (require.main === module) runner.main().catch(error => { console.error(error.message); process.exitCode = 1; });
