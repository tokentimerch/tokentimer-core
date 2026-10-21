"use strict";
// Existing installed journey dependencies plus the exact native fault producer.
module.exports=Object.freeze([...new Set([...require('./certops-windows-failed-rollback-sources'),...require('../tests/e2e/helpers/certops-windows-installed-bind-failure-native').REQUIRED_SOURCES,'scripts/certops_windows_bind_failure_native_proof.py','scripts/certops-windows-bind-failure-native.js','scripts/certops-windows-bind-failure-native-sources.js','scripts/certops-windows-bind-interposer-compile.test.ps1','.github/workflows/certops-windows-installed-bind-failure.yml'])]);
