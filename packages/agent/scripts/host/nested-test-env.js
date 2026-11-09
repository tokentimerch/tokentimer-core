"use strict";

// A nested node:test process must start its own reporter, not inherit the
// parent test runner's private child protocol. Preserve all other settings.
function nestedTestEnv(environment) {
  const child = { ...environment };
  delete child.NODE_TEST_CONTEXT;
  return child;
}
module.exports = { nestedTestEnv };
