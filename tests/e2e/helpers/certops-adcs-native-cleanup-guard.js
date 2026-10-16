"use strict";
/** Cleanup errors must retain durable enrollment journals for later recovery.
 * Once any native custody cleanup fails, successful later actions cannot release state. */
const assert = require("node:assert/strict");
function createNativeCleanupGuard() {
  let failed = false;
  return {
    async run(action) {
      try {
        return await action();
      } catch (error) {
        failed = true;
        throw error;
      }
    },
    assertStateRemovable() {
      assert.equal(
        failed,
        false,
        "Preserve durable state after unresolved native key cleanup",
      );
    },
  };
}
module.exports = { createNativeCleanupGuard };
