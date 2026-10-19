"use strict";
// Pure ownership regression: no Windows operations, certificates or services.
const test = require("node:test"),
  assert = require("node:assert/strict");
const {
  createNativeCleanupGuard,
} = require("../tests/e2e/helpers/certops-adcs-native-cleanup-guard");
test("public cleanup followed by key refusal preserves durable state despite later success", async () => {
  const guard = createNativeCleanupGuard();
  let publicRemoved = false,
    stateRemoved = false;
  await guard.run(() => {
    publicRemoved = true;
  });
  await assert.rejects(
    guard.run(() => {
      throw Error("key still protected");
    }),
  );
  await guard.run(() => {});
  assert.equal(publicRemoved, true);
  assert.throws(() => {
    guard.assertStateRemovable();
    stateRemoved = true;
  }, /Preserve durable state/);
  assert.equal(stateRemoved, false);
});
test("all confirmed native cleanups allow final state removal", async () => {
  const guard = createNativeCleanupGuard();
  await guard.run(() => {});
  guard.assertStateRemovable();
});
