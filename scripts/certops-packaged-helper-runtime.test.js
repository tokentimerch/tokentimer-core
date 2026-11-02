"use strict";
/** Pure proof and ordinary temporary-file ownership controls. Never launch a
 * native chain helper or service host from this supporting test. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const helper = require("../packages/agent/scripts/host/packaged-helper-runtime-fixture");
function fixture() { return { scope: helper.SCOPE, metadataOnly: true, serviceInstalled: false, cmcPackagedQualified: false, nativeGoVerifierPackagedQualified: false, architecture: "amd64", chainHelperSha256: "a".repeat(64), wrongProtocolHostSha256: "b".repeat(64), ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) }; }
test("packaged protocol/path proof requires every observation without promoting CMC/service/verifier", () => {
  assert.equal(helper.verifyProof(fixture()), true);
  for (const flag of helper.FLAGS) {
    const missing = fixture(); delete missing[flag]; assert.throws(() => helper.verifyProof(missing));
    for (const wrong of [false, 1, null, "true"]) assert.throws(() => helper.verifyProof({ ...fixture(), [flag]: wrong }));
  }
  for (const patch of [{ scope: "packaged-cmc-qualified" }, { cmcPackagedQualified: true }, { nativeGoVerifierPackagedQualified: true }, { serviceInstalled: true }, { metadataOnly: false }, { architecture: "arm64" }, { privateInventory: "forbidden" }, { chainHelperSha256: "bad" }, { wrongProtocolHostSha256: "a".repeat(64) }]) assert.throws(() => helper.verifyProof({ ...fixture(), ...patch }));
});
test("exact owned helper restoration retains original file ID; foreign replacement is preserved", () => {
  const base = path.resolve(__dirname, "../.build"); fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "packaged-helper-identity-"));
  try {
    const target = path.join(root, "helper with spaces café [literal].exe"), backup = target + ".original";
    fs.writeFileSync(target, "ordinary original public bytes", { flag: "wx" }); const original = helper.identity(target);
    fs.renameSync(target, backup); fs.writeFileSync(target, "ordinary replacement bytes", { flag: "wx" }); const replacement = helper.identity(target);
    helper.restoreOriginal({ target, backup, original, replacement }); helper.assertIdentity(target, original);
    fs.renameSync(target, backup); fs.writeFileSync(target, "ordinary replacement bytes", { flag: "wx" }); const expected = helper.identity(target);
    fs.renameSync(target, target + ".moved"); fs.writeFileSync(target, "foreign bytes", { flag: "wx" });
    assert.throws(() => helper.restoreOriginal({ target, backup, original, replacement: expected }));
    helper.assertIdentity(backup, original); assert.equal(fs.readFileSync(target, "utf8"), "foreign bytes");
    assert.equal(helper.assertCleanupSafe(root), true);
  } finally { fs.rmSync(root, { recursive: true }); }
});
