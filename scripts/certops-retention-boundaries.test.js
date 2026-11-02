"use strict";
/** Supporting real loader/temporary-ledger boundary checks. No native service,
 * certificate, key or binding operations; no elapsed qualification claim. */
const assert = require("node:assert/strict"), test = require("node:test"), fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const config = require("../packages/agent/src/config");
const fixture = require("../packages/agent/scripts/host/retention-reference-fixture");
test("native reference proof rejects missing/coerced facts and elapsed retention promotion", () => {
  const proof = { scope: "native-collector-supporting-ledger-reference-lifecycle", elapsed24HourQualified: false, ...Object.fromEntries(fixture.fields.map(field => [field, true])) };
  fixture.verifyProof(proof);
  for (const field of fixture.fields) { const missing = { ...proof }; delete missing[field]; assert.throws(() => fixture.verifyProof(missing)); assert.throws(() => fixture.verifyProof({ ...proof, [field]: false })); }
  assert.throws(() => fixture.verifyProof({ ...proof, elapsed24HourQualified: true })); assert.throws(() => fixture.verifyProof({ ...proof, rawNativeInventory: [] }));
});
test("production config loader preserves exact supported retention and cadence boundaries without rewriting custody state", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-retention-boundary-"));
  try {
    config.ensureConfigDir(directory); const file = path.join(directory, "config.json"), marker = path.join(directory, "ledger-control.json"); fs.writeFileSync(marker, "supporting immutable custody control");
    const verify = windows => { const bytes = JSON.stringify({ serverUrl: "https://qualification.example.test", ...(windows === undefined ? {} : { windows }) }); fs.writeFileSync(file, bytes); const result = config.loadAgentConfig({ configDir: directory }); assert.equal(fs.readFileSync(file, "utf8"), bytes); assert.equal(fs.readFileSync(marker, "utf8"), "supporting immutable custody control"); return result.windows; };
    assert.deepEqual(verify(undefined), { supersededRetentionHours: 168, sweepIntervalMs: 21600000 }); assert.deepEqual(verify(null), verify({}));
    for (const hours of [24, 168, 720]) for (const interval of [1, 21600000, 2147483647]) assert.deepEqual(verify({ supersededRetentionHours: hours, sweepIntervalMs: interval }), { supersededRetentionHours: hours, sweepIntervalMs: interval });
    for (const windows of [...[0, 23, 721, -1, 24.5, "24", null, true].map(supersededRetentionHours => ({ supersededRetentionHours })), ...[0, -1, 0.5, "1", null, true].map(sweepIntervalMs => ({ sweepIntervalMs })), [], "disabled", false]) {
      const bytes = JSON.stringify({ serverUrl: "https://qualification.example.test", windows }); fs.writeFileSync(file, bytes); assert.throws(() => config.loadAgentConfig({ configDir: directory })); assert.equal(fs.readFileSync(file, "utf8"), bytes); assert.equal(fs.readFileSync(marker, "utf8"), "supporting immutable custody control");
    }
  } finally { assert.equal(path.dirname(directory), os.tmpdir()); assert.match(path.basename(directory), /^certops-retention-boundary-/); fs.rmSync(directory, { recursive: true }); }
});
