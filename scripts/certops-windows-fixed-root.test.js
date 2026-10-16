"use strict";
/** Supporting proof and destructive-cleanup boundaries; no service, registry,
 * certificate store or canonical directory is touched by these tests. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const fixture = require("../tests/e2e/helpers/certops-windows-fixed-root");
test("full CLI rollback preservation requires process creation/executable/service path, not PID alone", () => {
  const { assertServiceStable } = require("../tests/e2e/helpers/certops-windows-cli-second-rename");
  const host = path.win32.join(fixture.canonicalRoot, "app/bin/tokentimer-agent-host-amd64.exe");
  const identity = { pid: 1234, state: "Running", owner: "S-1-5-18", created: "2026-10-14T10:00:00.0000000Z", executable: host, servicePath: '"' + host + '" --state-dir owned' };
  assertServiceStable(identity, { ...identity });
  for (const change of [{ created: "2026-10-14T10:01:00.0000000Z" }, { executable: "C:\\other.exe" }, { servicePath: '"C:\\other.exe" --state-dir owned' }, { owner: "S-1-5-19" }, { state: "Stopped" }]) assert.throws(() => assertServiceStable(identity, { ...identity, ...change }));
});
test("canonical lifecycle proof refuses missing or coerced facts and migration overclaims", () => {
  const proof = { ...Object.fromEntries(fixture.fields.map(field => [field, true])), scope: "unmodified-candidate-cli-canonical-root-same-version-reapplication" };
  assert.equal(fixture.verifyProof(proof), true);
  for (const field of fixture.fields) {
    for (const invalid of [false, null, 1, "true"]) assert.throws(() => fixture.verifyProof({ ...proof, [field]: invalid }));
    const missing = { ...proof }; delete missing[field]; assert.throws(() => fixture.verifyProof(missing));
  }
  for (const scope of ["published-upgrade", "full-cli-second-rename", "temporary-owned-root"]) assert.throws(() => fixture.verifyProof({ ...proof, scope }));
  assert.throws(() => fixture.verifyProof({ ...proof, rawCredential: "private" }));
});
test("canonical root cleanup refuses foreign paths, file identities, ownership and live services", () => {
  const token = "a".repeat(32), receipt = { root: fixture.canonicalRoot, token, fileId: "42" };
  const owned = { root: fixture.canonicalRoot, token, receipt, fileId: 42n, serviceAbsent: true };
  assert.equal(fixture.assertCanonicalOwnership(owned), true);
  for (const change of [{ root: "C:\\ProgramData" }, { root: fixture.canonicalRoot + "-other" }, { root: fixture.canonicalRoot + "\\.." }, { token: "b".repeat(32) }, { fileId: 43n }, { serviceAbsent: false }, { receipt: { ...receipt, root: "C:\\elsewhere" } }]) assert.throws(() => fixture.assertCanonicalOwnership({ ...owned, ...change }));
});
test("canonical lane remains manual, fresh hosted and independently cleaned", () => {
  const source = fs.readFileSync(path.join(__dirname, "../.github/workflows/certops-windows-fixed-root.yml"), "utf8");
  assert.match(source, /workflow_dispatch:/); assert.doesNotMatch(source, /pull_request:|schedule:|push:/);
  assert.match(source, /windows_server: \[windows-2022, windows-2025\]/);
  assert.match(source, /CERTOPS_REAL_WINDOWS_FIXED_ROOT_REQUIRED/);
  assert.match(source, /if: always\(\)\s+run: \|\s+if \(\$env:CERTOPS_FIXED_ROOT_OWNER_TOKEN\)/);
  assert.match(source, /node scripts\/certops-windows-fixed-root-cleanup.js/);
  const slots = require("../docs/certops/release-qualification-matrix.json").slots.filter(slot => slot.suite === fixture.suite);
  assert.equal(slots.length, 2); for (const slot of slots) assert.deepEqual(slot.requiredSources, fixture.requiredSources);
});
