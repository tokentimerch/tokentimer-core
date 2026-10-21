"use strict";
/** Pure source/proof controls only. No TCP listener, PowerShell, HTTP.sys,
 * certificate or native IIS operation executes in these offline tests. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("../packages/agent/scripts/host/ipv6-wildcard-fixture"),
  base = require("../packages/agent/scripts/host/ipv6-shadow-fixture");
const proof = () => ({
  scope: h.SCOPE,
  installedAgentQualified: false,
  caQualified: false,
  ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
});
test("wildcard scope requires every fact and cannot substitute concrete or installed evidence", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of h.FLAGS) {
    const bad = proof();
    delete bad[key];
    assert.throws(() => h.verifyProof(bad));
    assert.throws(() => h.verifyProof({ ...proof(), [key]: false }));
  }
  for (const patch of [
    { scope: base.SCOPE },
    { installedAgentQualified: true },
    { caQualified: true },
    { ipv4WildcardQualified: true },
    { rawOwnershipReceipt: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
  assert.throws(() => base.verifyProof(proof()));
});
test("exact variant mapping cannot widen to IPv4 wildcard or arbitrary addresses", () => {
  assert.deepEqual(base.variantContract("wildcard"), {
    address: "[::]",
    scope: h.SCOPE,
  });
  assert.deepEqual(base.variantContract("concrete"), {
    address: "[::1]",
    scope: base.SCOPE,
  });
  for (const value of ["ipv4", "0.0.0.0", "[::2]", "", undefined])
    assert.throws(() => base.variantContract(value));
});
test("one unresolved guard blocks both variants without erasing private receipt", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-ipv6-wildcard-proof-"),
  );
  try {
    const guard = path.join(root, base.guardName);
    fs.writeFileSync(guard, "owned", { flag: "wx" });
    assert.throws(() => h.assertCleanupSafe(root));
    assert.throws(() => base.assertCleanupSafe(root));
    assert.equal(fs.readFileSync(guard, "utf8"), "owned");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("wildcard source requires both-stack target-port availability before native mutation", () => {
  const source = fs.readFileSync(
      path.join(
        __dirname,
        "../packages/agent/scripts/host/ipv6-shadow-fixture.js",
      ),
      "utf8",
    ),
    wrapper = fs.readFileSync(
      path.join(
        __dirname,
        "../packages/agent/scripts/host/ipv6-wildcard-fixture.js",
      ),
      "utf8",
    );
  const before = source.indexOf("assertNoPortConflicts(await listing()");
  assert.ok(before >= 0);
  for (const marker of [
    'await assertPortAvailable("::", port)',
    'await assertPortAvailable("127.0.0.1", port)',
  ]) {
    const position = source.indexOf(marker);
    assert.ok(position >= 0 && position < before);
  }
  assert.ok(wrapper.includes('qualifyIpv6ShadowVariant(context, "wildcard")'));
  assert.equal(
    h.REQUIRED_SOURCES.includes(
      "packages/agent/scripts/host/ipv6-shadow-fixture.js",
    ),
    true,
  );
});

test("wildcard parent admission follows completed concrete cleanup and precedes borrowed certificate removal", () => {
  const source = fs.readFileSync(
      path.join(__dirname, "../packages/agent/scripts/host/iis-fixture.js"),
      "utf8",
    ),
    first = source.indexOf("windows-iis-ipv6-native-shadow-rollback"),
    second = source.indexOf("windows-iis-ipv6-wildcard-shadow-rollback"),
    destructive = source.indexOf("windows-iis-rollback-failure");
  assert.ok(first >= 0 && second > first && destructive > second);
  assert.ok(source.includes("await fixture.qualifyIpv6Wildcard("));
});
