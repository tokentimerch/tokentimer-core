"use strict";
/** Offline proof and actual shared address-contract regressions. These tests do
 * not invoke PowerShell, open network listeners or mutate native certificates. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const h = require("../packages/agent/scripts/host/ipv4-wildcard-fixture");
const base = require("../packages/agent/scripts/host/ipv6-shadow-fixture");
const valid = () => ({
  scope: h.SCOPE,
  installedAgentQualified: false,
  caQualified: false,
  ...Object.fromEntries(h.FLAGS.map((key) => [key, true])),
});
test("IPv4 wildcard proof requires every native fact and rejects scope promotion", () => {
  assert.equal(h.verifyProof(valid()), true);
  for (const key of Object.keys(valid())) {
    const missing = valid();
    delete missing[key];
    assert.throws(() => h.verifyProof(missing));
  }
  for (const key of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...valid(), [key]: false }));
  for (const patch of [
    { scope: base.SCOPE },
    { scope: base.WILDCARD_SCOPE },
    { installedAgentQualified: true },
    { caQualified: true },
    { rawNativeReceipt: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...valid(), ...patch }));
  assert.throws(() => base.verifyProof(valid()));
});
test("explicit wildcard address contract preserves existing IPv6 selectors", () => {
  assert.deepEqual(base.variantContract("ipv4-wildcard"), {
    address: "0.0.0.0",
    scope: h.SCOPE,
  });
  assert.deepEqual(base.variantContract("concrete"), {
    address: "[::1]",
    scope: base.SCOPE,
  });
  assert.deepEqual(base.variantContract("wildcard"), {
    address: "[::]",
    scope: base.WILDCARD_SCOPE,
  });
  assert.ok(h.FLAGS.includes("trustedIpv4BaselineRecovered"));
  assert.ok(h.FLAGS.includes("actualIpv4ShadowObserved"));
  assert.equal(
    h.FLAGS.some((key) => key.includes("Ipv6")),
    false,
  );
  for (const variant of ["0.0.0.0", "ipv4", "[::]", undefined])
    assert.throws(() => base.variantContract(variant));
});
test("native IPv4 variant uses one exact target for IIS, live TLS and guarded cleanup", () => {
  const source = fs.readFileSync(
    path.join(
      __dirname,
      "../packages/agent/scripts/host/ipv6-shadow-fixture.js",
    ),
    "utf8",
  );
  assert.match(source, /targetHost = ipv4Wildcard \? "127\.0\.0\.1" : "::1"/);
  assert.match(
    source,
    /targetAddress = ipv4Wildcard \? "127\.0\.0\.1" : "\[::1\]"/,
  );
  assert.equal(
    (source.match(/Binding='\$\{targetAddress\}:\$\{port\}:localhost'/g) || [])
      .length,
    2,
  );
  assert.match(source, /await expectTls\(targetHost, port, shadow\)/);
  assert.match(source, /assert\.equal\(result\.rolledBack, true\)/);
  assert.match(source, /flags\s*\.filter/);
});

test("host hook registers its own proof before later variants borrow custody", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../packages/agent/scripts/host/iis-fixture.js"),
    "utf8",
  );
  const start = source.indexOf(
    'gate.scenario("windows-iis-ipv4-wildcard-shadow-rollback"',
  );
  const next = source.indexOf(
    'gate.scenario("windows-iis-ipv6-native-shadow-rollback"',
  );
  assert.ok(start > 0 && next > start);
  assert.match(
    source.slice(start, next),
    /nativeIpv4WildcardShadow = await fixture.qualifyIpv4Wildcard/,
  );
  assert.match(source.slice(start, next), /fixture.verifyProof/);
  assert.match(source.slice(start, next), /fixture.REQUIRED_SOURCES/);
  assert.ok(source.indexOf('run("certutil.exe", ["-delstore"', next) > next);
});
