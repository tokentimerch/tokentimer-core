"use strict";
/** Offline contract controls only; native IPv6/IIS/HTTP.sys/TLS operations remain
 * gated to the protected disposable host and are not executed by these tests. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto");
const h = require("../packages/agent/scripts/host/ipv6-shadow-fixture"),
  iis = require("../packages/agent/src/windows-iis");
const proof = () => ({
  scope: h.SCOPE,
  installedAgentQualified: false,
  caQualified: false,
  ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
});
test("IPv6 supporting proof requires every actual native fact and forbids installed or CA promotion", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of h.FLAGS) {
    const missing = proof();
    delete missing[key];
    assert.throws(() => h.verifyProof(missing));
    assert.throws(() => h.verifyProof({ ...proof(), [key]: false }));
  }
  for (const patch of [
    { installedAgentQualified: true },
    { caQualified: true },
    { scope: "installed" },
    { privateOwnershipReceipt: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});
test("real product selector and verification contracts preserve concrete IPv6 and isolate IPv4 sibling", () => {
  const binding = {
    address: "[::1]",
    port: 18443,
    site: "owned",
    store: "My",
    sniHost: "localhost",
  };
  assert.equal(
    iis.formatBindingSelector(binding),
    "hostnameport=localhost:18443",
  );
  assert.deepEqual(iis.resolveVerificationTarget(binding), {
    host: "::1",
    servername: "localhost",
  });
  const rows = [
    { keyedBy: "ipport", ipPort: "[0:0:0:0:0:0:0:1]:18443" },
    { keyedBy: "ipport", ipPort: "127.0.0.1:18444" },
    { keyedBy: "hostnameport", ipPort: "localhost:18443" },
  ];
  assert.deepEqual(h.selectEndpoint(rows, "ipport=[::1]:18443"), [rows[0]]);
  assert.deepEqual(h.selectEndpoint(rows, "hostnameport=localhost:18443"), [
    rows[2],
  ]);
  assert.deepEqual(h.selectEndpoint(rows, "ipport=127.0.0.1:18443"), []);
});
test("endpoint deletion refuses a foreign application, certificate or store", () => {
  const id = crypto.randomUUID(),
    row = { thumbprint: "A".repeat(40), storeName: "My", appId: `{${id}}` },
    policy = { thumbprints: [row.thumbprint], appIds: [id] };
  h.assertOwnedEndpoint(row, policy);
  for (const patch of [
    { appId: crypto.randomUUID() },
    { thumbprint: "B".repeat(40) },
    { storeName: "WebHosting" },
  ])
    assert.throws(() => h.assertOwnedEndpoint({ ...row, ...patch }, policy));
  assert.throws(() => h.assertOwnedEndpoint(undefined, policy));
});
test("sticky borrowed-key guard refuses parent cleanup and native site scripts reject injection", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-ipv6-proof-"));
  try {
    h.assertCleanupSafe(root);
    fs.writeFileSync(path.join(root, h.guardName), "owned", { flag: "wx" });
    assert.throws(() => h.assertCleanupSafe(root));
    assert.equal(
      fs.readFileSync(path.join(root, h.guardName), "utf8"),
      "owned",
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  const script = h.siteScript({
    name: `CertOps-IPv6-${crypto.randomUUID()}`,
    directory: root,
    information: "[::1]:18443:localhost",
    sni: true,
  });
  assert.ok(script.includes(".Bindings[0].SslFlags=1"));
  assert.throws(() =>
    h.siteScript({
      name: "foreign';Remove-Item",
      directory: root,
      information: "[::1]:18443:localhost",
      sni: true,
    }),
  );
  assert.throws(() =>
    h.siteScript({
      name: `CertOps-IPv6-${crypto.randomUUID()}`,
      directory: root,
      information: "*;bad",
      sni: true,
    }),
  );
});

test("wildcard and other selectors cannot silently confound either owned fixture port", () => {
  h.assertNoPortConflicts(
    [{ keyedBy: "ipport", ipPort: "[::]:18445" }],
    [18443, 18444],
  );
  for (const ipPort of [
    "[::]:18443",
    "0.0.0.0:18443",
    "127.0.0.1:18444",
    "foreign.example:18443",
  ])
    assert.throws(() => h.assertNoPortConflicts([{ ipPort }], [18443, 18444]));
  assert.throws(() =>
    h.assertNoPortConflicts([{ ipPort: null }], [18443, 18444]),
  );
});
test("nested and root host cleanup guard borrowed keys before native removal", () => {
  const parent = fs.readFileSync(
      path.join(__dirname, "../packages/agent/scripts/host/iis-fixture.js"),
      "utf8",
    ),
    host = fs.readFileSync(
      path.join(
        __dirname,
        "../packages/agent/scripts/host/windows-host.test.js",
      ),
      "utf8",
    );
  assert.ok(
    parent.indexOf("windows-iis-ipv6-native-shadow-rollback") <
      parent.indexOf("windows-iis-rollback-failure"),
  );
  const cleanup = parent.slice(parent.indexOf("  finally {"));
  assert.ok(
    cleanup.indexOf("ipv6-shadow-fixture") <
      cleanup.indexOf("if (siteCreated)"),
  );
  assert.ok(
    host.includes(
      'require("./ipv6-shadow-fixture").assertCleanupSafe(workDir)',
    ),
  );
});
