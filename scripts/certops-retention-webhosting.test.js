"use strict";
/** Supporting closed proof and source admission only: no native certificate,
 * service, CA, retention mutation or elapsed-wait qualification executes. */
const test = require("node:test"),
  assert = require("node:assert/strict");
const h = require("../packages/agent/scripts/host/retention-webhosting-fixture");
function elapsed() {
  return {
    mode: "real-clock-two-cutover-expiry-grace",
    successfulCutovers: 2,
    predecessorCertificatesRemoved: 2,
    predecessorKeysRemoved: 2,
    lineageRowsFinalized: 2,
    immediateDeferralPreservedCustody: true,
    immutableHistoryPreserved: true,
    replacementTrustedBoundCustodyUnchanged: true,
    interruptedNativeDeleteRecovered: true,
    configuredRetentionHours: 24,
    fullRetentionWindowQualified: false,
    waitedMonotonicMs: 420000,
    ownedInterruption: {
      scope: "owned-short-retention-native-interruption-drain",
      assignedBeforeResume: true,
      rootExit86: true,
      nativeActiveZero: true,
      nativeHandlesClosed: true,
      wrapperClosed: true,
    },
  };
}
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    store: "WebHosting",
    storeReceipt: {
      store: "WebHosting",
      ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
    },
    elapsed: elapsed(),
    borrowedReplacement: {
      sameOriginalMyCustodyAndInventory: true,
      sameOriginalMyPrivateKeyPossession: true,
      mirrorRemovedWithoutDeletingSharedKey: true,
      originalFixtureCertificateAndKeyRemoved: true,
    },
    fullRetentionWindowQualified: false,
    installedServiceTimerQualified: false,
  };
}
test("WebHosting expiry proof requires distinct native store receipt and actual inherited elapsed controls", () => {
  h.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const value = proof();
    delete value[key];
    assert.throws(() => h.verifyProof(value));
  }
  for (const key of h.FLAGS) {
    const value = proof();
    value.storeReceipt[key] = false;
    assert.throws(() => h.verifyProof(value));
  }
  for (const patch of [
    { store: "My" },
    { fullRetentionWindowQualified: true },
    { installedServiceTimerQualified: true },
    { rawContainer: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
  for (const patch of [
    { store: "My" },
    { nativeIisWebHostingStoreObserved: false },
    { privateStoreRows: [] },
  ]) {
    const value = proof();
    Object.assign(value.storeReceipt, patch);
    assert.throws(() => h.verifyProof(value));
  }
  const value = proof();
  value.elapsed.waitedMonotonicMs = 0;
  assert.throws(() => h.verifyProof(value));
});
test("non-default wrapper refuses a My-only engine before native work", () => {
  for (const engine of [
    {},
    { SUPPORTED_STORES: ["My"], qualifyElapsedRetention() {} },
    { SUPPORTED_STORES: ["My", "WebHosting"], qualifyElapsedRetention() {} },
  ])
    assert.throws(() => h.verifyEngineContract(engine));
  assert.doesNotThrow(() =>
    h.verifyEngineContract({
      SUPPORTED_STORES: ["My", "WebHosting"],
      qualifyElapsedRetention() {},
      verifyElapsedStoreResult() {},
    }),
  );
});
test("WebHosting contained child grammar is explicit and cannot change original resident contract", () => {
  const {
      parseArguments,
    } = require("../packages/agent/scripts/host/retention-interrupted-child"),
    base = [
      "C:\\owned\\elapsed-retention-00000000-0000-4000-8000-000000000000\\state",
      "A".repeat(40),
      "tokentimer-enr-00000000-0000-4000-8000-000000000000",
    ],
    go = "--owned-go=C:\\owned\\go";
  assert.equal(
    parseArguments([...base, "--store=WebHosting", go]).store,
    "WebHosting",
  );
  assert.equal(parseArguments(base).store, undefined);
  for (const args of [
    [...base, "--store=Root", go],
    [...base, "--store=WebHosting"],
    [...base, "--retention-hours=168", "--store=WebHosting", go],
    [...base, "C:\\owned\\resident.json", "b".repeat(64), "--store=WebHosting"],
    [...base, "--store=My", "--store=WebHosting", go],
  ])
    assert.throws(() => parseArguments(args));
});
test("retention TLS success waits for actual socket close before native mutation can continue", async () => {
  const tls = require("node:tls"),
    { EventEmitter } = require("node:events"),
    engine = require("../packages/agent/scripts/host/retention-elapsed-fixture");
  const original = tls.connect;
  let socket,
    verified = false,
    finished = false;
  try {
    tls.connect = (_options, onSecure) => {
      socket = new EventEmitter();
      socket.authorized = true;
      socket.getPeerCertificate = () => ({
        fingerprint: "AA:".repeat(19) + "AA",
      });
      socket.setTimeout = () => socket;
      socket.destroy = () => {
        verified = true;
        return socket;
      };
      setImmediate(onSecure);
      return socket;
    };
    const pending = engine
      .trustedLeaf(443, "owned-public-ca", "AA".repeat(20))
      .then(() => {
        finished = true;
      });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(verified, true);
    assert.equal(finished, false);
    socket.emit("close");
    await pending;
    assert.equal(finished, true);
  } finally {
    tls.connect = original;
  }
});
test("borrowed replacement proof requires native My preservation before explicit original fixture cleanup", () => {
  for (const flag of Object.keys(proof().borrowedReplacement)) {
    const value = proof();
    value.borrowedReplacement[flag] = false;
    assert.throws(() => h.verifyProof(value));
  }
  const value = proof();
  value.borrowedReplacement.rawUniqueName = "private";
  assert.throws(() => h.verifyProof(value));
  const replacement = require("../packages/agent/scripts/host/retention-webhosting-replacement");
  assert.throws(() => replacement.custodyScript("Root", "A".repeat(40)));
  assert.throws(() =>
    replacement.removalScript("Root;evil", "A".repeat(40), "b".repeat(64)),
  );
  for (const store of ["My", "WebHosting", "Root"]) {
    const script = replacement.removalScript(
      store,
      "A".repeat(40),
      "b".repeat(64),
    );
    assert.ok(!script.includes("-DeleteKey"));
    assert.ok(script.includes("ComputeHash"));
  }
});
test("WebHosting runner remains manual Azure-free and bounded without replacing existing My controls", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    { createRequire } = require("node:module"),
    yaml = createRequire(
      require.resolve(
        path.resolve(__dirname, "../node_modules/mocha/package.json"),
      ),
    )("js-yaml"),
    name = "certops-windows-webhosting-retention.yml",
    workflow = yaml.load(
      fs.readFileSync(
        path.join(__dirname, "../.github/workflows", name),
        "utf8",
      ),
    ),
    runner = require("./certops-windows-webhosting-retention");
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(workflow.permissions, { contents: "read" });
  assert.equal(workflow.jobs.native["timeout-minutes"], 20);
  assert.equal(
    workflow.jobs.native.steps.find(
      (x) =>
        x.name === "Genuine WebHosting expiry grace and owned native recovery",
    )["timeout-minutes"],
    15,
  );
  assert.equal(workflow.jobs.native.if, "github.ref == 'refs/heads/main'");
  assert.deepEqual(workflow.jobs.native.strategy.matrix.os, [
    "windows-2022",
    "windows-2025",
  ]);
  assert.deepEqual(
    require("./certops-workflow-security").validateWorkflow(workflow, name),
    [],
  );
  for (const source of runner.REQUIRED_SOURCES)
    assert.ok(fs.existsSync(path.resolve(__dirname, "..", source)), source);
  assert.ok(!JSON.stringify(workflow).includes("AZURE"));
  assert.deepEqual(
    require("../packages/agent/scripts/host/retention-policy-expiry-proof")
      .POLICIES,
    [168, 720],
  );
});
