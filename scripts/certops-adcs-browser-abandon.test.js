"use strict";
/** Bounded proof, native-observation refusal and retained-owner lifecycle only.
 * These checks never launch Chromium, mutate trust or execute native AD CS. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-adcs-browser-abandon"),
  {
    releaseBrowserResource,
  } = require("../tests/e2e/helpers/certops-adcs-browser-session");
const id = "11111111-1111-1111-1111-111111111111",
  job = "22222222-2222-2222-2222-222222222222";
function proof() {
  return {
    scope: helper.SCOPE,
    enrollmentId: id,
    cleanupJobId: job,
    abandonPosts: 1,
    keepPosts: 0,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
function native() {
  return {
    enrollmentId: id,
    cleanupJobId: job,
    journalState: "abandoned",
    enrollmentState: "abandoned",
    keyPresent: false,
    acceptedLeafCount: 0,
    actualCaRequests: 0,
    auditCount: 1,
    originalJobStatus: "orphaned_unknown_effect",
    needsOperatorReconciliation: true,
  };
}
test("browser abandonment requires explicit single mutation and every native fact", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const value = proof();
    delete value[key];
    assert.throws(() => helper.verifyProof(value));
  }
  for (const change of [
    (p) => (p.scope = "api-only"),
    (p) => (p.abandonPosts = 2),
    (p) => (p.keepPosts = 1),
    (p) => (p.cleanupJobId = "not-a-job"),
    (p) => (p.rawTrace = "private"),
  ]) {
    const value = proof();
    change(value);
    assert.throws(() => helper.verifyProof(value));
  }
  for (const flag of helper.FLAGS) {
    const value = proof();
    value[flag] = false;
    assert.throws(() => helper.verifyProof(value));
  }
});
test("only actual matching native cleanup can complete the browser action proof", () => {
  assert.equal(helper.verifyNativeCompletion(native(), id), true);
  for (const key of Object.keys(native())) {
    const value = native();
    delete value[key];
    assert.throws(() => helper.verifyNativeCompletion(value, id), key);
    const bad = native();
    bad[key] =
      typeof bad[key] === "boolean"
        ? !bad[key]
        : typeof bad[key] === "number"
          ? bad[key] + 1
          : "invalid";
    assert.throws(() => helper.verifyNativeCompletion(bad, id), key);
  }
  assert.throws(() => helper.verifyNativeCompletion(native(), job));
  assert.throws(() => helper.verifyNativeCompletion(native(), undefined));
});
test("released sequential browser owner cannot delete a later trust receipt", async () => {
  let receipt = true,
    live = true,
    closes = 0;
  const resource = releaseBrowserResource({
    hasOwnershipReceipt: () => receipt,
    hasLiveChild: () => live,
    close() {
      closes++;
      live = false;
      receipt = false;
    },
  });
  assert.equal(resource.hasLiveChild(), true);
  await resource.close();
  assert.equal(resource.hasLiveChild(), false);
  receipt = true;
  live = true;
  assert.equal(resource.hasOwnershipReceipt(), false);
  await resource.close();
  assert.equal(closes, 1);
  assert.equal(receipt, true);
  assert.equal(live, true);
});
test("failed browser drainage retains retryable ownership", async () => {
  let fail = true,
    closes = 0;
  const resource = releaseBrowserResource({
    hasOwnershipReceipt: () => true,
    hasLiveChild: () => true,
    close() {
      closes++;
      if (fail) throw Error("retained");
    },
  });
  await assert.rejects(resource.close());
  assert.equal(resource.hasOwnershipReceipt(), true);
  assert.equal(resource.hasLiveChild(), true);
  fail = false;
  await resource.close();
  assert.equal(closes, 2);
  assert.equal(resource.hasOwnershipReceipt(), false);
});
test("critical UI route, runtime and native observer sources are explicit", () => {
  assert.equal(
    new Set(helper.REQUIRED_SOURCES).size,
    helper.REQUIRED_SOURCES.length,
  );
  for (const file of helper.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile());
  assert.equal(helper.REQUIRED_SCENARIOS.length, 2);
  const session = fs.readFileSync(
    path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-adcs-browser-session.js",
    ),
    "utf8",
  );
  assert.ok(session.includes("ignoreHTTPSErrors: false"));
  assert.ok(session.includes('require("playwright/package.json").version'));
});

test("closed original journey owner preserves a later live session receipt after failed drainage", async () => {
  const os = require("node:os"),
    base = require("../tests/e2e/helpers/certops-adcs-browser-journey");
  const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-browser-release-"),
    ),
    receipt = path.join(directory, "browser-api-trust.json");
  try {
    fs.writeFileSync(receipt, "first public owner");
    let removals = 0;
    const original = base.createOwnedBrowserResource({
      getServer: () => ({
        process: () => ({ pid: 1, exitCode: 0, signalCode: null }),
      }),
      receipt,
      removeTrust: () => {
        removals++;
        fs.unlinkSync(receipt);
      },
    });
    await original.close();
    assert.equal(removals, 1);
    fs.writeFileSync(receipt, "later public owner");
    const active = base.createOwnedBrowserResource({
      getServer: () => ({
        process: () => ({ pid: 2, exitCode: null, signalCode: null }),
        close: () => Promise.reject(Error("retained")),
        kill: () => Promise.reject(Error("retained")),
      }),
      receipt,
      removeTrust: () => {
        throw Error("Must not remove live owner's trust");
      },
    });
    await assert.rejects(active.close(), /preserve browser trust/);
    await original.close();
    assert.equal(removals, 1);
    assert.equal(fs.readFileSync(receipt, "utf8"), "later public owner");
    assert.equal(active.hasLiveChild(), true);
    assert.equal(active.hasOwnershipReceipt(), true);
  } finally {
    if (fs.existsSync(receipt)) fs.unlinkSync(receipt);
    fs.rmdirSync(directory);
  }
});
