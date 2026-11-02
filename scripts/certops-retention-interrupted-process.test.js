"use strict";
// Pure process-custody contracts: no native collector or certificate fixture runs.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const helper = require("../packages/agent/scripts/host/retention-interrupted-process");
function proof() {
  return {
    scope: "owned-short-retention-native-interruption-drain",
    assignedBeforeResume: true,
    rootExit86: true,
    nativeActiveZero: true,
    nativeHandlesClosed: true,
    wrapperClosed: true,
  };
}
test("short retention child proof requires exact retained containment and closed wrapper", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const missing = proof();
    delete missing[key];
    assert.throws(() => helper.verifyProof(missing));
    const wrong = proof();
    wrong[key] = false;
    assert.throws(() => helper.verifyProof(wrong));
  }
  assert.throws(() =>
    helper.verifyProof({ ...proof(), rawProcessCommand: "private" }),
  );
});
test("durable short retention receipt blocks broad cleanup even without a live JS owner", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-short-retention-guard-"),
  );
  try {
    helper.assertCleanupSafe(root);
    const receipt = path.join(root, ".preserve-short-retention-owned.json");
    fs.writeFileSync(receipt, "{}", { flag: "wx" });
    assert.throws(() => helper.assertCleanupSafe(root));
    fs.unlinkSync(receipt);
    helper.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
test("native collector gate follows suspended owned launch and cleanup drains before key removal", () => {
  const source = fs.readFileSync(
    require.resolve("../packages/agent/scripts/host/retention-interrupted-process"),
    "utf8",
  );
  assert.match(source, /startContainedNativeProcess/);
  assert.match(source, /onCreated/);
  assert.match(source, /stopAndDrain/);
  assert.doesNotMatch(source, /taskkill|Stop-Process/);
  const engine = fs.readFileSync(
    require.resolve("../packages/agent/scripts/host/retention-elapsed-fixture"),
    "utf8",
  );
  assert.doesNotMatch(engine, /spawnSync/);
  assert.ok(
    engine.lastIndexOf("drainBeforeCleanup") <
      engine.lastIndexOf("removeAbandonedKeyContainer"),
  );
  assert.match(engine, /CngKey\]::Exists/);
});

test("actual child argument parser handles all short policies and original resident arguments without native work", () => {
  const {
    parseArguments,
  } = require("../packages/agent/scripts/host/retention-interrupted-child");
  const state = path.win32.join(
      "C:\\certops-owned",
      "elapsed-retention-11111111-1111-1111-1111-111111111111",
      "state",
    ),
    go = path.win32.join(path.win32.dirname(state), "interrupted-native-go"),
    thumb = "A".repeat(40),
    container = "tokentimer-enr-11111111-1111-1111-1111-111111111111";
  for (const hours of [24, 168, 720]) {
    const args = [
      state,
      thumb,
      container,
      ...(hours === 24 ? [] : [`--retention-hours=${hours}`]),
      `--owned-go=${go}`,
    ];
    const value = parseArguments(args);
    assert.equal(value.retentionHours, hours);
    assert.equal(value.ownedGo, go);
    assert.equal(value.residentConfigPath, undefined);
    assert.equal(args.at(-1), `--owned-go=${go}`);
  }
  const config =
    "C:\\ttqualification\\retention24h\\" +
    "b".repeat(64) +
    "\\keeper-config.json";
  const resident = [state, thumb, container, config, "c".repeat(64)];
  assert.equal(parseArguments(resident).retentionHours, 24);
  assert.equal(parseArguments(resident).residentConfigPath, config);
  for (const args of [
    [state, thumb, container, "--retention-hours=24"],
    [state, thumb, container, "--retention-hours=721"],
    [...resident, `--owned-go=${go}`],
    [...resident, "--retention-hours=168"],
    [state, thumb, container, "--retention-hours=168", "extra"],
  ])
    assert.throws(() => parseArguments(args));
});
