"use strict";

/** Retention boundary proof. A wait under 24 hours cannot qualify the elapsed
 * run. Configuration and deadline boundaries do not claim that run either. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-windows-retention-boundaries");

const RUN = "e5".repeat(16);

function manifest() {
  return helper.createRunManifest({
    runId: RUN,
    root: `C:\\qualification\\tt-ret-${RUN}`,
  });
}

test("configuration and deadline boundaries do not claim a 24 hour elapsed run", () => {
  const owned = manifest();
  const cases = [
    [0, "zero", false],
    [-4, "negative", false],
    [23, "below-minimum", false],
    [helper.MIN_RETENTION_HOURS, "minimum", true],
    [helper.DEFAULT_RETENTION_HOURS, "default", true],
    [helper.DEFAULT_RETENTION_HOURS + 1, "above-default", true],
    [helper.MAX_RETENTION_HOURS, "above-default", true],
    [helper.MAX_RETENTION_HOURS + 1, "above-maximum", false],
  ];
  for (const [hours, boundary, accepted] of cases) {
    const result = helper.classifyConfiguration(owned, hours);
    helper.verifyProof(result.proof);
    assert.equal(result.proof.boundary, boundary, String(hours));
    assert.equal(result.proof.acceptedConfiguration, accepted);
    assert.equal(result.proof.twentyFourHourElapsedQualified, false);
    assert.equal(result.passed, false);
    assert.throws(() => helper.qualificationGate(result.proof), /cannot be shortened/);
  }
  assert.throws(() => helper.classifyConfiguration(owned, 1.5));
  const deadline = helper.classifyDeadline(owned, { deadlineMs: 1000, nowMs: 1000 });
  assert.equal(deadline.proof.boundary, "exact-deadline");
  assert.equal(helper.classifyDeadline(owned, { deadlineMs: 1000, nowMs: 999 }).proof.boundary, "before-deadline");
  assert.equal(helper.classifyDeadline(owned, { deadlineMs: 1000, nowMs: 1001 }).proof.boundary, "after-deadline");
  assert.equal(deadline.proof.twentyFourHourElapsedQualified, false);
  assert.throws(() =>
    helper.assertOwnedCommands(owned, [{ file: "netsh.exe", args: ["int", "ip", "reset"] }]),
  );
});

test("a wait below 24 hours fails the qualification gate", () => {
  const owned = manifest();
  const shortWait = helper.DAY_MS - 1;
  assert.throws(() => helper.evaluateElapsed(owned, shortWait), (error) => {
    assert.equal(error.passed, false);
    assert.equal(error.twentyFourHourElapsedQualified, false);
    assert.equal(error.proof.twentyFourHourElapsedQualified, false);
    assert.equal(error.proof.waitedMs, shortWait);
    assert.match(error.message, /cannot be shortened/);
    return true;
  });
  assert.throws(() => helper.evaluateElapsed(owned, helper.DAY_MS), /does not claim the elapsed run/);
  const proof = helper.classifyConfiguration(owned, helper.DEFAULT_RETENTION_HOURS).proof;
  assert.throws(() => helper.verifyProof({ ...proof, twentyFourHourElapsedQualified: true }));
  for (const flag of helper.CLOSED) {
    assert.throws(() => helper.verifyProof({ ...proof, [flag]: true }), flag);
  }
  const entry = require("./certops-windows-retention-boundaries");
  assert.equal(entry.run({ probe: {} }).passed, false);
  const script = path.resolve(__dirname, "certops-windows-retention-boundaries.js");
  const spawned = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(spawned.status, 1);
  assert.equal(JSON.parse(spawned.stdout).passed, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-ret-"));
  try {
    const file = path.join(dir, "elapsed.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        kind: "elapsed",
        runId: RUN,
        root: owned.root,
        waitedMs: 60 * 60 * 1000,
      }),
    );
    const checked = spawnSync(process.execPath, [script, "--check", file], { encoding: "utf8" });
    assert.equal(checked.status, 1);
    const body = JSON.parse(checked.stdout);
    assert.equal(body.passed, false);
    assert.equal(body.twentyFourHourElapsedQualified, false);
    assert.equal(body.proof.twentyFourHourElapsedQualified, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.resolve(__dirname, "..");
  for (const rel of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, rel)), true, rel);
});
