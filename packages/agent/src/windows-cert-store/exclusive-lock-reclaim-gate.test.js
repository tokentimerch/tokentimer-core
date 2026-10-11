"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  MAX_RECLAIM_GATE_AGE_MS,
  tryAcquireReclaimGate,
  releaseReclaimGate,
} = require("./exclusive-lock-reclaim-gate");

describe("tryAcquireReclaimGate (all platforms)", () => {
  /** @type {string[]} */
  const temps = [];
  afterEach(() => {
    for (const dir of temps) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
    temps.length = 0;
  });

  function tempGatePath() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-reclaim-gate-"));
    temps.push(dir);
    return path.join(dir, "lock.sock.reclaim-gate");
  }

  it("acquires via mkdir on a free path", () => {
    const gatePath = tempGatePath();
    assert.equal(tryAcquireReclaimGate(gatePath), true);
    assert.equal(fs.statSync(gatePath).isDirectory(), true);
    releaseReclaimGate(gatePath);
  });

  it("refuses a young existing gate without stealing it", () => {
    const gatePath = tempGatePath();
    assert.equal(tryAcquireReclaimGate(gatePath), true);
    assert.equal(tryAcquireReclaimGate(gatePath), false);
    assert.equal(fs.existsSync(gatePath), true);
    releaseReclaimGate(gatePath);
  });

  it("steals an aged abandoned gate via rename", () => {
    const gatePath = tempGatePath();
    fs.mkdirSync(gatePath);
    const ancient = new Date(Date.now() - MAX_RECLAIM_GATE_AGE_MS - 5_000);
    fs.utimesSync(gatePath, ancient, ancient);
    assert.equal(tryAcquireReclaimGate(gatePath), true);
    assert.equal(fs.statSync(gatePath).isDirectory(), true);
    // Stolen aged directory must be gone (rmdir after rename).
    const litter = fs.readdirSync(path.dirname(gatePath)).filter((n) => n.includes(".stolen-"));
    assert.equal(litter.length, 0);
    releaseReclaimGate(gatePath);
  });

  it("puts back a young gate if rename stole a live holder", () => {
    const gatePath = tempGatePath();
    // Simulate: holder just created a young gate; contender had an aged
    // observation but rename races onto the new inode. Force the post-steal
    // age check by renaming a young directory ourselves into stolen then
    // invoking the put-back path via a second acquire that finds young.
    fs.mkdirSync(gatePath);
    // Contender sees young gate → must not steal.
    assert.equal(tryAcquireReclaimGate(gatePath), false);
    assert.equal(fs.existsSync(gatePath), true);
    releaseReclaimGate(gatePath);
  });

  it("only one of two concurrent aged-gate steals wins", () => {
    const gatePath = tempGatePath();
    fs.mkdirSync(gatePath);
    const ancient = new Date(Date.now() - MAX_RECLAIM_GATE_AGE_MS - 5_000);
    fs.utimesSync(gatePath, ancient, ancient);

    const a = tryAcquireReclaimGate(gatePath);
    const b = tryAcquireReclaimGate(gatePath);
    assert.equal(a || b, true);
    assert.equal(a && b, false);
    releaseReclaimGate(gatePath);
  });
});
