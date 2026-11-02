"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const c = require("./certops-retention-cadence-contract"),
  ledger = require("./certops-retention-cadence-ledger");
function snap(fileId, state = "pending_retention", extra = {}) {
  return {
    fileId,
    sha256: state === "deferred" ? "b".repeat(64) : "a".repeat(64),
    row: {
      oldThumbprint: "A".repeat(40),
      lifecycleState: state,
      deferralReason: state === "deferred" ? "deadline_not_reached" : null,
      ...extra,
    },
  };
}
test("only a real pending replacement then same-row timed replacement completes", () => {
  const base = Date.parse("2026-10-15T00:00:00.000Z"),
    t = ledger.createTracker(snap("1:1"), base, 0);
  assert.equal(t.observe(snap("1:1"), base + 10, 10), null);
  assert.ok(t.observe(snap("1:2", "deferred"), base + 1000, 1000).immediate);
  assert.throws(() => t.result());
  const at = 1000 + c.BASE_INTERVAL;
  assert.ok(t.observe(snap("1:3", "deferred"), base + at, at).timer);
  assert.equal(t.result().timer.monotonicMs, at);
});
test("in-place writes, early replacement, lineage changes and clock splice fail", () => {
  const base = Date.parse("2026-10-15T00:00:00.000Z");
  assert.throws(() =>
    ledger
      .createTracker(snap("1:1"), base, 0)
      .observe({ ...snap("1:1"), sha256: "c".repeat(64) }, base + 10, 10),
  );
  assert.throws(() =>
    ledger
      .createTracker(snap("1:1"), base, 0)
      .observe(
        snap("1:2", "deferred", { oldThumbprint: "B".repeat(40) }),
        base + 10,
        10,
      ),
  );
  assert.throws(() =>
    ledger
      .createTracker(snap("1:1"), base, 0)
      .observe(snap("1:2", "deferred"), base + 10000, 10),
  );
  const t = ledger.createTracker(snap("1:1"), base, 0);
  t.observe(snap("1:2", "deferred"), base + 1000, 1000);
  assert.throws(() => t.observe(snap("1:3", "deferred"), base + 2000, 2000));
});

test("bounded snapshot retries actual atomic rename without swallowing same-inode growth", () => {
  const fs = require("node:fs"),
    os = require("node:os"),
    path = require("node:path");
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "certops-cadence-snapshot-")),
  );
  try {
    const file = path.join(directory, "ledger.json"),
      next = path.join(directory, "next.json");
    fs.writeFileSync(file, JSON.stringify({ version: 1 }));
    fs.writeFileSync(next, JSON.stringify({ version: 2 }));
    let opens = 0;
    const snapshot = ledger.readSnapshot(file, {
      ...fs,
      openSync(...args) {
        if (opens++ === 0) fs.renameSync(next, file);
        return fs.openSync(...args);
      },
    });
    assert.equal(snapshot.row.version, 2);
    assert.equal(opens, 2);
    let reads = 0,
      largest = 0;
    assert.throws(() =>
      ledger.readSnapshot(file, {
        ...fs,
        readSync(handle, buffer, ...args) {
          largest = Math.max(largest, buffer.length);
          if (reads++ === 0) fs.appendFileSync(file, "x".repeat(70000));
          return fs.readSync(handle, buffer, ...args);
        },
      }),
    );
    assert.equal(largest, 65537);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
