"use strict";
/** Read-only ledger transition recognizer used by the resident observer.
 * No collector, clock override, ledger write, or certificate operation is exposed.
 * A real native oracle must independently bind the sole installed writer.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const c = require("./certops-retention-cadence-contract");
function sha(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
function identity(stat) {
  assert.ok(stat.isFile() && !stat.isSymbolicLink());
  assert.ok(
    stat.dev > 0n && stat.ino > 0n,
    "Stable native file identity required",
  );
  return `${stat.dev}:${stat.ino}`;
}
function readSnapshot(file, io = fs) {
  const replaced = () =>
    Object.assign(new Error("Atomic ledger replacement during read"), {
      code: "CADENCE_LEDGER_REPLACED",
    });
  for (let attempt = 0; attempt < 3; attempt++) {
    let handle;
    try {
      const before = io.lstatSync(file, { bigint: true }),
        fileId = identity(before);
      assert.ok(
        before.size > 0n && before.size <= 65536n,
        "Ledger bytes exceed bound",
      );
      handle = io.openSync(
        file,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
      );
      const opened = io.fstatSync(handle, { bigint: true });
      if (identity(opened) !== fileId) throw replaced();
      assert.equal(opened.size, before.size, "In-place ledger size changed");
      assert.equal(
        opened.mtimeNs,
        before.mtimeNs,
        "In-place ledger bytes changed",
      );
      // Read at most one byte over the accepted maximum. A concurrent grow
      // cannot turn the pre-read stat into an unbounded allocation/read.
      const buffer = Buffer.alloc(65537);
      let length = 0;
      while (length < buffer.length) {
        const count = io.readSync(
          handle,
          buffer,
          length,
          buffer.length - length,
          length,
        );
        if (count === 0) break;
        length += count;
      }
      assert.ok(
        length <= 65536 && BigInt(length) === opened.size,
        "Ledger size changed during bounded read",
      );
      const after = io.fstatSync(handle, { bigint: true });
      assert.equal(identity(after), fileId);
      assert.equal(after.size, opened.size, "In-place ledger size changed");
      assert.equal(
        after.mtimeNs,
        opened.mtimeNs,
        "In-place ledger bytes changed",
      );
      if (identity(io.lstatSync(file, { bigint: true })) !== fileId)
        throw replaced();
      const bytes = buffer.subarray(0, length);
      return {
        fileId,
        sha256: sha(bytes),
        row: JSON.parse(bytes.toString("utf8")),
      };
    } catch (error) {
      // Only a disappeared/replaced path can retry. Reparse/nonregular paths,
      // size growth, same-inode writes and malformed bytes always fail closed.
      if (
        !["ENOENT", "CADENCE_LEDGER_REPLACED"].includes(error.code) ||
        attempt === 2
      )
        throw error;
    } finally {
      if (handle !== undefined) io.closeSync(handle);
    }
  }
  throw new Error("Owned ledger snapshot unavailable");
}
function immutable(row) {
  const result = { ...row };
  delete result.lifecycleState;
  delete result.deferralReason;
  return result;
}
function verifyTransition(previous, next, expectedState) {
  assert.ok(
    ["pending_retention", "deferred"].includes(previous.row.lifecycleState),
  );
  assert.equal(next.row.lifecycleState, expectedState);
  assert.equal(next.row.deferralReason, "deadline_not_reached");
  assert.notEqual(
    next.fileId,
    previous.fileId,
    "Atomic replacement identity must change",
  );
  // Avoid printing native key/container/DER values in assertion failure diffs.
  assert.ok(
    require("node:util").isDeepStrictEqual(
      immutable(previous.row),
      immutable(next.row),
    ),
    "Immutable owned ledger lineage changed",
  );
  if (previous.row.lifecycleState === "deferred")
    assert.equal(
      next.sha256,
      previous.sha256,
      "Timer must rewrite the same deferred production row",
    );
  return true;
}
function createTracker(pending, startWallMs, startMonotonicMs) {
  assert.equal(pending.row.lifecycleState, "pending_retention");
  assert.equal(pending.row.deferralReason, null);
  for (const n of [startWallMs, startMonotonicMs])
    assert.ok(Number.isSafeInteger(n) && n >= 0);
  let previous = pending,
    immediate = null,
    completed = null,
    last = startMonotonicMs;
  return {
    observe(snapshot, wallMs, monotonicMs) {
      assert.ok(
        Number.isSafeInteger(wallMs) &&
          Number.isSafeInteger(monotonicMs) &&
          monotonicMs >= last,
      );
      assert.ok(monotonicMs - startMonotonicMs < c.MAX);
      assert.ok(
        Math.abs(wallMs - startWallMs - (monotonicMs - startMonotonicMs)) <=
          5000,
        "Wall/monotonic divergence",
      );
      last = monotonicMs;
      if (snapshot.fileId === previous.fileId) {
        assert.equal(
          snapshot.sha256,
          previous.sha256,
          "In-place ledger mutation forbidden",
        );
        if (immediate)
          assert.ok(
            monotonicMs <=
              immediate.monotonicMs + c.MAX_INTERVAL + c.OBSERVATION_MARGIN,
            "Default timer did not rewrite ledger",
          );
        return null;
      }
      assert.equal(completed, null, "Unexpected extra timer rewrite");
      verifyTransition(previous, snapshot, "deferred");
      if (!immediate) {
        assert.ok(
          monotonicMs - startMonotonicMs < c.OBSERVATION_MARGIN,
          "Immediate startup sweep not observed promptly",
        );
        immediate = {
          monotonicMs,
          observedAt: new Date(wallMs).toISOString(),
          fileId: snapshot.fileId,
        };
      } else {
        c.verifyTimerWindow(immediate.monotonicMs, monotonicMs, monotonicMs);
        completed = {
          monotonicMs,
          observedAt: new Date(wallMs).toISOString(),
          fileId: snapshot.fileId,
        };
      }
      previous = snapshot;
      return completed
        ? { immediate: { ...immediate }, timer: { ...completed } }
        : { immediate: { ...immediate } };
    },
    result() {
      assert.ok(completed, "Actual timer rewrite not observed");
      return { immediate: { ...immediate }, timer: { ...completed } };
    },
  };
}
module.exports = {
  sha,
  identity,
  readSnapshot,
  immutable,
  verifyTransition,
  createTracker,
};
