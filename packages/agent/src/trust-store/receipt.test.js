"use strict";

const { describe, it, afterEach, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const receipt = require("./receipt.js");

const STORE = "Root";
const FP_A = "a".repeat(64);
const FP_B = "b".repeat(64);

const tempDirs = [];
function makeTempReceiptDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-trust-receipt-test-"));
  tempDirs.push(dir);
  return path.join(dir, "receipts");
}
afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe("trust-store/receipt: id and path determinism", () => {
  it("receiptId is deterministic for the same (store, fingerprint) pair", () => {
    const id1 = receipt.receiptId(STORE, FP_A);
    const id2 = receipt.receiptId(STORE, FP_A);
    assert.equal(id1, id2);
    assert.match(id1, /^[a-f0-9]{64}$/);
  });

  it("receiptId differs for different fingerprints under the same store", () => {
    assert.notEqual(receipt.receiptId(STORE, FP_A), receipt.receiptId(STORE, FP_B));
  });

  it("receiptId differs for the same fingerprint under different stores (cross-signed-root independence)", () => {
    assert.notEqual(receipt.receiptId("Root", FP_A), receipt.receiptId("CA", FP_A));
  });

  it("rejects an invalid store or fingerprint", () => {
    assert.throws(() => receipt.receiptId("", FP_A));
    assert.throws(() => receipt.receiptId(STORE, "not-a-fingerprint"));
  });
});

describe("trust-store/receipt: validateReceiptRow", () => {
  function validRow(overrides = {}) {
    return {
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-1",
      transitionGeneration: 1,
      state: "installed",
      intentWrittenAt: new Date().toISOString(),
      finalizedAt: new Date().toISOString(),
      ...overrides,
    };
  }

  it("accepts a well-formed row and normalizes field order/derived id", () => {
    const validated = receipt.validateReceiptRow(validRow());
    assert.equal(validated.id, receipt.receiptId(STORE, FP_A));
    assert.equal(validated.store, STORE);
  });

  const badCases = [
    ["missing store", { store: undefined }],
    ["bad fingerprint", { fingerprintSha256: "xyz" }],
    ["bad jobId", { jobId: "" }],
    ["non-integer generation", { transitionGeneration: 1.5 }],
    ["zero generation", { transitionGeneration: 0 }],
    ["invalid state", { state: "bogus" }],
    ["bad intentWrittenAt", { intentWrittenAt: "not-a-date" }],
    ["bad finalizedAt", { finalizedAt: "not-a-date" }],
  ];
  for (const [label, overrides] of badCases) {
    it(`rejects ${label}`, () => {
      assert.throws(() => receipt.validateReceiptRow(validRow(overrides)));
    });
  }

  it("rejects a row whose own id field does not match its derived id", () => {
    assert.throws(() => receipt.validateReceiptRow(validRow({ id: "wrong-id" })));
  });

  it("rejects a non-object row", () => {
    assert.throws(() => receipt.validateReceiptRow(null));
    assert.throws(() => receipt.validateReceiptRow("nope"));
  });
});

describe("trust-store/receipt: install lifecycle (real temp directory, atomic write + fsync)", () => {
  it("readReceipt returns null when no receipt has ever been written", () => {
    const receiptDir = makeTempReceiptDir();
    assert.equal(receipt.readReceipt(receiptDir, STORE, FP_A), null);
  });

  it("writeIntentReceipt -> readReceipt -> finalizeReceipt round-trips through pending_install -> installed", () => {
    const receiptDir = makeTempReceiptDir();

    const intent = receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-install-1",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    assert.equal(intent.state, "pending_install");
    assert.equal(intent.finalizedAt, null);

    const afterIntent = receipt.readReceipt(receiptDir, STORE, FP_A);
    assert.equal(afterIntent.row.state, "pending_install");
    assert.equal(afterIntent.row.jobId, "job-install-1");

    const finalized = receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-install-1",
      transitionGeneration: 1,
    });
    assert.equal(finalized.state, "installed");
    assert.notEqual(finalized.finalizedAt, null);

    const afterFinalize = receipt.readReceipt(receiptDir, STORE, FP_A);
    assert.equal(afterFinalize.row.state, "installed");
  });

  it("writeIntentReceipt allows re-writing the SAME jobId/transitionGeneration over its own pending row (resumed attempt after a crash)", () => {
    const receiptDir = makeTempReceiptDir();

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-resumable",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    const resumed = receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-resumable",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    assert.equal(resumed.state, "pending_install");
    assert.equal(resumed.jobId, "job-resumable");
  });

  it("writeIntentReceipt refuses to overwrite an existing pending row owned by a DIFFERENT jobId/transitionGeneration", () => {
    const receiptDir = makeTempReceiptDir();

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-first",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    assert.throws(
      () =>
        receipt.writeIntentReceipt({
          receiptDir,
          store: STORE,
          fingerprintSha256: FP_A,
          jobId: "job-second",
          transitionGeneration: 2,
          intentState: "pending_install",
        }),
      /refusing to overwrite/,
    );

    // The refused write must not have clobbered the original pending row.
    const stillPending = receipt.readReceipt(receiptDir, STORE, FP_A);
    assert.equal(stillPending.row.jobId, "job-first");
    assert.equal(stillPending.row.transitionGeneration, 1);
  });

  it("writeIntentReceipt with reclaimStalePending:true overwrites a stale pending row owned by a DIFFERENT jobId/transitionGeneration", () => {
    const receiptDir = makeTempReceiptDir();

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-crashed",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    // Simulates the caller having re-probed the live OS store and confirmed
    // the crashed job's intent never reached it, so there is nothing left
    // to race against (see writeIntentReceipt's reclaimStalePending doc).
    const reclaimed = receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-retry",
      transitionGeneration: 3,
      intentState: "pending_install",
      reclaimStalePending: true,
    });

    assert.equal(reclaimed.jobId, "job-retry");
    assert.equal(reclaimed.transitionGeneration, 3);
    const onDisk = receipt.readReceipt(receiptDir, STORE, FP_A);
    assert.equal(onDisk.row.jobId, "job-retry");
    assert.equal(onDisk.row.transitionGeneration, 3);
  });

  it("writeIntentReceipt with reclaimStalePending:true does not need to reclaim its OWN pending row (no-op passthrough)", () => {
    const receiptDir = makeTempReceiptDir();

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-resumed",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    const resumed = receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-resumed",
      transitionGeneration: 1,
      intentState: "pending_install",
      reclaimStalePending: true,
    });

    assert.equal(resumed.jobId, "job-resumed");
    assert.equal(resumed.transitionGeneration, 1);
  });

  it("writeIntentReceipt -> finalizeReceipt round-trips through pending_remove -> removed", () => {
    const receiptDir = makeTempReceiptDir();
    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-install-1",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-install-1",
      transitionGeneration: 1,
    });

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-remove-1",
      transitionGeneration: 2,
      intentState: "pending_remove",
    });
    const finalized = receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-remove-1",
      transitionGeneration: 2,
    });
    assert.equal(finalized.state, "removed");
  });

  it("two different fingerprints under the same store persist as fully independent receipts", () => {
    const receiptDir = makeTempReceiptDir();
    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-a",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_B,
      jobId: "job-b",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-a",
      transitionGeneration: 1,
    });

    const a = receipt.readReceipt(receiptDir, STORE, FP_A);
    const b = receipt.readReceipt(receiptDir, STORE, FP_B);
    assert.equal(a.row.state, "installed");
    assert.equal(b.row.state, "pending_install");
  });
});

describe("trust-store/receipt: finalizeReceipt guards", () => {
  it("throws RECEIPT_MISSING when no intent row exists", () => {
    const receiptDir = makeTempReceiptDir();
    assert.throws(
      () =>
        receipt.finalizeReceipt({
          receiptDir,
          store: STORE,
          fingerprintSha256: FP_A,
          jobId: "job-1",
          transitionGeneration: 1,
        }),
      /RECEIPT_MISSING|no intent receipt exists/,
    );
  });

  it("throws RECEIPT_CORRUPT when the existing row on disk fails to parse/validate, distinct from RECEIPT_MISSING", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = receipt.receiptRowPath(receiptDir, STORE, FP_A);
    fs.writeFileSync(rowPath, "{ not valid json", "utf8");

    assert.throws(
      () =>
        receipt.finalizeReceipt({
          receiptDir,
          store: STORE,
          fingerprintSha256: FP_A,
          jobId: "job-1",
          transitionGeneration: 1,
        }),
      (err) => err.code === "RECEIPT_CORRUPT" && /is corrupt/.test(err.message),
    );
  });

  it("throws RECEIPT_GENERATION_MISMATCH when jobId/transitionGeneration differ from the intent row", () => {
    const receiptDir = makeTempReceiptDir();
    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-1",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    assert.throws(
      () =>
        receipt.finalizeReceipt({
          receiptDir,
          store: STORE,
          fingerprintSha256: FP_A,
          jobId: "job-1",
          transitionGeneration: 2,
        }),
      /RECEIPT_GENERATION_MISMATCH|was written for/,
    );
    assert.throws(
      () =>
        receipt.finalizeReceipt({
          receiptDir,
          store: STORE,
          fingerprintSha256: FP_A,
          jobId: "job-2",
          transitionGeneration: 1,
        }),
      /RECEIPT_GENERATION_MISMATCH|was written for/,
    );
  });

  it("throws RECEIPT_NOT_PENDING when finalizing an already-terminal row", () => {
    const receiptDir = makeTempReceiptDir();
    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-1",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-1",
      transitionGeneration: 1,
    });
    assert.throws(
      () =>
        receipt.finalizeReceipt({
          receiptDir,
          store: STORE,
          fingerprintSha256: FP_A,
          jobId: "job-1",
          transitionGeneration: 1,
        }),
      /RECEIPT_NOT_PENDING|terminal state/,
    );
  });
});

describe("trust-store/receipt: missing/corrupt fail-safe", () => {
  it("readReceipt reports {corrupt: true} for malformed JSON on disk, distinct from null (missing)", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = receipt.receiptRowPath(receiptDir, STORE, FP_A);
    fs.writeFileSync(rowPath, "{ not valid json", "utf8");

    const result = receipt.readReceipt(receiptDir, STORE, FP_A);
    assert.notEqual(result, null);
    assert.equal(result.corrupt, true);
    assert.ok(result.error instanceof Error);
  });

  it("readReceipt reports {corrupt: true} for a row that fails shape validation", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = receipt.receiptRowPath(receiptDir, STORE, FP_A);
    fs.writeFileSync(
      rowPath,
      JSON.stringify({ store: STORE, fingerprintSha256: FP_A, state: "not-a-real-state" }),
      "utf8",
    );

    const result = receipt.readReceipt(receiptDir, STORE, FP_A);
    assert.equal(result.corrupt, true);
  });

  it("a missing receipt is null, never confused with a corrupt one", () => {
    const receiptDir = makeTempReceiptDir();
    assert.equal(receipt.readReceipt(receiptDir, STORE, FP_A), null);
  });
});

describe("trust-store/receipt: classifyRecoveryOutcome (decision 20(d) crash-recovery cases)", () => {
  function baseRow(overrides = {}) {
    return {
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-1",
      transitionGeneration: 1,
      intentWrittenAt: new Date().toISOString(),
      finalizedAt: null,
      ...overrides,
    };
  }

  it("pending_install classifies as crash_before_mutation", () => {
    assert.equal(
      receipt.classifyRecoveryOutcome(baseRow({ state: "pending_install" })),
      "crash_before_mutation",
    );
  });

  it("pending_remove classifies as crash_before_mutation", () => {
    assert.equal(
      receipt.classifyRecoveryOutcome(baseRow({ state: "pending_remove" })),
      "crash_before_mutation",
    );
  });

  it("installed classifies as confirmed_installed (never re-derived from a bare presence check)", () => {
    assert.equal(
      receipt.classifyRecoveryOutcome(
        baseRow({ state: "installed", finalizedAt: new Date().toISOString() }),
      ),
      "confirmed_installed",
    );
  });

  it("removed classifies as confirmed_removed", () => {
    assert.equal(
      receipt.classifyRecoveryOutcome(
        baseRow({ state: "removed", finalizedAt: new Date().toISOString() }),
      ),
      "confirmed_removed",
    );
  });
});

describe("trust-store/receipt: sweepReceipts startup sweep", () => {
  it("reports every persisted receipt's recovery classification, skips nothing, and separates corrupt rows", () => {
    const receiptDir = makeTempReceiptDir();

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-a",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-a",
      transitionGeneration: 1,
    });

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_B,
      jobId: "job-b",
      transitionGeneration: 1,
      intentState: "pending_install",
    });

    fs.mkdirSync(receiptDir, { recursive: true });
    const corruptPath = receipt.receiptRowPath(receiptDir, "CA", FP_A);
    fs.writeFileSync(corruptPath, "not json at all", "utf8");

    const sweep = receipt.sweepReceipts({ receiptDir });
    assert.equal(sweep.rows.length, 2);
    assert.equal(sweep.corrupt.length, 1);

    const byFingerprint = new Map(sweep.rows.map((r) => [r.fingerprintSha256, r]));
    assert.equal(byFingerprint.get(FP_A).outcome, "confirmed_installed");
    assert.equal(byFingerprint.get(FP_B).outcome, "crash_before_mutation");
  });

  it("sweepReceipts over an empty/never-created directory returns no rows and no corruption", () => {
    const receiptDir = makeTempReceiptDir();
    const sweep = receipt.sweepReceipts({ receiptDir });
    assert.deepEqual(sweep.rows, []);
    assert.deepEqual(sweep.corrupt, []);
  });
});

describe("trust-store/receipt: readReceiptById guards (startup-sweep hardening against a tampered receiptDir)", () => {
  it("reports {corrupt: true} for a symlink at the receipt path, never following it", (t) => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const targetPath = path.join(receiptDir, "real-target.json");
    fs.writeFileSync(targetPath, "not a receipt, just a symlink target", "utf8");
    const id = "deadbeef00000000000000000000000000000000000000000000000000beef";
    const linkPath = path.join(receiptDir, `${id}.json`);
    try {
      fs.symlinkSync(targetPath, linkPath, "file");
    } catch (err) {
      // skip-reason: no-host - symlink creation is unavailable on this host
      // (commonly Windows without Developer Mode / elevated privileges).
      t.skip(`symlink creation is unavailable: ${err.code || err.message}`);
      return;
    }

    const result = receipt.readReceiptById(receiptDir, id);
    assert.notEqual(result, null);
    assert.equal(result.corrupt, true);
    assert.match(result.error.message, /not a regular file/);
  });

  it("reports {corrupt: true} for a receipt file exceeding MAX_RECEIPT_ROW_BYTES, without reading its contents into memory", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const id = "cafebabe00000000000000000000000000000000000000000000000000face";
    const rowPath = path.join(receiptDir, `${id}.json`);
    fs.writeFileSync(rowPath, Buffer.alloc(receipt.MAX_RECEIPT_ROW_BYTES + 1));

    const result = receipt.readReceiptById(receiptDir, id);
    assert.notEqual(result, null);
    assert.equal(result.corrupt, true);
    assert.match(result.error.message, new RegExp(`exceeds ${receipt.MAX_RECEIPT_ROW_BYTES} bytes`));
  });

  it("a same-shaped tampered receipt is caught by sweepReceipts as corrupt, not silently skipped or trusted", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });

    receipt.writeIntentReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-a",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    receipt.finalizeReceipt({
      receiptDir,
      store: STORE,
      fingerprintSha256: FP_A,
      jobId: "job-a",
      transitionGeneration: 1,
    });

    const oversizedId = "cafebabe00000000000000000000000000000000000000000000000000face";
    fs.writeFileSync(path.join(receiptDir, `${oversizedId}.json`), Buffer.alloc(receipt.MAX_RECEIPT_ROW_BYTES + 1));

    const symlinkId = "deadbeef00000000000000000000000000000000000000000000000000beef";
    const targetPath = path.join(receiptDir, "real-target.json");
    fs.writeFileSync(targetPath, "not a receipt", "utf8");
    let symlinkCreated = true;
    try {
      fs.symlinkSync(targetPath, path.join(receiptDir, `${symlinkId}.json`), "file");
    } catch (_err) {
      symlinkCreated = false;
    }

    const sweep = receipt.sweepReceipts({ receiptDir });
    assert.equal(sweep.rows.length, 1);
    assert.equal(sweep.rows[0].fingerprintSha256, FP_A);
    // real-target.json itself is also listed (any *.json file qualifies),
    // so the corrupt count is 2 (oversized + real-target) plus the symlink
    // only when this host actually supports creating one.
    assert.equal(sweep.corrupt.length, symlinkCreated ? 3 : 2);
  });
});

describe("trust-store/receipt: platform-specific protection", () => {
  it("ensureReceiptDir creates a directory that this process can immediately write into", () => {
    const receiptDir = makeTempReceiptDir();
    receipt.ensureReceiptDir(receiptDir);
    assert.equal(fs.existsSync(receiptDir), true);
    const stats = fs.statSync(receiptDir);
    assert.equal(stats.isDirectory(), true);
    if (process.platform !== "win32") {
      assert.equal(stats.mode & 0o777, 0o700);
    }
  });

  it("writeFileAtomically leaves no stray temp file behind on success", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = path.join(receiptDir, "test-row.json");
    receipt.writeFileAtomically(rowPath, "{}\n", 0o600);
    const entries = fs.readdirSync(receiptDir);
    assert.deepEqual(entries, ["test-row.json"]);
  });

  it("writeFileAtomically closes and unlinks the sibling temp file, then rethrows, when the write fails after the fd was opened", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = path.join(receiptDir, "test-row.json");

    const writeFileSyncMock = mock.method(fs, "writeFileSync", () => {
      throw new Error("simulated write failure");
    });
    try {
      assert.throws(
        () => receipt.writeFileAtomically(rowPath, "{}\n", 0o600),
        /simulated write failure/,
      );
    } finally {
      writeFileSyncMock.mock.restore();
    }

    // No sibling .tmp file (or the real target) survives a failed write.
    assert.deepEqual(fs.readdirSync(receiptDir), []);
  });

  it("writeFileAtomically never leaves a torn file behind: a failed write is never mistaken for a valid receipt", () => {
    const receiptDir = makeTempReceiptDir();
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = path.join(receiptDir, "test-row.json");

    const fsyncSyncMock = mock.method(fs, "fsyncSync", () => {
      throw new Error("simulated fsync failure");
    });
    try {
      assert.throws(
        () => receipt.writeFileAtomically(rowPath, "{}\n", 0o600),
        /simulated fsync failure/,
      );
    } finally {
      fsyncSyncMock.mock.restore();
    }

    assert.equal(fs.existsSync(rowPath), false);
    assert.deepEqual(fs.readdirSync(receiptDir), []);
  });
});
