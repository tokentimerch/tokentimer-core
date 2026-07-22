"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  REPLAY_REJECTION_REASON,
  DEFAULT_MAX_ENTRIES,
  createReplayCache,
} = require("./index.js");

const IS_WIN32 = process.platform === "win32";

const tempDirs = [];

function makeStorePath() {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tokentimer-agent-replay-test-"),
  );
  tempDirs.push(dir);
  return path.join(dir, "nested", "replay-store.json");
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_err) {
      // best-effort cleanup
    }
  }
});

const NOW_MS = Date.parse("2026-07-22T12:00:00.000Z");
const FUTURE_MS = NOW_MS + 5 * 60 * 1000;

function entry(overrides = {}) {
  return {
    nonce: crypto.randomUUID(),
    jobId: `job-${crypto.randomUUID()}`,
    expiresAt: FUTURE_MS,
    ...overrides,
  };
}

describe("createReplayCache basics", () => {
  it("allows a fresh nonce+jobId via check, then rejects after consume", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    const job = entry();

    assert.deepEqual(cache.check(job), { allowed: true });
    assert.deepEqual(cache.consume(job), { allowed: true });

    const rechecked = cache.check(job);
    assert.equal(rechecked.allowed, false);
    assert.equal(rechecked.rejectionReason, REPLAY_REJECTION_REASON);
    assert.match(rechecked.detail, /replay rejected/i);
  });

  it("treats a duplicate consume as a replay (idempotent-reject)", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    const job = entry();

    assert.deepEqual(cache.consume(job), { allowed: true });
    const second = cache.consume(job);
    assert.equal(second.allowed, false);
    assert.equal(second.rejectionReason, REPLAY_REJECTION_REASON);
  });

  it("keys by nonce + jobId: same nonce with a different jobId is distinct", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    const nonce = crypto.randomUUID();

    assert.deepEqual(
      cache.consume(entry({ nonce, jobId: "job-a" })),
      { allowed: true },
    );
    assert.deepEqual(
      cache.consume(entry({ nonce, jobId: "job-b" })),
      { allowed: true },
    );
    assert.equal(cache.consume(entry({ nonce, jobId: "job-a" })).allowed, false);
  });

  it("does not confuse composite keys via concatenation ambiguity", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    assert.deepEqual(
      cache.consume(entry({ nonce: "aaaabbbbccccdddd:x", jobId: "y" })),
      { allowed: true },
    );
    assert.deepEqual(
      cache.consume(entry({ nonce: "aaaabbbbccccdddd", jobId: "x:y" })),
      { allowed: true },
    );
  });

  it("accepts expiresAt as an ISO string or epoch ms", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    assert.deepEqual(
      cache.consume(entry({ expiresAt: new Date(FUTURE_MS).toISOString() })),
      { allowed: true },
    );
    assert.deepEqual(cache.consume(entry({ expiresAt: FUTURE_MS })), {
      allowed: true,
    });
  });

  it("throws on programmer error: bad inputs to check/consume/factory", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    assert.throws(() => cache.check({ jobId: "j", expiresAt: FUTURE_MS }), /nonce/);
    assert.throws(() => cache.consume({ nonce: "n", expiresAt: FUTURE_MS }), /jobId/);
    assert.throws(
      () => cache.consume({ nonce: "n", jobId: "j", expiresAt: "garbage" }),
      /expiresAt/,
    );
    assert.throws(() => createReplayCache({}), /storePath/);
    assert.throws(
      () => createReplayCache({ storePath: makeStorePath(), maxEntries: 0 }),
      /maxEntries/,
    );
  });
});

describe("persistence", () => {
  it("persists consumed nonces across cache instances (restart survival)", () => {
    const storePath = makeStorePath();
    const job = entry();

    const first = createReplayCache({ storePath, now: () => NOW_MS });
    assert.deepEqual(first.consume(job), { allowed: true });

    const second = createReplayCache({ storePath, now: () => NOW_MS });
    const replayed = second.check(job);
    assert.equal(replayed.allowed, false);
    assert.equal(replayed.rejectionReason, REPLAY_REJECTION_REASON);
  });

  it("writes the store file with 0600 permissions on non-win32", { skip: IS_WIN32 }, () => {
    const storePath = makeStorePath();
    const cache = createReplayCache({ storePath, now: () => NOW_MS });
    cache.consume(entry());
    const mode = fs.statSync(storePath).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it("starts fresh when the store file does not exist", () => {
    const cache = createReplayCache({ storePath: makeStorePath(), now: () => NOW_MS });
    assert.equal(cache.size(), 0);
  });

  it("fails loud on invalid JSON in the store file", () => {
    const storePath = makeStorePath();
    fs.mkdirSync(path.dirname(storePath), { recursive: true });
    fs.writeFileSync(storePath, "{not json", "utf8");
    assert.throws(
      () => createReplayCache({ storePath, now: () => NOW_MS }),
      /invalid JSON.*tamper signal/s,
    );
  });

  it("fails loud on an unexpected store shape", () => {
    const storePath = makeStorePath();
    fs.mkdirSync(path.dirname(storePath), { recursive: true });
    fs.writeFileSync(storePath, JSON.stringify({ schemaVersion: 99 }), "utf8");
    assert.throws(
      () => createReplayCache({ storePath, now: () => NOW_MS }),
      /unexpected shape/,
    );
  });

  it("fails loud on a malformed entry inside an otherwise valid store", () => {
    const storePath = makeStorePath();
    fs.mkdirSync(path.dirname(storePath), { recursive: true });
    fs.writeFileSync(
      storePath,
      JSON.stringify({
        schemaVersion: 1,
        entries: [{ nonce: "n", jobId: 42, expiresAtMs: FUTURE_MS }],
      }),
      "utf8",
    );
    assert.throws(
      () => createReplayCache({ storePath, now: () => NOW_MS }),
      /malformed entry at index 0/,
    );
  });
});

describe("sweep and bounded growth", () => {
  it("sweep drops entries whose expiresAt has passed and reports the count", () => {
    const storePath = makeStorePath();
    const cache = createReplayCache({ storePath, now: () => NOW_MS });

    const expired = entry({ expiresAt: NOW_MS + 1000 });
    const alive = entry({ expiresAt: FUTURE_MS });
    cache.consume(expired);
    cache.consume(alive);
    assert.equal(cache.size(), 2);

    const removed = cache.sweep(NOW_MS + 2000);
    assert.equal(removed, 1);
    assert.equal(cache.size(), 1);

    // The expired pair is forgettable: window checks reject it anyway.
    assert.deepEqual(cache.check(expired), { allowed: true });
    assert.equal(cache.check(alive).allowed, false);
  });

  it("sweep persists the pruned store", () => {
    const storePath = makeStorePath();
    const cache = createReplayCache({ storePath, now: () => NOW_MS });
    cache.consume(entry({ expiresAt: NOW_MS + 1000 }));
    cache.sweep(NOW_MS + 2000);

    const reloaded = createReplayCache({ storePath, now: () => NOW_MS });
    assert.equal(reloaded.size(), 0);
  });

  it("rejects new jobs with job_replay_rejected when full after sweep, never evicting unexpired nonces", () => {
    const cache = createReplayCache({
      storePath: makeStorePath(),
      maxEntries: 2,
      now: () => NOW_MS,
    });

    const first = entry();
    const second = entry();
    assert.deepEqual(cache.consume(first), { allowed: true });
    assert.deepEqual(cache.consume(second), { allowed: true });

    const overflow = cache.consume(entry());
    assert.equal(overflow.allowed, false);
    assert.equal(overflow.rejectionReason, REPLAY_REJECTION_REASON);
    assert.match(overflow.detail, /full/i);
    assert.match(overflow.detail, /reopen the replay window/i);

    // The previously consumed nonces must still be present (no eviction).
    assert.equal(cache.check(first).allowed, false);
    assert.equal(cache.check(second).allowed, false);
  });

  it("frees capacity via sweep when full entries have expired", () => {
    let clock = NOW_MS;
    const cache = createReplayCache({
      storePath: makeStorePath(),
      maxEntries: 2,
      now: () => clock,
    });

    cache.consume(entry({ expiresAt: NOW_MS + 1000 }));
    cache.consume(entry({ expiresAt: NOW_MS + 1000 }));

    // Advance past expiry: the internal sweep during consume frees room.
    clock = NOW_MS + 5000;
    assert.deepEqual(cache.consume(entry({ expiresAt: clock + 60000 })), {
      allowed: true,
    });
    assert.equal(cache.size(), 1);
  });

  it("exposes the documented default bound", () => {
    assert.equal(DEFAULT_MAX_ENTRIES, 5000);
  });
});
