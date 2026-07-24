"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { DEFAULT_MAX_SAMPLES, createClockOffsetEstimator } = require("./index.js");

const LOCAL_NOW_MS = Date.parse("2026-07-22T12:00:00.000Z");

function httpDate(epochMs) {
  return new Date(epochMs).toUTCString();
}

describe("createClockOffsetEstimator", () => {
  it("returns null from getOffsetMs before any sample", () => {
    const estimator = createClockOffsetEstimator();
    assert.equal(estimator.getOffsetMs(), null);
    assert.equal(estimator.sampleCount(), 0);
  });

  it("computes serverTime - localTime from one Date header sample", () => {
    const estimator = createClockOffsetEstimator();
    // Server 10s ahead of the local clock => positive offset.
    const sample = estimator.estimateFromResponseDate(
      httpDate(LOCAL_NOW_MS + 10000),
      LOCAL_NOW_MS,
    );
    assert.equal(sample, 10000);
    assert.equal(estimator.getOffsetMs(), 10000);
  });

  it("yields a negative offset when the local clock is ahead of the server", () => {
    const estimator = createClockOffsetEstimator();
    estimator.estimateFromResponseDate(
      httpDate(LOCAL_NOW_MS - 30000),
      LOCAL_NOW_MS,
    );
    assert.equal(estimator.getOffsetMs(), -30000);
  });

  it("quantizes to seconds via the HTTP Date format (sub-second truth is invisible)", () => {
    const estimator = createClockOffsetEstimator();
    // Server time with 750ms sub-second component: toUTCString drops it.
    const sample = estimator.estimateFromResponseDate(
      httpDate(LOCAL_NOW_MS + 750),
      LOCAL_NOW_MS,
    );
    assert.equal(sample, 0);
  });

  it("uses the median of the rolling window to reject latency-spike outliers", () => {
    const estimator = createClockOffsetEstimator();
    for (const offset of [2000, 2000, -60000, 2000, 3000]) {
      estimator.estimateFromResponseDate(
        httpDate(LOCAL_NOW_MS + offset),
        LOCAL_NOW_MS,
      );
    }
    assert.equal(estimator.getOffsetMs(), 2000);
  });

  it("averages the two middle samples for an even-sized window", () => {
    const estimator = createClockOffsetEstimator();
    for (const offset of [1000, 2000, 3000, 4000]) {
      estimator.estimateFromResponseDate(
        httpDate(LOCAL_NOW_MS + offset),
        LOCAL_NOW_MS,
      );
    }
    assert.equal(estimator.getOffsetMs(), 2500);
  });

  it("caps the window at maxSamples, dropping the oldest sample", () => {
    const estimator = createClockOffsetEstimator({ maxSamples: 3 });
    for (const offset of [100000, 1000, 1000, 1000]) {
      estimator.estimateFromResponseDate(
        httpDate(LOCAL_NOW_MS + offset),
        LOCAL_NOW_MS,
      );
    }
    assert.equal(estimator.sampleCount(), 3);
    assert.equal(estimator.getOffsetMs(), 1000);
  });

  it("defaults the window size to 5 samples", () => {
    const estimator = createClockOffsetEstimator();
    for (let i = 0; i < 10; i += 1) {
      estimator.estimateFromResponseDate(httpDate(LOCAL_NOW_MS), LOCAL_NOW_MS);
    }
    assert.equal(estimator.sampleCount(), DEFAULT_MAX_SAMPLES);
    assert.equal(DEFAULT_MAX_SAMPLES, 5);
  });

  it("ignores missing or unparseable Date headers without recording a sample", () => {
    const estimator = createClockOffsetEstimator();
    assert.equal(estimator.estimateFromResponseDate(undefined, LOCAL_NOW_MS), null);
    assert.equal(estimator.estimateFromResponseDate("", LOCAL_NOW_MS), null);
    assert.equal(
      estimator.estimateFromResponseDate("not-a-date", LOCAL_NOW_MS),
      null,
    );
    assert.equal(estimator.sampleCount(), 0);
    assert.equal(estimator.getOffsetMs(), null);
  });

  it("throws on programmer error: non-finite localNowMs or bad maxSamples", () => {
    const estimator = createClockOffsetEstimator();
    assert.throws(
      () => estimator.estimateFromResponseDate(httpDate(LOCAL_NOW_MS), NaN),
      /localNowMs/,
    );
    assert.throws(() => createClockOffsetEstimator({ maxSamples: 0 }), /maxSamples/);
    assert.throws(
      () => createClockOffsetEstimator({ maxSamples: 1.5 }),
      /maxSamples/,
    );
  });
});
