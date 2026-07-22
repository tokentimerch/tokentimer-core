"use strict";

/**
 * Clock-offset estimation from HTTP Date response headers (CertOps Phase 4
 * runtime, ADR-0003 clock-drift awareness).
 *
 * Every control-plane HTTP response carries a Date header stamped with the
 * server's clock. Comparing it to the local clock at receive time yields an
 * estimate of `serverTime - localTime` (offsetMs): positive means the local
 * clock is BEHIND the server. This is the `clockOffsetMs` value the
 * agent-protocol envelope reports on heartbeat/result messages and the
 * adjustment checkJobTimeWindow applies when validating a signed job's
 * [issuedAt, expiresAt] window.
 *
 * Accuracy caveat (documented per task spec): the HTTP Date header has
 * 1-SECOND resolution (RFC 9110 IMF-fixdate), so each individual sample has
 * up to ~1s of quantization error, plus one-way network latency (the header
 * is stamped when the server builds the response, and we timestamp on
 * receipt, so samples skew slightly negative by the response transit time).
 * This is deliberately a coarse estimator: it exists to catch drift in the
 * seconds-to-minutes range that would break the signed-job time window (30s
 * default tolerance), not to be an NTP replacement.
 *
 * Smoothing: a small rolling window of the last N samples (default 5) with
 * a MEDIAN aggregate. Median over mean because individual samples are
 * contaminated by occasional latency spikes (slow response => one very
 * negative sample); the median discards such outliers entirely instead of
 * letting them drag the estimate.
 *
 * This module is self-contained (node builtins only, plain-data API) per
 * the packages/agent module conventions. The protocol client does NOT
 * import it; the caller wires the client's onServerDate callback to
 * estimateFromResponseDate (see src/index.js wiring, done separately).
 */

const DEFAULT_MAX_SAMPLES = 5;

/**
 * Creates a rolling clock-offset estimator.
 *
 * @param {object} [options]
 * @param {number} [options.maxSamples=5] rolling window size; oldest sample
 *   is dropped once the window is full
 * @returns {{
 *   estimateFromResponseDate: (dateHeaderValue: string, localNowMs: number) => (number|null),
 *   getOffsetMs: () => (number|null),
 *   sampleCount: () => number,
 * }}
 */
function createClockOffsetEstimator({ maxSamples = DEFAULT_MAX_SAMPLES } = {}) {
  if (!Number.isInteger(maxSamples) || maxSamples <= 0) {
    throw new Error(
      "clock: createClockOffsetEstimator maxSamples must be a positive integer",
    );
  }

  /** @type {number[]} oldest first */
  const samples = [];

  /**
   * Ingests one HTTP Date header sample and returns that single sample's
   * offset (serverTime - localTime, in ms), or null when the header is
   * missing/unparseable (in which case no sample is recorded -- a bad
   * header must not poison the rolling window).
   *
   * Second-granularity note: Date.parse of an IMF-fixdate yields whole
   * seconds, so the returned offset inherits up to ~1s quantization error
   * per sample; consumers should use getOffsetMs() (the median over the
   * window) rather than trusting any single sample.
   *
   * @param {string} dateHeaderValue value of the response's Date header
   * @param {number} localNowMs local epoch ms captured when the response
   *   was received
   * @returns {number|null} this sample's offsetMs, or null if unusable
   */
  function estimateFromResponseDate(dateHeaderValue, localNowMs) {
    if (!Number.isFinite(localNowMs)) {
      throw new Error(
        "clock: estimateFromResponseDate requires a finite localNowMs",
      );
    }
    if (typeof dateHeaderValue !== "string" || dateHeaderValue.length === 0) {
      return null;
    }
    const serverMs = Date.parse(dateHeaderValue);
    if (Number.isNaN(serverMs)) {
      return null;
    }

    const offsetMs = serverMs - localNowMs;
    samples.push(offsetMs);
    if (samples.length > maxSamples) {
      samples.shift();
    }
    return offsetMs;
  }

  /**
   * Current best estimate: the median of the rolling window, rounded to an
   * integer (the protocol envelope's clockOffsetMs is an integer), or null
   * when no samples have been ingested yet. Callers must treat null as
   * "unknown" and skip offset adjustment (checkJobTimeWindow already
   * ignores non-finite/non-integer offsets).
   *
   * @returns {number|null}
   */
  function getOffsetMs() {
    if (samples.length === 0) return null;
    const sorted = [...samples].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    const median =
      sorted.length % 2 === 1
        ? sorted[mid]
        : (sorted[mid - 1] + sorted[mid]) / 2;
    return Math.round(median);
  }

  function sampleCount() {
    return samples.length;
  }

  return { estimateFromResponseDate, getOffsetMs, sampleCount };
}

module.exports = {
  DEFAULT_MAX_SAMPLES,
  createClockOffsetEstimator,
};
