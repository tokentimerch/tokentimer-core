"use strict";

/**
 * Post-deploy certificate verification (CertOps M5).
 *
 * After the deploy module writes a renewed certificate and the target
 * service reloads, dispatch must confirm the endpoint is actually serving
 * the certificate that was deployed. This module does that by fingerprint
 * pinning: connect, take the peer certificate's DER bytes, sha256 them, and
 * compare against the expected fingerprint computed from the deployed PEM.
 *
 * Why rejectUnauthorized: false -- this is deliberate, not an oversight.
 * Chain validation against the local trust store is the wrong check here:
 * a freshly deployed certificate may carry a chain the agent host's local
 * store does not trust (yet), private CAs are a normal CertOps deployment
 * scenario, and staging/--dry-run CAs are untrusted by design. The
 * fingerprint comparison IS the verification: it proves byte-identity
 * between the certificate the endpoint serves and the certificate that was
 * deployed, which is strictly stronger evidence of "the deploy took" than
 * chain trust would be.
 *
 * Error discipline: network problems (refused, timeout, reset, DNS) are
 * expected operational outcomes and yield { verified: false, ... } -- this
 * function never throws for those. It throws only on programmer error
 * (missing/malformed host, port, or expected fingerprint).
 *
 * Fingerprint form: lowercase, no colons, 64 hex chars -- identical
 * semantics to the discovery module's normalizeFingerprint (which is
 * exported there but deliberately not imported here; modules in this
 * package are self-contained and accept plain data only).
 *
 * This module handles only public certificate material (DER/PEM of certs).
 * No private key is ever read, transmitted, or accepted by any function
 * here (D5 / ADR-0001 zero key custody).
 */

const crypto = require("node:crypto");
const tls = require("node:tls");

const DEFAULT_TLS_PORT = 443;
const DEFAULT_TIMEOUT_MS = 10000;

/** Lowercase-hex sha256, optionally colon-separated, case-insensitive. */
const FINGERPRINT_INPUT_PATTERN = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$|^[0-9a-f]{64}$/i;

const PEM_CERTIFICATE_PATTERN =
  /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/;

/**
 * Normalizes a sha256 fingerprint to the schema form: strip colons,
 * lowercase. Mirrors discovery's normalizeFingerprint semantics exactly
 * (duplicated rather than imported; see module header).
 *
 * @param {string} fingerprint
 * @returns {string}
 */
function normalizeFingerprint(fingerprint) {
  return String(fingerprint || "")
    .replace(/:/g, "")
    .toLowerCase();
}

/**
 * @param {Buffer} derBytes
 * @returns {string} lowercase 64-hex-char sha256 of the DER bytes
 */
function sha256HexOfDer(derBytes) {
  return crypto.createHash("sha256").update(derBytes).digest("hex");
}

/**
 * Computes the sha256 fingerprint (lowercase hex, no colons) of the DER
 * encoding of the FIRST certificate block in a PEM string. Dispatch uses
 * this to derive the expected fingerprint from the deployed PEM file (which
 * may be a fullchain file; the leaf certificate comes first by convention,
 * and the leaf is what the peer presents as its own certificate).
 *
 * @param {string} certPem PEM text containing at least one CERTIFICATE block
 * @returns {string}
 */
function computeCertificateFingerprint(certPem) {
  if (typeof certPem !== "string" || certPem.length === 0) {
    throw new Error(
      "verify: computeCertificateFingerprint requires a non-empty PEM string",
    );
  }

  const match = PEM_CERTIFICATE_PATTERN.exec(certPem);
  if (!match) {
    throw new Error(
      "verify: computeCertificateFingerprint found no CERTIFICATE block in the provided PEM",
    );
  }

  const base64Body = match[1].replace(/\s+/g, "");
  let der;
  try {
    der = Buffer.from(base64Body, "base64");
  } catch {
    der = null;
  }
  if (!der || der.length === 0) {
    throw new Error(
      "verify: computeCertificateFingerprint could not decode the CERTIFICATE block as base64",
    );
  }

  return sha256HexOfDer(der);
}

/**
 * Verifies that the certificate served at host:port matches an expected
 * sha256 fingerprint.
 *
 * Comparison is case-insensitive and colon-tolerant on the expected value
 * (normalized to lowercase no-colon hex before comparing). The actual
 * fingerprint is always reported in the normalized form so it can be reused
 * directly in evidence.
 *
 * @param {object} options
 * @param {string} options.host hostname or IP to connect to.
 * @param {number} [options.port] TCP port, default 443.
 * @param {string} [options.servername] SNI name; defaults to `host` (node's
 *   tls.connect default), pass explicitly when verifying by IP against an
 *   SNI-routed endpoint.
 * @param {string} options.expectedFingerprintSha256 sha256 fingerprint of
 *   the deployed certificate's DER, hex, with or without colons, any case
 *   (e.g. from computeCertificateFingerprint or discovery's
 *   fingerprintSha256).
 * @param {number} [options.timeoutMs] connection/handshake budget, default
 *   10000 ms.
 * @param {Function} [options.connectImpl] injection point for tests; must
 *   mimic tls.connect(options) => socket (an EventEmitter with
 *   getPeerCertificate/end/destroy/setTimeout).
 * @returns {Promise<
 *   { verified: true, actualFingerprintSha256: string }
 *   | { verified: false, actualFingerprintSha256: string|null, detail: string }
 * >}
 */
function verifyDeployedCertificate({
  host,
  port = DEFAULT_TLS_PORT,
  servername,
  expectedFingerprintSha256,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  connectImpl = tls.connect,
} = {}) {
  // Programmer-error validation: these throw synchronously, they are bugs
  // in the caller, not network outcomes.
  if (typeof host !== "string" || host.length === 0) {
    throw new Error("verify: verifyDeployedCertificate requires a non-empty host");
  }
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(
      `verify: port must be an integer in [1, 65535], got ${JSON.stringify(port)}`,
    );
  }
  if (
    typeof expectedFingerprintSha256 !== "string" ||
    !FINGERPRINT_INPUT_PATTERN.test(expectedFingerprintSha256)
  ) {
    throw new Error(
      "verify: expectedFingerprintSha256 must be a sha256 hex fingerprint " +
        `(64 hex chars, colons optional), got ${JSON.stringify(expectedFingerprintSha256)}`,
    );
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `verify: timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }
  if (typeof connectImpl !== "function") {
    throw new Error("verify: connectImpl must be a function");
  }

  const expected = normalizeFingerprint(expectedFingerprintSha256);

  return new Promise((resolve) => {
    let settled = false;
    let socket = null;
    let timer = null;

    function settle(result) {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      if (socket) {
        try {
          socket.destroy();
        } catch {
          // Best-effort teardown; the result has already been decided.
        }
      }
      resolve(result);
    }

    function fail(detail) {
      settle({ verified: false, actualFingerprintSha256: null, detail });
    }

    // One overall wall-clock budget covering connect + handshake, enforced
    // locally instead of relying on socket idle timeouts (which reset on
    // activity and would not bound a slow-loris handshake).
    timer = setTimeout(() => {
      fail(`Connection to ${host}:${port} timed out after ${timeoutMs} ms.`);
    }, timeoutMs);

    try {
      socket = connectImpl({
        host,
        port,
        ...(servername !== undefined ? { servername } : {}),
        // Deliberate: fingerprint pinning, not chain validation. See the
        // module header for the full rationale (fresh deploys, private CAs,
        // staging endpoints). The sha256 comparison below is the actual
        // verification.
        rejectUnauthorized: false,
      });
    } catch (err) {
      fail(`TLS connect to ${host}:${port} failed: ${err?.message || err}`);
      return;
    }

    socket.on("secureConnect", () => {
      let peerCert;
      try {
        peerCert = socket.getPeerCertificate();
      } catch (err) {
        fail(
          `Could not obtain peer certificate from ${host}:${port}: ${err?.message || err}`,
        );
        return;
      }

      const der = peerCert && peerCert.raw;
      if (!Buffer.isBuffer(der) || der.length === 0) {
        fail(
          `Peer at ${host}:${port} presented no certificate (or an empty one).`,
        );
        return;
      }

      const actual = sha256HexOfDer(der);
      if (actual === expected) {
        settle({ verified: true, actualFingerprintSha256: actual });
      } else {
        settle({
          verified: false,
          actualFingerprintSha256: actual,
          detail:
            `Fingerprint mismatch at ${host}:${port}: expected ${expected}, ` +
            `endpoint presented ${actual}.`,
        });
      }
    });

    socket.on("error", (err) => {
      fail(`TLS connection to ${host}:${port} failed: ${err?.message || err}`);
    });
  });
}

module.exports = {
  verifyDeployedCertificate,
  computeCertificateFingerprint,
  normalizeFingerprint,
};
