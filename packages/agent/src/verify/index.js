"use strict";

/**
 * Certificate verification for CertOps agent deploys.
 *
 * Two complementary surfaces:
 *
 * 1. Pre-deploy validation (`validateCertificateForDeploy`): real X.509
 *    parsing via node:crypto's X509Certificate. Confirms the leaf parses,
 *    the private key matches when supplied (`checkPrivateKey`; explicit
 *    null/undefined skips only key-match for key-less standalone deploys),
 *    every requested SAN is present, the validity window covers "now"
 *    (with clock-skew tolerance), and -- when intermediate PEMs are
 *    supplied -- the leaf-to-intermediate signature chain verifies. Full
 *    chain-of-trust against a host root store is deliberately out of scope
 *    (private/staging CAs are normal); callers that need that check do it
 *    out of band.
 *
 * 2. Post-deploy fingerprint pinning (`verifyDeployedCertificate`): after
 *    deploy + reload, connect to the endpoint, take the peer certificate's
 *    DER bytes, sha256 them, and compare against the expected fingerprint
 *    computed from the deployed PEM.
 *
 * Why rejectUnauthorized: false on the TLS connect -- this is deliberate,
 * not an oversight. Chain validation against the local trust store is the
 * wrong check for post-deploy pinning: a freshly deployed certificate may
 * carry a chain the agent host's local store does not trust (yet), private
 * CAs are a normal CertOps deployment scenario, and staging/--dry-run CAs
 * are untrusted by design. The fingerprint comparison IS the verification:
 * it proves byte-identity between the certificate the endpoint serves and
 * the certificate that was deployed.
 *
 * Error discipline:
 *   - validateCertificateForDeploy returns { valid: false, code, detail }
 *     for validation failures (never throws for bad certs/keys/SANs).
 *   - verifyDeployedCertificate yields { verified: false, ... } for network
 *     problems and throws only on programmer error (missing/malformed host,
 *     port, or expected fingerprint).
 *
 * Fingerprint form: lowercase, no colons, 64 hex chars -- identical
 * semantics to the discovery module's normalizeFingerprint (which is
 * exported there but deliberately not imported here; modules in this
 * package are self-contained and accept plain data only).
 *
 * Private-key custody (D5 / ADR-0001): validateCertificateForDeploy accepts
 * private key PEM / KeyObject transiently solely for `checkPrivateKey`, or
 * null/undefined to skip key-match while still validating everything else.
 * The key is never returned, logged, or retained. Post-deploy fingerprint
 * pinning never touches private key material.
 */

const crypto = require("node:crypto");
const tls = require("node:tls");

const DEFAULT_TLS_PORT = 443;
const DEFAULT_TIMEOUT_MS = 10000;
/** Default clock-skew tolerance for validity-window checks (5 minutes). */
const DEFAULT_CLOCK_SKEW_SECONDS = 300;

/** Lowercase-hex sha256, optionally colon-separated, case-insensitive. */
const FINGERPRINT_INPUT_PATTERN = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$|^[0-9a-f]{64}$/i;

const PEM_CERTIFICATE_PATTERN =
  /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/;

const PEM_CERTIFICATE_BLOCK_PATTERN =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

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
 * Splits a PEM blob into individual CERTIFICATE blocks (leaf first when
 * fullchain-ordered). Returns an empty array when none are present.
 * @param {string} pem
 * @returns {string[]}
 */
function splitCertificatePems(pem) {
  if (typeof pem !== "string" || pem.length === 0) return [];
  const matches = pem.match(PEM_CERTIFICATE_BLOCK_PATTERN);
  return matches ? [...matches] : [];
}

/**
 * Parses DNS names from an X509Certificate.subjectAltName string
 * ("DNS:a.example, DNS:b.example, IP Address:...").
 * @param {string|undefined} subjectAltName
 * @returns {string[]} lowercase DNS names
 */
function parseDnsSans(subjectAltName) {
  if (typeof subjectAltName !== "string" || subjectAltName.length === 0) {
    return [];
  }
  const names = [];
  for (const part of subjectAltName.split(",")) {
    const trimmed = part.trim();
    const match = /^DNS:(.+)$/i.exec(trimmed);
    if (match) names.push(match[1].trim().toLowerCase());
  }
  return names;
}

/**
 * @param {string} code
 * @param {string} detail
 * @returns {{ valid: false, code: string, detail: string }}
 */
function invalidCert(code, detail) {
  return { valid: false, code, detail };
}

/**
 * Parses a Date from X509Certificate.validFrom / validTo.
 * @param {string} value
 * @returns {Date|null}
 */
function parseCertDate(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms) : null;
}

/**
 * Pre-deploy certificate validation using node:crypto X509Certificate.
 *
 * Checks, in order:
 *   1. leaf PEM parses as X.509
 *   2. when a private key is supplied: key parses and matches the leaf
 *      (`checkPrivateKey`). Explicit `null`/`undefined` skips ONLY this
 *      step (see privateKeyPem contract below); every other check still runs.
 *   3. every requested SAN/domain is present in subjectAltName (DNS)
 *   4. validity window covers `now` within clockSkewSeconds
 *   5. when intermediate PEMs are provided (via `chainPems` or additional
 *      CERTIFICATE blocks after the leaf in `certificatePem`), each link's
 *      signature verifies against the next cert's public key and each
 *      intermediate's own validity window is acceptable
 *
 * Does NOT verify chain-of-trust to a host root store (private/staging CAs
 * are in scope for CertOps; that check is out of band).
 *
 * Private-key contract (security-sensitive):
 *   - Non-empty string / Buffer / KeyObject: full validation including
 *     key-match. Behavior is identical to the historical required-key path.
 *   - `null` or `undefined`: deliberate "no local key available" signal used
 *     by standalone deploy jobs. Key-match is skipped; PEM parse, SAN,
 *     validity-window, and chain checks still run and can still reject.
 *   - Empty string (`""`): hard `PRIVATE_KEY_PARSE_FAILED`. Callers that
 *     accidentally pass an empty string are treated as buggy, not as
 *     key-less deploy — do not conflate with `null`.
 *
 * @param {object} input
 * @param {string} input.certificatePem leaf PEM, or leaf+intermediates fullchain
 * @param {string|Buffer|crypto.KeyObject|null|undefined} input.privateKeyPem
 *   private key material for the leaf (PEM string, DER Buffer, or KeyObject),
 *   or null/undefined to skip key-match only. Used only for checkPrivateKey;
 *   never returned.
 * @param {string[]} [input.requestedSans] domains that MUST appear as DNS SANs
 * @param {string[]} [input.chainPems] optional intermediate certificate PEMs
 *   (used when not already present after the leaf in certificatePem)
 * @param {() => Date} [input.now] injectable clock
 * @param {number} [input.clockSkewSeconds] validity-window skew, default 300
 * @returns {
 *   | { valid: true, fingerprintSha256: string, subjectAltNames: string[], validFrom: string, validTo: string }
 *   | { valid: false, code: string, detail: string }
 * }
 */
function validateCertificateForDeploy({
  certificatePem,
  privateKeyPem,
  requestedSans = [],
  chainPems = [],
  now = () => new Date(),
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
} = {}) {
  if (typeof certificatePem !== "string" || certificatePem.length === 0) {
    return invalidCert(
      "CERTIFICATE_PARSE_FAILED",
      "verify: certificatePem must be a non-empty PEM string",
    );
  }
  // null/undefined => skip key-match only. Empty string remains a hard failure
  // so a caller that forgot to load a key cannot silently weaken validation.
  const skipKeyMatch = privateKeyPem === null || privateKeyPem === undefined;
  if (!skipKeyMatch && typeof privateKeyPem === "string" && privateKeyPem.length === 0) {
    return invalidCert(
      "PRIVATE_KEY_PARSE_FAILED",
      "verify: privateKeyPem is required for key/certificate matching",
    );
  }
  if (!Array.isArray(requestedSans) || !requestedSans.every((s) => typeof s === "string")) {
    return invalidCert(
      "SAN_MISMATCH",
      "verify: requestedSans must be an array of strings",
    );
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    return invalidCert(
      "CERTIFICATE_PARSE_FAILED",
      "verify: clockSkewSeconds must be a non-negative number",
    );
  }

  const pemBlocks = splitCertificatePems(certificatePem);
  if (pemBlocks.length === 0) {
    return invalidCert(
      "CERTIFICATE_PARSE_FAILED",
      "verify: certificatePem contains no CERTIFICATE block",
    );
  }

  let leaf;
  try {
    leaf = new crypto.X509Certificate(pemBlocks[0]);
  } catch (err) {
    return invalidCert(
      "CERTIFICATE_PARSE_FAILED",
      `verify: leaf certificate could not be parsed as X.509: ${err?.message || err}`,
    );
  }

  if (!skipKeyMatch) {
    let privateKey;
    try {
      privateKey =
        typeof privateKeyPem === "object" &&
        privateKeyPem !== null &&
        typeof privateKeyPem.type === "string" &&
        privateKeyPem.type === "private"
          ? privateKeyPem
          : crypto.createPrivateKey(privateKeyPem);
    } catch (err) {
      return invalidCert(
        "PRIVATE_KEY_PARSE_FAILED",
        `verify: private key could not be parsed: ${err?.message || err}`,
      );
    }

    let keyMatches = false;
    try {
      keyMatches = leaf.checkPrivateKey(privateKey);
    } catch (err) {
      return invalidCert(
        "PRIVATE_KEY_MISMATCH",
        `verify: private key does not match certificate public key: ${err?.message || err}`,
      );
    }
    if (!keyMatches) {
      return invalidCert(
        "PRIVATE_KEY_MISMATCH",
        "verify: private key does not match the leaf certificate public key",
      );
    }
  }

  const presentSans = parseDnsSans(leaf.subjectAltName);
  const missingSans = requestedSans
    .map((name) => String(name).trim().toLowerCase())
    .filter((name) => name.length > 0)
    .filter((name) => !presentSans.includes(name));
  if (missingSans.length > 0) {
    return invalidCert(
      "SAN_MISMATCH",
      `verify: certificate subjectAltName is missing requested DNS name(s): ${missingSans.join(", ")} ` +
        `(present: ${presentSans.length > 0 ? presentSans.join(", ") : "none"})`,
    );
  }

  const skewMs = clockSkewSeconds * 1000;
  const instant = now();
  if (!(instant instanceof Date) || Number.isNaN(instant.getTime())) {
    return invalidCert(
      "CERTIFICATE_PARSE_FAILED",
      "verify: now() must return a valid Date",
    );
  }

  const validFrom = parseCertDate(leaf.validFrom);
  const validTo = parseCertDate(leaf.validTo);
  if (!validFrom || !validTo) {
    return invalidCert(
      "CERTIFICATE_PARSE_FAILED",
      "verify: leaf certificate validity dates could not be parsed",
    );
  }
  if (instant.getTime() + skewMs < validFrom.getTime()) {
    return invalidCert(
      "NOT_YET_VALID",
      `verify: leaf certificate is not yet valid (validFrom=${leaf.validFrom}, now=${instant.toISOString()}, skew=${clockSkewSeconds}s)`,
    );
  }
  if (instant.getTime() - skewMs > validTo.getTime()) {
    return invalidCert(
      "EXPIRED",
      `verify: leaf certificate is expired (validTo=${leaf.validTo}, now=${instant.toISOString()}, skew=${clockSkewSeconds}s)`,
    );
  }

  // Build the intermediate list: remaining blocks in certificatePem, then
  // any explicitly supplied chainPems (dedupe by fingerprint).
  const intermediatePems = [];
  const seenFp = new Set([normalizeFingerprint(leaf.fingerprint256)]);
  for (const block of pemBlocks.slice(1)) {
    intermediatePems.push(block);
  }
  if (Array.isArray(chainPems)) {
    for (const block of chainPems) {
      if (typeof block !== "string" || block.length === 0) continue;
      for (const part of splitCertificatePems(block)) {
        intermediatePems.push(part);
      }
    }
  }

  if (intermediatePems.length > 0) {
    let child = leaf;
    for (let i = 0; i < intermediatePems.length; i += 1) {
      let issuer;
      try {
        issuer = new crypto.X509Certificate(intermediatePems[i]);
      } catch (err) {
        return invalidCert(
          "CHAIN_INVALID",
          `verify: intermediate certificate at chain index ${i} could not be parsed: ${err?.message || err}`,
        );
      }
      const fp = normalizeFingerprint(issuer.fingerprint256);
      if (seenFp.has(fp)) continue;
      seenFp.add(fp);

      let signatureOk = false;
      try {
        signatureOk = child.verify(issuer.publicKey);
      } catch (err) {
        return invalidCert(
          "CHAIN_INVALID",
          `verify: chain signature check failed at link ${i}: ${err?.message || err}`,
        );
      }
      if (!signatureOk) {
        return invalidCert(
          "CHAIN_INVALID",
          `verify: certificate at chain link ${i} was not signed by the next intermediate`,
        );
      }

      const issuerFrom = parseCertDate(issuer.validFrom);
      const issuerTo = parseCertDate(issuer.validTo);
      if (!issuerFrom || !issuerTo) {
        return invalidCert(
          "CHAIN_INVALID",
          `verify: intermediate at chain index ${i} has unparseable validity dates`,
        );
      }
      if (instant.getTime() + skewMs < issuerFrom.getTime()) {
        return invalidCert(
          "CHAIN_INVALID",
          `verify: intermediate at chain index ${i} is not yet valid (validFrom=${issuer.validFrom})`,
        );
      }
      if (instant.getTime() - skewMs > issuerTo.getTime()) {
        return invalidCert(
          "CHAIN_INVALID",
          `verify: intermediate at chain index ${i} is expired (validTo=${issuer.validTo})`,
        );
      }

      child = issuer;
    }
  }

  return {
    valid: true,
    fingerprintSha256: normalizeFingerprint(leaf.fingerprint256),
    subjectAltNames: presentSans,
    validFrom: leaf.validFrom,
    validTo: leaf.validTo,
  };
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
  validateCertificateForDeploy,
  verifyDeployedCertificate,
  computeCertificateFingerprint,
  normalizeFingerprint,
  splitCertificatePems,
  parseDnsSans,
  DEFAULT_CLOCK_SKEW_SECONDS,
};
