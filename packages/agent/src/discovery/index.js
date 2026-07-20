"use strict";

/**
 * Filesystem certificate discovery (CertOps M4 bootstrap).
 *
 * M4 milestone scope (CertOps plan): "filesystem certificate discovery
 * (detect key presence without reading content)". This module's job is
 * inventory/observation only -- it walks a directory tree looking for
 * public certificate files and reports what it finds, plus whether a
 * private key *appears* to be co-located with a given certificate.
 *
 * Zero private-key custody (D5, ADR-0001) is a hard invariant for the whole
 * platform. Even though later milestones (M5: src/keys, src/deploy, etc.)
 * make this agent load-bearing for actual key handling, THIS module never
 * reads private key bytes into memory and never returns key content in any
 * result shape. Detection of "this looks like a key file" is deliberately
 * limited to two cheap, bounded signals:
 *   1. filename convention (PRIVATE_KEY_FILENAME_PATTERNS) -- a heuristic
 *      only, not authoritative.
 *   2. a bounded content peek (peekLooksLikePrivateKeyPem) that reads at
 *      most the first 4096 bytes of a file and checks for a PEM private-key
 *      header line. It never reads past that header, and never reads an
 *      entire large file just to decide "not a key".
 *
 * This module is self-contained: it accepts plain data (directory paths,
 * options, an onWarning callback) as function parameters and does not
 * import sibling agent modules (config, policy, evidence, etc.). Wiring
 * this into the agent entrypoint is left to src/index.js.
 *
 * Style note: the PEM header regex here intentionally mirrors the style of
 * PRIVATE_KEY_PEM_LABEL_PATTERN / PRIVATE_KEY_PEM_PATTERN in
 * apps/api/utils/secretMaterial.js (same "BEGIN ... PRIVATE KEY" shape) for
 * consistency across the codebase. This module does not import that file --
 * it has no dependency on apps/api, and duplicating a small regex is
 * preferable to reaching across the execution-plane/control-plane boundary.
 */

const fs = require("node:fs");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");

// Maximum number of bytes read when peeking at a candidate key file. This is
// an inspection bound, not a full read: even a multi-gigabyte file (or an
// unrelated large binary that happens to match an extension) never has more
// than this many bytes pulled into memory by peekLooksLikePrivateKeyPem.
const KEY_PEEK_MAX_BYTES = 4096;

// Mirrors the "BEGIN ... PRIVATE KEY" label shape used by
// apps/api/utils/secretMaterial.js's PRIVATE_KEY_PEM_LABEL_PATTERN /
// PRIVATE_KEY_PEM_PATTERN, duplicated here (not imported) to keep this
// package dependency-free with respect to apps/api. Matches PKCS#8
// (BEGIN PRIVATE KEY), PKCS#1 (BEGIN RSA PRIVATE KEY), SEC1 (BEGIN EC
// PRIVATE KEY), DSA, and encrypted variants (BEGIN ENCRYPTED PRIVATE KEY).
// Deliberately does NOT match PUBLIC KEY, CERTIFICATE, or CERTIFICATE
// REQUEST blocks.
const PRIVATE_KEY_PEM_LABEL_PATTERN = String.raw`(?:[A-Z0-9]+\s+)*PRIVATE\s+KEY`;
const PRIVATE_KEY_PEM_HEADER_PATTERN = new RegExp(
  String.raw`-----\s*BEGIN\s+${PRIVATE_KEY_PEM_LABEL_PATTERN}\s*-----`,
  "i",
);

/**
 * Filename conventions that commonly indicate a private key file.
 *
 * IMPORTANT: this is a heuristic (filename convention), not authoritative.
 * A file can be named however an operator likes; the content peek in
 * peekLooksLikePrivateKeyPem is the stronger signal and should always be
 * preferred when a definitive answer is needed. This list exists so
 * discovery can flag likely key files cheaply (no I/O at all) before
 * falling back to the content peek, and so operators get a fast, readable
 * "this filename looks like a key" signal in warnings/results.
 *
 * Each entry is a RegExp tested against the file's basename (case
 * insensitive). Deliberately more precise than a bare "*.key" / "*key*.pem"
 * glob would be: broad globs like "*key*.pem" would flag ordinary
 * certificate files with "key" in an unrelated part of the name (e.g.
 * "monkey-cert.pem"), so each pattern below anchors on a specific,
 * conventional key-naming fragment or extension instead.
 * @type {RegExp[]}
 */
const PRIVATE_KEY_FILENAME_PATTERNS = Object.freeze([
  // Extensions conventionally used only for private key material.
  /\.key$/i,
  /\.keypair$/i,
  // Common "privkey"/"private-key"/"private_key" naming fragments, in any
  // position in the basename (e.g. privkey.pem, server-private-key.pem).
  /privkey/i,
  /private-key/i,
  /private_key/i,
  // OpenSSH-style key basenames (id_rsa, id_ecdsa, id_ed25519, and their
  // "-cert.pub"-less private counterparts; the ".pub" companion file is a
  // public key and is intentionally not matched here).
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub$)/i,
]);

/**
 * Returns true if `fileName` matches any of PRIVATE_KEY_FILENAME_PATTERNS.
 * Filename-only check; performs no filesystem I/O.
 * @param {string} fileName basename to test (not a full path)
 * @returns {boolean}
 */
function filenameLooksLikePrivateKey(fileName) {
  return PRIVATE_KEY_FILENAME_PATTERNS.some((pattern) => pattern.test(fileName));
}

/**
 * Peeks at the first bytes of a file to check whether it looks like a PEM
 * private key, without ever reading the whole file and without ever
 * returning file content.
 *
 * Reads at most KEY_PEEK_MAX_BYTES (4096) bytes via a fixed-size buffer and
 * fs.openSync/fs.readSync, then checks (via regex) whether a
 * "-----BEGIN ... PRIVATE KEY-----" header line appears in the peeked
 * bytes. Does not read past that header line's worth of bytes conceptually
 * -- the 4096-byte cap is the hard ceiling regardless of whether a header is
 * found early or not at all; a real PEM header always appears within the
 * first few dozen bytes of a well-formed key file, so 4096 bytes is a
 * generous bound that still avoids slurping a large/unrelated file.
 *
 * Resilient to a noisy filesystem: ENOENT, EACCES, EISDIR (and any other
 * open/read error) are caught and result in `false`, never a thrown
 * exception, since discovery must keep scanning past files it cannot open.
 * Problems are reported via the optional `onWarning` callback rather than
 * thrown.
 *
 * @param {string} filePath absolute or relative path to peek at
 * @param {{ onWarning?: (message: string) => void }} [options]
 * @returns {boolean} true if the peeked bytes contain a private-key PEM header
 */
function peekLooksLikePrivateKeyPem(filePath, { onWarning = () => {} } = {}) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
  } catch (err) {
    onWarning(
      `discovery: could not open "${filePath}" for key-content peek: ${err?.message || err}`,
    );
    return false;
  }

  try {
    const buffer = Buffer.alloc(KEY_PEEK_MAX_BYTES);
    const bytesRead = fs.readSync(fd, buffer, 0, KEY_PEEK_MAX_BYTES, 0);
    const peeked = buffer.toString("utf8", 0, bytesRead);
    return PRIVATE_KEY_PEM_HEADER_PATTERN.test(peeked);
  } catch (err) {
    onWarning(
      `discovery: could not read "${filePath}" for key-content peek: ${err?.message || err}`,
    );
    return false;
  } finally {
    try {
      fs.closeSync(fd);
    } catch (_err) {
      // Best-effort close; nothing meaningful to do if this fails.
    }
  }
}

/**
 * Converts an X509Certificate.fingerprint256 colon-hex string (e.g.
 * "AA:BB:CC:...") into the schema's lowercase, no-colon, 64-hex-char form
 * (matching `^[a-f0-9]{64}$` in
 * packages/contracts/certops/agent-protocol.schema.json's
 * evidenceBody.evidenceItems[].fingerprintSha256).
 *
 * @param {string} nodeCryptoFingerprint256
 * @returns {string}
 */
function normalizeFingerprint(nodeCryptoFingerprint256) {
  return String(nodeCryptoFingerprint256 || "")
    .replace(/:/g, "")
    .toLowerCase();
}

/**
 * Returns the co-located key basename candidates for a certificate file
 * path, e.g. "server.crt" -> ["server.key", "server.keypair"]. This is the
 * "sibling-same-basename" convention referenced in the module's spec: a key
 * with the same basename as the certificate, differing only by extension.
 *
 * @param {string} certBaseNameWithoutExt basename without its extension
 * @returns {string[]} candidate key file basenames (not full paths)
 */
function siblingKeyBasenameCandidates(certBaseNameWithoutExt) {
  return [".key", ".keypair"].map((ext) => `${certBaseNameWithoutExt}${ext}`);
}

/**
 * Determines whether a private key appears to be co-located (same
 * directory, same basename) next to a certificate file. Only ever performs
 * the bounded item-2 content peek against candidate files; never reads a
 * full key file.
 *
 * @param {string} dirPath directory containing the certificate file
 * @param {string} certFileName certificate file's basename
 * @param {Set<string>} dirEntryNames all basenames present in dirPath (for a
 *   cheap existence check before peeking)
 * @param {(message: string) => void} onWarning
 * @returns {boolean}
 */
function detectCoLocatedKey(dirPath, certFileName, dirEntryNames, onWarning) {
  const ext = path.extname(certFileName);
  const baseWithoutExt = certFileName.slice(0, certFileName.length - ext.length);

  for (const candidateName of siblingKeyBasenameCandidates(baseWithoutExt)) {
    if (dirEntryNames.has(candidateName)) return true;
  }

  // A same-basename file under a *certificate-like* extension can also
  // actually be a private key that was miscategorized (e.g. "server.pem"
  // holding a key instead of a cert). Peek at same-basename siblings that
  // are not the certificate file itself, using only the bounded content
  // check -- never a full read.
  for (const candidateName of dirEntryNames) {
    if (candidateName === certFileName) continue;
    const candidateExt = path.extname(candidateName);
    const candidateBase = candidateName.slice(
      0,
      candidateName.length - candidateExt.length,
    );
    if (candidateBase !== baseWithoutExt) continue;
    if (filenameLooksLikePrivateKey(candidateName)) return true;
    if (
      peekLooksLikePrivateKeyPem(path.join(dirPath, candidateName), {
        onWarning,
      })
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Parses a certificate file buffer as an X.509 certificate and extracts
 * only public, non-sensitive fields. Never throws: parse failures are
 * reported in the returned shape via `parsed: false` / `parseError`.
 *
 * @param {string} filePath
 * @param {Buffer} fileBuffer
 * @returns {object} certificate result entry (without coLocatedKeyDetected,
 *   which the caller attaches separately)
 */
function parseCertificateFile(filePath, fileBuffer) {
  try {
    const cert = new X509Certificate(fileBuffer);
    return {
      path: filePath,
      parsed: true,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      serialNumber: cert.serialNumber,
      // fingerprint256 is the same fingerprint concept referenced by the
      // schema's fingerprintSha256 field (evidence/agent-protocol schema),
      // but node:crypto's X509Certificate exposes it as colon-separated hex.
      // Normalize it here to the schema's lowercase-no-colons 64-hex-char
      // form so callers integrating with evidence/schema get the expected
      // shape directly rather than each having to normalize independently.
      fingerprint256: cert.fingerprint256,
      fingerprintSha256: normalizeFingerprint(cert.fingerprint256),
      subjectAltName: cert.subjectAltName ?? null,
    };
  } catch (err) {
    return {
      path: filePath,
      parsed: false,
      parseError: err?.message || String(err),
    };
  }
}

/**
 * Walks `dirPath` looking for certificate files, bounded by `maxDepth` and
 * `maxFiles` so a misconfigured caller (e.g. pointing this at "/") cannot
 * trigger a runaway scan. Never throws on a per-entry filesystem error;
 * such errors are reported via `onWarning` and the walk continues.
 *
 * @param {string} dirPath
 * @param {object} options
 * @param {boolean} [options.recursive]
 * @param {number} [options.maxDepth]
 * @param {number} [options.maxFiles]
 * @param {string[]} [options.extensions]
 * @param {(message: string) => void} [options.onWarning]
 * @returns {{ certificates: object[], warnings: string[], scannedFileCount: number, truncated: boolean }}
 */
function discoverCertificatesInDirectory(
  dirPath,
  {
    recursive = true,
    maxDepth = 6,
    maxFiles = 5000,
    extensions = [".pem", ".crt", ".cer", ".cert"],
    onWarning = () => {},
  } = {},
) {
  const warnings = [];
  const certificates = [];
  let scannedFileCount = 0;
  let truncated = false;

  const normalizedExtensions = new Set(
    extensions.map((ext) => ext.toLowerCase()),
  );

  function warn(message) {
    warnings.push(message);
    onWarning(message);
  }

  /**
   * @param {string} currentDir
   * @param {number} depth
   * @returns {boolean} whether the walk should keep going (false once a
   *   bound has been hit, so callers can stop descending immediately)
   */
  function walk(currentDir, depth) {
    if (truncated) return false;

    if (depth > maxDepth) {
      truncated = true;
      warn(
        `discovery: maxDepth (${maxDepth}) exceeded at "${currentDir}"; stopping descent.`,
      );
      return false;
    }

    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      warn(`discovery: could not read directory "${currentDir}": ${err?.message || err}`);
      return true;
    }

    const dirEntryNames = new Set(entries.map((entry) => entry.name));
    const subDirs = [];

    for (const entry of entries) {
      if (scannedFileCount >= maxFiles) {
        truncated = true;
        warn(
          `discovery: maxFiles (${maxFiles}) reached while scanning "${currentDir}"; stopping scan.`,
        );
        return false;
      }

      if (entry.isDirectory()) {
        if (recursive) subDirs.push(entry.name);
        continue;
      }

      if (!entry.isFile()) continue;

      scannedFileCount += 1;

      const ext = path.extname(entry.name).toLowerCase();
      if (!normalizedExtensions.has(ext)) continue;

      const fullPath = path.join(currentDir, entry.name);
      let fileBuffer;
      try {
        fileBuffer = fs.readFileSync(fullPath);
      } catch (err) {
        warn(`discovery: could not read certificate file "${fullPath}": ${err?.message || err}`);
        continue;
      }

      const certResult = parseCertificateFile(fullPath, fileBuffer);
      certResult.coLocatedKeyDetected = detectCoLocatedKey(
        currentDir,
        entry.name,
        dirEntryNames,
        warn,
      );
      certificates.push(certResult);
    }

    if (truncated) return false;

    for (const subDirName of subDirs) {
      const keepGoing = walk(path.join(currentDir, subDirName), depth + 1);
      if (!keepGoing) return false;
    }

    return true;
  }

  walk(dirPath, 0);

  return { certificates, warnings, scannedFileCount, truncated };
}

/**
 * Convenience wrapper that runs discoverCertificatesInDirectory across
 * multiple directories and merges the results.
 *
 * @param {string[]} directories
 * @param {object} [options] same options accepted by
 *   discoverCertificatesInDirectory, applied to every directory scanned
 * @returns {{ certificates: object[], warnings: string[], scannedFileCount: number, truncated: boolean }}
 */
function discoverCertificates(directories, options = {}) {
  const merged = {
    certificates: [],
    warnings: [],
    scannedFileCount: 0,
    truncated: false,
  };

  for (const dirPath of directories) {
    const result = discoverCertificatesInDirectory(dirPath, options);
    merged.certificates.push(...result.certificates);
    merged.warnings.push(...result.warnings);
    merged.scannedFileCount += result.scannedFileCount;
    merged.truncated = merged.truncated || result.truncated;
  }

  return merged;
}

module.exports = {
  PRIVATE_KEY_FILENAME_PATTERNS,
  peekLooksLikePrivateKeyPem,
  discoverCertificatesInDirectory,
  discoverCertificates,
  normalizeFingerprint,
};
