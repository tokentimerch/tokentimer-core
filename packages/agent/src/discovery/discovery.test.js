"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execSync } = require("node:child_process");

const {
  PRIVATE_KEY_FILENAME_PATTERNS,
  peekLooksLikePrivateKeyPem,
  discoverCertificatesInDirectory,
  discoverCertificates,
  normalizeFingerprint,
} = require("./index.js");

const SCHEMA_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

const tempDirs = [];

function makeTempDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-discovery-test-"));
  tempDirs.push(dir);
  return dir;
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

// --- openssl availability probe (test setup only; never used from the
// production discovery module, which has zero external-dependency I/O). ---

function findOpensslBinary() {
  const candidates = [
    "openssl",
    "C:\\Program Files\\Git\\usr\\bin\\openssl.exe",
    "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe",
  ];
  for (const candidate of candidates) {
    try {
      execSync(`"${candidate}" version`, { stdio: "ignore" });
      return candidate;
    } catch (_err) {
      // try next candidate
    }
  }
  return null;
}

const OPENSSL_BINARY = findOpensslBinary();

/**
 * Generates a throwaway self-signed cert+key pair into `dir` using openssl
 * (test setup only). Returns the absolute paths written. The key material
 * lives only in the per-test temp directory, which is removed in afterEach.
 */
function generateSelfSignedCertWithOpenssl(dir, basename = "server") {
  const keyPath = path.join(dir, `${basename}.key`);
  const certPath = path.join(dir, `${basename}.crt`);
  execSync(
    `"${OPENSSL_BINARY}" req -x509 -newkey rsa:2048 -keyout "${keyPath}" ` +
      `-out "${certPath}" -days 1 -nodes -subj "/CN=discovery-test.local"`,
    { stdio: "ignore" },
  );
  return { keyPath, certPath };
}

describe("PRIVATE_KEY_FILENAME_PATTERNS", () => {
  function anyPatternMatches(fileName) {
    return PRIVATE_KEY_FILENAME_PATTERNS.some((pattern) => pattern.test(fileName));
  }

  it("flags common private-key filename conventions", () => {
    const positives = [
      "server.key",
      "id_rsa",
      "id_ecdsa",
      "id_ed25519",
      "privkey.pem",
      "server-private-key.pem",
      "server_private_key.pem",
      "backup.keypair",
    ];
    for (const fileName of positives) {
      assert.ok(anyPatternMatches(fileName), `expected "${fileName}" to be flagged`);
    }
  });

  it("does not flag ordinary certificate filenames", () => {
    const negatives = [
      "server.crt",
      "server.pem",
      "chain.cer",
      "monkey-cert.pem",
      "id_rsa.pub",
      "ca-bundle.cert",
    ];
    for (const fileName of negatives) {
      assert.ok(!anyPatternMatches(fileName), `expected "${fileName}" NOT to be flagged`);
    }
  });
});

describe("peekLooksLikePrivateKeyPem", () => {
  it("returns true for a file with a PEM private-key header, without reading/returning the body", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "suspicious.pem");
    const garbageBody = "not-a-real-key-body-just-garbage-bytes-for-the-test\n".repeat(20);
    fs.writeFileSync(
      filePath,
      `-----BEGIN RSA PRIVATE KEY-----\n${garbageBody}-----END RSA PRIVATE KEY-----\n`,
      "utf8",
    );

    const result = peekLooksLikePrivateKeyPem(filePath);

    assert.strictEqual(typeof result, "boolean");
    assert.equal(result, true);
  });

  it("returns false for a file without a PEM private-key header", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "not-a-key.txt");
    fs.writeFileSync(filePath, "just some ordinary text content\n", "utf8");

    assert.equal(peekLooksLikePrivateKeyPem(filePath), false);
  });

  it("does not match PUBLIC KEY or CERTIFICATE headers", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "not-private.pem");
    fs.writeFileSync(
      filePath,
      "-----BEGIN CERTIFICATE-----\nMIIB...garbage...\n-----END CERTIFICATE-----\n",
      "utf8",
    );

    assert.equal(peekLooksLikePrivateKeyPem(filePath), false);
  });

  it("returns false (not throw) for a missing file, and calls onWarning", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "does-not-exist.pem");
    let warned = false;

    let result;
    assert.doesNotThrow(() => {
      result = peekLooksLikePrivateKeyPem(filePath, {
        onWarning: () => {
          warned = true;
        },
      });
    });
    assert.equal(result, false);
    assert.equal(warned, true);
  });

  it("caps the read at 4096 bytes rather than reading a large file in full", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "large.pem");
    // A private-key header placed far past the 4096-byte peek window must
    // not be detected: the function must not read the whole file to find it.
    const filler = "x".repeat(5000);
    fs.writeFileSync(
      filePath,
      `${filler}\n-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n`,
      "utf8",
    );

    assert.equal(peekLooksLikePrivateKeyPem(filePath), false);
  });
});

describe("discoverCertificatesInDirectory", () => {
  it("returns empty results for an empty directory", () => {
    const dir = makeTempDir();
    const result = discoverCertificatesInDirectory(dir);

    assert.deepEqual(result.certificates, []);
    assert.deepEqual(result.warnings, []);
    assert.equal(result.truncated, false);
  });

  it("marks a garbage .pem file as parsed: false with a parseError, without throwing", () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, "garbage.pem"), "this is not a certificate at all\n", "utf8");

    const result = discoverCertificatesInDirectory(dir);

    assert.equal(result.certificates.length, 1);
    const [entry] = result.certificates;
    assert.equal(entry.parsed, false);
    assert.ok(typeof entry.parseError === "string" && entry.parseError.length > 0);
    assert.equal(entry.path, path.join(dir, "garbage.pem"));
  });

  it("does not crash the whole scan when one file is garbage and another is valid", () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, "garbage.pem"), "garbage\n", "utf8");
    fs.writeFileSync(path.join(dir, "other.crt"), "also garbage\n", "utf8");

    const result = discoverCertificatesInDirectory(dir);

    assert.equal(result.certificates.length, 2);
    assert.ok(result.certificates.every((entry) => entry.parsed === false));
  });

  it("triggers truncated: true and calls onWarning when maxDepth is exceeded", () => {
    const dir = makeTempDir();
    const nested = path.join(dir, "a", "b", "c");
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, "deep.crt"), "garbage\n", "utf8");

    const warnings = [];
    const result = discoverCertificatesInDirectory(dir, {
      maxDepth: 1,
      onWarning: (message) => warnings.push(message),
    });

    assert.equal(result.truncated, true);
    assert.ok(warnings.length > 0);
    assert.ok(warnings.some((message) => message.includes("maxDepth")));
  });

  it("triggers truncated: true and calls onWarning when maxFiles is reached", () => {
    const dir = makeTempDir();
    for (let index = 0; index < 5; index += 1) {
      fs.writeFileSync(path.join(dir, `file-${index}.crt`), "garbage\n", "utf8");
    }

    const warnings = [];
    const result = discoverCertificatesInDirectory(dir, {
      maxFiles: 2,
      onWarning: (message) => warnings.push(message),
    });

    assert.equal(result.truncated, true);
    assert.ok(warnings.some((message) => message.includes("maxFiles")));
    assert.ok(result.scannedFileCount <= 2);
  });

  it("does not descend into subdirectories when recursive is false", () => {
    const dir = makeTempDir();
    const nested = path.join(dir, "nested");
    fs.mkdirSync(nested);
    fs.writeFileSync(path.join(nested, "nested.crt"), "garbage\n", "utf8");
    fs.writeFileSync(path.join(dir, "top.crt"), "garbage\n", "utf8");

    const result = discoverCertificatesInDirectory(dir, { recursive: false });

    assert.equal(result.certificates.length, 1);
    assert.equal(result.certificates[0].path, path.join(dir, "top.crt"));
  });

  it("ignores files whose extension is not in the configured extensions list", () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, "readme.txt"), "not a cert\n", "utf8");

    const result = discoverCertificatesInDirectory(dir);

    assert.equal(result.certificates.length, 0);
  });

  it("sets coLocatedKeyDetected: true when a same-basename .key file sits next to a certificate (filename convention)", () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, "server.crt"), "garbage cert content\n", "utf8");
    fs.writeFileSync(path.join(dir, "server.key"), "garbage key content\n", "utf8");

    const result = discoverCertificatesInDirectory(dir);

    assert.equal(result.certificates.length, 1);
    assert.equal(result.certificates[0].coLocatedKeyDetected, true);
  });

  it("sets coLocatedKeyDetected: false when no sibling key file is present", () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, "server.crt"), "garbage cert content\n", "utf8");

    const result = discoverCertificatesInDirectory(dir);

    assert.equal(result.certificates.length, 1);
    assert.equal(result.certificates[0].coLocatedKeyDetected, false);
  });

  it(
    "parses a real self-signed certificate and extracts public fields, normalizing the fingerprint",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const dir = makeTempDir();
      generateSelfSignedCertWithOpenssl(dir, "server");

      const result = discoverCertificatesInDirectory(dir);

      assert.equal(result.certificates.length, 1);
      const [entry] = result.certificates;
      assert.equal(entry.parsed, true);
      assert.ok(entry.subject.includes("discovery-test.local"));
      assert.ok(typeof entry.issuer === "string");
      assert.ok(typeof entry.validFrom === "string");
      assert.ok(typeof entry.validTo === "string");
      assert.ok(typeof entry.serialNumber === "string");
      assert.ok(typeof entry.fingerprint256 === "string" && entry.fingerprint256.includes(":"));
      assert.match(entry.fingerprintSha256, SCHEMA_FINGERPRINT_PATTERN);
      // The real key must be detected as co-located, but its bytes must
      // never appear anywhere in the certificate result entry.
      assert.equal(entry.coLocatedKeyDetected, true);
      const serialized = JSON.stringify(entry);
      assert.ok(!serialized.includes("PRIVATE KEY"));
    },
  );

  it(
    "never reads private key bytes into the returned certificate entry, even when it peeks the key",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const dir = makeTempDir();
      const { keyPath } = generateSelfSignedCertWithOpenssl(dir, "server");
      const rawKeyBytes = fs.readFileSync(keyPath, "utf8");

      const result = discoverCertificatesInDirectory(dir);

      const serialized = JSON.stringify(result);
      // The actual key body (base64 payload lines) must never leak into the
      // discovery result, only the boolean coLocatedKeyDetected signal.
      const keyBodyLine = rawKeyBytes.split("\n").find((line) => line.length > 40);
      assert.ok(keyBodyLine, "expected the generated key to have a body line to check against");
      assert.ok(!serialized.includes(keyBodyLine));
    },
  );
});

describe("discoverCertificates (multi-directory wrapper)", () => {
  it("merges certificates, warnings, and scannedFileCount across directories", () => {
    const dirA = makeTempDir();
    const dirB = makeTempDir();
    fs.writeFileSync(path.join(dirA, "a.crt"), "garbage\n", "utf8");
    fs.writeFileSync(path.join(dirB, "b.crt"), "garbage\n", "utf8");
    fs.writeFileSync(path.join(dirB, "c.crt"), "garbage\n", "utf8");

    const result = discoverCertificates([dirA, dirB]);

    assert.equal(result.certificates.length, 3);
    assert.equal(result.scannedFileCount, 3);
    assert.equal(result.truncated, false);
  });

  it("reports truncated: true if any sub-scan is truncated", () => {
    const dirA = makeTempDir();
    const dirB = makeTempDir();
    for (let index = 0; index < 3; index += 1) {
      fs.writeFileSync(path.join(dirB, `file-${index}.crt`), "garbage\n", "utf8");
    }

    const result = discoverCertificates([dirA, dirB], { maxFiles: 1 });

    assert.equal(result.truncated, true);
  });
});

describe("normalizeFingerprint", () => {
  it("converts a colon-hex fingerprint to lowercase, no-colon, 64-char form", () => {
    const colonHex = Array.from({ length: 32 }, (_v, index) =>
      (index % 16).toString(16).padStart(2, "0").toUpperCase(),
    ).join(":");

    const normalized = normalizeFingerprint(colonHex);

    assert.match(normalized, SCHEMA_FINGERPRINT_PATTERN);
    assert.equal(normalized, normalized.toLowerCase());
    assert.equal(normalized.includes(":"), false);
    assert.equal(normalized.length, 64);
  });

  it("matches the schema's fingerprintSha256 pattern exactly", () => {
    const sample =
      "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:" +
      "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    assert.match(normalizeFingerprint(sample), SCHEMA_FINGERPRINT_PATTERN);
  });
});
