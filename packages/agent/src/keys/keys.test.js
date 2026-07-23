"use strict";

/**
 * Tests for packages/agent/src/keys/index.js.
 *
 * CSR validation strategy: the generated CSR is round-tripped without
 * openssl by (a) parsing the DER with a tiny TLV reader, (b) recreating the
 * public key from the embedded SPKI via crypto.createPublicKey, and
 * (c) verifying the CSR self-signature with crypto.verify over the
 * CertificationRequestInfo DER. When openssl is available on PATH the CSR
 * is additionally verified with `openssl req -verify -noout`; that check
 * skips gracefully when openssl is unavailable.
 */

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  SUPPORTED_ALGORITHM_NAMES,
  generateKeyPairToFile,
  generateCsr,
  getPublicKeyFingerprint,
} = require("./index.js");

const IS_WIN32 = process.platform === "win32";

const tempDirs = [];

function makeTempKeyDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-keys-test-"));
  tempDirs.push(dir);
  // Nested, not-yet-existing subdirectory so tests also cover recursive
  // parent-dir creation with 0700.
  return path.join(dir, "keys");
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

/**
 * Minimal DER TLV reader for test-side CSR parsing (decode-only; the module
 * under test owns encoding).
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {{tag: number, start: number, headerLength: number, length: number, valueStart: number, valueEnd: number}}
 */
function readTlv(buf, offset) {
  const tag = buf[offset];
  let length = buf[offset + 1];
  let headerLength = 2;
  if (length & 0x80) {
    const lengthBytes = length & 0x7f;
    length = 0;
    for (let i = 0; i < lengthBytes; i += 1) {
      length = length * 256 + buf[offset + 2 + i];
    }
    headerLength += lengthBytes;
  }
  const valueStart = offset + headerLength;
  return {
    tag,
    start: offset,
    headerLength,
    length,
    valueStart,
    valueEnd: valueStart + length,
  };
}

function pemToDer(pem, label) {
  const match = pem.match(
    new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`),
  );
  assert.ok(match, `PEM must contain a ${label} block`);
  return Buffer.from(match[1].replace(/\s+/g, ""), "base64");
}

/**
 * Parses a CSR DER into its three top-level parts plus the embedded SPKI.
 * @param {Buffer} csrDer
 */
function parseCsr(csrDer) {
  const outer = readTlv(csrDer, 0);
  assert.equal(outer.tag, 0x30, "CSR outer tag must be SEQUENCE");
  assert.equal(outer.valueEnd, csrDer.length, "CSR outer length must span the whole DER");

  const cri = readTlv(csrDer, outer.valueStart);
  assert.equal(cri.tag, 0x30, "CertificationRequestInfo must be SEQUENCE");
  const criDer = csrDer.subarray(cri.start, cri.valueEnd);

  const sigAlg = readTlv(csrDer, cri.valueEnd);
  assert.equal(sigAlg.tag, 0x30, "signatureAlgorithm must be SEQUENCE");

  const sigBits = readTlv(csrDer, sigAlg.valueEnd);
  assert.equal(sigBits.tag, 0x03, "signature must be BIT STRING");
  assert.equal(csrDer[sigBits.valueStart], 0x00, "BIT STRING must have 0 unused bits");
  const signature = csrDer.subarray(sigBits.valueStart + 1, sigBits.valueEnd);

  // Inside CRI: INTEGER version, subject Name, SPKI, [0] attributes.
  const version = readTlv(csrDer, cri.valueStart);
  assert.equal(version.tag, 0x02, "CSR version must be INTEGER");
  assert.equal(csrDer[version.valueStart], 0x00, "CSR version must be 0");
  const subject = readTlv(csrDer, version.valueEnd);
  assert.equal(subject.tag, 0x30, "subject Name must be SEQUENCE");
  const spki = readTlv(csrDer, subject.valueEnd);
  assert.equal(spki.tag, 0x30, "SubjectPublicKeyInfo must be SEQUENCE");
  const spkiDer = csrDer.subarray(spki.start, spki.valueEnd);
  const attributes = readTlv(csrDer, spki.valueEnd);
  assert.equal(attributes.tag, 0xa0, "attributes must be context [0]");

  return { criDer, signature, spkiDer };
}

function opensslAvailable() {
  try {
    const probe = spawnSync("openssl", ["version"], { encoding: "utf8" });
    return probe.status === 0;
  } catch (_err) {
    return false;
  }
}

describe("generateKeyPairToFile", () => {
  for (const algorithm of SUPPORTED_ALGORITHM_NAMES) {
    it(`generates a ${algorithm} keypair, writes the file, and returns only public material`, () => {
      const keyPath = path.join(makeTempKeyDir(), `${algorithm}.key.pem`);
      const result = generateKeyPairToFile({ keyPath, algorithm });

      assert.deepEqual(Object.keys(result).sort(), ["algorithm", "keyPath", "publicKeyPem"]);
      assert.equal(result.keyPath, keyPath);
      assert.equal(result.algorithm, algorithm);
      assert.ok(result.publicKeyPem.includes("-----BEGIN PUBLIC KEY-----"));
      assert.ok(!JSON.stringify(result).includes("PRIVATE KEY"));

      // The file on disk is a loadable PKCS#8 private key whose public half
      // matches the returned publicKeyPem.
      const onDisk = fs.readFileSync(keyPath, "utf8");
      assert.ok(onDisk.includes("-----BEGIN PRIVATE KEY-----"));
      const derivedPublic = crypto
        .createPublicKey(crypto.createPrivateKey(onDisk))
        .export({ type: "spki", format: "pem" })
        .toString();
      assert.equal(derivedPublic, result.publicKeyPem);
    });
  }

  it("rejects an unsupported algorithm with a clear error", () => {
    const keyPath = path.join(makeTempKeyDir(), "bad.key.pem");
    assert.throws(
      () => generateKeyPairToFile({ keyPath, algorithm: "dsa-1024" }),
      /unsupported algorithm/,
    );
  });

  it("rejects a missing keyPath", () => {
    assert.throws(() => generateKeyPairToFile({}), /keyPath must be a non-empty string/);
  });

  it("sets 0600 on the key file and 0700 on the parent dir on non-win32", { skip: IS_WIN32 }, () => {
    const dir = makeTempKeyDir();
    const keyPath = path.join(dir, "perm.key.pem");
    generateKeyPairToFile({ keyPath });
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  });

  it("refuses to overwrite an existing key file unless overwrite is true", () => {
    const keyPath = path.join(makeTempKeyDir(), "overwrite.key.pem");
    const first = generateKeyPairToFile({ keyPath });
    assert.throws(
      () => generateKeyPairToFile({ keyPath }),
      /refusing to overwrite existing key file/,
    );
    const second = generateKeyPairToFile({ keyPath, overwrite: true });
    assert.notEqual(second.publicKeyPem, first.publicKeyPem);
  });

  it("refuses to write through a symlink at the key path", { skip: IS_WIN32 }, () => {
    const dir = makeTempKeyDir();
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const realTarget = path.join(dir, "attacker-target.pem");
    fs.writeFileSync(realTarget, "sentinel", { mode: 0o600 });
    const linkPath = path.join(dir, "linked.key.pem");
    fs.symlinkSync(realTarget, linkPath);

    for (const overwrite of [false, true]) {
      assert.throws(
        () => generateKeyPairToFile({ keyPath: linkPath, overwrite }),
        /not a\s+regular file|refusing to write key/,
      );
    }
    // The symlink target was never clobbered with key material.
    assert.equal(fs.readFileSync(realTarget, "utf8"), "sentinel");
  });

  it("rotation replaces the key atomically and leaves no temp files behind", () => {
    const dir = makeTempKeyDir();
    const keyPath = path.join(dir, "rotate.key.pem");
    const first = generateKeyPairToFile({ keyPath });
    const second = generateKeyPairToFile({ keyPath, overwrite: true });
    assert.notEqual(second.publicKeyPem, first.publicKeyPem);

    // The on-disk key is complete and matches the returned public half.
    const derivedPublic = crypto
      .createPublicKey(crypto.createPrivateKey(fs.readFileSync(keyPath, "utf8")))
      .export({ type: "spki", format: "pem" })
      .toString();
    assert.equal(derivedPublic, second.publicKeyPem);

    const leftovers = fs.readdirSync(dir).filter((name) => name.endsWith(".tmp"));
    assert.deepEqual(leftovers, []);
  });

  it("never includes 'PRIVATE KEY' in a thrown error message", () => {
    const keyPath = path.join(makeTempKeyDir(), "err.key.pem");
    generateKeyPairToFile({ keyPath });
    for (const throwing of [
      () => generateKeyPairToFile({ keyPath }),
      () => generateKeyPairToFile({ keyPath: "", algorithm: "ec-p256" }),
      () => generateKeyPairToFile({ keyPath: `${keyPath}.other`, algorithm: "nope" }),
    ]) {
      try {
        throwing();
        assert.fail("expected the call to throw");
      } catch (err) {
        assert.ok(!String(err.message).includes("PRIVATE KEY"));
      }
    }
  });
});

describe("getPublicKeyFingerprint", () => {
  it("returns the sha256 hex of the SPKI DER", () => {
    const keyPath = path.join(makeTempKeyDir(), "fp.key.pem");
    const { publicKeyPem } = generateKeyPairToFile({ keyPath });
    const { fingerprintSha256 } = getPublicKeyFingerprint({ keyPath });

    assert.match(fingerprintSha256, /^[a-f0-9]{64}$/);
    const expected = crypto
      .createHash("sha256")
      .update(crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }))
      .digest("hex");
    assert.equal(fingerprintSha256, expected);
  });

  it("is stable across calls and distinct across keys", () => {
    const dir = makeTempKeyDir();
    const keyPathA = path.join(dir, "a.key.pem");
    const keyPathB = path.join(dir, "b.key.pem");
    generateKeyPairToFile({ keyPath: keyPathA });
    generateKeyPairToFile({ keyPath: keyPathB });

    const fpA1 = getPublicKeyFingerprint({ keyPath: keyPathA }).fingerprintSha256;
    const fpA2 = getPublicKeyFingerprint({ keyPath: keyPathA }).fingerprintSha256;
    const fpB = getPublicKeyFingerprint({ keyPath: keyPathB }).fingerprintSha256;
    assert.equal(fpA1, fpA2);
    assert.notEqual(fpA1, fpB);
  });

  it("rejects a missing keyPath", () => {
    assert.throws(() => getPublicKeyFingerprint({}), /keyPath must be a non-empty string/);
  });
});

describe("generateCsr", () => {
  for (const algorithm of ["ec-p256", "rsa-2048"]) {
    it(`builds a parseable, self-signature-valid CSR for ${algorithm}`, () => {
      const keyPath = path.join(makeTempKeyDir(), `${algorithm}-csr.key.pem`);
      const generated = generateKeyPairToFile({ keyPath, algorithm });

      const altNames = ["example.com", "www.example.com"];
      const { csrPem, publicKeyPem } = generateCsr({
        keyPath,
        subject: { commonName: "example.com", organization: "TokenTimer Test" },
        altNames,
      });

      assert.ok(csrPem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
      assert.equal(publicKeyPem, generated.publicKeyPem);
      assert.ok(!csrPem.includes("PRIVATE KEY"));

      const csrDer = pemToDer(csrPem, "CERTIFICATE REQUEST");
      const { criDer, signature, spkiDer } = parseCsr(csrDer);

      // Round-trip: the embedded SPKI must load via createPublicKey and
      // match the returned public key.
      const embeddedPublic = crypto.createPublicKey({
        key: spkiDer,
        format: "der",
        type: "spki",
      });
      assert.equal(
        embeddedPublic.export({ type: "spki", format: "pem" }).toString(),
        publicKeyPem,
      );

      // Manual self-signature verification over the CertificationRequestInfo DER.
      assert.equal(crypto.verify("sha256", criDer, embeddedPublic, signature), true);

      // CN and each SAN must appear as encoded strings in the DER bytes.
      assert.ok(criDer.includes(Buffer.from("example.com", "utf8")));
      for (const san of altNames) {
        assert.ok(criDer.includes(Buffer.from(san, "ascii")), `SAN ${san} missing from DER`);
      }
    });
  }

  it("supports rsa-3072 keys with the same RSA signature path", () => {
    const keyPath = path.join(makeTempKeyDir(), "rsa3072-csr.key.pem");
    generateKeyPairToFile({ keyPath, algorithm: "rsa-3072" });
    const { csrPem } = generateCsr({ keyPath, subject: { commonName: "rsa3072.example.com" } });
    const csrDer = pemToDer(csrPem, "CERTIFICATE REQUEST");
    const { criDer, signature, spkiDer } = parseCsr(csrDer);
    const embeddedPublic = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    assert.equal(crypto.verify("sha256", criDer, embeddedPublic, signature), true);
  });

  it("encodes optional O/OU/C subject fields into the DER", () => {
    const keyPath = path.join(makeTempKeyDir(), "dn.key.pem");
    generateKeyPairToFile({ keyPath });
    const { csrPem } = generateCsr({
      keyPath,
      subject: {
        commonName: "dn.example.com",
        organization: "TokenTimer GmbH",
        organizationalUnit: "CertOps",
        country: "DE",
      },
    });
    const csrDer = pemToDer(csrPem, "CERTIFICATE REQUEST");
    assert.ok(csrDer.includes(Buffer.from("dn.example.com", "utf8")));
    assert.ok(csrDer.includes(Buffer.from("TokenTimer GmbH", "utf8")));
    assert.ok(csrDer.includes(Buffer.from("CertOps", "utf8")));
    assert.ok(csrDer.includes(Buffer.from("DE", "ascii")));
  });

  it("builds a CSR with no SANs (empty attributes block)", () => {
    const keyPath = path.join(makeTempKeyDir(), "nosan.key.pem");
    generateKeyPairToFile({ keyPath });
    const { csrPem } = generateCsr({ keyPath, subject: { commonName: "nosan.example.com" } });
    const csrDer = pemToDer(csrPem, "CERTIFICATE REQUEST");
    const { criDer, signature, spkiDer } = parseCsr(csrDer);
    const embeddedPublic = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    assert.equal(crypto.verify("sha256", criDer, embeddedPublic, signature), true);
  });

  it("throws a clear 'not supported' error for Ed25519 CSRs (documented deviation)", () => {
    const keyPath = path.join(makeTempKeyDir(), "ed.key.pem");
    generateKeyPairToFile({ keyPath, algorithm: "ed25519" });
    assert.throws(
      () => generateCsr({ keyPath, subject: { commonName: "ed.example.com" } }),
      /Ed25519 CSR generation is not supported/,
    );
  });

  it("validates subject and altNames shapes with clear errors", () => {
    const keyPath = path.join(makeTempKeyDir(), "shape.key.pem");
    generateKeyPairToFile({ keyPath });
    assert.throws(() => generateCsr({ keyPath }), /subject must be an object/);
    assert.throws(
      () => generateCsr({ keyPath, subject: {} }),
      /commonName must be a non-empty string/,
    );
    assert.throws(
      () => generateCsr({ keyPath, subject: { commonName: "x", country: "Germany" } }),
      /country must be a 2-letter uppercase/,
    );
    assert.throws(
      () => generateCsr({ keyPath, subject: { commonName: "x" }, altNames: [42] }),
      /altNames must be an array of non-empty strings/,
    );
  });

  it("never includes 'PRIVATE KEY' in any thrown error message", () => {
    const keyPath = path.join(makeTempKeyDir(), "csr-err.key.pem");
    generateKeyPairToFile({ keyPath, algorithm: "ed25519" });
    for (const throwing of [
      () => generateCsr({ keyPath, subject: { commonName: "x" } }),
      () => generateCsr({ keyPath: "", subject: { commonName: "x" } }),
      () => generateCsr({ keyPath, subject: null }),
    ]) {
      try {
        throwing();
        assert.fail("expected the call to throw");
      } catch (err) {
        assert.ok(!String(err.message).includes("PRIVATE KEY"));
      }
    }
  });

  it("verifies the CSR with openssl when available", { skip: !opensslAvailable() }, () => {
    const dir = makeTempKeyDir();
    const keyPath = path.join(dir, "openssl.key.pem");
    generateKeyPairToFile({ keyPath });
    const { csrPem } = generateCsr({
      keyPath,
      subject: { commonName: "openssl.example.com" },
      altNames: ["openssl.example.com"],
    });

    const csrPath = path.join(dir, "openssl.csr.pem");
    fs.writeFileSync(csrPath, csrPem, "utf8");
    const result = spawnSync(
      "openssl",
      ["req", "-verify", "-noout", "-in", csrPath],
      { encoding: "utf8" },
    );
    assert.equal(
      result.status,
      0,
      `openssl req -verify failed: ${result.stderr || result.stdout}`,
    );
  });
});

describe("zero-custody return-value guard", () => {
  it("no exported function return value contains a PRIVATE KEY marker", () => {
    const keyPath = path.join(makeTempKeyDir(), "guard.key.pem");
    const genResult = generateKeyPairToFile({ keyPath });
    const csrResult = generateCsr({ keyPath, subject: { commonName: "guard.example.com" } });
    const fpResult = getPublicKeyFingerprint({ keyPath });

    for (const result of [genResult, csrResult, fpResult]) {
      assert.ok(!JSON.stringify(result).includes("PRIVATE KEY"));
    }
  });
});
