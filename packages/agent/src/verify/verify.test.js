"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const { EventEmitter } = require("node:events");
const { X509Certificate } = require("node:crypto");

const {
  validateCertificateForDeploy,
  verifyDeployedCertificate,
  computeCertificateFingerprint,
  normalizeFingerprint,
} = require("./index.js");

/**
 * Real OpenSSL-generated fixtures (see fixtures/generate-fixtures.sh).
 * Keys are TEST-ONLY material committed solely so checkPrivateKey and
 * negative cases exercise the real X509Certificate path end to end.
 */
const FIXTURES_DIR = path.join(__dirname, "fixtures");

function readFixture(name) {
  return fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8");
}

const FIXTURE_CERT_PEM = readFixture("selfsigned.crt.pem");
const FIXTURE_KEY_PEM = readFixture("leaf.key.pem");
const LEAF_CERT_PEM = readFixture("leaf.crt.pem");
const LEAF_FULLCHAIN_PEM = readFixture("leaf-fullchain.crt.pem");
const INTERMEDIATE_CERT_PEM = readFixture("intermediate.crt.pem");
const CHAIN_LEAF_CERT_PEM = readFixture("chain-leaf.crt.pem");
const CHAIN_LEAF_KEY_PEM = readFixture("chain-leaf.key.pem");
const CHAIN_LEAF_FULLCHAIN_PEM = readFixture("chain-leaf-fullchain.crt.pem");
const WRONG_SAN_CERT_PEM = readFixture("wrong-san.crt.pem");
const WRONG_SAN_KEY_PEM = readFixture("wrong-san.key.pem");
const MISMATCH_KEY_PEM = readFixture("mismatch.key.pem");
const EXPIRED_CERT_PEM = readFixture("expired.crt.pem");
const EXPIRED_KEY_PEM = readFixture("expired.key.pem");
const FUTURE_CERT_PEM = readFixture("future.crt.pem");
const FUTURE_KEY_PEM = readFixture("future.key.pem");

const fixtureX509 = new X509Certificate(FIXTURE_CERT_PEM);
const FIXTURE_DER = fixtureX509.raw;
const FIXTURE_FINGERPRINT = normalizeFingerprint(fixtureX509.fingerprint256);

const OTHER_FINGERPRINT = "0".repeat(64);

/**
 * connectImpl stub mimicking tls.connect: returns a socket-like
 * EventEmitter and emits the configured outcome asynchronously.
 *
 * @param {object} outcome
 * @param {Buffer|null} [outcome.peerDer] DER to present on secureConnect
 * @param {Error} [outcome.error] error to emit instead of secureConnect
 * @param {boolean} [outcome.hang] never emit anything (timeout path)
 * @param {object|undefined} [outcome.peerCertOverride] raw value returned by
 *   getPeerCertificate (to simulate a missing/empty peer certificate)
 */
function makeConnectStub(outcome) {
  const seenOptions = [];

  function connectStub(options) {
    seenOptions.push(options);
    const socket = new EventEmitter();
    socket.destroyed = false;
    socket.destroy = () => {
      socket.destroyed = true;
    };
    socket.getPeerCertificate = () => {
      if ("peerCertOverride" in outcome) return outcome.peerCertOverride;
      return { raw: outcome.peerDer };
    };

    process.nextTick(() => {
      if (outcome.hang) return;
      if (outcome.error) {
        socket.emit("error", outcome.error);
      } else {
        socket.emit("secureConnect");
      }
    });

    return socket;
  }

  connectStub.seenOptions = seenOptions;
  return connectStub;
}

function baseVerifyInputs(connectImpl, overrides = {}) {
  return {
    host: "web-01.example.com",
    port: 8443,
    expectedFingerprintSha256: FIXTURE_FINGERPRINT,
    connectImpl,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// computeCertificateFingerprint
// ---------------------------------------------------------------------------

test("computeCertificateFingerprint matches node:crypto's fingerprint256 for the fixture", () => {
  const computed = computeCertificateFingerprint(FIXTURE_CERT_PEM);
  assert.equal(computed, FIXTURE_FINGERPRINT);
  assert.match(computed, /^[a-f0-9]{64}$/);
});

test("computeCertificateFingerprint uses the FIRST cert of a fullchain-style PEM", () => {
  const fullchainLike = `${FIXTURE_CERT_PEM}\n${FIXTURE_CERT_PEM}`;
  assert.equal(
    computeCertificateFingerprint(fullchainLike),
    FIXTURE_FINGERPRINT,
  );
});

test("computeCertificateFingerprint throws on empty / non-PEM input", () => {
  assert.throws(() => computeCertificateFingerprint(""), /non-empty PEM/);
  assert.throws(
    () => computeCertificateFingerprint("not a pem at all"),
    /no CERTIFICATE block/,
  );
});

// ---------------------------------------------------------------------------
// normalizeFingerprint
// ---------------------------------------------------------------------------

test("normalizeFingerprint strips colons and lowercases (discovery semantics)", () => {
  assert.equal(normalizeFingerprint("AA:BB:cc:DD"), "aabbccdd");
  assert.equal(normalizeFingerprint(""), "");
});

// ---------------------------------------------------------------------------
// verifyDeployedCertificate: happy / mismatch paths (connectImpl stub)
// ---------------------------------------------------------------------------

test("matching fingerprint => verified: true with normalized actual", async () => {
  const connectImpl = makeConnectStub({ peerDer: FIXTURE_DER });
  const result = await verifyDeployedCertificate(baseVerifyInputs(connectImpl));

  assert.deepEqual(result, {
    verified: true,
    actualFingerprintSha256: FIXTURE_FINGERPRINT,
  });
});

test("expected fingerprint with colons and uppercase still matches", async () => {
  const colonUpper = FIXTURE_FINGERPRINT.toUpperCase()
    .match(/.{2}/g)
    .join(":");
  const connectImpl = makeConnectStub({ peerDer: FIXTURE_DER });

  const result = await verifyDeployedCertificate(
    baseVerifyInputs(connectImpl, { expectedFingerprintSha256: colonUpper }),
  );

  assert.equal(result.verified, true);
  assert.equal(result.actualFingerprintSha256, FIXTURE_FINGERPRINT);
});

test("mismatched fingerprint => verified: false, reports actual fingerprint", async () => {
  const connectImpl = makeConnectStub({ peerDer: FIXTURE_DER });
  const result = await verifyDeployedCertificate(
    baseVerifyInputs(connectImpl, { expectedFingerprintSha256: OTHER_FINGERPRINT }),
  );

  assert.equal(result.verified, false);
  assert.equal(result.actualFingerprintSha256, FIXTURE_FINGERPRINT);
  assert.match(result.detail, /Fingerprint mismatch/);
  assert.match(result.detail, new RegExp(OTHER_FINGERPRINT));
});

test("peer presenting no certificate => verified: false with detail", async () => {
  const connectImpl = makeConnectStub({ peerCertOverride: {} });
  const result = await verifyDeployedCertificate(baseVerifyInputs(connectImpl));

  assert.equal(result.verified, false);
  assert.equal(result.actualFingerprintSha256, null);
  assert.match(result.detail, /no certificate/);
});

test("connect options: rejectUnauthorized false, servername passthrough", async () => {
  const connectImpl = makeConnectStub({ peerDer: FIXTURE_DER });
  await verifyDeployedCertificate(
    baseVerifyInputs(connectImpl, { servername: "sni.example.com" }),
  );

  assert.equal(connectImpl.seenOptions.length, 1);
  const options = connectImpl.seenOptions[0];
  assert.equal(options.rejectUnauthorized, false);
  assert.equal(options.host, "web-01.example.com");
  assert.equal(options.port, 8443);
  assert.equal(options.servername, "sni.example.com");
});

// ---------------------------------------------------------------------------
// verifyDeployedCertificate: error / timeout paths
// ---------------------------------------------------------------------------

test("socket error => verified: false with detail, never throws", async () => {
  const connectImpl = makeConnectStub({
    error: new Error("connect ECONNREFUSED 127.0.0.1:8443"),
  });
  const result = await verifyDeployedCertificate(baseVerifyInputs(connectImpl));

  assert.equal(result.verified, false);
  assert.equal(result.actualFingerprintSha256, null);
  assert.match(result.detail, /ECONNREFUSED/);
});

test("handshake that never completes => verified: false via timeout", async () => {
  const connectImpl = makeConnectStub({ hang: true });
  const result = await verifyDeployedCertificate(
    baseVerifyInputs(connectImpl, { timeoutMs: 50 }),
  );

  assert.equal(result.verified, false);
  assert.equal(result.actualFingerprintSha256, null);
  assert.match(result.detail, /timed out after 50 ms/);
});

test("connectImpl throwing synchronously => verified: false, never throws", async () => {
  const connectImpl = () => {
    throw new Error("synchronous connect explosion");
  };
  const result = await verifyDeployedCertificate(baseVerifyInputs(connectImpl));

  assert.equal(result.verified, false);
  assert.match(result.detail, /synchronous connect explosion/);
});

test("real connection against a closed port => verified: false with detail", async () => {
  // Reserve an ephemeral port, then close the listener so nothing is
  // listening there: the real tls.connect (default connectImpl) must fail
  // with a connection error, not a throw. This is the one path that needs
  // no certificate, so it can use a real socket (see the fixture comment
  // for why the handshake paths are stub-based).
  const port = await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const claimed = server.address().port;
      server.close((err) => (err ? reject(err) : resolve(claimed)));
    });
    server.on("error", reject);
  });

  const result = await verifyDeployedCertificate({
    host: "127.0.0.1",
    port,
    expectedFingerprintSha256: FIXTURE_FINGERPRINT,
    timeoutMs: 5000,
  });

  assert.equal(result.verified, false);
  assert.equal(result.actualFingerprintSha256, null);
  assert.match(result.detail, /failed|timed out/);
});

// ---------------------------------------------------------------------------
// programmer-error validation (throws)
// ---------------------------------------------------------------------------

test("missing host throws", () => {
  assert.throws(
    () =>
      verifyDeployedCertificate({
        expectedFingerprintSha256: FIXTURE_FINGERPRINT,
      }),
    /non-empty host/,
  );
});

test("missing or malformed expected fingerprint throws", () => {
  assert.throws(
    () => verifyDeployedCertificate({ host: "example.com" }),
    /expectedFingerprintSha256/,
  );
  assert.throws(
    () =>
      verifyDeployedCertificate({
        host: "example.com",
        expectedFingerprintSha256: "zz".repeat(32),
      }),
    /expectedFingerprintSha256/,
  );
  assert.throws(
    () =>
      verifyDeployedCertificate({
        host: "example.com",
        expectedFingerprintSha256: "abc123",
      }),
    /expectedFingerprintSha256/,
  );
});

test("invalid port throws", () => {
  assert.throws(
    () =>
      verifyDeployedCertificate({
        host: "example.com",
        port: 70000,
        expectedFingerprintSha256: FIXTURE_FINGERPRINT,
      }),
    /port/,
  );
});

// ---------------------------------------------------------------------------
// validateCertificateForDeploy (real X.509 fixtures)
// ---------------------------------------------------------------------------

test("validateCertificateForDeploy accepts a matching self-signed leaf + key + SANs", () => {
  const result = validateCertificateForDeploy({
    certificatePem: FIXTURE_CERT_PEM,
    privateKeyPem: FIXTURE_KEY_PEM,
    requestedSans: ["valid.example.com", "www.valid.example.com"],
  });
  assert.equal(result.valid, true);
  assert.equal(result.fingerprintSha256, FIXTURE_FINGERPRINT);
  assert.ok(result.subjectAltNames.includes("valid.example.com"));
  assert.ok(result.subjectAltNames.includes("www.valid.example.com"));
});

test("validateCertificateForDeploy accepts a CA-signed leaf with fullchain intermediates", () => {
  const result = validateCertificateForDeploy({
    certificatePem: LEAF_FULLCHAIN_PEM,
    privateKeyPem: FIXTURE_KEY_PEM,
    requestedSans: ["valid.example.com"],
  });
  assert.equal(result.valid, true, result.detail);
});

test("validateCertificateForDeploy verifies leaf→intermediate chain via chainPems", () => {
  const result = validateCertificateForDeploy({
    certificatePem: CHAIN_LEAF_CERT_PEM,
    privateKeyPem: CHAIN_LEAF_KEY_PEM,
    requestedSans: ["chain.example.com"],
    chainPems: [INTERMEDIATE_CERT_PEM],
  });
  assert.equal(result.valid, true, result.detail);

  const fullchain = validateCertificateForDeploy({
    certificatePem: CHAIN_LEAF_FULLCHAIN_PEM,
    privateKeyPem: CHAIN_LEAF_KEY_PEM,
    requestedSans: ["chain.example.com"],
  });
  assert.equal(fullchain.valid, true, fullchain.detail);
});

test("validateCertificateForDeploy rejects a mismatched private key", () => {
  const result = validateCertificateForDeploy({
    certificatePem: LEAF_CERT_PEM,
    privateKeyPem: MISMATCH_KEY_PEM,
    requestedSans: ["valid.example.com"],
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "PRIVATE_KEY_MISMATCH");
  assert.match(result.detail, /does not match/i);
});

test("validateCertificateForDeploy rejects missing requested SANs", () => {
  const result = validateCertificateForDeploy({
    certificatePem: WRONG_SAN_CERT_PEM,
    privateKeyPem: WRONG_SAN_KEY_PEM,
    requestedSans: ["valid.example.com"],
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "SAN_MISMATCH");
  assert.match(result.detail, /valid\.example\.com/);
});

test("validateCertificateForDeploy rejects an expired certificate", () => {
  const result = validateCertificateForDeploy({
    certificatePem: EXPIRED_CERT_PEM,
    privateKeyPem: EXPIRED_KEY_PEM,
    requestedSans: ["expired.example.com"],
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "EXPIRED");
  assert.match(result.detail, /expired/i);
});

test("validateCertificateForDeploy rejects a not-yet-valid certificate", () => {
  const result = validateCertificateForDeploy({
    certificatePem: FUTURE_CERT_PEM,
    privateKeyPem: FUTURE_KEY_PEM,
    requestedSans: ["future.example.com"],
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "NOT_YET_VALID");
  assert.match(result.detail, /not yet valid/i);
});

test("validateCertificateForDeploy rejects unparseable / fake PEM", () => {
  const result = validateCertificateForDeploy({
    certificatePem:
      "-----BEGIN CERTIFICATE-----\nMIIBfake-cert-body-for-tests\n-----END CERTIFICATE-----\n",
    privateKeyPem: FIXTURE_KEY_PEM,
    requestedSans: ["valid.example.com"],
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_PARSE_FAILED");
});

test("validateCertificateForDeploy rejects a broken chain signature link", () => {
  // Present the wrong-SAN cert as if it were the issuer of the leaf.
  const result = validateCertificateForDeploy({
    certificatePem: LEAF_CERT_PEM,
    privateKeyPem: FIXTURE_KEY_PEM,
    requestedSans: ["valid.example.com"],
    chainPems: [WRONG_SAN_CERT_PEM],
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CHAIN_INVALID");
});
