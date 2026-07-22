"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const net = require("node:net");
const { EventEmitter } = require("node:events");
const { X509Certificate } = require("node:crypto");

const {
  verifyDeployedCertificate,
  computeCertificateFingerprint,
  normalizeFingerprint,
} = require("./index.js");

/**
 * Static PUBLIC certificate fixture (self-signed, CN
 * certops-verify-fixture.test, generated once for this test file). Public
 * material only -- per the zero key custody invariant, NO private key
 * fixture exists anywhere in the repo, so this cert can never be used to
 * serve traffic; it exists purely as parse/fingerprint input.
 *
 * Test-strategy note (documented choice): generating a fresh self-signed
 * certificate at runtime without dependencies is not possible with
 * node:crypto alone (it can create keypairs and parse X.509, but has no
 * certificate-signing API), and vendoring a private key fixture to run a
 * real tls.createServer is forbidden. The happy/mismatch handshake paths
 * are therefore exercised through a connectImpl stub that mimics
 * tls.connect, while the connection-error path uses a REAL socket against
 * a port with no listener (no certificate needed for that).
 */
const FIXTURE_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDLTCCAhWgAwIBAgIUNNNJnkEUxHbRL7iDNJAUsL9ldbAwDQYJKoZIhvcNAQEL
BQAwJjEkMCIGA1UEAwwbY2VydG9wcy12ZXJpZnktZml4dHVyZS50ZXN0MB4XDTI2
MDcyMjA1MjUzNVoXDTM2MDcxOTA1MjUzNVowJjEkMCIGA1UEAwwbY2VydG9wcy12
ZXJpZnktZml4dHVyZS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA2ukFK8Np/lO9PUjkTZ0LUtHPH7SRyfJMgMks9XMlyIfn2vsMI4YpbLh1WD82
A2b08wxlaxbilElqtuoPOWtUgk99SNLW170tAzKf3X/Yvf/sh8MJp7bJTjQY2o5x
LgU1HoFb/HtcMvB6xjsJZppn9cwNk1qWRvBb8cL8VDiseg1h8RTUNCoDWTlDpiUf
04+BFImTRNky8j/SmhlHmtrOoHwYu3bul+OuYmbFH+Sxm+/ZGK6LbdnqEAfugBHg
UNtbiaFLFiceU2+CHF2+tMROqxj2wefVX9dQzyXLlTOPhgbEAk86jwe5UKJNREKT
vkn3ibR5bxc992fLSGPQ3oziDQIDAQABo1MwUTAdBgNVHQ4EFgQU4YR1yo0mQmDa
NCGg2i28Vace8UYwHwYDVR0jBBgwFoAU4YR1yo0mQmDaNCGg2i28Vace8UYwDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAJcsjXHpAOzi4Fwi6wSWZ
aacLB76johdLGTXK1FGbN8+2PVISXUJ/wsNhoYSu9qtYyuVdxsAiiUBT1xupD0ca
MG85NmVqKVLN2WzT9OFSWSsA4HlIc37kUamApq7VZ2VMylCpQI1A9fhfb5ZbRYhM
1Gfhfx1UaAnWcs0AAsGjxeCrNKizZfBRUsmap0V+yeXLIOBE/tJxwaHu14qLx+Ws
Uw7sRZcMXBIEmaNAi4EEX6eJ0zUcKLUI0glUsEpNId3VaKR63L2IXOxxEXvlYrXs
rDRLsqd2zwJUBZ5zeUp3Ji++P4IM/DBkbrbtr8PX9Rj2U5ZRxQQ4ZE+ifMJqDeKy
Cw==
-----END CERTIFICATE-----
`;

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
