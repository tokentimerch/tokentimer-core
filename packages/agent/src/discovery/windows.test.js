"use strict";

/**
 * Tests for packages/agent/src/discovery/windows.js -- the adapter that
 * normalizes ../windows-discovery's canonical certutil/netsh/appcmd
 * enumeration into the same observation-input shape ../index.js's
 * discoverCertificates produces for filesystem certificates. Real
 * certutil/netsh/appcmd parsing is exercised in
 * ../windows-discovery/windows-discovery.test.js; this file focuses on the
 * adapter's own responsibilities: cross-referencing bindings against the
 * store, resolving iis_binding vs http_sys, and the fingerprint-completion
 * PowerShell step this module owns.
 */

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execSync } = require("node:child_process");

const {
  collectWindowsDiscoveryObservations,
  fetchRawCertificateDerByThumbprint,
  computeFingerprintSha256,
  parseNodeSubjectAltName,
  readSubjectAltNamesFromDer,
  resolveSubjectAltNames,
} = require("./windows.js");

const CERTUTIL_STORE_OUTPUT = `My "Personal"
================ Certificate 0 ================
Serial Number: 1a2b3c4d5e
Issuer: CN=Test Root CA
 NotBefore: 1/1/2026 12:00 AM
 NotAfter: 1/1/2027 12:00 AM
Subject: CN=store-only.example.com
Cert Hash(sha1): aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd
CertUtil: -store command completed successfully.
`;

const CERTUTIL_EMPTY_STORE_OUTPUT = `My "Personal"
CertUtil: -store command completed successfully.
`;

/**
 * Builds a minimal single-entry certutil -store -v block for a given
 * thumbprint/subject, formatted as `Cert Hash(sha1)` (space-separated hex
 * pairs, matching certutil's real output), so a test's netsh/http.sys
 * binding fixture and its certutil store fixture always reference the same
 * certificate by construction rather than by two independently-typed
 * literals.
 */
function certutilStoreOutputFor(thumbprint, subject, { hasPrivateKey = false } = {}) {
  const hexPairs = thumbprint.match(/.{2}/g).join(" ");
  return `My "Personal"
================ Certificate 0 ================
Serial Number: 1a2b3c4d5e
Issuer: CN=Test Root CA
 NotBefore: 1/1/2026 12:00 AM
 NotAfter: 1/1/2027 12:00 AM
Subject: CN=${subject}
Cert Hash(sha1): ${hexPairs}
${hasPrivateKey ? "  Key Container = tokentimer-job-1-abcd1234\n  Provider = Microsoft Software Key Storage Provider\n" : ""}CertUtil: -store command completed successfully.
`;
}

function makeExecFileImplRouter({ certutilStdout, netshStdout, appcmdStdout, certutilExitCode, netshExitCode }) {
  return function execFileImpl(file, args, options, callback) {
    process.nextTick(() => {
      if (String(file).includes("certutil")) {
        if (certutilExitCode) {
          callback({ code: certutilExitCode }, "", "certutil: access denied");
          return;
        }
        callback(null, certutilStdout ?? CERTUTIL_EMPTY_STORE_OUTPUT, "");
        return;
      }
      if (String(file).includes("netsh")) {
        if (netshExitCode) {
          callback({ code: netshExitCode }, "", "netsh: access denied");
          return;
        }
        callback(null, netshStdout ?? "", "");
        return;
      }
      // appcmd (IIS site listing) -- a nonzero exit here is normal (no IIS
      // management tools installed), never treated as an adapter failure.
      if (!appcmdStdout) {
        callback({ code: 1 }, "", "");
        return;
      }
      callback(null, appcmdStdout, "");
    });
  };
}

function fakeSpawnResult({ status = 0, stdout = "", stderr = "", error = null } = {}) {
  return { status, stdout, stderr, error };
}

// --- openssl availability probe (test setup only) ---

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
const tempDirs = [];

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

function generateSelfSignedCertDerBase64(commonName) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-windows-adapter-test-"));
  tempDirs.push(dir);
  const keyPath = path.join(dir, "server.key");
  const pemPath = path.join(dir, "server.crt");
  const derPath = path.join(dir, "server.der");
  execSync(
    `"${OPENSSL_BINARY}" req -x509 -newkey rsa:2048 -keyout "${keyPath}" ` +
      `-out "${pemPath}" -days 1 -nodes -subj "/CN=${commonName}"`,
    { stdio: "ignore" },
  );
  execSync(`"${OPENSSL_BINARY}" x509 -in "${pemPath}" -outform der -out "${derPath}"`, {
    stdio: "ignore",
  });
  return fs.readFileSync(derPath).toString("base64");
}

/**
 * Same as generateSelfSignedCertDerBase64, but with a real Subject
 * Alternative Name extension (via an openssl config file), for tests that
 * need to prove SANs are read from the certificate's own raw bytes rather
 * than from certutil's -v text dump.
 */
function generateSelfSignedCertWithSanDerBase64(commonName, sanEntries) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-windows-adapter-san-test-"));
  tempDirs.push(dir);
  const keyPath = path.join(dir, "server.key");
  const pemPath = path.join(dir, "server.crt");
  const derPath = path.join(dir, "server.der");
  const cnfPath = path.join(dir, "san.cnf");
  const cnf = [
    "[req]",
    "distinguished_name = req_distinguished_name",
    "x509_extensions = v3_req",
    "prompt = no",
    "[req_distinguished_name]",
    `CN = ${commonName}`,
    "[v3_req]",
    `subjectAltName = ${sanEntries.join(",")}`,
    "",
  ].join("\n");
  fs.writeFileSync(cnfPath, cnf);
  execSync(
    `"${OPENSSL_BINARY}" req -x509 -newkey rsa:2048 -keyout "${keyPath}" ` +
      `-out "${pemPath}" -days 1 -nodes -config "${cnfPath}"`,
    { stdio: "ignore" },
  );
  execSync(`"${OPENSSL_BINARY}" x509 -in "${pemPath}" -outform der -out "${derPath}"`, {
    stdio: "ignore",
  });
  return fs.readFileSync(derPath).toString("base64");
}

describe("computeFingerprintSha256", () => {
  it(
    "computes a real SHA-256 fingerprint from base64 DER bytes",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const derBase64 = generateSelfSignedCertDerBase64("fingerprint-test.example.com");
      const fingerprint = computeFingerprintSha256(derBase64);
      assert.match(fingerprint, /^[a-f0-9]{64}$/);
    },
  );

  it("returns null (not throw) for malformed input", () => {
    const warnings = [];
    assert.equal(computeFingerprintSha256("not-valid-base64-der", (m) => warnings.push(m)), null);
    assert.ok(warnings.length > 0);
  });

  it("returns null for null/undefined input without warning", () => {
    assert.equal(computeFingerprintSha256(null), null);
    assert.equal(computeFingerprintSha256(undefined), null);
  });
});

describe("fetchRawCertificateDerByThumbprint", () => {
  it("rejects an invalid storeLocation/storeName without spawning powershell", () => {
    const warnings = [];
    let spawnCalled = false;
    const spawn = () => {
      spawnCalled = true;
      return fakeSpawnResult({ stdout: JSON.stringify({ items: [] }) });
    };

    const result = fetchRawCertificateDerByThumbprint({
      storeLocation: "LocalMachine; Remove-Item C:\\",
      spawn,
      onWarning: (m) => warnings.push(m),
    });

    assert.equal(result.size, 0);
    assert.equal(spawnCalled, false);
    assert.ok(warnings.some((m) => m.includes("invalid storeLocation")));
  });

  it("returns an empty map and warns when powershell is unavailable (ENOENT)", () => {
    const warnings = [];
    const spawn = () => fakeSpawnResult({ error: { code: "ENOENT" } });

    const result = fetchRawCertificateDerByThumbprint({ spawn, onWarning: (m) => warnings.push(m) });

    assert.equal(result.size, 0);
    assert.ok(warnings.some((m) => m.includes("not available")));
  });

  it("maps lowercased thumbprint -> RawCertificateBase64", () => {
    const stdout = JSON.stringify({
      items: [{ Thumbprint: "AABBCC", RawCertificateBase64: "ZGVy" }],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = fetchRawCertificateDerByThumbprint({ spawn });

    assert.equal(result.get("aabbcc"), "ZGVy");
  });
});

describe("parseNodeSubjectAltName", () => {
  it("parses Node's X509Certificate#subjectAltName comma-separated format into bare values", () => {
    const result = parseNodeSubjectAltName("DNS:example.com, DNS:www.example.com, IP Address:10.0.0.5");
    assert.deepEqual(result, ["example.com", "www.example.com", "10.0.0.5"]);
  });

  it("returns [] for undefined/empty input", () => {
    assert.deepEqual(parseNodeSubjectAltName(undefined), []);
    assert.deepEqual(parseNodeSubjectAltName(""), []);
  });

  it("ignores entries it does not recognize rather than throwing", () => {
    assert.deepEqual(parseNodeSubjectAltName("othername:some-value, DNS:example.com"), ["example.com"]);
  });
});

describe("readSubjectAltNamesFromDer", () => {
  it(
    "reads real SAN entries directly from a certificate's own raw DER bytes",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const derBase64 = generateSelfSignedCertWithSanDerBase64("san-adapter-test.example.com", [
        "DNS:san-adapter-test.example.com",
        "DNS:alt.san-adapter-test.example.com",
        "IP:10.0.0.9",
      ]);
      const sans = readSubjectAltNamesFromDer(derBase64);
      assert.deepEqual(sans, [
        "san-adapter-test.example.com",
        "alt.san-adapter-test.example.com",
        "10.0.0.9",
      ]);
    },
  );

  it("returns [] (not throw) for malformed input", () => {
    const warnings = [];
    assert.deepEqual(readSubjectAltNamesFromDer("not-valid-base64-der", (m) => warnings.push(m)), []);
    assert.ok(warnings.length > 0);
  });

  it("returns [] for null/undefined input without warning", () => {
    assert.deepEqual(readSubjectAltNamesFromDer(null), []);
    assert.deepEqual(readSubjectAltNamesFromDer(undefined), []);
  });
});

describe("resolveSubjectAltNames", () => {
  it(
    "prefers the raw-bytes-derived SANs over windows-discovery's certutil-text-parsed list",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const derBase64 = generateSelfSignedCertWithSanDerBase64("resolve-san-test.example.com", [
        "DNS:from-der.example.com",
      ]);
      const cert = { subjectAlternativeNames: ["from-certutil-text.example.com"] };
      assert.equal(resolveSubjectAltNames(cert, derBase64), "from-der.example.com");
    },
  );

  it("falls back to windows-discovery's certutil-text-parsed SANs when raw bytes are unavailable", () => {
    const cert = { subjectAlternativeNames: ["from-certutil-text.example.com"] };
    assert.equal(resolveSubjectAltNames(cert, undefined), "from-certutil-text.example.com");
  });

  it("returns an empty string when neither source has SANs", () => {
    const cert = { subjectAlternativeNames: [] };
    assert.equal(resolveSubjectAltNames(cert, undefined), "");
  });
});

describe("collectWindowsDiscoveryObservations", () => {
  it(
    "reports a windows_store observation using windows-discovery's parsed fields plus an adapter-computed fingerprint",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    async () => {
      const derBase64 = generateSelfSignedCertDerBase64("store-only.example.com");
      const execFileImpl = makeExecFileImplRouter({ certutilStdout: CERTUTIL_STORE_OUTPUT });
      const spawn = () =>
        fakeSpawnResult({
          stdout: JSON.stringify({
            items: [{ Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD", RawCertificateBase64: derBase64 }],
          }),
        });

      const observations = await collectWindowsDiscoveryObservations({ execFileImpl, spawn });

      assert.equal(observations.length, 1);
      const [obs] = observations;
      assert.equal(obs.locationKind, "windows_store");
      assert.match(obs.fingerprintSha256, /^[a-f0-9]{64}$/);
      assert.equal(obs.locationSlot, "LocalMachine/My/store-only.example.com");
      assert.equal(obs.keyPresent, false);
      assert.equal(obs.subject, "CN=store-only.example.com");
      // Never leaks raw certificate bytes or key material into the
      // observation shape handed off to the evidence-building caller.
      const serialized = JSON.stringify(obs);
      assert.ok(!serialized.includes(derBase64));
      assert.ok(!serialized.toLowerCase().includes("privatekey"));
    },
  );

  it(
    "resolves an http.sys binding matched to an IIS site as iis_binding, reusing the store's fingerprint",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    async () => {
      const derBase64 = generateSelfSignedCertDerBase64("iis-bound.example.com");
      const thumbprint = "1122334455667788990011223344556677889900";
      const netshStdout = [
        "SSL Certificate bindings:",
        "-------------------------",
        "",
        "    IP:port                      : 10.0.0.5:443",
        `    Certificate Hash             : ${thumbprint}`,
        "    Certificate Store Name       : My",
        "",
      ].join("\r\n");
      const appcmdStdout = 'SITE "Default Web Site" (id:1,bindings:https/10.0.0.5:443:,state:Started)\n';
      const execFileImpl = makeExecFileImplRouter({
        certutilStdout: certutilStoreOutputFor(thumbprint, "iis-bound.example.com", { hasPrivateKey: true }),
        netshStdout,
        appcmdStdout,
      });
      const spawn = () =>
        fakeSpawnResult({
          stdout: JSON.stringify({ items: [{ Thumbprint: thumbprint, RawCertificateBase64: derBase64 }] }),
        });

      const observations = await collectWindowsDiscoveryObservations({ execFileImpl, spawn });

      const iisObservation = observations.find((o) => o.locationKind === "iis_binding");
      const storeObservation = observations.find((o) => o.locationKind === "windows_store");
      assert.ok(iisObservation, "expected an iis_binding observation");
      assert.equal(iisObservation.siteName, "Default Web Site");
      assert.equal(iisObservation.port, 443);
      assert.equal(iisObservation.fingerprintSha256, storeObservation.fingerprintSha256);
      // A binding never holds its own key handle -- it references the
      // store entry by thumbprint, cross-referenced from the same
      // machine-store enumeration used to resolve subject/issuer above.
      assert.equal(iisObservation.keyPresent, true);
      assert.equal(storeObservation.keyPresent, true);
    },
  );

  it(
    "reports an http.sys binding with no matching IIS site as http_sys, not iis_binding",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    async () => {
      const derBase64 = generateSelfSignedCertDerBase64("httpsys-bound.example.com");
      const thumbprint = "9988776655443322110099887766554433221100";
      const netshStdout = [
        "    IP:port                      : 0.0.0.0:8443",
        `    Certificate Hash             : ${thumbprint}`,
        "",
      ].join("\r\n");
      const execFileImpl = makeExecFileImplRouter({
        certutilStdout: certutilStoreOutputFor(thumbprint, "httpsys-bound.example.com"),
        netshStdout,
      });
      const spawn = () =>
        fakeSpawnResult({
          stdout: JSON.stringify({ items: [{ Thumbprint: thumbprint, RawCertificateBase64: derBase64 }] }),
        });

      const observations = await collectWindowsDiscoveryObservations({ execFileImpl, spawn });

      const httpSysObservation = observations.find((o) => o.locationKind === "http_sys");
      assert.ok(httpSysObservation, "expected an http_sys observation");
      assert.equal(httpSysObservation.locationSlot, "0.0.0.0:8443");
      assert.match(httpSysObservation.fingerprintSha256, /^[a-f0-9]{64}$/);
    },
  );

  it("skips a binding whose thumbprint is not found in the machine store, with a warning", async () => {
    const netshStdout = [
      "    IP:port                      : 0.0.0.0:8443",
      "    Certificate Hash             : ffffffffffffffffffffffffffffffffffffffff",
      "",
    ].join("\r\n");
    const execFileImpl = makeExecFileImplRouter({
      certutilStdout: CERTUTIL_EMPTY_STORE_OUTPUT,
      netshStdout,
    });
    const warnings = [];

    const observations = await collectWindowsDiscoveryObservations({
      execFileImpl,
      onWarning: (m) => warnings.push(m),
    });

    assert.equal(observations.length, 0);
    assert.ok(warnings.some((m) => m.includes("not found")));
  });

  it("returns [] (not throw) when the store and http.sys surfaces are both empty", async () => {
    const execFileImpl = makeExecFileImplRouter({ certutilStdout: CERTUTIL_EMPTY_STORE_OUTPUT });

    const observations = await collectWindowsDiscoveryObservations({ execFileImpl });

    assert.deepEqual(observations, []);
  });

  it("skips a windows_store certificate and warns when no fingerprint is available (powershell unavailable)", async () => {
    const execFileImpl = makeExecFileImplRouter({ certutilStdout: CERTUTIL_STORE_OUTPUT });
    const spawn = () => fakeSpawnResult({ error: { code: "ENOENT" } });
    const warnings = [];

    const observations = await collectWindowsDiscoveryObservations({
      execFileImpl,
      spawn,
      onWarning: (m) => warnings.push(m),
    });

    assert.deepEqual(observations, []);
    assert.ok(warnings.some((m) => m.includes("no fingerprint available")));
  });

  it("propagates a warning (not throw) when the certutil store query itself fails outright", async () => {
    const execFileImpl = makeExecFileImplRouter({ certutilExitCode: 5 });
    const warnings = [];

    const observations = await collectWindowsDiscoveryObservations({
      execFileImpl,
      onWarning: (m) => warnings.push(m),
    });

    assert.deepEqual(observations, []);
    assert.ok(warnings.some((m) => m.includes("windows_store")));
  });

  it("propagates a warning (not throw) when the netsh binding query itself fails outright", async () => {
    const execFileImpl = makeExecFileImplRouter({
      certutilStdout: CERTUTIL_EMPTY_STORE_OUTPUT,
      netshExitCode: 5,
    });
    const warnings = [];

    const observations = await collectWindowsDiscoveryObservations({
      execFileImpl,
      onWarning: (m) => warnings.push(m),
    });

    assert.deepEqual(observations, []);
    assert.ok(warnings.some((m) => m.includes("http_sys")));
  });

  // End-to-end regression for the 2026-08-08 real-host finding: on an
  // affected host, ../windows-discovery's own certutil -v fallback (see its
  // test suite) already keeps windows_store observations flowing even
  // though -v itself fails; this test additionally proves the adapter
  // still recovers real SANs in that exact scenario, via the certificate's
  // own raw bytes rather than certutil's (broken) -v text dump.
  it(
    "still reports real subjectAltNames end-to-end when certutil -v fails but plain certutil -store and raw-bytes fingerprinting both succeed",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    async () => {
      const thumbprint = "aabbccddeeff00112233445566778899aabbccdd";
      const derBase64 = generateSelfSignedCertWithSanDerBase64("v-broken.example.com", [
        "DNS:v-broken.example.com",
        "DNS:alt.v-broken.example.com",
      ]);
      const plainStdout = certutilStoreOutputFor(thumbprint, "v-broken.example.com");
      const execFileImpl = (file, args, options, callback) => {
        process.nextTick(() => {
          if (String(file).includes("certutil")) {
            if (args.includes("-v")) {
              const error = Object.assign(new Error("NTE_NOT_FOUND"), { code: -2146893807 });
              callback(error, "My \"Personal\"\n", "CertUtil: Object was not found.\n");
              return;
            }
            callback(null, plainStdout, "");
            return;
          }
          // No http.sys bindings / IIS sites in this scenario.
          callback({ code: 1 }, "", "");
        });
      };
      const spawn = () =>
        fakeSpawnResult({
          stdout: JSON.stringify({ items: [{ Thumbprint: thumbprint, RawCertificateBase64: derBase64 }] }),
        });

      const observations = await collectWindowsDiscoveryObservations({ execFileImpl, spawn });

      assert.equal(observations.length, 1);
      const [obs] = observations;
      assert.equal(obs.locationKind, "windows_store");
      assert.equal(obs.subjectAltNames, "v-broken.example.com,alt.v-broken.example.com");
    },
  );
});
