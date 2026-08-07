"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execSync } = require("node:child_process");

const {
  listMachineStoreCertificates,
  listIisBindings,
  listHttpSysBindings,
  collectWindowsDiscoveryObservations,
} = require("./windows.js");

function fakeSpawnResult({ status = 0, stdout = "", stderr = "", error = null } = {}) {
  return { status, stdout, stderr, error };
}

// --- openssl availability probe (test setup only), mirroring discovery.test.js ---

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

/**
 * Generates a throwaway self-signed cert and returns its DER bytes as
 * base64, i.e. exactly the shape `.RawData` would produce for a real
 * machine-store entry (test setup only; production code never shells out
 * to openssl).
 */
function generateSelfSignedCertDerBase64(commonName = "windows-discovery-test.local") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-windows-discovery-test-"));
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


describe("listMachineStoreCertificates", () => {
  it("parses a well-formed PowerShell items payload into public metadata only", () => {
    const stdout = JSON.stringify({
      items: [
        {
          Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
          Subject: "CN=example.com",
          Issuer: "CN=Example CA",
          SerialNumber: "01AB",
          NotBefore: "2026-01-01T00:00:00.0000000Z",
          NotAfter: "2027-01-01T00:00:00.0000000Z",
          SubjectAltNames: "example.com,www.example.com",
        },
      ],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listMachineStoreCertificates({ spawn });

    assert.equal(result.length, 1);
    const [entry] = result;
    assert.equal(entry.thumbprint, "aabbccddeeff00112233445566778899aabbccdd");
    assert.equal(entry.subject, "CN=example.com");
    assert.equal(entry.issuer, "CN=Example CA");
    assert.equal(entry.storeLocation, "LocalMachine");
    assert.equal(entry.storeName, "My");
    // Never a key field, never key bytes, anywhere in the returned shape.
    const serialized = JSON.stringify(entry);
    assert.ok(!serialized.toLowerCase().includes("privatekey"));
    assert.ok(!serialized.includes("PRIVATE KEY"));
  });

  it("maps HasPrivateKey to a plain keyPresent boolean, never key material", () => {
    const stdout = JSON.stringify({
      items: [
        { Thumbprint: "aa11", HasPrivateKey: true },
        { Thumbprint: "bb22", HasPrivateKey: false },
      ],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const [withKey, withoutKey] = listMachineStoreCertificates({ spawn });

    assert.equal(withKey.keyPresent, true);
    assert.equal(withoutKey.keyPresent, false);
  });

  it("treats a missing HasPrivateKey as false, not unknown, at this layer", () => {
    // The store-enumeration layer always gets a real boolean from
    // PowerShell for a real certificate; a missing/malformed value here
    // (fixture gap, not a real Windows response) defaults conservatively
    // to false rather than propagating undefined into keyMode derivation.
    const stdout = JSON.stringify({ items: [{ Thumbprint: "cc33" }] });
    const spawn = () => fakeSpawnResult({ stdout });

    const [entry] = listMachineStoreCertificates({ spawn });

    assert.equal(entry.keyPresent, false);
  });

  it("returns [] and does not throw when the items payload is empty", () => {
    const spawn = () => fakeSpawnResult({ stdout: JSON.stringify({ items: [] }) });

    const result = listMachineStoreCertificates({ spawn });

    assert.deepEqual(result, []);
  });

  it("tolerates a bare (non-array) items payload defensively", () => {
    // @{ items = @($out) } always yields an array even for one item, but the
    // consumer still tolerates a bare object defensively.
    const stdout = JSON.stringify({
      items: {
        Thumbprint: "1122334455667788990011223344556677889900",
        Subject: "CN=solo.example.com",
      },
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listMachineStoreCertificates({ spawn });

    assert.equal(result.length, 1);
    assert.equal(result[0].thumbprint, "1122334455667788990011223344556677889900");
  });

  it("returns [] and calls onWarning when powershell exits non-zero", () => {
    const warnings = [];
    const spawn = () => fakeSpawnResult({ status: 1, stderr: "boom" });

    const result = listMachineStoreCertificates({ spawn, onWarning: (m) => warnings.push(m) });

    assert.deepEqual(result, []);
    assert.ok(warnings.length > 0);
    assert.ok(warnings[0].includes("windows_store"));
  });

  it("returns [] and calls onWarning when powershell is not installed (ENOENT)", () => {
    const warnings = [];
    const spawn = () => fakeSpawnResult({ error: { code: "ENOENT" } });

    const result = listMachineStoreCertificates({ spawn, onWarning: (m) => warnings.push(m) });

    assert.deepEqual(result, []);
    assert.ok(warnings.some((m) => m.includes("not available")));
  });

  it("returns [] and calls onWarning when stdout is not valid JSON", () => {
    const warnings = [];
    const spawn = () => fakeSpawnResult({ stdout: "not json at all" });

    const result = listMachineStoreCertificates({ spawn, onWarning: (m) => warnings.push(m) });

    assert.deepEqual(result, []);
    assert.ok(warnings.some((m) => m.includes("could not parse")));
  });

  it("rejects an invalid storeLocation/storeName without spawning powershell", () => {
    const warnings = [];
    let spawnCalled = false;
    const spawn = () => {
      spawnCalled = true;
      return fakeSpawnResult({ stdout: JSON.stringify({ items: [] }) });
    };

    const result = listMachineStoreCertificates({
      storeLocation: "LocalMachine; Remove-Item C:\\",
      spawn,
      onWarning: (m) => warnings.push(m),
    });

    assert.deepEqual(result, []);
    assert.equal(spawnCalled, false);
    assert.ok(warnings.some((m) => m.includes("invalid storeLocation")));
  });

  it("filters out items missing a thumbprint", () => {
    const stdout = JSON.stringify({
      items: [{ Subject: "CN=no-thumbprint.example.com" }],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listMachineStoreCertificates({ spawn });

    assert.deepEqual(result, []);
  });
});

describe("listIisBindings", () => {
  it("parses IIS binding items and lowercases the thumbprint", () => {
    const stdout = JSON.stringify({
      items: [
        {
          SiteName: "Default Web Site",
          Port: "443",
          SniHost: "example.com",
          Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
          StoreName: "My",
        },
      ],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listIisBindings({ spawn });

    assert.equal(result.length, 1);
    const [binding] = result;
    assert.equal(binding.siteName, "Default Web Site");
    assert.equal(binding.port, 443);
    assert.equal(binding.sniHost, "example.com");
    assert.equal(binding.thumbprint, "aabbccddeeff00112233445566778899aabbccdd");
    assert.equal(binding.storeLocation, "LocalMachine");
    assert.equal(binding.storeName, "My");
  });

  it("returns [] and warns (not throw) when WebAdministration module is absent", () => {
    const warnings = [];
    const spawn = () =>
      fakeSpawnResult({
        status: 1,
        stderr: "Import-Module : The specified module 'WebAdministration' was not loaded",
      });

    const result = listIisBindings({ spawn, onWarning: (m) => warnings.push(m) });

    assert.deepEqual(result, []);
    assert.ok(warnings.some((m) => m.includes("iis_binding")));
  });

  it("normalizes a null sniHost to null rather than an empty string", () => {
    const stdout = JSON.stringify({
      items: [{ SiteName: "Site1", Port: "443", SniHost: "", Thumbprint: null, StoreName: "My" }],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listIisBindings({ spawn });

    assert.equal(result.length, 1);
    assert.equal(result[0].sniHost, null);
    assert.equal(result[0].thumbprint, null);
  });

  it("defaults port to 443 when Port is missing/unparsable", () => {
    const stdout = JSON.stringify({
      items: [{ SiteName: "Site1", Port: undefined, Thumbprint: "aa", StoreName: "My" }],
    });
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listIisBindings({ spawn });

    assert.equal(result[0].port, 443);
  });
});

describe("listHttpSysBindings", () => {
  it("parses standard (English) netsh http show sslcert output", () => {
    const stdout = [
      "SSL Certificate bindings:",
      "-------------------------",
      "",
      "    IP:port                      : 0.0.0.0:8443",
      "    Certificate Hash             : aabbccddeeff00112233445566778899aabbccdd",
      "    Application ID               : {00000000-0000-0000-0000-000000000000}",
      "    Certificate Store Name       : MY",
      "",
    ].join("\r\n");
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listHttpSysBindings({ spawn });

    assert.equal(result.length, 1);
    assert.equal(result[0].hostname, "0.0.0.0");
    assert.equal(result[0].port, 8443);
    assert.equal(result[0].thumbprint, "aabbccddeeff00112233445566778899aabbccdd");
  });

  it("parses localized (non-English) netsh output by value shape, not label text", () => {
    // Regression test: the French UI label "Adresse IP:port" contains a
    // colon inside the label itself, and localized labels use non-ASCII
    // punctuation (guillemet quotes) that must not break parsing.
    const stdout = [
      "Liaisons de certificat SSL :",
      "----------------------------",
      "",
      "    Adresse IP:port                      : 0.0.0.0:44300",
      "    Hachage du certificat             : 259a9a2ab37dbd4ee04877fd292a8fe62d56a3dd",
      "    ID de l'application               : {214124cd-d05b-4309-9af9-9caa44b2b74a}",
      "    Nom du magasin de certificats :       : MY",
      "",
    ].join("\r\n");
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listHttpSysBindings({ spawn });

    assert.equal(result.length, 1);
    assert.equal(result[0].hostname, "0.0.0.0");
    assert.equal(result[0].port, 44300);
    assert.equal(result[0].thumbprint, "259a9a2ab37dbd4ee04877fd292a8fe62d56a3dd");
  });

  it("parses multiple bindings separated by blank lines", () => {
    const stdout = [
      "    IP:port                      : 0.0.0.0:44300",
      "    Certificate Hash             : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "",
      "    IP:port                      : 0.0.0.0:44301",
      "    Certificate Hash             : bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "",
    ].join("\r\n");
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listHttpSysBindings({ spawn });

    assert.equal(result.length, 2);
    assert.equal(result[0].port, 44300);
    assert.equal(result[1].port, 44301);
    assert.notEqual(result[0].thumbprint, result[1].thumbprint);
  });

  it("returns a null thumbprint (not throw) when the certificate hash line is absent", () => {
    const stdout = ["    IP:port                      : 0.0.0.0:44300", ""].join("\r\n");
    const spawn = () => fakeSpawnResult({ stdout });

    const result = listHttpSysBindings({ spawn });

    assert.equal(result.length, 1);
    assert.equal(result[0].thumbprint, null);
  });

  it("returns [] and warns when netsh is not available (ENOENT)", () => {
    const warnings = [];
    const spawn = () => fakeSpawnResult({ error: { code: "ENOENT" } });

    const result = listHttpSysBindings({ spawn, onWarning: (m) => warnings.push(m) });

    assert.deepEqual(result, []);
    assert.ok(warnings.some((m) => m.includes("not available")));
  });

  it("returns [] for empty netsh output (no bindings configured)", () => {
    const spawn = () => fakeSpawnResult({ stdout: "" });

    const result = listHttpSysBindings({ spawn });

    assert.deepEqual(result, []);
  });
});

describe("collectWindowsDiscoveryObservations", () => {
  /**
   * Builds a single `spawn` stand-in that dispatches to different canned
   * results depending on which underlying command/script is invoked, since
   * collectWindowsDiscoveryObservations calls all three list* functions
   * through the same injected spawn.
   */
  function makeDispatchingSpawn({ storeStdout, iisStdout, netshStdout }) {
    return (file, args) => {
      if (file === "netsh") {
        return fakeSpawnResult({ stdout: netshStdout ?? "" });
      }
      const script = String(args?.[3] || "");
      if (script.includes("WebAdministration")) {
        return fakeSpawnResult({ stdout: iisStdout ?? JSON.stringify({ items: [] }) });
      }
      return fakeSpawnResult({ stdout: storeStdout ?? JSON.stringify({ items: [] }) });
    };
  }

  it(
    "computes a real SHA-256 fingerprint from RawData for a windows_store entry",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const derBase64 = generateSelfSignedCertDerBase64("store-only.example.com");
      const storeStdout = JSON.stringify({
        items: [
          {
            Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
            Subject: "CN=store-only.example.com",
            Issuer: "CN=store-only.example.com",
            SerialNumber: "01",
            NotBefore: "2026-01-01T00:00:00.0000000Z",
            NotAfter: "2027-01-01T00:00:00.0000000Z",
            SubjectAltNames: "",
            RawCertificateBase64: derBase64,
            HasPrivateKey: false,
          },
        ],
      });
      const spawn = makeDispatchingSpawn({ storeStdout });

      const observations = collectWindowsDiscoveryObservations({ spawn });

      assert.equal(observations.length, 1);
      const [obs] = observations;
      assert.equal(obs.locationKind, "windows_store");
      assert.match(obs.fingerprintSha256, /^[a-f0-9]{64}$/);
      assert.equal(obs.locationSlot, "LocalMachine/My/store-only.example.com");
      // A confirmed-absent key is reported as a plain false fact, exactly
      // as observed -- not omitted, not guessed true.
      assert.equal(obs.keyPresent, false);
      // Never leaks raw certificate bytes or key material into the
      // observation shape handed off to the evidence-building caller.
      const serialized = JSON.stringify(obs);
      assert.ok(!serialized.includes(derBase64));
      assert.ok(!serialized.toLowerCase().includes("privatekey"));
    },
  );

  it(
    "resolves an IIS binding's thumbprint against the store and reuses the same fingerprint",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const derBase64 = generateSelfSignedCertDerBase64("iis-bound.example.com");
      const thumbprint = "1122334455667788990011223344556677889900";
      const storeStdout = JSON.stringify({
        items: [
          {
            Thumbprint: thumbprint,
            Subject: "CN=iis-bound.example.com",
            Issuer: "CN=iis-bound.example.com",
            RawCertificateBase64: derBase64,
            HasPrivateKey: true,
          },
        ],
      });
      const iisStdout = JSON.stringify({
        items: [
          {
            SiteName: "Default Web Site",
            Port: "443",
            SniHost: "iis-bound.example.com",
            Thumbprint: thumbprint,
            StoreName: "My",
          },
        ],
      });
      const spawn = makeDispatchingSpawn({ storeStdout, iisStdout });

      const observations = collectWindowsDiscoveryObservations({ spawn });

      const iisObservation = observations.find((o) => o.locationKind === "iis_binding");
      const storeObservation = observations.find((o) => o.locationKind === "windows_store");
      assert.ok(iisObservation, "expected an iis_binding observation");
      assert.equal(iisObservation.locationSlot, "Default Web Site:443#iis-bound.example.com");
      assert.equal(iisObservation.fingerprintSha256, storeObservation.fingerprintSha256);
      // A binding never holds its own key handle -- it references the
      // store entry by thumbprint -- so its keyPresent fact is the
      // cross-referenced store entry's, not independently determined.
      assert.equal(iisObservation.keyPresent, true);
      assert.equal(storeObservation.keyPresent, true);
    },
  );

  it("skips a binding whose thumbprint is not found in the machine store, with a warning", () => {
    const iisStdout = JSON.stringify({
      items: [
        {
          SiteName: "Orphan Site",
          Port: "443",
          SniHost: null,
          Thumbprint: "ffffffffffffffffffffffffffffffffffffffff",
          StoreName: "My",
        },
      ],
    });
    const spawn = makeDispatchingSpawn({ iisStdout });
    const warnings = [];

    const observations = collectWindowsDiscoveryObservations({ spawn, onWarning: (m) => warnings.push(m) });

    assert.equal(observations.length, 0);
    assert.ok(warnings.some((m) => m.includes("Orphan Site") && m.includes("not found")));
  });

  it("returns [] (not throw) when the store, IIS, and http.sys surfaces are all empty", () => {
    const spawn = makeDispatchingSpawn({});

    const observations = collectWindowsDiscoveryObservations({ spawn });

    assert.deepEqual(observations, []);
  });

  it(
    "resolves an http.sys binding's thumbprint against the store",
    { skip: !OPENSSL_BINARY ? "openssl is not available on this machine" : false },
    () => {
      const derBase64 = generateSelfSignedCertDerBase64("httpsys-bound.example.com");
      const thumbprint = "9988776655443322110099887766554433221100";
      const storeStdout = JSON.stringify({
        items: [
          {
            Thumbprint: thumbprint,
            Subject: "CN=httpsys-bound.example.com",
            RawCertificateBase64: derBase64,
          },
        ],
      });
      const netshStdout = [
        "    IP:port                      : 0.0.0.0:8443",
        `    Certificate Hash             : ${thumbprint}`,
        "",
      ].join("\r\n");
      const spawn = makeDispatchingSpawn({ storeStdout, netshStdout });

      const observations = collectWindowsDiscoveryObservations({ spawn });

      const httpSysObservation = observations.find((o) => o.locationKind === "http_sys");
      assert.ok(httpSysObservation, "expected an http_sys observation");
      assert.equal(httpSysObservation.locationSlot, "0.0.0.0:8443");
      assert.match(httpSysObservation.fingerprintSha256, /^[a-f0-9]{64}$/);
    },
  );
});
