"use strict";

/**
 * Tests for packages/agent/src/windows-discovery/index.js.
 *
 * PowerShell/certutil/netsh/appcmd invocations are exercised through
 * injected execFile stubs (same pattern as the sibling
 * windows-cert-store/windows-iis modules). The German and French certutil
 * fixtures are trimmed copies of real Windows Server and Windows 11
 * output; the store query JSON matches what Windows PowerShell 5.1 emits.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { X509Certificate } = require("node:crypto");

const {
  buildStoreQueryScript,
  parseStoreQueryOutput,
  parseNodeSubjectAltName,
  splitCertutilStoreBlocks,
  parseCertutilKeyInfo,
  parseNetshSslcertBindings,
  parseAppcmdSiteListOutput,
  findSitesForBinding,
  listMachineStoreCertificates,
  listHttpSysBindings,
  listIisSites,
  discoverWindowsCertificateInventory,
} = require("./index.js");

const SAMPLE_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD";
const OTHER_THUMBPRINT = "11223344556677889900AABBCCDDEEFF00112233";

// EC P-256, CN=www.example.com, SAN DNS:www.example.com, DNS:example.com, IP:10.0.0.5.
const SAN_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBuTCCAWCgAwIBAgIUA+2GVAwmAglQq2NglPLJBqzbHbEwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMB4XDTI2MTAwODE2NTEyMFoXDTM2
MTAwNTE2NTEyMFowGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEQSXXWHZASeePjojKSJ4YSj476eJPGawgh6yVeOjI
ARwawL2vjec/t1Tk6aXKRAfLoTGwPOgwkIG7m1lCVINiGKOBgzCBgDAdBgNVHQ4E
FgQUhDzyxJU4qH27lHFdIldK4Zj+MvYwHwYDVR0jBBgwFoAUhDzyxJU4qH27lHFd
IldK4Zj+MvYwDwYDVR0TAQH/BAUwAwEB/zAtBgNVHREEJjAkgg93d3cuZXhhbXBs
ZS5jb22CC2V4YW1wbGUuY29thwQKAAAFMAoGCCqGSM49BAMCA0cAMEQCIAZwIplN
5eSk616Gt/WeVEKrpiiIC3qZJBWmChMh7HgPAiB0xVvz080YD5t+XqPCXGOudEbJ
nhKKLrWtsrcRdzlSyw==
-----END CERTIFICATE-----`;
const SAN_CERT_DER = new X509Certificate(SAN_CERT_PEM).raw;

const JAN_1_2026 = Date.UTC(2026, 0, 1);
const JAN_1_2027 = Date.UTC(2027, 0, 1);

function codeUnits(text) {
  return Array.from({ length: text.length }, (_unused, index) => text.charCodeAt(index));
}

function storeItem({
  thumbprint = SAMPLE_THUMBPRINT,
  subject = "CN=www.example.com",
  issuer = "CN=Test Root CA",
  notBefore = JAN_1_2026,
  notAfter = JAN_1_2027,
  serialNumber = "1A2B3C4D5E",
  hasPrivateKey = false,
  rawData = [],
} = {}) {
  return {
    thumbprint,
    subject: codeUnits(subject),
    issuer: codeUnits(issuer),
    notBefore: `/Date(${notBefore})/`,
    notAfter: `/Date(${notAfter})/`,
    serialNumber,
    hasPrivateKey,
    rawData: Array.from(rawData),
  };
}

// ConvertTo-Json escapes the slashes around /Date(...)/.
function powershellJson(items) {
  return JSON.stringify({ items }).replace(/"\/Date\((-?\d+)\)\/"/g, '"\\/Date($1)\\/"');
}

const STORE_JSON = powershellJson([
  storeItem({ hasPrivateKey: true, rawData: SAN_CERT_DER }),
  storeItem({ thumbprint: OTHER_THUMBPRINT, subject: "CN=old.example.com", serialNumber: "9F8E7D6C5B" }),
]);
const EMPTY_STORE_JSON = powershellJson([]);

const CERTUTIL_KEY_INFO_EN = `My "Personal"
================ Certificate 0 ================
Serial Number: 1a2b3c4d5e
Issuer: CN=Test Root CA
 NotBefore: 1/1/2026 12:00 AM
 NotAfter: 1/1/2027 12:00 AM
Subject: CN=www.example.com
Non-root Certificate
Cert Hash(sha1): aabbccddeeff00112233445566778899aabbccdd
  Key Container = tokentimer-job-1-abcd1234
  Unique container name: a11a37ef57bb64c3f31f8f99421d1550_e64079bf-f1d8-450e-ba59-2f4d921306df
  Provider = Microsoft Software Key Storage Provider
Private key is NOT exportable
Encryption test passed

================ Certificate 1 ================
Serial Number: 9f8e7d6c5b
Issuer: CN=Test Root CA
 NotBefore: 6/1/2025 12:00 AM
 NotAfter: 6/1/2026 12:00 AM
Subject: CN=old.example.com
Non-root Certificate
Cert Hash(sha1): 11223344556677889900aabbccddeeff00112233
No key provider information
CertUtil: -store command completed successfully.
`;

const CERTUTIL_KEY_INFO_DE = `My "Eigene Zertifikate"
================ Zertifikat 14 ================
Seriennummer: 1a2b3c4d5e
Aussteller: CN=Test Root CA
 Nicht vor: 01.01.2026 01:00
 Nicht nach: 01.01.2027 01:00
Antragsteller: CN=www.example.com
Kein Stammzertifikat
Vorlage: TTWebServer
Zertifikathash(sha1): aabbccddeeff00112233445566778899aabbccdd
  Schl\uFFFDsselcontainer = tokentimer-job-1-abcd1234
  Eindeutiger Containername: a11a37ef57bb64c3f31f8f99421d1550_e64079bf-f1d8-450e-ba59-2f4d921306df
  Anbieter = Microsoft Software Key Storage Provider
Der private Schl\uFFFDssel ist NICHT exportierbar
Verschl\uFFFDsselungstest wurde durchgef\uFFFDhrt
CertUtil: -store-Befehl wurde erfolgreich ausgef\uFFFDhrt.
`;

// French puts a non-breaking space before ":" and before the key
// container's "=".
const CERTUTIL_KEY_INFO_FR = `My "Personnel"
================ Certificat 0 ================
Numéro de série : 1a2b3c4d5e
Émetteur: CN=Test Root CA
 NotBefore : 01/01/2026 01:00
 NotAfter : 01/01/2027 01:00
Objet: CN=www.example.com
Il ne s’agit pas d’un certificat racine
Hach. cert. (sha1)\u00A0: aabbccddeeff00112233445566778899aabbccdd
  Conteneur de clé\u00A0= tokentimer-job-1-abcd1234
  Fournisseur = Microsoft Software Key Storage Provider
Test de chiffrement réussi
CertUtil: -store La commande s’est terminée correctement.
`;

// The same output read through an OEM code page: the accented letter and
// the non-breaking space decode to replacement characters.
const CERTUTIL_KEY_INFO_FR_OEM = CERTUTIL_KEY_INFO_FR.replace(/[é\u00A0]/g, "\uFFFD");

const CERTUTIL_KEY_INFO_FR_SPACED_HASH = CERTUTIL_KEY_INFO_FR.replace(
  "aabbccddeeff00112233445566778899aabbccdd",
  "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd",
);

// Real `appcmd list site` line format:
//   SITE "Default Web Site" (id:1,bindings:http/*:80:,https/*:443:www.example.com,state:Started)
const APPCMD_LIST_SITE_OUTPUT = `SITE "Default Web Site" (id:1,bindings:http/*:80:,https/*:443:,state:Started)
SITE "Secure Site" (id:2,bindings:https/10.0.0.5:8443:,https/*:9443:sni.example.com,state:Started)
`;

const NETSH_SHOW_SSLCERT_OUTPUT = `
SSL Certificate bindings:
-------------------------

    IP:port                      : 10.0.0.5:443
    Certificate Hash              : aabbccddeeff00112233445566778899aabbccdd
    Application ID              : {12345678-1234-1234-1234-123456789012}
    Certificate Store Name        : My

    IP:port                      : 0.0.0.0:8443
    Certificate Hash              : 112233445566778899001122334455667788990a
    Application ID              : {87654321-4321-4321-4321-210987654321}
    Certificate Store Name        : WebHosting
`;

// Real, captured (not hand-authored) netsh http show sslcert output for a
// hostname-keyed (SNI, via hostnameport=) binding, from a real-host
// verification run against a live IIS SNI binding. This is the format
// parseNetshSslcertBindings originally failed to recognize at all.
const NETSH_SHOW_SSLCERT_HOSTNAME_OUTPUT = `
SSL Certificate bindings:
-------------------------

    Hostname:port                : sni-precision.tokentimer-verify.local:10443
    Certificate Hash             : daa61c502810ca0952df77a0d4194c32085b5abd
    Application ID               : {65f12961-a6a1-4736-a36e-af476fd0d37a}
    Certificate Store Name       : My
`;

const NETSH_SHOW_SSLCERT_MIXED_OUTPUT = `${NETSH_SHOW_SSLCERT_OUTPUT}
    Hostname:port                : sni-precision.tokentimer-verify.local:10443
    Certificate Hash             : daa61c502810ca0952df77a0d4194c32085b5abd
    Application ID               : {65f12961-a6a1-4736-a36e-af476fd0d37a}
    Certificate Store Name       : My
`;

/** execFile stub factory, mirroring the sibling modules' makeExecStub. */
function makeExecStub(response) {
  const calls = [];
  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    process.nextTick(() => callback(response.error || null, response.stdout || "", response.stderr || ""));
  }
  execFileStub.calls = calls;
  return execFileStub;
}

/** Routes each executable to its own canned response; unrouted calls fail. */
function makeExecRouter(responses) {
  const calls = [];
  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    const name = String(file).toLowerCase();
    const key = ["powershell", "certutil", "netsh", "appcmd"].find((tool) => name.includes(tool));
    const response = responses[key] || { error: Object.assign(new Error("unexpected"), { code: 1 }) };
    process.nextTick(() => callback(response.error || null, response.stdout || "", response.stderr || ""));
  }
  execFileStub.calls = calls;
  return execFileStub;
}

const denied = (stderr = "Access is denied.") => ({ error: Object.assign(new Error("denied"), { code: 5 }), stderr });

// ---------------------------------------------------------------------------
// buildStoreQueryScript / parseStoreQueryOutput
// ---------------------------------------------------------------------------

describe("buildStoreQueryScript", () => {
  it("reads the LocalMachine store through the Cert: provider with the store name single-quoted", () => {
    const script = buildStoreQueryScript("WebHosting");
    assert.match(script, /\$path = 'Cert:\\LocalMachine\\WebHosting'/);
    assert.match(script, /Test-Path -LiteralPath \$path/);
  });

  it("uses only constructs that Constrained Language Mode allows", () => {
    const script = buildStoreQueryScript("My");
    assert.doesNotMatch(script, /PSCustomObject|\[Convert\]|\[Console\]|ToUniversalTime|Add-Type|New-Object/);
  });

  it("keeps nested arrays as arrays (ConvertTo-Json defaults to depth 2)", () => {
    assert.match(buildStoreQueryScript("My"), /ConvertTo-Json -InputObject @\{ items = \$items \} -Compress -Depth 4/);
  });
});

describe("parseStoreQueryOutput", () => {
  it("decodes subject and issuer from UTF-16 code units, including non-ASCII names", () => {
    const [cert] = parseStoreQueryOutput(
      powershellJson([storeItem({ subject: "CN=Müller GmbH, O=Société Générale", issuer: "CN=Zürich CA" })]),
    );
    assert.equal(cert.subject, "CN=Müller GmbH, O=Société Générale");
    assert.equal(cert.issuer, "CN=Zürich CA");
  });

  it("decodes a single-character subject that serializes as a one-element array", () => {
    const [cert] = parseStoreQueryOutput(powershellJson([storeItem({ subject: "C" })]));
    assert.equal(cert.subject, "C");
  });

  it("reports an empty subject as null", () => {
    const [cert] = parseStoreQueryOutput(powershellJson([storeItem({ subject: "" })]));
    assert.equal(cert.subject, null);
  });

  it("reports validity dates as ISO 8601 UTC regardless of the host's date format", () => {
    const [cert] = parseStoreQueryOutput(STORE_JSON);
    assert.equal(cert.notBefore, "2026-01-01T00:00:00.000Z");
    assert.equal(cert.notAfter, "2027-01-01T00:00:00.000Z");
  });

  it("normalizes the serial number to certutil's form: lowercase, without the DER sign byte", () => {
    const [cert] = parseStoreQueryOutput(powershellJson([storeItem({ serialNumber: "00F300F1E194A05C" })]));
    assert.equal(cert.serialNumber, "f300f1e194a05c");
  });

  it("reads subject alternative names from the certificate's own DER bytes", () => {
    const [cert] = parseStoreQueryOutput(STORE_JSON);
    assert.deepEqual(cert.subjectAlternativeNames, ["www.example.com", "example.com", "10.0.0.5"]);
  });

  it("returns [] for subjectAlternativeNames when the bytes do not parse", () => {
    const [, cert] = parseStoreQueryOutput(STORE_JSON);
    assert.deepEqual(cert.subjectAlternativeNames, []);
  });

  it("uppercases thumbprints and reads hasPrivateKey as a strict boolean", () => {
    const certs = parseStoreQueryOutput(
      powershellJson([
        storeItem({ thumbprint: SAMPLE_THUMBPRINT.toLowerCase(), hasPrivateKey: true }),
        storeItem({ thumbprint: OTHER_THUMBPRINT, hasPrivateKey: "True" }),
      ]),
    );
    assert.equal(certs[0].thumbprint, SAMPLE_THUMBPRINT);
    assert.equal(certs[0].hasPrivateKey, true);
    assert.equal(certs[1].hasPrivateKey, false);
  });

  it("drops entries without a valid thumbprint", () => {
    const certs = parseStoreQueryOutput(powershellJson([storeItem({ thumbprint: "not-a-thumbprint" }), storeItem()]));
    assert.equal(certs.length, 1);
  });

  it("never returns raw certificate bytes or anything resembling key material", () => {
    const serialized = JSON.stringify(parseStoreQueryOutput(STORE_JSON));
    assert.doesNotMatch(serialized, /rawData|PRIVATE KEY/);
  });

  it("returns [] for an empty or missing store", () => {
    assert.deepEqual(parseStoreQueryOutput(EMPTY_STORE_JSON), []);
  });

  it("throws on output that is not the expected JSON", () => {
    assert.throws(() => parseStoreQueryOutput("Get-ChildItem : Access denied"));
    assert.throws(() => parseStoreQueryOutput('{"value":[]}'), /no items field/);
  });
});

describe("parseNodeSubjectAltName", () => {
  it("parses Node's comma-separated format into bare values", () => {
    assert.deepEqual(
      parseNodeSubjectAltName("DNS:example.com, DNS:www.example.com, IP Address:10.0.0.5"),
      ["example.com", "www.example.com", "10.0.0.5"],
    );
  });

  it("preserves JSON-quoted values containing commas", () => {
    assert.deepEqual(parseNodeSubjectAltName('DNS:example.com, URI:"https://example.com/a,b"'), [
      "example.com",
      "https://example.com/a,b",
    ]);
  });
});

// ---------------------------------------------------------------------------
// splitCertutilStoreBlocks / parseCertutilKeyInfo
// ---------------------------------------------------------------------------

describe("splitCertutilStoreBlocks", () => {
  it("splits on the banner line whatever language its word is in", () => {
    assert.equal(splitCertutilStoreBlocks(CERTUTIL_KEY_INFO_EN).length, 2);
    assert.equal(splitCertutilStoreBlocks(CERTUTIL_KEY_INFO_DE).length, 1);
    assert.equal(splitCertutilStoreBlocks(CERTUTIL_KEY_INFO_FR).length, 1);
  });

  it("returns an empty array for unrecognizable output", () => {
    assert.deepEqual(splitCertutilStoreBlocks("garbage\r\nmore garbage\r\n"), []);
  });
});

describe("parseCertutilKeyInfo", () => {
  const thumbprints = new Set([SAMPLE_THUMBPRINT, OTHER_THUMBPRINT]);
  const expected = {
    keyContainer: "tokentimer-job-1-abcd1234",
    keyProvider: "Microsoft Software Key Storage Provider",
  };

  it("reads the key container and provider from English output, skipping the colon-labeled unique name", () => {
    assert.deepEqual(parseCertutilKeyInfo(CERTUTIL_KEY_INFO_EN, thumbprints).get(SAMPLE_THUMBPRINT), expected);
  });

  it("reads the key container and provider from German output", () => {
    assert.deepEqual(parseCertutilKeyInfo(CERTUTIL_KEY_INFO_DE, thumbprints).get(SAMPLE_THUMBPRINT), expected);
  });

  it("reads the key container, not the provider, when its label ends in a non-breaking space (French)", () => {
    assert.deepEqual(parseCertutilKeyInfo(CERTUTIL_KEY_INFO_FR, thumbprints).get(SAMPLE_THUMBPRINT), expected);
  });

  it("reads French output decoded through an OEM code page", () => {
    assert.deepEqual(parseCertutilKeyInfo(CERTUTIL_KEY_INFO_FR_OEM, thumbprints).get(SAMPLE_THUMBPRINT), expected);
  });

  it("matches a hash printed as space-separated byte pairs", () => {
    assert.deepEqual(
      parseCertutilKeyInfo(CERTUTIL_KEY_INFO_FR_SPACED_HASH, thumbprints).get(SAMPLE_THUMBPRINT),
      expected,
    );
  });

  it("handles CRLF line endings", () => {
    const crlf = CERTUTIL_KEY_INFO_DE.replace(/\n/g, "\r\n");
    assert.deepEqual(parseCertutilKeyInfo(crlf, thumbprints).get(SAMPLE_THUMBPRINT), expected);
  });

  it("reports neither field when only one of the two lines is recognized, so the provider never stands in for the container", () => {
    const containerLineUnrecognized = CERTUTIL_KEY_INFO_EN.replace("  Key Container =", "  Key: Container =");
    assert.deepEqual(parseCertutilKeyInfo(containerLineUnrecognized, thumbprints).get(SAMPLE_THUMBPRINT), {
      keyContainer: null,
      keyProvider: null,
    });
  });

  it("reports null key fields for a certificate without key provider information", () => {
    assert.deepEqual(parseCertutilKeyInfo(CERTUTIL_KEY_INFO_EN, thumbprints).get(OTHER_THUMBPRINT), {
      keyContainer: null,
      keyProvider: null,
    });
  });

  it("ignores blocks whose hash is not one of the requested thumbprints", () => {
    const result = parseCertutilKeyInfo(CERTUTIL_KEY_INFO_EN, new Set([OTHER_THUMBPRINT]));
    assert.equal(result.has(SAMPLE_THUMBPRINT), false);
  });
});

// ---------------------------------------------------------------------------
// parseNetshSslcertBindings
// ---------------------------------------------------------------------------

describe("parseNetshSslcertBindings", () => {
  it("parses every binding block into ipPort/thumbprint/storeName/appId", () => {
    const bindings = parseNetshSslcertBindings(NETSH_SHOW_SSLCERT_OUTPUT);
    assert.equal(bindings.length, 2);
    assert.equal(bindings[0].ipPort, "10.0.0.5:443");
    assert.equal(bindings[0].thumbprint, SAMPLE_THUMBPRINT);
    assert.equal(bindings[0].storeName, "My");
    assert.equal(bindings[0].appId, "{12345678-1234-1234-1234-123456789012}");
    assert.equal(bindings[0].keyedBy, "ipport");
    assert.equal(bindings[1].ipPort, "0.0.0.0:8443");
    assert.equal(bindings[1].storeName, "WebHosting");
  });

  it("returns an empty array when there are no bindings", () => {
    assert.deepEqual(parseNetshSslcertBindings("\r\nSSL Certificate bindings:\r\n-------------------------\r\n\r\n"), []);
  });

  it("parses a real hostname-keyed (SNI, hostnameport=) binding block, not just IP:port ones (2026-08-05 real-host finding)", () => {
    const bindings = parseNetshSslcertBindings(NETSH_SHOW_SSLCERT_HOSTNAME_OUTPUT);
    assert.equal(bindings.length, 1);
    assert.equal(bindings[0].ipPort, "sni-precision.tokentimer-verify.local:10443");
    assert.equal(bindings[0].keyedBy, "hostnameport");
    assert.equal(bindings[0].thumbprint, "DAA61C502810CA0952DF77A0D4194C32085B5ABD");
    assert.equal(bindings[0].storeName, "My");
  });

  it("parses a mix of IP:port and Hostname:port blocks in the same (unfiltered) netsh output, dropping none of them", () => {
    const bindings = parseNetshSslcertBindings(NETSH_SHOW_SSLCERT_MIXED_OUTPUT);
    assert.equal(bindings.length, 3);
    assert.deepEqual(bindings.map((b) => b.keyedBy), ["ipport", "ipport", "hostnameport"]);
  });
});

// ---------------------------------------------------------------------------
// listMachineStoreCertificates
// ---------------------------------------------------------------------------

describe("listMachineStoreCertificates", () => {
  it("joins the store query's fields with certutil's key container and provider", async () => {
    const execFileImpl = makeExecRouter({ powershell: { stdout: STORE_JSON }, certutil: { stdout: CERTUTIL_KEY_INFO_EN } });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.certificates.length, 2);
    const [keyed, unkeyed] = result.certificates;
    assert.equal(keyed.thumbprint, SAMPLE_THUMBPRINT);
    assert.equal(keyed.subject, "CN=www.example.com");
    assert.equal(keyed.notAfter, "2027-01-01T00:00:00.000Z");
    assert.equal(keyed.hasPrivateKey, true);
    assert.equal(keyed.keyContainer, "tokentimer-job-1-abcd1234");
    assert.equal(keyed.keyProvider, "Microsoft Software Key Storage Provider");
    assert.equal(unkeyed.hasPrivateKey, false);
    assert.equal(unkeyed.keyContainer, null);
    assert.ok(result.certificates.every((cert) => cert.store === "My"));
  });

  it("resolves the key container on German and French hosts", async () => {
    for (const certutilStdout of [CERTUTIL_KEY_INFO_DE, CERTUTIL_KEY_INFO_FR, CERTUTIL_KEY_INFO_FR_OEM]) {
      const execFileImpl = makeExecRouter({ powershell: { stdout: STORE_JSON }, certutil: { stdout: certutilStdout } });
      const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
      assert.equal(result.ok, true);
      assert.equal(result.certificates[0].keyContainer, "tokentimer-job-1-abcd1234");
    }
  });

  it("runs Windows PowerShell without a profile, without PSModulePath, then non-verbose certutil -store", async () => {
    const execFileImpl = makeExecRouter({ powershell: { stdout: STORE_JSON }, certutil: { stdout: CERTUTIL_KEY_INFO_EN } });
    await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(execFileImpl.calls.length, 2);
    const [query, keyInfo] = execFileImpl.calls;
    assert.equal(query.file, "powershell.exe");
    assert.deepEqual(query.args.slice(0, 3), ["-NoProfile", "-NonInteractive", "-Command"]);
    assert.equal(query.args[3], buildStoreQueryScript("My"));
    assert.ok(!Object.keys(query.options.env).some((key) => key.toLowerCase() === "psmodulepath"));
    assert.equal(keyInfo.file, "certutil.exe");
    assert.deepEqual(keyInfo.args, ["-store", "My"]);
  });

  it("skips certutil entirely when no certificate has a private key", async () => {
    const execFileImpl = makeExecRouter({
      powershell: { stdout: powershellJson([storeItem({ thumbprint: OTHER_THUMBPRINT })]) },
    });
    const result = await listMachineStoreCertificates({ store: "Root", execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(execFileImpl.calls.length, 1);
  });

  it("reports an empty or missing store as ok: true, certificates: []", async () => {
    const execFileImpl = makeExecRouter({ powershell: { stdout: EMPTY_STORE_JSON } });
    const result = await listMachineStoreCertificates({ store: "WebHosting", execFileImpl });
    assert.deepEqual(result, { ok: true, certificates: [] });
  });

  it("returns ok: false when the store query fails", async () => {
    const execFileImpl = makeExecRouter({ powershell: denied() });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 5);
  });

  it("returns ok: false when the store query output is not JSON", async () => {
    const execFileImpl = makeExecRouter({ powershell: { stdout: "Cert: drive not found" } });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.match(result.stderrExcerpt, /unreadable store query output/);
  });

  it("returns ok: false when certutil fails, rather than reporting keyed certificates without a container", async () => {
    const execFileImpl = makeExecRouter({ powershell: { stdout: STORE_JSON }, certutil: denied() });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 5);
  });

  it("returns ok: false when certutil does not report a container for a keyed certificate", async () => {
    const withoutContainer = CERTUTIL_KEY_INFO_EN.replace(/^ {2}(Key Container|Provider) = .*\n/gm, "");
    const execFileImpl = makeExecRouter({ powershell: { stdout: STORE_JSON }, certutil: { stdout: withoutContainer } });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.match(result.stderrExcerpt, new RegExp(`no key container for ${SAMPLE_THUMBPRINT}`));
  });

  it("returns ok: false when a keyed certificate is missing from certutil's listing (store changed in between)", async () => {
    const execFileImpl = makeExecRouter({
      powershell: { stdout: STORE_JSON },
      certutil: { stdout: 'My "Personal"\nCertUtil: -store command completed successfully.\n' },
    });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
  });

  it("rejects an invalid store name before invoking execFile", async () => {
    const execFileImpl = makeExecRouter({});
    for (const store of ["My/../evil", "My'; Remove-Item C:\\", "..", "."]) {
      await assert.rejects(
        listMachineStoreCertificates({ store, execFileImpl }),
        /valid Windows certificate store name/,
      );
    }
    assert.equal(execFileImpl.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// listHttpSysBindings
// ---------------------------------------------------------------------------

describe("listHttpSysBindings", () => {
  it("returns parsed bindings on success", async () => {
    const execFileImpl = makeExecStub({ stdout: NETSH_SHOW_SSLCERT_OUTPUT });
    const result = await listHttpSysBindings({ execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.bindings.length, 2);
  });

  it("treats no-bindings-configured as ok: true, bindings: []", async () => {
    const error = Object.assign(new Error("none"), { code: 1 });
    const execFileImpl = makeExecStub({ error, stdout: "No SSL certificate bindings exist." });
    const result = await listHttpSysBindings({ execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.bindings, []);
  });

  it("returns ok: false on a genuine netsh failure", async () => {
    const error = Object.assign(new Error("denied"), { code: 5 });
    const execFileImpl = makeExecStub({ error, stderr: "Access is denied." });
    const result = await listHttpSysBindings({ execFileImpl });
    assert.equal(result.ok, false);
  });
});

// ---------------------------------------------------------------------------
// parseAppcmdSiteListOutput / findSitesForBinding / listIisSites
// ---------------------------------------------------------------------------

describe("parseAppcmdSiteListOutput", () => {
  it("parses one record per SITE line with decoded bindings", () => {
    const sites = parseAppcmdSiteListOutput(APPCMD_LIST_SITE_OUTPUT);
    assert.equal(sites.length, 2);
    assert.equal(sites[0].name, "Default Web Site");
    assert.equal(sites[0].id, "1");
    assert.equal(sites[0].state, "Started");
    assert.deepEqual(sites[0].bindings, [
      { protocol: "http", address: "*", port: "80", hostHeader: "" },
      { protocol: "https", address: "*", port: "443", hostHeader: "" },
    ]);
    assert.equal(sites[1].name, "Secure Site");
    assert.deepEqual(sites[1].bindings, [
      { protocol: "https", address: "10.0.0.5", port: "8443", hostHeader: "" },
      { protocol: "https", address: "*", port: "9443", hostHeader: "sni.example.com" },
    ]);
  });

  it("returns [] for output with no SITE lines", () => {
    assert.deepEqual(parseAppcmdSiteListOutput("No sites configured\r\n"), []);
  });
});

describe("findSitesForBinding", () => {
  const sites = parseAppcmdSiteListOutput(APPCMD_LIST_SITE_OUTPUT);

  it("matches an IP-keyed binding to a site with a wildcard address and no host header", () => {
    assert.deepEqual(findSitesForBinding(sites, { ipPort: "10.0.0.5:443", keyedBy: "ipport" }), ["Default Web Site"]);
  });

  it("matches an IP-keyed binding to a site bound to the exact same address", () => {
    assert.deepEqual(findSitesForBinding(sites, { ipPort: "10.0.0.5:8443", keyedBy: "ipport" }), ["Secure Site"]);
  });

  it("matches a hostname-keyed (SNI) binding by host header, not address", () => {
    assert.deepEqual(
      findSitesForBinding(sites, { ipPort: "sni.example.com:9443", keyedBy: "hostnameport" }),
      ["Secure Site"],
    );
  });

  it("never matches an IP-keyed binding against a site binding that has a host header (no SNI signal to disambiguate)", () => {
    assert.deepEqual(findSitesForBinding(sites, { ipPort: "0.0.0.0:9443", keyedBy: "ipport" }), []);
  });

  it("returns [] when no site's bindings match at all", () => {
    assert.deepEqual(findSitesForBinding(sites, { ipPort: "10.0.0.9:12345", keyedBy: "ipport" }), []);
  });
});

describe("listIisSites", () => {
  it("returns parsed sites on success", async () => {
    const execFileImpl = makeExecStub({ stdout: APPCMD_LIST_SITE_OUTPUT });
    const result = await listIisSites({ execFileImpl, appcmdPath: "appcmd.exe" });
    assert.equal(result.ok, true);
    assert.equal(result.sites.length, 2);
  });

  it("returns ok: true, sites: [] when appcmd is unavailable, never ok: false", async () => {
    const error = Object.assign(new Error("not found"), { code: 9009 });
    const execFileImpl = makeExecStub({ error, stderr: "'appcmd' is not recognized as an internal or external command" });
    const result = await listIisSites({ execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.sites, []);
  });
});

// ---------------------------------------------------------------------------
// discoverWindowsCertificateInventory
// ---------------------------------------------------------------------------

describe("discoverWindowsCertificateInventory", () => {
  it("cross-references store certificates with the bindings and IIS sites that reference them", async () => {
    const execFileImpl = makeExecRouter({
      powershell: { stdout: STORE_JSON },
      certutil: { stdout: CERTUTIL_KEY_INFO_EN },
      netsh: { stdout: NETSH_SHOW_SSLCERT_OUTPUT },
      appcmd: { stdout: APPCMD_LIST_SITE_OUTPUT },
    });

    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl, appcmdPath: "appcmd.exe" });
    assert.equal(result.ok, true);
    const bound = result.certificates.find((c) => c.thumbprint === SAMPLE_THUMBPRINT);
    assert.deepEqual(bound.boundAt, ["10.0.0.5:443"]);
    assert.deepEqual(bound.boundSites, ["Default Web Site"]);

    const unbound = result.certificates.find((c) => c.thumbprint !== SAMPLE_THUMBPRINT);
    assert.deepEqual(unbound.boundAt, []);
    assert.deepEqual(unbound.boundSites, []);
  });

  it("reports boundSites: [] (not an error) when appcmd/IIS management tools are unavailable", async () => {
    const execFileImpl = makeExecRouter({
      powershell: { stdout: STORE_JSON },
      certutil: { stdout: CERTUTIL_KEY_INFO_EN },
      netsh: { stdout: NETSH_SHOW_SSLCERT_OUTPUT },
      appcmd: { error: Object.assign(new Error("not found"), { code: 9009 }), stderr: "'appcmd' is not recognized" },
    });

    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl, appcmdPath: "appcmd.exe" });
    assert.equal(result.ok, true);
    assert.ok(result.certificates.every((cert) => Array.isArray(cert.boundSites) && cert.boundSites.length === 0));
  });

  it("surfaces a store query failure distinctly from an empty store", async () => {
    const execFileImpl = makeExecRouter({ powershell: denied() });
    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.code, "STORE_QUERY_FAILED");
  });

  it("surfaces a binding query failure distinctly", async () => {
    const execFileImpl = makeExecRouter({ powershell: { stdout: EMPTY_STORE_JSON }, netsh: denied() });
    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.code, "BINDING_QUERY_FAILED");
  });

  it("never touches the binding query's actual store scoping (reports bindings for all stores)", async () => {
    const execFileImpl = makeExecRouter({
      powershell: { stdout: EMPTY_STORE_JSON },
      netsh: { stdout: NETSH_SHOW_SSLCERT_OUTPUT },
    });
    const result = await discoverWindowsCertificateInventory({ store: "WebHosting", execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.certificates, []);
  });
});
