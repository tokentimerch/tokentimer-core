"use strict";

/**
 * Tests for packages/agent/src/windows-discovery/index.js.
 *
 * certutil/netsh invocations are exercised through injected execFile stubs
 * (same pattern as the sibling windows-cert-store/windows-iis modules).
 * Sample stdout fixtures below are modeled on certutil -store and
 * netsh http show sslcert's documented/previously-observed text format;
 * this module has NOT yet been run against the real tools on a real host
 * (see the module's own doc comment), so these fixtures are a best-effort
 * reproduction, not a captured real transcript.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  splitCertutilStoreBlocks,
  parseCertutilStoreBlock,
  parseNetshSslcertBindings,
  listMachineStoreCertificates,
  listHttpSysBindings,
  discoverWindowsCertificateInventory,
} = require("./index.js");

const SAMPLE_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD";

const CERTUTIL_STORE_OUTPUT = `My "Personal"
================ Certificate 0 ================
Serial Number: 1a2b3c4d5e
Issuer: CN=Test Root CA
 NotBefore: 1/1/2026 12:00 AM
 NotAfter: 1/1/2027 12:00 AM
Subject: CN=www.example.com
Certificate Template Name (Certificate Type): WebServer
Signature matches Public Key
Cert Hash(sha1): aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd
  Key Container = tokentimer-job-1-abcd1234
  Provider = Microsoft Software Key Storage Provider
  Signature test passed
================ Certificate 1 ================
Serial Number: 9f8e7d6c5b
Issuer: CN=Test Root CA
 NotBefore: 6/1/2025 12:00 AM
 NotAfter: 6/1/2026 12:00 AM
Subject: CN=old.example.com
Cert Hash(sha1): 11 22 33 44 55 66 77 88 99 00 aa bb cc dd ee ff 00 11 22 33
CertUtil: -store command completed successfully.
`;

const CERTUTIL_EMPTY_STORE_OUTPUT = `My "WebHosting"
CertUtil: -store command completed successfully.
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
// hostname-keyed (SNI, via hostnameport=) binding, from the 2026-08-05
// real-host verification run (WIIS-05 / WDISC-04). This is the format
// splitCertutilStoreBlocks' sibling parseNetshSslcertBindings originally
// failed to recognize at all.
const NETSH_SHOW_SSLCERT_HOSTNAME_OUTPUT = `
SSL Certificate bindings:
-------------------------

    Hostname:port                : wiis05.tokentimer-verify.local:10443
    Certificate Hash             : daa61c502810ca0952df77a0d4194c32085b5abd
    Application ID               : {65f12961-a6a1-4736-a36e-af476fd0d37a}
    Certificate Store Name       : My
`;

const NETSH_SHOW_SSLCERT_MIXED_OUTPUT = `${NETSH_SHOW_SSLCERT_OUTPUT}
    Hostname:port                : wiis05.tokentimer-verify.local:10443
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

// ---------------------------------------------------------------------------
// splitCertutilStoreBlocks / parseCertutilStoreBlock
// ---------------------------------------------------------------------------

describe("splitCertutilStoreBlocks", () => {
  it("splits multiple certificate entries on the banner line", () => {
    const blocks = splitCertutilStoreBlocks(CERTUTIL_STORE_OUTPUT);
    assert.equal(blocks.length, 2);
  });

  it("returns an empty array for an empty store", () => {
    assert.deepEqual(splitCertutilStoreBlocks(CERTUTIL_EMPTY_STORE_OUTPUT), []);
  });

  it("returns an empty array for unrecognizable output", () => {
    assert.deepEqual(splitCertutilStoreBlocks("garbage\r\nmore garbage\r\n"), []);
  });
});

describe("parseCertutilStoreBlock", () => {
  it("extracts subject/issuer/validity/serial/thumbprint from a well-formed block", () => {
    const [certWithKey] = splitCertutilStoreBlocks(CERTUTIL_STORE_OUTPUT);
    const parsed = parseCertutilStoreBlock(certWithKey);
    assert.equal(parsed.thumbprint, SAMPLE_THUMBPRINT);
    assert.equal(parsed.subject, "CN=www.example.com");
    assert.equal(parsed.issuer, "CN=Test Root CA");
    assert.equal(parsed.serialNumber, "1a2b3c4d5e");
    assert.equal(parsed.notBefore, "1/1/2026 12:00 AM");
    assert.equal(parsed.notAfter, "1/1/2027 12:00 AM");
  });

  it("reports hasPrivateKey: true when a Key Container line is present", () => {
    const [certWithKey] = splitCertutilStoreBlocks(CERTUTIL_STORE_OUTPUT);
    const parsed = parseCertutilStoreBlock(certWithKey);
    assert.equal(parsed.hasPrivateKey, true);
    assert.equal(parsed.keyContainer, "tokentimer-job-1-abcd1234");
    assert.equal(parsed.keyProvider, "Microsoft Software Key Storage Provider");
  });

  it("reports hasPrivateKey: false when no Key Container/Provider line is present", () => {
    const [, certWithoutKey] = splitCertutilStoreBlocks(CERTUTIL_STORE_OUTPUT);
    const parsed = parseCertutilStoreBlock(certWithoutKey);
    assert.equal(parsed.hasPrivateKey, false);
    assert.equal(parsed.keyContainer, null);
  });

  it("never reads or returns anything resembling key material, only presence", () => {
    const [certWithKey] = splitCertutilStoreBlocks(CERTUTIL_STORE_OUTPUT);
    const parsed = parseCertutilStoreBlock(certWithKey);
    const serialized = JSON.stringify(parsed);
    assert.doesNotMatch(serialized, /PRIVATE KEY/);
  });

  it("degrades gracefully (nulls, not throws) on a block missing fields", () => {
    const parsed = parseCertutilStoreBlock("Subject: CN=weird.example.com\r\n");
    assert.equal(parsed.thumbprint, null);
    assert.equal(parsed.subject, "CN=weird.example.com");
    assert.equal(parsed.hasPrivateKey, false);
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
    assert.equal(bindings[0].ipPort, "wiis05.tokentimer-verify.local:10443");
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
  it("returns parsed certificates on success", async () => {
    const execFileImpl = makeExecStub({ stdout: CERTUTIL_STORE_OUTPUT });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.certificates.length, 2);
  });

  it("treats an empty/nonexistent store as ok: true, certificates: []", async () => {
    const error = Object.assign(new Error("not found"), { code: 1 });
    const execFileImpl = makeExecStub({ error, stdout: "Cannot find object or property." });
    const result = await listMachineStoreCertificates({ store: "WebHosting", execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.certificates, []);
  });

  it("returns ok: false on a genuine certutil failure", async () => {
    const error = Object.assign(new Error("denied"), { code: 5 });
    const execFileImpl = makeExecStub({ error, stderr: "Access is denied." });
    const result = await listMachineStoreCertificates({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 5);
  });

  it("rejects an invalid store name before invoking execFile", async () => {
    const execFileImpl = makeExecStub({ stdout: "" });
    await assert.rejects(
      listMachineStoreCertificates({ store: "My/../evil", execFileImpl }),
      /valid Windows certificate store name/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });

  it("invokes certutil -store <name> with the expected argv", async () => {
    const execFileImpl = makeExecStub({ stdout: CERTUTIL_EMPTY_STORE_OUTPUT });
    await listMachineStoreCertificates({ store: "My", execFileImpl, certutilPath: "certutil.exe" });
    assert.equal(execFileImpl.calls.length, 1);
    assert.deepEqual(execFileImpl.calls[0].args, ["-store", "My"]);
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
// discoverWindowsCertificateInventory
// ---------------------------------------------------------------------------

describe("discoverWindowsCertificateInventory", () => {
  it("cross-references store certificates with the bindings that reference them", async () => {
    const execFileImpl = (file, args, options, callback) => {
      if (args[0] === "-store") {
        return makeExecStub({ stdout: CERTUTIL_STORE_OUTPUT })(file, args, options, callback);
      }
      return makeExecStub({ stdout: NETSH_SHOW_SSLCERT_OUTPUT })(file, args, options, callback);
    };

    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl });
    assert.equal(result.ok, true);
    const bound = result.certificates.find((c) => c.thumbprint === SAMPLE_THUMBPRINT);
    assert.deepEqual(bound.boundAt, ["10.0.0.5:443"]);

    const unbound = result.certificates.find((c) => c.thumbprint !== SAMPLE_THUMBPRINT);
    assert.deepEqual(unbound.boundAt, []);
  });

  it("surfaces a store query failure distinctly from an empty store", async () => {
    const error = Object.assign(new Error("denied"), { code: 5 });
    const execFileImpl = makeExecStub({ error, stderr: "Access is denied." });
    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.code, "STORE_QUERY_FAILED");
  });

  it("surfaces a binding query failure distinctly", async () => {
    let call = 0;
    const execFileImpl = (file, args, options, callback) => {
      call += 1;
      if (call === 1) {
        return makeExecStub({ stdout: CERTUTIL_EMPTY_STORE_OUTPUT })(file, args, options, callback);
      }
      const error = Object.assign(new Error("denied"), { code: 5 });
      return makeExecStub({ error, stderr: "Access is denied." })(file, args, options, callback);
    };
    const result = await discoverWindowsCertificateInventory({ store: "My", execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.code, "BINDING_QUERY_FAILED");
  });

  it("never touches the binding query's actual store scoping (reports bindings for all stores)", async () => {
    const execFileImpl = (file, args, options, callback) => {
      if (args[0] === "-store") {
        return makeExecStub({ stdout: CERTUTIL_EMPTY_STORE_OUTPUT })(file, args, options, callback);
      }
      return makeExecStub({ stdout: NETSH_SHOW_SSLCERT_OUTPUT })(file, args, options, callback);
    };
    const result = await discoverWindowsCertificateInventory({ store: "WebHosting", execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.certificates, []);
  });
});
