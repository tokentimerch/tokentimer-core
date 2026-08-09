"use strict";

/**
 * Tests for packages/agent/src/windows-iis/index.js.
 *
 * netsh invocations are exercised through an injected execFile stub (same
 * pattern as the sibling acme/windows-cert-store modules); the post-bind
 * TLS handshake is exercised through an injected connectImpl stub, the
 * exact pattern already used by verify/verify.test.js for
 * verifyDeployedCertificate (this module's real dependency, not a mock of
 * it). The fixture certificate is the one already committed for
 * verify/verify.test.js, so both thumbprint (sha1) and fingerprint
 * (sha256) expectations are cross-checked against node:crypto's own
 * X509Certificate for both digests.
 *
 * Real-host verification (real netsh.exe, a real IIS site, a real http.sys
 * binding change) is tracked separately as the next milestone and is NOT
 * claimed here.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { X509Certificate } = require("node:crypto");

const {
  THUMBPRINT_PATTERN,
  WILDCARD_BINDING_ADDRESSES,
  BIND_ADD_RETRY_DELAYS_MS,
  assertValidBinding,
  resolveVerificationTarget,
  formatIpPort,
  generateAppId,
  normalizeThumbprint,
  parseSslcertParameters,
  formatPreservedParamArgs,
  checkSniPrecedenceConflict,
  queryCurrentBinding,
  bindCertificate,
  deployIisBinding,
} = require("./index.js");
const { computeCertificateFingerprint } = require("../verify/index.js");

const FIXTURE_CERT_PEM = fs.readFileSync(
  path.join(__dirname, "..", "verify", "fixtures", "selfsigned.crt.pem"),
  "utf8",
);
const fixtureX509 = new X509Certificate(FIXTURE_CERT_PEM);
const FIXTURE_THUMBPRINT = fixtureX509.fingerprint.replace(/:/g, "");
const FIXTURE_FINGERPRINT_SHA256 = fixtureX509.fingerprint256.replace(/:/g, "").toLowerCase();
const OTHER_THUMBPRINT = "AA".repeat(20);

const VALID_BINDING = Object.freeze({
  address: "10.0.0.5",
  port: 443,
  store: "My",
  site: "Default Web Site",
});

/** execFile stub factory, mirroring the sibling modules' makeExecStub. */
function makeExecStub(responsesByCommand) {
  const calls = [];
  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    const key = args[1]; // "show" | "add" | "delete"
    const response = responsesByCommand(key, args) || { error: null, stdout: "", stderr: "" };
    process.nextTick(() => callback(response.error, response.stdout || "", response.stderr || ""));
  }
  execFileStub.calls = calls;
  return execFileStub;
}

/** connectImpl stub, adapted from verify/verify.test.js's makeConnectStub. */
function makeConnectStub(outcome) {
  const seenOptions = [];
  function connectStub(options) {
    seenOptions.push(options);
    const socket = new EventEmitter();
    socket.destroy = () => {};
    socket.getPeerCertificate = () => ({ raw: outcome.peerDer });
    process.nextTick(() => {
      if (outcome.error) socket.emit("error", outcome.error);
      else socket.emit("secureConnect");
    });
    return socket;
  }
  connectStub.seenOptions = seenOptions;
  return connectStub;
}

// ---------------------------------------------------------------------------
// assertValidBinding
// ---------------------------------------------------------------------------

describe("assertValidBinding", () => {
  it("accepts a concrete-IP binding", () => {
    assert.doesNotThrow(() => assertValidBinding(VALID_BINDING));
  });

  it("accepts each documented wildcard address", () => {
    for (const address of Object.keys(WILDCARD_BINDING_ADDRESSES)) {
      assert.doesNotThrow(() => assertValidBinding({ ...VALID_BINDING, address }));
    }
  });

  it("accepts an optional valid sniHost", () => {
    assert.doesNotThrow(() =>
      assertValidBinding({ ...VALID_BINDING, sniHost: "www.example.com" }),
    );
  });

  it("rejects a port outside [1, 65535]", () => {
    assert.throws(() => assertValidBinding({ ...VALID_BINDING, port: 0 }), /binding.port/);
    assert.throws(() => assertValidBinding({ ...VALID_BINDING, port: 65536 }), /binding.port/);
  });

  it("rejects an invalid sniHost", () => {
    assert.throws(
      () => assertValidBinding({ ...VALID_BINDING, sniHost: "not a host!" }),
      /binding.sniHost/,
    );
  });

  it("rejects a store name outside the safe alphabet", () => {
    assert.throws(
      () => assertValidBinding({ ...VALID_BINDING, store: "My/../evil" }),
      /binding.store/,
    );
  });

  it("rejects a missing site", () => {
    assert.throws(() => assertValidBinding({ ...VALID_BINDING, site: "" }), /binding.site/);
  });
});

// ---------------------------------------------------------------------------
// resolveVerificationTarget: decision 13's "never a DNS-resolved name"
// ---------------------------------------------------------------------------

describe("resolveVerificationTarget", () => {
  it("returns the binding's own concrete IP unchanged", () => {
    const target = resolveVerificationTarget({ address: "10.0.0.5", port: 443 });
    assert.equal(target.host, "10.0.0.5");
  });

  it("maps every wildcard address to its own loopback probe, never a hostname", () => {
    assert.equal(resolveVerificationTarget({ address: "*" }).host, "127.0.0.1");
    assert.equal(resolveVerificationTarget({ address: "0.0.0.0" }).host, "127.0.0.1");
    assert.equal(resolveVerificationTarget({ address: "[::]" }).host, "::1");
  });

  it("strips IPv6 brackets from a concrete IPv6 literal", () => {
    const target = resolveVerificationTarget({ address: "[2001:db8::1]" });
    assert.equal(target.host, "2001:db8::1");
  });

  it("forwards sniHost as servername when present, undefined otherwise", () => {
    assert.equal(
      resolveVerificationTarget({ address: "10.0.0.5", sniHost: "www.example.com" }).servername,
      "www.example.com",
    );
    assert.equal(resolveVerificationTarget({ address: "10.0.0.5" }).servername, undefined);
  });
});

// ---------------------------------------------------------------------------
// formatIpPort / generateAppId / normalizeThumbprint
// ---------------------------------------------------------------------------

describe("formatIpPort", () => {
  it("joins address and port with a colon", () => {
    assert.equal(formatIpPort({ address: "10.0.0.5", port: 443 }), "10.0.0.5:443");
  });
});

describe("generateAppId", () => {
  it("produces a brace-wrapped GUID, unique per call", () => {
    const a = generateAppId();
    const b = generateAppId();
    assert.match(a, /^\{[0-9a-f-]{36}\}$/i);
    assert.notEqual(a, b);
  });
});

describe("normalizeThumbprint", () => {
  it("uppercases a valid 40-hex-char thumbprint", () => {
    assert.equal(normalizeThumbprint(FIXTURE_THUMBPRINT.toLowerCase()), FIXTURE_THUMBPRINT.toUpperCase());
  });

  it("rejects a malformed thumbprint", () => {
    assert.throws(() => normalizeThumbprint("not-a-thumbprint"), /THUMBPRINT_PATTERN|40-hex-char/);
  });

  it("THUMBPRINT_PATTERN accepts the fixture's real thumbprint", () => {
    assert.equal(THUMBPRINT_PATTERN.test(FIXTURE_THUMBPRINT), true);
  });
});

// ---------------------------------------------------------------------------
// queryCurrentBinding
// ---------------------------------------------------------------------------

describe("queryCurrentBinding", () => {
  it("parses the Certificate Hash line from netsh's show sslcert output", async () => {
    const execFileImpl = makeExecStub(() => ({
      error: null,
      stdout: `SSL Certificate bindings:\r\n-------------------------\r\n\r\n    IP:port                      : 10.0.0.5:443\r\n    Certificate Hash              : ${FIXTURE_THUMBPRINT}\r\n    Application ID              : {00000000-0000-0000-0000-000000000000}\r\n`,
    }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.thumbprint, FIXTURE_THUMBPRINT.toUpperCase());
  });

  it("returns thumbprint: null (ok: true) when netsh reports nothing bound", async () => {
    const error = Object.assign(new Error("netsh failed"), { code: 1 });
    const execFileImpl = makeExecStub(() => ({
      error,
      stdout: "The system cannot find the file specified.\r\n",
    }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.thumbprint, null);
  });

  it("returns ok: false on a genuine netsh failure", async () => {
    const error = Object.assign(new Error("access denied"), { code: 5 });
    const execFileImpl = makeExecStub(() => ({ error, stderr: "Access is denied." }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 5);
    assert.match(result.stderrExcerpt, /Access is denied/);
  });

  it("invokes netsh http show sslcert with the expected ipport argv", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
    await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(execFileImpl.calls.length, 1);
    const call = execFileImpl.calls[0];
    assert.deepEqual(call.args, ["http", "show", "sslcert", "ipport=10.0.0.5:443"]);
    assert.equal(call.options.shell, undefined);
  });

  it("invokes netsh http show sslcert with hostnameport= when the binding has an sniHost", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
    await queryCurrentBinding({
      binding: { ...VALID_BINDING, sniHost: "www.example.com" },
      execFileImpl,
    });
    const call = execFileImpl.calls[0];
    assert.deepEqual(call.args, ["http", "show", "sslcert", "hostnameport=www.example.com:443"]);
  });

  it("also parses the non-thumbprint parameters into result.parameters (rebind-settings preservation)", async () => {
    const execFileImpl = makeExecStub(() => ({
      error: null,
      stdout: [
        `Certificate Hash              : ${FIXTURE_THUMBPRINT}`,
        "Application ID              : {00000000-0000-0000-0000-000000000000}",
        "Certificate Store Name       : My",
        "Verify Client Certificate Revocation : Enabled",
        "Verify Revocation Using Cached Client Certificate Only : Disabled",
        "Usage Check                  : Enabled",
        "Revocation Freshness Time    : 0",
        "URL Retrieval Timeout        : 0",
        "Ctl Identifier               : (null)",
        "Ctl Store Name                : (null)",
        "DS Mapper Usage              : Disabled",
        "Negotiate Client Certificate : Enabled",
      ].join("\r\n"),
    }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.parameters, {
      verifyClientCertRevocation: true,
      verifyRevocationWithCachedClientCertOnly: false,
      usageCheck: true,
      revocationFreshnessTime: 0,
      urlRetrievalTimeout: 0,
      ctlIdentifier: null,
      ctlStoreName: null,
      dsMapperUsage: false,
      negotiateClientCert: true,
    });
  });

  it("returns parameters: {} (not throwing, not defaulting fields) when nothing is bound yet", async () => {
    const error = Object.assign(new Error("netsh failed"), { code: 1 });
    const execFileImpl = makeExecStub(() => ({
      error,
      stdout: "The system cannot find the file specified.\r\n",
    }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.thumbprint, null);
    assert.equal(result.parameters, undefined);
  });
});

// ---------------------------------------------------------------------------
// parseSslcertParameters / formatPreservedParamArgs: rebind-settings
// preservation round-trip
// ---------------------------------------------------------------------------

describe("parseSslcertParameters", () => {
  it("omits a field entirely when its label is absent from the output, rather than defaulting it", () => {
    const parsed = parseSslcertParameters("Certificate Hash              : AA\r\n");
    assert.deepEqual(parsed, {});
  });

  it("reads a real Ctl Identifier/Ctl Store Name pair when both are set", () => {
    const parsed = parseSslcertParameters(
      ["Ctl Identifier                : MyCtl", "Ctl Store Name                : CA"].join("\r\n"),
    );
    assert.equal(parsed.ctlIdentifier, "MyCtl");
    assert.equal(parsed.ctlStoreName, "CA");
  });

  it("reads the newer per-connection policy flags when they report a real Set/Not-Set value", () => {
    // Real-host finding (2026-08-09): every newer per-connection flag on a
    // real Windows Server 2025 build renders as "Set"/"Not Set" when
    // explicitly configured, the same vocabulary previously believed
    // (2026-08-07) to be unique to "Disable Legacy TLS Versions" -- see the
    // dedicated regression test below for the full real transcript that
    // proved this.
    const parsed = parseSslcertParameters(
      [
        "Reject Connections            : Not Set",
        "Disable HTTP2                 : Set",
        "Disable QUIC                  : Not Set",
        "Disable OCSP Stapling         : Set",
        "Enable Token Binding          : Not Set",
      ].join("\r\n"),
    );
    assert.equal("rejectConnections" in parsed, false);
    assert.equal(parsed.disableHttp2, true);
    assert.equal("disableQuic" in parsed, false);
    assert.equal(parsed.disableOcspStapling, true);
    assert.equal("enableTokenBinding" in parsed, false);
  });

  it("also accepts the newer per-connection policy flags' Enabled/Disabled vocabulary defensively, in case a different Windows build ever reports them that way", () => {
    // Not the vocabulary any real host observed so far actually uses (see
    // above), but accepted the same way disableLegacyTls already
    // defensively accepts both vocabularies: "Disabled" is treated the
    // same as "Not Set" (omitted, never forced to false), since none of
    // these fields' real defaults are ever the opposite of "off".
    const parsed = parseSslcertParameters(
      ["Disable HTTP2                 : Enabled", "Disable QUIC                  : Disabled"].join("\r\n"),
    );
    assert.equal(parsed.disableHttp2, true);
    assert.equal("disableQuic" in parsed, false);
  });

  it("omits (does not default) a newer per-connection policy flag reported as 'Not Set'", () => {
    const parsed = parseSslcertParameters(
      [
        "Disable HTTP2                 : Not Set",
        "Disable QUIC                  : Not Set",
        "Enable Token Binding          : Not Set",
        "Log Extended Events           : Not Set",
        "Enable Session Ticket         : Not Set",
      ].join("\r\n"),
    );
    assert.deepEqual(parsed, {});
  });

  it("reads 'Disable Legacy TLS Versions: Set' as true, not omitted (Microsoft's documented vocabulary for this field is Set/Not Set, not Enabled/Disabled/Not Set)", () => {
    // Captured real `netsh http show sslcert` output shape
    // (learn.microsoft.com/security/engineering/disable-legacy-tls: "Watch
    // for Disable Legacy TLS Versions: Set/Not Set") -- a PR review found
    // (2026-08-07) that the Enabled/Disabled/Not-Set regex every sibling
    // per-connection flag used at the time never matches a bare "Set", so
    // this field was silently dropped from the preserved-parameters set
    // entirely. (2026-08-09 real-host finding: every sibling flag turned
    // out to have the exact same gap -- see the dedicated regression test
    // below.)
    const parsed = parseSslcertParameters(
      [
        "Certificate Store Name        : My",
        "Reject Connections            : Disabled",
        "Disable HTTP2                 : Not Set",
        "Disable QUIC                  : Not Set",
        "Disable TLS1.2                : Not Set",
        "Disable TLS1.3                : Not Set",
        "Disable OCSP Stapling         : Not Set",
        "Enable Token Binding          : Not Set",
        "Log Extended Events           : Not Set",
        "Disable Legacy TLS Versions   : Set",
        "Enable Session Ticket         : Not Set",
      ].join("\r\n"),
    );
    assert.equal(parsed.disableLegacyTls, true);
  });

  it("reads 'Disable Legacy TLS Versions: Not Set' (the real captured default) as omitted, not false", () => {
    // Captured real `netsh http show sslcert` output shape (every source
    // above reports "Not Set" as this field's own default, never
    // "Disabled").
    const parsed = parseSslcertParameters("Disable Legacy TLS Versions  : Not Set\r\n");
    assert.equal("disableLegacyTls" in parsed, false);
  });

  it("also accepts 'Disable Legacy TLS Versions: Enabled'/'Disabled' defensively, in case a future Windows build reports this field the same way as its siblings", () => {
    assert.equal(parseSslcertParameters("Disable Legacy TLS Versions : Enabled\r\n").disableLegacyTls, true);
    assert.equal("disableLegacyTls" in parseSslcertParameters("Disable Legacy TLS Versions : Disabled\r\n"), false);
  });

  it("real-host regression (2026-08-09, tokentimer-winverify-vm, Windows Server 2025 build 26100): every newer per-connection flag, not only Disable Legacy TLS Versions, renders as Set/Not Set, and the pre-fix parser silently dropped all of them", () => {
    // Exact real `netsh http show sslcert` transcript captured after
    // binding a real certificate with seven of these flags explicitly set
    // via a real `netsh http add sslcert ... disablehttp2=enable
    // disablequic=enable disablelegacytls=enable enabletokenbinding=enable
    // logextendedevents=enable enablesessionticket=enable
    // disablesessionid=enable` call (the real-host verification pass,
    // `windows-iis-flag-preservation-and-sni-shadowing-verify.js`).
    // Every one of these seven rendered as "Set", not "Enabled" -- proving
    // the original per-field Enabled/Disabled/Not-Set regex never matched
    // a real positive value for ANY of them, not only disableLegacyTls as
    // the 2026-08-07 fix assumed.
    const realTranscript = [
      "    IP:port                      : 0.0.0.0:21443",
      "    Certificate Store Name       : My",
      "    Reject Connections           : Disabled",
      "    Disable HTTP2                : Set",
      "    Disable QUIC                 : Set",
      "    Disable TLS1.2               : Not Set",
      "    Disable TLS1.3               : Not Set",
      "    Disable OCSP Stapling        : Not Set",
      "    Enable Token Binding         : Set",
      "    Log Extended Events          : Set",
      "    Disable Legacy TLS Versions  : Set",
      "    Enable Session Ticket        : Set",
      "    Disable Session ID           : Set",
      "    Enable Caching Client Hello  : Not Set",
    ].join("\r\n");
    const parsed = parseSslcertParameters(realTranscript);
    assert.equal(parsed.disableHttp2, true);
    assert.equal(parsed.disableQuic, true);
    assert.equal(parsed.enableTokenBinding, true);
    assert.equal(parsed.logExtendedEvents, true);
    assert.equal(parsed.disableLegacyTls, true);
    assert.equal(parsed.enableSessionTicket, true);
    assert.equal(parsed.disableSessionId, true);
    assert.deepEqual(formatPreservedParamArgs(parsed).sort(), [
      "disablehttp2=enable",
      "disablelegacytls=enable",
      "disablequic=enable",
      "disablesessionid=enable",
      "enablesessionticket=enable",
      "enabletokenbinding=enable",
      "logextendedevents=enable",
    ].sort());
  });
});

describe("formatPreservedParamArgs -> parseSslcertParameters round-trip for Disable Legacy TLS Versions", () => {
  it("an outgoing binding with legacy TLS disabled (netsh's 'Set' vocabulary) survives a rebind and reproduces disablelegacytls=enable", () => {
    const outgoingStdout = [
      "Certificate Store Name        : My",
      "Disable Legacy TLS Versions   : Set",
    ].join("\r\n");
    const parsed = parseSslcertParameters(outgoingStdout);
    const args = formatPreservedParamArgs(parsed);
    assert.deepEqual(args, ["disablelegacytls=enable"]);
  });
});


describe("formatPreservedParamArgs", () => {
  it("returns an empty array for {} (nothing to preserve, e.g. a first-ever bind)", () => {
    assert.deepEqual(formatPreservedParamArgs({}), []);
    assert.deepEqual(formatPreservedParamArgs(), []);
  });

  it("emits enable/disable flags for every boolean field present", () => {
    const args = formatPreservedParamArgs({
      verifyClientCertRevocation: true,
      verifyRevocationWithCachedClientCertOnly: false,
      usageCheck: true,
      dsMapperUsage: false,
      negotiateClientCert: true,
    });
    assert.deepEqual(args, [
      "verifyclientcertrevocation=enable",
      "verifyrevocationwithcachedclientcertonly=disable",
      "usagecheck=enable",
      "dsmapperusage=disable",
      "clientcertnegotiation=enable",
    ]);
  });

  it("emits numeric fields verbatim for any non-zero value", () => {
    const args = formatPreservedParamArgs({ revocationFreshnessTime: 3600, urlRetrievalTimeout: 5000 });
    assert.deepEqual(args, ["revocationfreshnesstime=3600", "urlretrievaltimeout=5000"]);
  });

  it("omits revocationFreshnessTime/urlRetrievalTimeout when the outgoing binding reports netsh's own default of 0 (real-host finding: `add sslcert` rejects an explicit 0 for either flag with 'The parameter is incorrect' on Windows Server 2025 build 26100.32860, even though 0 is netsh's own default-on-omission and is documented as a legal value; every other integer value is accepted)", () => {
    assert.deepEqual(
      formatPreservedParamArgs({ revocationFreshnessTime: 0, urlRetrievalTimeout: 0 }),
      [],
    );
  });

  it("omits only the zero-valued one of the pair, still emitting the genuinely non-zero one", () => {
    assert.deepEqual(formatPreservedParamArgs({ revocationFreshnessTime: 0, urlRetrievalTimeout: 5000 }), [
      "urlretrievaltimeout=5000",
    ]);
    assert.deepEqual(formatPreservedParamArgs({ revocationFreshnessTime: 3600, urlRetrievalTimeout: 0 }), [
      "revocationfreshnesstime=3600",
    ]);
  });

  it("emits sslctlidentifier + sslctlstorename together only when ctlIdentifier is a real (non-null) value", () => {
    assert.deepEqual(formatPreservedParamArgs({ ctlIdentifier: "MyCtl", ctlStoreName: "CA" }), [
      "sslctlidentifier=MyCtl",
      "sslctlstorename=CA",
    ]);
  });

  it("omits both CTL flags when ctlIdentifier is null (the common 'not configured' case)", () => {
    assert.deepEqual(formatPreservedParamArgs({ ctlIdentifier: null, ctlStoreName: null }), []);
  });

  it("emits enable/disable flags for the newer per-connection policy fields present", () => {
    const args = formatPreservedParamArgs({
      rejectConnections: false,
      disableHttp2: true,
      disableQuic: false,
      disableLegacyTls: true,
      disableTls12: false,
      disableTls13: false,
      disableOcspStapling: true,
      enableTokenBinding: false,
      logExtendedEvents: true,
      enableSessionTicket: true,
      disableSessionId: false,
    });
    assert.deepEqual(args, [
      "reject=disable",
      "disablehttp2=enable",
      "disablequic=disable",
      "disablelegacytls=enable",
      "disabletls12=disable",
      "disabletls13=disable",
      "disableocspstapling=enable",
      "enabletokenbinding=disable",
      "logextendedevents=enable",
      "enablesessionticket=enable",
      "disablesessionid=disable",
    ]);
  });

  it("round-trips a full parseSslcertParameters output (including the newer flags) back into valid netsh add sslcert flags", () => {
    const parameters = parseSslcertParameters(
      [
        "Verify Client Certificate Revocation : Enabled",
        "Usage Check                  : Enabled",
        "Revocation Freshness Time    : 120",
        "Negotiate Client Certificate : Disabled",
        "Reject Connections           : Not Set",
        "Disable HTTP2                : Set",
        "Disable QUIC                 : Not Set",
        "Disable OCSP Stapling        : Set",
      ].join("\r\n"),
    );
    const args = formatPreservedParamArgs(parameters);
    assert.deepEqual(args, [
      "verifyclientcertrevocation=enable",
      "usagecheck=enable",
      "revocationfreshnesstime=120",
      "clientcertnegotiation=disable",
      "disablehttp2=enable",
      "disableocspstapling=enable",
    ]);
  });
});

// ---------------------------------------------------------------------------
// bindCertificate: delete-then-add, argv shape
// ---------------------------------------------------------------------------

describe("bindCertificate", () => {
  it("issues a delete then an add sslcert call, in that order", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));

    const result = await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(execFileImpl.calls.length, 2);
    assert.deepEqual(execFileImpl.calls[0].args.slice(0, 2), ["http", "delete"]);
    assert.deepEqual(execFileImpl.calls[1].args.slice(0, 2), ["http", "add"]);
    assert.match(
      execFileImpl.calls[1].args.join(" "),
      new RegExp(`certhash=${FIXTURE_THUMBPRINT.toUpperCase()}`),
    );
    assert.match(execFileImpl.calls[1].args.join(" "), /certstorename=My/);
  });

  it("includes preserveParameters flags in the add sslcert call when provided", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));

    const result = await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      preserveParameters: { usageCheck: true, negotiateClientCert: false },
      execFileImpl,
    });

    assert.equal(result.ok, true);
    const addArgs = execFileImpl.calls[1].args;
    assert.equal(addArgs.includes("usagecheck=enable"), true);
    assert.equal(addArgs.includes("clientcertnegotiation=disable"), true);
  });

  it("adds no extra flags when preserveParameters is omitted (default {}), unchanged from before this fix", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));

    await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
    });

    const addArgs = execFileImpl.calls[1].args;
    assert.deepEqual(addArgs, [
      "http",
      "add",
      "sslcert",
      "ipport=10.0.0.5:443",
      `certhash=${FIXTURE_THUMBPRINT.toUpperCase()}`,
      addArgs[5], // appid=<random guid>, not asserted here
      "certstorename=My",
    ]);
  });

  it("ignores the delete call's exit code (nothing-to-delete is not a failure)", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "delete") {
        return { error: Object.assign(new Error("not found"), { code: 1 }) };
      }
      return { error: null, stdout: "" };
    });

    const result = await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
    });
    assert.equal(result.ok, true);
  });

  it("returns ok: false when the add call fails with a non-transient error (no retries)", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "add") {
        return { error: Object.assign(new Error("failed"), { code: 87 }), stderr: "Some other failure." };
      }
      return { error: null, stdout: "" };
    });

    const result = await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
    });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 87);
    // delete + a single add attempt, no retries for a non-transient error.
    assert.equal(execFileImpl.calls.filter((call) => call.args[1] === "add").length, 1);
  });

  it("retries the add call on 'The parameter is incorrect.' and succeeds once the transient error clears", async () => {
    let addAttempts = 0;
    const succeedOnAttempt = 3;
    const execFileImpl = makeExecStub((key) => {
      if (key === "add") {
        addAttempts += 1;
        if (addAttempts < succeedOnAttempt) {
          return {
            error: Object.assign(new Error("failed"), { code: 87 }),
            stderr: "The parameter is incorrect.",
          };
        }
        return { error: null, stdout: "" };
      }
      return { error: null, stdout: "" };
    });
    const delays = [];
    const delayImpl = async (ms) => {
      delays.push(ms);
    };

    const result = await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
      delayImpl,
    });
    assert.equal(result.ok, true);
    assert.equal(addAttempts, succeedOnAttempt);
    // The first two attempts each consumed the transient-error branch's
    // delay before retrying; the third attempt succeeded. Derived from the
    // real BIND_ADD_RETRY_DELAYS_MS schedule rather than hardcoded, so a
    // future widening of the schedule (see that constant's doc comment)
    // does not require updating an unrelated magic number here.
    assert.deepEqual(delays, BIND_ADD_RETRY_DELAYS_MS.slice(0, succeedOnAttempt - 1));
  });

  it("gives up after exhausting all retries when 'The parameter is incorrect.' persists", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "add") {
        return { error: Object.assign(new Error("failed"), { code: 87 }), stderr: "The parameter is incorrect." };
      }
      return { error: null, stdout: "" };
    });
    const delays = [];
    const delayImpl = async (ms) => {
      delays.push(ms);
    };

    const result = await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
      delayImpl,
    });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 87);
    // 1 initial attempt + one retry per configured delay; every delay is
    // consumed since the transient error never clears. Derived from the
    // real BIND_ADD_RETRY_DELAYS_MS schedule rather than hardcoded (see
    // above).
    assert.equal(
      execFileImpl.calls.filter((call) => call.args[1] === "add").length,
      BIND_ADD_RETRY_DELAYS_MS.length + 1,
    );
    assert.deepEqual(delays, BIND_ADD_RETRY_DELAYS_MS);
  });

  it("binds via hostnameport= (not ipport=+sslctlidentifier) when the binding has an sniHost", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
    await bindCertificate({
      binding: { ...VALID_BINDING, sniHost: "www.example.com" },
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
    });
    // Both the delete and the add must target the hostnameport= selector;
    // sslctlidentifier must never appear (2026-08-05 real-host finding:
    // sslctlidentifier configures a client-certificate trust list, not SNI
    // dispatch -- see formatBindingSelector's doc comment).
    assert.match(execFileImpl.calls[0].args.join(" "), /hostnameport=www\.example\.com:443/);
    assert.match(execFileImpl.calls[1].args.join(" "), /hostnameport=www\.example\.com:443/);
    assert.doesNotMatch(execFileImpl.calls[1].args.join(" "), /sslctlidentifier/);
  });

  it("binds via ipport= when the binding has no sniHost", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
    await bindCertificate({
      binding: VALID_BINDING,
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      execFileImpl,
    });
    assert.match(execFileImpl.calls[1].args.join(" "), /ipport=10\.0\.0\.5:443/);
  });

  it("rejects an invalid thumbprint before invoking execFile", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null }));
    await assert.rejects(
      bindCertificate({ binding: VALID_BINDING, thumbprint: "bad", store: "My", execFileImpl }),
      /40-hex-char/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// deployIisBinding: full orchestration, decision 13
// ---------------------------------------------------------------------------

describe("deployIisBinding", () => {
  it("binds and verifies successfully, reporting outgoing/bound thumbprints", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return {
          error: null,
          stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n`,
        };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.outgoingThumbprint, OTHER_THUMBPRINT);
    assert.equal(result.boundThumbprint, FIXTURE_THUMBPRINT.toUpperCase());
    assert.equal(result.verifiedAt.host, VALID_BINDING.address);
    // The handshake only succeeds above because the stubbed peer cert bytes
    // (fixtureX509.raw) hash to the same sha256 fingerprint deployIisBinding
    // derives internally from certificatePem via computeCertificateFingerprint
    // -- cross-check that derivation against node:crypto's own digest of the
    // same fixture, independently of the stub.
    assert.equal(computeCertificateFingerprint(FIXTURE_CERT_PEM), FIXTURE_FINGERPRINT_SHA256);
  });

  it("verifies against the binding's own address, not a DNS name, for a wildcard binding", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    await deployIisBinding({
      binding: { ...VALID_BINDING, address: "*" },
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(connectImpl.seenOptions[0].host, "127.0.0.1");
  });

  it("rolls back to the outgoing thumbprint when verification fails", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return { error: null, stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` };
      }
      return { error: null, stdout: "" };
    });
    // Wrong peer cert bytes => fingerprint mismatch => verify fails.
    const connectImpl = makeConnectStub({ peerDer: Buffer.from([0x01, 0x02, 0x03]) });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "VERIFY_FAILED");
    assert.equal(result.rolledBack, true);
    assert.equal(result.outgoingThumbprint, OTHER_THUMBPRINT);

    // The rollback bind call: two netsh calls per bindCertificate
    // invocation (delete+add), so the second bindCertificate's add call is
    // execFileImpl.calls[5] (0,1 = first delete/add; 2 = show; 3,4 = ... )
    // -- rather than counting exact indices, assert on the LAST add call's
    // certhash instead, which is robust to the exact call ordering.
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 2);
    assert.match(addCalls[1].args.join(" "), new RegExp(`certhash=${OTHER_THUMBPRINT}`));
  });

  it("does not attempt a rollback when nothing was bound before (outgoingThumbprint null)", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return { error: Object.assign(new Error("none"), { code: 1 }), stdout: "The system cannot find the file specified." };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: Buffer.from([0x01, 0x02, 0x03]) });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "VERIFY_FAILED");
    assert.equal(result.rolledBack, false);
    assert.equal(result.outgoingThumbprint, null);

    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 1);
  });

  it("returns BIND_FAILED without touching verify when the add sslcert call fails", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") return { error: null, stdout: "" };
      if (key === "add") return { error: Object.assign(new Error("fail"), { code: 87 }), stderr: "bad" };
      return { error: null, stdout: "" };
    });
    let connectCalled = false;
    const connectImpl = () => {
      connectCalled = true;
      return makeConnectStub({ peerDer: fixtureX509.raw })();
    };

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "BIND_FAILED");
    assert.equal(connectCalled, false);
  });

  it("attempts a rollback to the outgoing thumbprint when the add sslcert call fails (real-host finding, 2026-08-05)", async () => {
    // The unconditional delete inside bindCertificate already ran by the
    // time add fails, so a BIND_FAILED with a non-null outgoingThumbprint
    // can leave the ipport genuinely unbound on a real host -- confirmed
    // by an actual VM run against a certificate with a broken key
    // association, which is exactly the scenario this test recreates via
    // a stub. Every "add" call fails (both the initial one and the
    // rollback attempt's own add), except we want the ROLLBACK add to
    // succeed, so only fail add calls whose certhash matches the NEW
    // (fixture) thumbprint, not the rollback's OTHER_THUMBPRINT.
    const execFileImpl = makeExecStub((key, args) => {
      if (key === "show") {
        return { error: null, stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` };
      }
      if (key === "add") {
        const isRollbackAdd = args.some((a) => a === `certhash=${OTHER_THUMBPRINT}`);
        if (!isRollbackAdd) {
          return { error: Object.assign(new Error("fail"), { code: 87 }), stderr: "bad key association" };
        }
        return { error: null, stdout: "" };
      }
      return { error: null, stdout: "" };
    });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "BIND_FAILED");
    assert.equal(result.outgoingThumbprint, OTHER_THUMBPRINT);
    assert.equal(result.rolledBack, true);
    assert.equal(result.rollbackVerifyDetail, undefined);

    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 2);
    assert.match(addCalls[1].args.join(" "), new RegExp(`certhash=${OTHER_THUMBPRINT}`));
  });

  it("does not attempt a rollback on BIND_FAILED when nothing was bound before", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") return { error: null, stdout: "" };
      if (key === "add") return { error: Object.assign(new Error("fail"), { code: 87 }), stderr: "bad" };
      return { error: null, stdout: "" };
    });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "BIND_FAILED");
    assert.equal(result.outgoingThumbprint, null);
    assert.equal(result.rolledBack, false);

    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 1);
  });

  it("returns QUERY_FAILED on a genuine netsh show failure, without binding anything", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return { error: Object.assign(new Error("denied"), { code: 5 }), stderr: "Access is denied." };
      }
      return { error: null, stdout: "" };
    });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl: makeConnectStub({ peerDer: fixtureX509.raw }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "QUERY_FAILED");
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 0);
  });

  it("rejects an invalid binding before invoking execFile", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null }));
    await assert.rejects(
      deployIisBinding({
        binding: { ...VALID_BINDING, port: 0 },
        certificatePem: FIXTURE_CERT_PEM,
        execFileImpl,
      }),
      /binding.port/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });

  it("rejects a missing certificatePem", async () => {
    await assert.rejects(
      deployIisBinding({ binding: VALID_BINDING, certificatePem: "" }),
      /certificatePem must be a non-empty PEM string/,
    );
  });

  // Idempotent skip + post-rollback re-verification (added 2026-08-05,
  // see the module doc comment on deployIisBinding for rationale).

  it("skips the delete+add mutation when already bound to the target certificate, but still verifies", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return { error: null, stdout: `Certificate Hash              : ${FIXTURE_THUMBPRINT}\r\n` };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.skippedMutation, true);
    assert.equal(result.outgoingThumbprint, FIXTURE_THUMBPRINT.toUpperCase());
    assert.equal(result.boundThumbprint, FIXTURE_THUMBPRINT.toUpperCase());

    // No delete/add netsh call at all: only the "show" query ran.
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    const deleteCalls = execFileImpl.calls.filter((c) => c.args[1] === "delete");
    assert.equal(addCalls.length, 0);
    assert.equal(deleteCalls.length, 0);
  });

  it("still fails verification when already bound but the handshake disagrees, without attempting a rollback", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return { error: null, stdout: `Certificate Hash              : ${FIXTURE_THUMBPRINT}\r\n` };
      }
      return { error: null, stdout: "" };
    });
    // Store/http.sys desync: thumbprint claims a match but the live
    // handshake serves different bytes.
    const connectImpl = makeConnectStub({ peerDer: Buffer.from([0x01, 0x02, 0x03]) });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "VERIFY_FAILED");
    assert.equal(result.rolledBack, false);
    assert.equal(result.outgoingThumbprint, FIXTURE_THUMBPRINT.toUpperCase());

    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 0);
  });

  it("re-queries the binding after a successful rollback and reports agreement", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return { error: null, stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: Buffer.from([0x01, 0x02, 0x03]) });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.rolledBack, true);
    assert.equal(result.rollbackVerifyDetail, undefined);

    // Two "show" calls: the initial pre-bind query, plus the post-rollback
    // re-verification query.
    const showCalls = execFileImpl.calls.filter((c) => c.args[1] === "show");
    assert.equal(showCalls.length, 2);
  });

  it("surfaces a non-fatal rollbackVerifyDetail when the post-rollback query disagrees", async () => {
    let showCallCount = 0;
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        showCallCount += 1;
        // First query (pre-bind): OTHER_THUMBPRINT was bound.
        // Second query (post-rollback): unexpectedly reports something else,
        // simulating a store/http.sys desync surviving the rollback bind.
        const hash = showCallCount === 1 ? OTHER_THUMBPRINT : FIXTURE_THUMBPRINT.toUpperCase();
        return { error: null, stdout: `Certificate Hash              : ${hash}\r\n` };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: Buffer.from([0x01, 0x02, 0x03]) });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.rolledBack, true);
    assert.match(result.rollbackVerifyDetail, /instead of the expected outgoing thumbprint/);
  });

  it("preserves the outgoing binding's revocation/negotiation settings across the delete+add rebind", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return {
          error: null,
          stdout: [
            `Certificate Hash              : ${OTHER_THUMBPRINT}`,
            "Usage Check                  : Enabled",
            "Negotiate Client Certificate : Enabled",
          ].join("\r\n"),
        };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, true);
    const addCall = execFileImpl.calls.find((c) => c.args[1] === "add");
    assert.equal(addCall.args.includes("usagecheck=enable"), true);
    assert.equal(addCall.args.includes("clientcertnegotiation=enable"), true);
  });

  it("carries the same preserved settings into a rollback bind, not just the primary bind", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return {
          error: null,
          stdout: [
            `Certificate Hash              : ${OTHER_THUMBPRINT}`,
            "Usage Check                  : Enabled",
          ].join("\r\n"),
        };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: Buffer.from([0x01, 0x02, 0x03]) });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.rolledBack, true);
    // Two "add" calls: the primary (verify-failed) bind, then the rollback
    // bind restoring OTHER_THUMBPRINT -- both should carry the preserved
    // usagecheck=enable flag read from the original outgoing binding.
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 2);
    for (const call of addCalls) {
      assert.equal(call.args.includes("usagecheck=enable"), true);
    }
  });
});

// ---------------------------------------------------------------------------
// checkSniPrecedenceConflict / deployIisBinding precedenceWarning
// (non-SNI/specific-IP vs SNI binding scope clarification)
// ---------------------------------------------------------------------------

describe("checkSniPrecedenceConflict", () => {
  const SNI_BINDING = Object.freeze({
    address: "10.0.0.5",
    port: 8443,
    sniHost: "www.example.com",
    store: "WebHosting",
    site: "SNI Site",
  });

  it("returns undefined when neither wildcard address has any non-SNI binding on the port", async () => {
    const execFileImpl = makeExecStub(() => ({
      error: Object.assign(new Error("not found"), { code: 1 }),
      stdout: "The system cannot find the file specified.\r\n",
    }));

    const warning = await checkSniPrecedenceConflict({
      binding: SNI_BINDING,
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.equal(warning, undefined);
  });

  it("warns when a non-SNI IPv4 wildcard (0.0.0.0) binding exists on the same port", async () => {
    const execFileImpl = makeExecStub((key, args) => {
      if (key === "show" && args.some((a) => a.includes("0.0.0.0"))) {
        return { error: null, stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` };
      }
      return {
        error: Object.assign(new Error("not found"), { code: 1 }),
        stdout: "The system cannot find the file specified.\r\n",
      };
    });

    const warning = await checkSniPrecedenceConflict({
      binding: SNI_BINDING,
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.match(warning, /ipport=0\.0\.0\.0:8443/);
    assert.match(warning, /hostnameport=www\.example\.com:8443/);
  });

  it("warns when a non-SNI IPv6 wildcard ([::]) binding exists on the same port", async () => {
    const execFileImpl = makeExecStub((key, args) => {
      if (key === "show" && args.some((a) => a.includes("[::]"))) {
        return { error: null, stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` };
      }
      return {
        error: Object.assign(new Error("not found"), { code: 1 }),
        stdout: "The system cannot find the file specified.\r\n",
      };
    });

    const warning = await checkSniPrecedenceConflict({
      binding: SNI_BINDING,
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.match(warning, /ipport=\[::\]:8443/);
  });

  it("swallows a query error for either wildcard rather than throwing or warning", async () => {
    const execFileImpl = () => {
      throw new Error("execFile blew up");
    };

    const warning = await checkSniPrecedenceConflict({
      binding: SNI_BINDING,
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.equal(warning, undefined);
  });

  it("warns when a non-SNI binding exists on a CONCRETE (non-wildcard) IP on the same port", async () => {
    // Neither wildcard form is bound, but a specific-IP ipport binding on
    // the same port shadows this SNI binding for clients connecting to
    // that exact IP -- the gap a PR review found (2026-08-07): checking
    // only the two wildcard forms missed this shape entirely.
    const execFileImpl = makeExecStub((key, args) => {
      if (key === "show" && args.length === 3) {
        // The unfiltered "netsh http show sslcert" full-listing call
        // (../windows-discovery's listHttpSysBindings): reports one
        // concrete-IP ipport binding on the same port as the SNI binding.
        return {
          error: null,
          stdout:
            `IP:port                       : 192.0.2.10:8443\r\n` +
            `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` +
            `Application ID                : {00000000-0000-0000-0000-000000000000}\r\n` +
            `Certificate Store Name        : My\r\n`,
        };
      }
      return {
        error: Object.assign(new Error("not found"), { code: 1 }),
        stdout: "The system cannot find the file specified.\r\n",
      };
    });

    const warning = await checkSniPrecedenceConflict({
      binding: SNI_BINDING,
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.match(warning, /ipport=192\.0\.2\.10:8443/);
    assert.match(warning, /hostnameport=www\.example\.com:8443/);
  });

  it("does not warn about a concrete-IP binding on a DIFFERENT port", async () => {
    const execFileImpl = makeExecStub((key, args) => {
      if (key === "show" && args.length === 3) {
        return {
          error: null,
          stdout:
            `IP:port                       : 192.0.2.10:9999\r\n` +
            `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n`,
        };
      }
      return {
        error: Object.assign(new Error("not found"), { code: 1 }),
        stdout: "The system cannot find the file specified.\r\n",
      };
    });

    const warning = await checkSniPrecedenceConflict({
      binding: SNI_BINDING,
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.equal(warning, undefined);
  });
});

describe("deployIisBinding precedenceWarning wiring", () => {
  const SNI_BINDING = Object.freeze({
    address: "10.0.0.5",
    port: 8443,
    sniHost: "www.example.com",
    store: "WebHosting",
    site: "SNI Site",
  });

  it("attaches precedenceWarning on a successful SNI deploy when a wildcard non-SNI binding shadows it", async () => {
    const execFileImpl = makeExecStub((key, args) => {
      if (key === "show" && args.some((a) => a.startsWith("hostnameport="))) {
        // The SNI binding's own pre-bind query: nothing bound yet.
        return {
          error: Object.assign(new Error("not found"), { code: 1 }),
          stdout: "The system cannot find the file specified.\r\n",
        };
      }
      if (key === "show" && args.some((a) => a.includes("0.0.0.0"))) {
        return { error: null, stdout: `Certificate Hash              : ${OTHER_THUMBPRINT}\r\n` };
      }
      if (key === "show") {
        return {
          error: Object.assign(new Error("not found"), { code: 1 }),
          stdout: "The system cannot find the file specified.\r\n",
        };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    const result = await deployIisBinding({
      binding: SNI_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, true);
    assert.match(result.precedenceWarning, /ipport=0\.0\.0\.0:8443/);
  });

  it("does NOT attach precedenceWarning for a non-SNI binding deploy (the check only applies to SNI deploys)", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return {
          error: Object.assign(new Error("not found"), { code: 1 }),
          stdout: "The system cannot find the file specified.\r\n",
        };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.precedenceWarning, undefined);
  });

  it("does NOT attach precedenceWarning for a successful SNI deploy when no shadowing binding exists", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "show") {
        return {
          error: Object.assign(new Error("not found"), { code: 1 }),
          stdout: "The system cannot find the file specified.\r\n",
        };
      }
      return { error: null, stdout: "" };
    });
    const connectImpl = makeConnectStub({ peerDer: fixtureX509.raw });

    const result = await deployIisBinding({
      binding: SNI_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.precedenceWarning, undefined);
  });
});
