"use strict";

/**
 * Tests for packages/agent/src/windows-iis/index.js.
 *
 * netsh and http.sys binding query invocations are exercised through an
 * injected execFile stub (same pattern as the sibling
 * acme/windows-cert-store modules); the post-bind
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
  canonicalSelectorValue,
  decodeHttpSysSettings,
  formatPreservedParamArgs,
  findUnsupportedNetshParams,
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

const NO_BINDINGS = JSON.stringify({ items: [] });

/**
 * execFile stub factory, mirroring the sibling modules' makeExecStub. Calls
 * are keyed "query" (the http.sys binding query), "help" (`netsh http add
 * sslcert help`), or by netsh verb ("add" | "delete"). A query answered
 * without stdout or error reports no bindings at all.
 */
function makeExecStub(responsesByCommand) {
  const calls = [];
  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    let key = args[1];
    if (String(args.at(-1)).includes("SslBindingInfo")) key = "query";
    else if (args[3] === "help") key = "help";
    const response = responsesByCommand(key, args) || { error: null, stdout: "", stderr: "" };
    const stdout = response.stdout || (key === "query" && !response.error ? NO_BINDINGS : "");
    process.nextTick(() => callback(response.error, stdout, response.stderr || ""));
  }
  execFileStub.calls = calls;
  return execFileStub;
}

const queryCalls = (execFileImpl) => execFileImpl.calls.filter((call) => String(call.args.at(-1)).includes("SslBindingInfo"));

const codeUnits = (text) => Array.from(text, (char) => char.charCodeAt(0));

/**
 * A successful http.sys binding query reporting `entries`, each
 * `{ ipPort | hostnamePort, thumbprint, settings? }` with settings as raw
 * registry values.
 */
function bindingsOutput(...entries) {
  const items = entries.map(({ ipPort, hostnamePort, thumbprint, settings = {} }) => {
    const values = { SslCertHash: Array.from(Buffer.from(thumbprint, "hex")), ...settings };
    if (!hostnamePort) return { kind: "SslBindingInfo", key: ipPort, values };
    return {
      kind: "SslSniBindingInfo",
      key: "{00000000-0000-0000-0000-000000000001}",
      values: { ...values, HostnamePort: { chars: codeUnits(hostnamePort) } },
    };
  });
  return { error: null, stdout: JSON.stringify({ items }) };
}

/** VALID_BINDING's selector bound to `thumbprint`. */
const boundAtValidBinding = (thumbprint, settings) => bindingsOutput({ ipPort: "10.0.0.5:443", thumbprint, settings });

/** Usage block of a real Windows Server 2019 `netsh http add sslcert help`. */
const NETSH_2019_ADD_HELP = [
  " ",
  "Usage: add sslcert hostnameport=<name:port> | ipport=<ipaddr:port> | ccs=<port>  ",
  "\tappid=<GUID> ",
  "\t[certhash=<string>]",
  "\t[certstorename=<string>]",
  "\t[verifyclientcertrevocation=enable|disable]",
  "\t[verifyrevocationwithcachedclientcertonly=enable|disable]",
  "\t[usagecheck=enable|disable]",
  "\t[revocationfreshnesstime=<u-int>]",
  "\t[urlretrievaltimeout=<u-int>]",
  "\t[sslctlidentifier=<string>]",
  "\t[sslctlstorename=<string>]",
  "\t[dsmapperusage=enable|disable]",
  "\t[clientcertnegotiation=enable|disable]",
  "\t[reject=enable|disable]",
  "\t[disablehttp2=enable|disable]",
  "\t[disablequic=enable|disable]",
  "\t[disablelegacytls=enable|disable]",
  "\t[disabletls12=enable|disable]",
  "\t[disabletls13=enable|disable]",
  "\t[disableocspstapling=enable|disable]",
  "",
].join("\r\n");

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
  it("reads the thumbprint bound at the binding's ipport from http.sys's configuration", async () => {
    const execFileImpl = makeExecStub(() => boundAtValidBinding(FIXTURE_THUMBPRINT));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.thumbprint, FIXTURE_THUMBPRINT.toUpperCase());
  });

  it("runs the binding query through PowerShell, never netsh, and without a shell", async () => {
    const execFileImpl = makeExecStub(() => null);
    await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(execFileImpl.calls.length, 1);
    const call = execFileImpl.calls[0];
    assert.equal(call.file, "powershell.exe");
    assert.match(call.args.at(-1), /SslSniBindingInfo/);
    assert.equal(call.options.shell, undefined);
  });

  it("returns thumbprint: null (ok: true) and no parameters when nothing is bound at the selector", async () => {
    const execFileImpl = makeExecStub(() => bindingsOutput({ ipPort: "10.0.0.6:443", thumbprint: OTHER_THUMBPRINT }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.equal(result.thumbprint, null);
    assert.equal(result.parameters, undefined);
  });

  it("returns ok: false when the query fails", async () => {
    const error = Object.assign(new Error("access denied"), { code: 5 });
    const execFileImpl = makeExecStub(() => ({ error, stderr: "Access is denied." }));

    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 5);
    assert.match(result.stderrExcerpt, /Access is denied/);
  });

  it("returns ok: false when the query output is unreadable", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "not json" }));
    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, null);
  });

  it("returns ok: false rather than 'nothing bound' when the binding exists but its hash is unreadable", async () => {
    const stdout = JSON.stringify({ items: [{ kind: "SslBindingInfo", key: "10.0.0.5:443", values: {} }] });
    const execFileImpl = makeExecStub(() => ({ error: null, stdout }));
    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, false);
    assert.match(result.stderrExcerpt, /ipport=10\.0\.0\.5:443 has no readable certificate hash/);
  });

  it("matches an sniHost binding against SNI entries only, case-insensitively", async () => {
    const execFileImpl = makeExecStub(() =>
      bindingsOutput(
        { ipPort: "10.0.0.5:443", thumbprint: OTHER_THUMBPRINT },
        { hostnamePort: "WWW.Example.com:443", thumbprint: FIXTURE_THUMBPRINT },
      ),
    );
    const result = await queryCurrentBinding({ binding: { ...VALID_BINDING, sniHost: "www.example.com" }, execFileImpl });
    assert.equal(result.thumbprint, FIXTURE_THUMBPRINT.toUpperCase());
  });

  it("matches a '*' binding against http.sys's 0.0.0.0 key and an IPv6 address in any spelling", async () => {
    const execFileImpl = makeExecStub(() =>
      bindingsOutput(
        { ipPort: "0.0.0.0:443", thumbprint: OTHER_THUMBPRINT },
        { ipPort: "[2001:db8::1]:443", thumbprint: FIXTURE_THUMBPRINT },
      ),
    );
    const wildcard = await queryCurrentBinding({ binding: { ...VALID_BINDING, address: "*" }, execFileImpl });
    assert.equal(wildcard.thumbprint, OTHER_THUMBPRINT);
    const ipv6 = await queryCurrentBinding({
      binding: { ...VALID_BINDING, address: "[2001:DB8:0:0::1]" },
      execFileImpl,
    });
    assert.equal(ipv6.thumbprint, FIXTURE_THUMBPRINT.toUpperCase());
  });

  it("decodes the binding's settings into result.parameters (rebind-settings preservation)", async () => {
    const execFileImpl = makeExecStub(() => boundAtValidBinding(FIXTURE_THUMBPRINT, { DefaultFlags: 0x2 }));

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
    assert.equal(result.unsupportedSettings, undefined);
  });

  it("reports settings it cannot carry over in result.unsupportedSettings", async () => {
    const execFileImpl = makeExecStub(() => boundAtValidBinding(FIXTURE_THUMBPRINT, { DefaultFlags: 0x2000 }));
    const result = await queryCurrentBinding({ binding: VALID_BINDING, execFileImpl });
    assert.equal(result.ok, true);
    assert.deepEqual(result.unsupportedSettings, ["DefaultFlags 0x2000"]);
  });
});

// ---------------------------------------------------------------------------
// canonicalSelectorValue
// ---------------------------------------------------------------------------

describe("canonicalSelectorValue", () => {
  it("lowercases hostnames and maps '*' to 0.0.0.0", () => {
    assert.equal(canonicalSelectorValue("WWW.Example.COM:443"), "www.example.com:443");
    assert.equal(canonicalSelectorValue("*:8443"), "0.0.0.0:8443");
  });

  it("compresses IPv6 literals", () => {
    assert.equal(canonicalSelectorValue("[2001:DB8:0:0:0:0:0:1]:443"), "[2001:db8::1]:443");
    assert.equal(canonicalSelectorValue("[::]:443"), "[::]:443");
  });

  it("leaves an unparseable IPv6 literal as written instead of throwing", () => {
    assert.equal(canonicalSelectorValue("[not:an:ip:zz]:443"), "[not:an:ip:zz]:443");
  });
});

// ---------------------------------------------------------------------------
// decodeHttpSysSettings / formatPreservedParamArgs: rebind-settings
// preservation round-trip
// ---------------------------------------------------------------------------

describe("decodeHttpSysSettings", () => {
  it("reports netsh's defaults for a binding with no settings at all", () => {
    assert.deepEqual(decodeHttpSysSettings({}), {
      unsupported: [],
      parameters: {
        verifyClientCertRevocation: true,
        verifyRevocationWithCachedClientCertOnly: false,
        usageCheck: true,
        revocationFreshnessTime: 0,
        urlRetrievalTimeout: 0,
        ctlIdentifier: null,
        ctlStoreName: null,
        dsMapperUsage: false,
        negotiateClientCert: false,
      },
    });
    assert.deepEqual(decodeHttpSysSettings(), decodeHttpSysSettings({}));
  });

  it("maps every DefaultSslCertCheckMode bit and the revocation timers", () => {
    const { parameters, unsupported } = decodeHttpSysSettings({
      DefaultSslCertCheckMode: 0x1 | 0x2 | 0x4 | 0x10000,
      DefaultSslRevocationFreshnessTime: 3600,
      DefaultSslRevocationUrlRetrievalTimeout: 5000,
    });
    assert.deepEqual(unsupported, []);
    assert.equal(parameters.verifyClientCertRevocation, false);
    assert.equal(parameters.verifyRevocationWithCachedClientCertOnly, true);
    assert.equal(parameters.usageCheck, false);
    assert.equal(parameters.revocationFreshnessTime, 3600);
    assert.equal(parameters.urlRetrievalTimeout, 5000);
  });

  it("maps the classic DefaultFlags bits", () => {
    const { parameters } = decodeHttpSysSettings({ DefaultFlags: 0x1 | 0x2 });
    assert.equal(parameters.dsMapperUsage, true);
    assert.equal(parameters.negotiateClientCert, true);
  });

  it("reads a CTL identifier and store pair", () => {
    const { parameters, unsupported } = decodeHttpSysSettings({
      DefaultSslCtlIdentifier: "MyCtl",
      DefaultSslCtlStoreName: "CA",
    });
    assert.deepEqual(unsupported, []);
    assert.equal(parameters.ctlIdentifier, "MyCtl");
    assert.equal(parameters.ctlStoreName, "CA");
  });

  it("reports the newer per-connection flags only when set, each from its own DefaultFlags bit", () => {
    const bits = {
      rejectConnections: 0x8,
      disableHttp2: 0x10,
      disableQuic: 0x20,
      disableTls13: 0x40,
      disableOcspStapling: 0x80,
      enableTokenBinding: 0x100,
      logExtendedEvents: 0x200,
      disableLegacyTls: 0x400,
      enableSessionTicket: 0x800,
      disableTls12: 0x1000,
      disableSessionId: 0x4000,
    };
    for (const [key, bit] of Object.entries(bits)) {
      const { parameters, unsupported } = decodeHttpSysSettings({ DefaultFlags: bit });
      assert.deepEqual(unsupported, [], key);
      const newer = Object.keys(parameters).filter((name) => Object.hasOwn(bits, name));
      assert.deepEqual(newer, [key]);
      assert.equal(parameters[key], true);
    }
    assert.equal("disableHttp2" in decodeHttpSysSettings({ DefaultFlags: 0 }).parameters, false);
  });

  it("round-trips a binding with seven newer flags set back into the same netsh flags", () => {
    const { parameters } = decodeHttpSysSettings({ DefaultFlags: 0x4f30 });
    assert.deepEqual(formatPreservedParamArgs(parameters), [
      "verifyclientcertrevocation=enable",
      "verifyrevocationwithcachedclientcertonly=disable",
      "usagecheck=enable",
      "dsmapperusage=disable",
      "clientcertnegotiation=disable",
      "disablehttp2=enable",
      "disablequic=enable",
      "disablelegacytls=enable",
      "enabletokenbinding=enable",
      "logextendedevents=enable",
      "enablesessionticket=enable",
      "disablesessionid=enable",
    ]);
  });

  it("lists unknown value names, flag bits and check-mode bits as unsupported", () => {
    const { unsupported } = decodeHttpSysSettings({
      DefaultFlags: (0x2 | 0x2000 | 0x80000000) >>> 0,
      DefaultSslCertCheckMode: 0x10000 | 0x8,
      DefaultSslSomethingNew: 1,
    });
    assert.deepEqual(unsupported.sort(), [
      "DefaultFlags 0x80002000",
      "DefaultSslCertCheckMode 0x8",
      "DefaultSslSomethingNew",
    ]);
  });

  it("lists a value of the wrong type as unsupported", () => {
    const { unsupported, parameters } = decodeHttpSysSettings({
      DefaultFlags: [1, 0, 0, 0],
      DefaultSslCtlIdentifier: 7,
    });
    assert.deepEqual(unsupported.sort(), ["DefaultFlags", "DefaultSslCtlIdentifier"]);
    assert.equal(parameters.ctlIdentifier, null);
  });

  it("lists a freshness time without its check-mode bit, or the bit without a time, as unsupported", () => {
    assert.deepEqual(decodeHttpSysSettings({ DefaultSslRevocationFreshnessTime: 3600 }).unsupported, [
      "DefaultSslRevocationFreshnessTime",
    ]);
    assert.deepEqual(decodeHttpSysSettings({ DefaultSslCertCheckMode: 0x4 }).unsupported, [
      "DefaultSslRevocationFreshnessTime",
    ]);
  });

  it("lists a CTL store without a CTL identifier as unsupported, since netsh cannot set it alone", () => {
    assert.deepEqual(decodeHttpSysSettings({ DefaultSslCtlStoreName: "CA" }).unsupported, ["DefaultSslCtlStoreName"]);
  });
});

describe("findUnsupportedNetshParams", () => {
  it("never asks netsh for its help when only classic parameters are replayed", async () => {
    const execFileImpl = makeExecStub(() => null);
    const missing = await findUnsupportedNetshParams({
      args: formatPreservedParamArgs(decodeHttpSysSettings({ DefaultFlags: 0x2 }).parameters),
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.deepEqual(missing, []);
    assert.equal(execFileImpl.calls.length, 0);
  });

  it("returns the newer parameters this host's netsh help does not list", async () => {
    const execFileImpl = makeExecStub((key) => (key === "help" ? { error: null, stdout: NETSH_2019_ADD_HELP } : null));
    const missing = await findUnsupportedNetshParams({
      args: ["usagecheck=enable", "disablehttp2=enable", "enablesessionticket=enable", "disablesessionid=enable"],
      execFileImpl,
      netshPath: "netsh.exe",
      timeoutMs: 1000,
    });
    assert.deepEqual(missing, ["enablesessionticket", "disablesessionid"]);
    assert.deepEqual(execFileImpl.calls[0].args, ["http", "add", "sslcert", "help"]);
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

  it("round-trips decoded http.sys settings (including the newer flags) back into valid netsh add sslcert flags", () => {
    const { parameters } = decodeHttpSysSettings({
      DefaultSslCertCheckMode: 0x4,
      DefaultSslRevocationFreshnessTime: 120,
      DefaultFlags: 0x1 | 0x10 | 0x80,
    });
    assert.deepEqual(formatPreservedParamArgs(parameters), [
      "verifyclientcertrevocation=enable",
      "verifyrevocationwithcachedclientcertonly=disable",
      "usagecheck=enable",
      "revocationfreshnesstime=120",
      "dsmapperusage=enable",
      "clientcertnegotiation=disable",
      "disablehttp2=enable",
      "disableocspstapling=enable",
    ]);
  });

  it("carries a CTL pair over with both flags", () => {
    const { parameters } = decodeHttpSysSettings({ DefaultSslCtlIdentifier: "MyCtl", DefaultSslCtlStoreName: "CA" });
    const args = formatPreservedParamArgs(parameters);
    assert.ok(args.includes("sslctlidentifier=MyCtl"));
    assert.ok(args.includes("sslctlstorename=CA"));
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
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT);
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
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT);
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
    // execFileImpl.calls[5] (0,1 = first delete/add; 2 = query; 3,4 = ... )
    // -- rather than counting exact indices, assert on the LAST add call's
    // certhash instead, which is robust to the exact call ordering.
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 2);
    assert.match(addCalls[1].args.join(" "), new RegExp(`certhash=${OTHER_THUMBPRINT}`));
  });

  it("does not attempt a rollback when nothing was bound before (outgoingThumbprint null)", async () => {
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
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
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT);
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

  it("returns QUERY_FAILED when the http.sys binding query fails, without binding anything", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") {
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
      if (key === "query") return boundAtValidBinding(FIXTURE_THUMBPRINT);
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

    // No delete/add netsh call at all: only the binding query ran.
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    const deleteCalls = execFileImpl.calls.filter((c) => c.args[1] === "delete");
    assert.equal(addCalls.length, 0);
    assert.equal(deleteCalls.length, 0);
  });

  it("still fails verification when already bound but the handshake disagrees, without attempting a rollback", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return boundAtValidBinding(FIXTURE_THUMBPRINT);
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
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT);
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

    // Two binding queries: the initial pre-bind query, plus the
    // post-rollback re-verification query.
    assert.equal(queryCalls(execFileImpl).length, 2);
  });

  it("surfaces a non-fatal rollbackVerifyDetail when the post-rollback query disagrees", async () => {
    let queryCount = 0;
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") {
        queryCount += 1;
        // First query (pre-bind): OTHER_THUMBPRINT was bound.
        // Second query (post-rollback): unexpectedly reports something else,
        // simulating a store/http.sys desync surviving the rollback bind.
        return boundAtValidBinding(queryCount === 1 ? OTHER_THUMBPRINT : FIXTURE_THUMBPRINT);
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
      if (key === "query") {
        return boundAtValidBinding(OTHER_THUMBPRINT, { DefaultFlags: 0x2, DefaultSslCertCheckMode: 0x10000 });
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
    assert.equal(addCall.args.includes("usagecheck=disable"), true);
    assert.equal(addCall.args.includes("clientcertnegotiation=enable"), true);
  });

  it("preserves a newer per-connection flag this host's netsh accepts", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT, { DefaultFlags: 0x400 });
      if (key === "help") return { error: null, stdout: NETSH_2019_ADD_HELP };
      return { error: null, stdout: "" };
    });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl: makeConnectStub({ peerDer: fixtureX509.raw }),
    });

    assert.equal(result.ok, true);
    const addCall = execFileImpl.calls.find((c) => c.args[1] === "add" && c.args[3] !== "help");
    assert.equal(addCall.args.includes("disablelegacytls=enable"), true);
  });

  it("refuses with UNSUPPORTED_BINDING_SETTINGS, touching nothing, when http.sys holds a setting the agent cannot read back", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT, { DefaultFlags: 0x2 | 0x2000 });
      return { error: null, stdout: "" };
    });
    let connectCalled = false;

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl: () => {
        connectCalled = true;
      },
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "UNSUPPORTED_BINDING_SETTINGS");
    assert.match(result.detail, /left unchanged: DefaultFlags 0x2000$/);
    assert.equal(result.outgoingThumbprint, OTHER_THUMBPRINT);
    assert.equal(result.rolledBack, false);
    assert.equal(connectCalled, false);
    assert.deepEqual(execFileImpl.calls.map((call) => call.file), ["powershell.exe"]);
  });

  it("refuses with UNSUPPORTED_BINDING_SETTINGS when this host's netsh does not offer a flag the binding uses", async () => {
    // netsh exits 0 without creating the binding when given a parameter it
    // does not know, which would leave the endpoint unbound.
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT, { DefaultFlags: 0x800 });
      if (key === "help") return { error: null, stdout: NETSH_2019_ADD_HELP };
      return { error: null, stdout: "" };
    });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl: makeConnectStub({ peerDer: fixtureX509.raw }),
    });

    assert.equal(result.code, "UNSUPPORTED_BINDING_SETTINGS");
    assert.match(result.detail, /enablesessionticket \(not supported by this host's netsh\)/);
    const netshCalls = execFileImpl.calls.filter((call) => call.file === "netsh.exe").map((call) => call.args.join(" "));
    assert.deepEqual(netshCalls, ["http add sslcert help"]);
  });

  it("does not refuse over unsupported settings when the binding already serves the target certificate", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return boundAtValidBinding(FIXTURE_THUMBPRINT, { DefaultFlags: 0x2000 });
      return { error: null, stdout: "" };
    });

    const result = await deployIisBinding({
      binding: VALID_BINDING,
      certificatePem: FIXTURE_CERT_PEM,
      execFileImpl,
      connectImpl: makeConnectStub({ peerDer: fixtureX509.raw }),
    });

    assert.equal(result.ok, true);
    assert.equal(result.skippedMutation, true);
  });

  it("carries the same preserved settings into a rollback bind, not just the primary bind", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return boundAtValidBinding(OTHER_THUMBPRINT, { DefaultSslCertCheckMode: 0x10000 });
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
    // usagecheck=disable flag read from the original outgoing binding.
    const addCalls = execFileImpl.calls.filter((c) => c.args[1] === "add");
    assert.equal(addCalls.length, 2);
    for (const call of addCalls) {
      assert.equal(call.args.includes("usagecheck=disable"), true);
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

  const check = (execFileImpl) =>
    checkSniPrecedenceConflict({ binding: SNI_BINDING, execFileImpl, powershellPath: "powershell.exe", timeoutMs: 1000 });

  it("returns undefined when no non-SNI binding exists on the port", async () => {
    const execFileImpl = makeExecStub(() =>
      bindingsOutput({ hostnamePort: "www.example.com:8443", thumbprint: OTHER_THUMBPRINT }),
    );
    assert.equal(await check(execFileImpl), undefined);
  });

  it("warns when a non-SNI IPv4 wildcard (0.0.0.0) binding exists on the same port", async () => {
    const warning = await check(makeExecStub(() => bindingsOutput({ ipPort: "0.0.0.0:8443", thumbprint: OTHER_THUMBPRINT })));
    assert.match(warning, /ipport=0\.0\.0\.0:8443/);
    assert.match(warning, /hostnameport=www\.example\.com:8443/);
  });

  it("warns when a non-SNI IPv6 wildcard ([::]) binding exists on the same port", async () => {
    const warning = await check(makeExecStub(() => bindingsOutput({ ipPort: "[::]:8443", thumbprint: OTHER_THUMBPRINT })));
    assert.match(warning, /ipport=\[::\]:8443/);
  });

  it("reports a wildcard before a concrete address when both shadow the binding", async () => {
    const warning = await check(
      makeExecStub(() =>
        bindingsOutput(
          { ipPort: "192.0.2.10:8443", thumbprint: OTHER_THUMBPRINT },
          { ipPort: "[::]:8443", thumbprint: OTHER_THUMBPRINT },
        ),
      ),
    );
    assert.match(warning, /ipport=\[::\]:8443/);
  });

  it("swallows a query error rather than throwing or warning", async () => {
    const execFileImpl = () => {
      throw new Error("execFile blew up");
    };
    assert.equal(await check(execFileImpl), undefined);
    const failing = makeExecStub(() => ({ error: Object.assign(new Error("denied"), { code: 5 }) }));
    assert.equal(await check(failing), undefined);
  });

  it("warns when a non-SNI binding exists on a CONCRETE (non-wildcard) IP on the same port", async () => {
    // Neither wildcard form is bound, but a specific-IP ipport binding on
    // the same port shadows this SNI binding for clients connecting to
    // that exact IP -- the gap a PR review found (2026-08-07): checking
    // only the two wildcard forms missed this shape entirely.
    const warning = await check(
      makeExecStub(() => bindingsOutput({ ipPort: "192.0.2.10:8443", thumbprint: OTHER_THUMBPRINT })),
    );
    assert.match(warning, /ipport=192\.0\.2\.10:8443/);
    assert.match(warning, /hostnameport=www\.example\.com:8443/);
  });

  it("does not warn about a concrete-IP binding on a DIFFERENT port", async () => {
    const warning = await check(
      makeExecStub(() => bindingsOutput({ ipPort: "192.0.2.10:9999", thumbprint: OTHER_THUMBPRINT })),
    );
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
    // Nothing is bound at the SNI selector itself yet.
    const execFileImpl = makeExecStub((key) => {
      if (key === "query") return bindingsOutput({ ipPort: "0.0.0.0:8443", thumbprint: OTHER_THUMBPRINT });
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
      if (key === "query") return bindingsOutput({ ipPort: "0.0.0.0:443", thumbprint: OTHER_THUMBPRINT });
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
    const execFileImpl = makeExecStub(() => ({ error: null, stdout: "" }));
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
