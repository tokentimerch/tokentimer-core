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
  assertValidBinding,
  resolveVerificationTarget,
  formatIpPort,
  generateAppId,
  normalizeThumbprint,
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

  it("returns ok: false when the add call fails", async () => {
    const execFileImpl = makeExecStub((key) => {
      if (key === "add") {
        return { error: Object.assign(new Error("failed"), { code: 87 }), stderr: "The parameter is incorrect." };
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
});
