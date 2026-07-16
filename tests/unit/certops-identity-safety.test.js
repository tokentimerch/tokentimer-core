"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_UNSAFE_IDENTITY,
  CertOpsIdentitySafetyError,
  assertSafeDnsIdentity,
  assertSafeHostname,
  assertSafeIpIdentity,
  checkSafeDnsIdentity,
  isSafeDnsIdentity,
  isSafeHostname,
  isWellFormedAceLabel,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/identitySafety.js"),
);

const CYRILLIC_A = "\u0430"; // looks like Latin 'a'

function assertRejects(fn, snippet) {
  assert.throws(fn, (error) => {
    assert.equal(error instanceof CertOpsIdentitySafetyError, true);
    assert.equal(error.code, CERTOPS_UNSAFE_IDENTITY);
    if (snippet) assert.match(error.message, snippet);
    return true;
  });
}

describe("CertOps identitySafety", () => {
  it("accepts valid Latin DNS names and hostnames", () => {
    for (const name of [
      "certops.example",
      "api.certops.example",
      "*.example.com",
      "localhost",
      "CertOps Test CA",
    ]) {
      assert.equal(isSafeDnsIdentity(name), true);
      assert.equal(assertSafeDnsIdentity(name), name);
      assert.equal(assertSafeHostname(name), name);
      assert.equal(isSafeHostname(name), true);
    }
  });

  it("accepts empty and null-ish DNS identities", () => {
    assert.equal(checkSafeDnsIdentity(""), null);
    assert.equal(checkSafeDnsIdentity(null), null);
    assert.equal(checkSafeDnsIdentity(undefined), null);
    assert.equal(isSafeDnsIdentity(""), true);
  });

  it("accepts well-formed punycode ACE labels", () => {
    const names = [
      "xn--fsq.com",
      "xn--bcher-kva.example",
      "api.xn--fsq.example",
      "*.xn--fsq.example",
    ];
    for (const name of names) {
      assert.equal(isSafeDnsIdentity(name), true);
      assert.equal(assertSafeDnsIdentity(name), name);
    }
    assert.equal(isWellFormedAceLabel("xn--fsq"), true);
    assert.equal(isWellFormedAceLabel("XN--FSQ"), true);
  });

  it("rejects malformed punycode ACE labels", () => {
    assert.equal(isWellFormedAceLabel("xn--"), false);
    assert.equal(isWellFormedAceLabel("xn--bad_label"), false);
    assertRejects(
      () => assertSafeDnsIdentity("xn--.example"),
      /punycode ACE/,
    );
    assertRejects(
      () => assertSafeDnsIdentity("xn--bad_label.example"),
      /punycode ACE/,
    );
  });

  it("rejects Latin+Cyrillic mixed-script DNS labels", () => {
    const mixed = `p${CYRILLIC_A}ypal.com`;
    assert.equal(isSafeDnsIdentity(mixed), false);
    assertRejects(() => assertSafeDnsIdentity(mixed), /homograph/);
    assertRejects(() => assertSafeHostname(mixed), /homograph/);
  });

  it("accepts pure non-ASCII DNS labels (genuine IDN U-labels)", () => {
    const pureCyrillic = `${CYRILLIC_A}${CYRILLIC_A}${CYRILLIC_A}.xn--p1ai`;
    // First label is pure Cyrillic; second is well-formed ACE.
    assert.equal(isSafeDnsIdentity(`${CYRILLIC_A}${CYRILLIC_A}${CYRILLIC_A}`), true);
    assert.equal(isSafeDnsIdentity(pureCyrillic), true);
  });

  it("rejects U+202E bidirectional override", () => {
    const spoofed = `evil.com\u202Egoogle.com`;
    assertRejects(() => assertSafeDnsIdentity(spoofed), /bidirectional/);
  });

  it("rejects bidirectional isolate controls", () => {
    assertRejects(
      () => assertSafeDnsIdentity(`safe\u2066evil.com`),
      /bidirectional/,
    );
  });

  it("rejects zero-width joiner and zero-width space", () => {
    assertRejects(
      () => assertSafeDnsIdentity(`goo\u200Dgle.com`),
      /zero-width/,
    );
    assertRejects(
      () => assertSafeDnsIdentity(`goo\u200Bgle.com`),
      /zero-width/,
    );
  });

  it("rejects control characters", () => {
    assertRejects(
      () => assertSafeDnsIdentity("evil\u0000.com"),
      /control character/,
    );
    assertRejects(
      () => assertSafeDnsIdentity("evil\t.com"),
      /control character/,
    );
  });

  it("does not apply DNS mixed-script rules to IP identities", () => {
    assert.equal(assertSafeIpIdentity("127.0.0.1"), "127.0.0.1");
    assert.equal(assertSafeIpIdentity("::1"), "::1");
    assert.equal(assertSafeIpIdentity("2001:db8::1"), "2001:db8::1");
  });

  it("still rejects invisible characters inside IP identity strings", () => {
    assertRejects(
      () => assertSafeIpIdentity("127.0.0\u200B.1"),
      /zero-width/,
    );
  });
});
