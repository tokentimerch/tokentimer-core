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
const GREEK_ALPHA = "\u03b1";
const GREEK_BETA = "\u03b2";
const CYRILLIC_VE = "\u0432";

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

  it("rejects Greek+Cyrillic mixed-script single label", () => {
    const mixed = `${GREEK_ALPHA}${GREEK_BETA}${CYRILLIC_VE}.example`;
    assert.equal(isSafeDnsIdentity(mixed), false);
    assertRejects(
      () => assertSafeDnsIdentity(mixed),
      /mixes multiple Unicode scripts/,
    );
    assertRejects(() => assertSafeHostname(mixed), /homograph/);
  });

  it("accepts single-script Greek-only labels", () => {
    const greek = `${GREEK_ALPHA}${GREEK_BETA}${GREEK_ALPHA}.example`;
    assert.equal(isSafeDnsIdentity(greek), true);
    assert.equal(assertSafeDnsIdentity(greek), greek);
  });

  it("accepts Japanese Han+Hiragana+Katakana labels", () => {
    const japanese = "\u6771\u4eac\u3072\u3089\u30ab\u30bf"; // 東京ひらカタ
    assert.equal(isSafeDnsIdentity(`${japanese}.example`), true);
    assert.equal(isSafeDnsIdentity(japanese), true);
  });

  it("accepts Han+Hangul and Han+Bopomofo labels", () => {
    const hanHangul = "\u6f22\ud55c\uae00"; // 漢한글
    const hanBopomofo = "\u6f22\u3105\u3106"; // 漢ㄅㄆ
    assert.equal(isSafeDnsIdentity(hanHangul), true);
    assert.equal(isSafeDnsIdentity(hanBopomofo), true);
  });

  it("rejects non-CJK script combinations with Han", () => {
    const hanCyrillic = `\u6f22${CYRILLIC_A}`; // Han + Cyrillic
    assert.equal(isSafeDnsIdentity(hanCyrillic), false);
    assertRejects(
      () => assertSafeDnsIdentity(hanCyrillic),
      /mixes multiple Unicode scripts/,
    );
  });

  it("rejects Hiragana+Hangul without Han as a disallowed combination", () => {
    const hiraganaHangul = "\u3072\ud55c"; // ひ한
    assert.equal(isSafeDnsIdentity(hiraganaHangul), false);
  });

  it("rejects mixed labels of scripts outside the historic hardcoded set", () => {
    // Bengali KA (U+0995) + Tamil KA (U+0B95): before full Unicode script
    // coverage both fell into a shared "Unrecognized" bucket and the mix
    // was accepted.
    const bengaliTamil = "\u0995\u0b95";
    assert.equal(isSafeDnsIdentity(bengaliTamil), false);
    assertRejects(
      () => assertSafeDnsIdentity(bengaliTamil),
      /mixes multiple Unicode scripts/,
    );
    assertRejects(
      () => assertSafeDnsIdentity(`${bengaliTamil}.example`),
      /Bengali, Tamil/,
    );
  });

  it("accepts pure single-script labels of previously unlisted scripts", () => {
    const pureBengali = "\u0995\u0996\u0997"; // ক খ গ
    const pureTamil = "\u0b95\u0b99\u0b9a"; // க ங ச
    assert.equal(isSafeDnsIdentity(pureBengali), true);
    assert.equal(assertSafeDnsIdentity(pureBengali), pureBengali);
    assert.equal(isSafeDnsIdentity(pureTamil), true);
    assert.equal(assertSafeDnsIdentity(pureTamil), pureTamil);
    assert.equal(isSafeDnsIdentity(`${pureTamil}.example`), true);
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
