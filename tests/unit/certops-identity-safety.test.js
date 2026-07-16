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

  // The declared engines minimum (node >=22.0.0) predates Unicode 16, so the
  // seven scripts introduced there may not compile as \p{Script=...} on the
  // oldest supported runtime. Validation must degrade to a controlled
  // fail-closed rejection, never a SyntaxError.
  const UNICODE16_SCRIPT_SAMPLES = [
    ["Garay", 0x10d50],
    ["Gurung_Khema", 0x16110],
    ["Kirat_Rai", 0x16d43],
    ["Ol_Onal", 0x1e5d0],
    ["Sunuwar", 0x11bc0],
    ["Todhri", 0x105c0],
    ["Tulu_Tigalari", 0x11380],
  ];

  function runtimeSupportsScript(name) {
    try {
      new RegExp(`\\p{Script=${name}}`, "u");
      return true;
    } catch {
      return false;
    }
  }

  it("never throws SyntaxError for Unicode 16 script characters on any supported runtime", () => {
    for (const [name, codePoint] of UNICODE16_SCRIPT_SAMPLES) {
      const label = String.fromCodePoint(codePoint).repeat(2);
      const result = checkSafeDnsIdentity(label);
      if (runtimeSupportsScript(name)) {
        // Unicode 16 runtime: pure single-script label of a known script.
        assert.equal(result, null, `${name} single-script label accepted`);
      } else {
        // Pre-Unicode-16 runtime: the script cannot be resolved, so the
        // label is rejected fail-closed with a controlled identity error.
        assert.equal(result instanceof CertOpsIdentitySafetyError, true);
        assert.match(result.message, /unresolved Unicode script/);
      }
    }
  });

  it("rejects labels mixing a Unicode 16 script with another script on all runtimes", () => {
    // Mixed with Bengali: on Unicode 16 runtimes this is a two-script mix;
    // on older runtimes the unresolved character already rejects the label.
    for (const [, codePoint] of UNICODE16_SCRIPT_SAMPLES) {
      const mixed = `\u0995${String.fromCodePoint(codePoint)}`;
      const result = checkSafeDnsIdentity(mixed);
      assert.equal(result instanceof CertOpsIdentitySafetyError, true);
      assert.match(
        result.message,
        /mixes multiple Unicode scripts|unresolved Unicode script/,
      );
    }
  });

  it("resolves every known script name without throwing during validation", () => {
    // Exercise the full matcher list through the public API: a Latin label
    // forces the linear scan across all compiled matchers at least once,
    // and no compilation failure may escape as an exception.
    assert.doesNotThrow(() => checkSafeDnsIdentity("z\u00fcrich"));
    assert.doesNotThrow(() => checkSafeDnsIdentity("\u4e2d\u6587"));
    assert.doesNotThrow(() =>
      checkSafeDnsIdentity(String.fromCodePoint(0x10d50, 0x11380)),
    );
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
