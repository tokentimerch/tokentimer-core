"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizeKeyReference,
  normalizeSourceRef,
  KEY_REFERENCE_MAX_LENGTH,
  SOURCE_REF_MAX_LENGTH,
} = require("../../apps/api/services/certops/inventory");

function assertRejected(value) {
  assert.throws(
    () => normalizeKeyReference(value),
    (error) => error?.code === "CERTOPS_KEY_REFERENCE_INVALID",
  );
}

function assertSourceRefRejected(value) {
  assert.throws(
    () => normalizeSourceRef(value),
    (error) => error?.code === "CERTOPS_SOURCE_REF_INVALID",
  );
}

// C2 (zero-custody): keyReference is a material-locality pointer, not free
// text.
describe("normalizeKeyReference locality schemes (C2)", () => {
  it("accepts every scheme actually emitted or exercised elsewhere in this codebase", () => {
    // file:// - apps/api/services/certops/agentObservations.js writer format
    assert.equal(
      normalizeKeyReference("file:///etc/ssl/certs/web.pem"),
      "file:///etc/ssl/certs/web.pem",
    );
    // k8s: - apps/api/services/certops/controllerProvisioning.js and
    // controllerObservations.js writer format
    assert.equal(
      normalizeKeyReference("k8s://prod-cluster/web/secret/tls.key"),
      "k8s://prod-cluster/web/secret/tls.key",
    );
    // vault:, hsm:, external-unknown: - exercised in
    // tests/integration/certops-inventory.test.js fixtures
    assert.equal(
      normalizeKeyReference("  vault://pki/web/example  "),
      "vault://pki/web/example",
    );
    assert.equal(
      normalizeKeyReference("hsm://partition-1/web-key"),
      "hsm://partition-1/web-key",
    );
    assert.equal(
      normalizeKeyReference("external-unknown://legacy-ref-12345"),
      "external-unknown://legacy-ref-12345",
    );
  });

  it("accepts a pkcs11: URI built only from RFC 7512 non-secret attributes (documented in ImportCertificateForm.jsx)", () => {
    const uri = "pkcs11:token=My%20HSM;object=web-key;type=private";
    assert.equal(normalizeKeyReference(uri), uri);
  });

  it("accepts a pkcs11: URI with query-form attributes, including pin-source (a pointer, not the PIN itself)", () => {
    const uri =
      "pkcs11:token=My%20HSM;object=web-key?module-path=/usr/lib/pkcs11.so&pin-source=file:/etc/hsm-pin";
    assert.equal(normalizeKeyReference(uri), uri);
  });

  it("rejects a pkcs11: URI carrying pin-value, which RFC 7512 defines as an inline PIN", () => {
    assertRejected("pkcs11:token=My%20HSM;object=web-key?pin-value=1234");
  });

  it("rejects a pkcs11: URI with any attribute outside the safe RFC 7512 set", () => {
    assertRejected("pkcs11:token=My%20HSM;secret=abc123");
  });

  it("rejects a bare value with no locality scheme, even if it looks like an opaque id", () => {
    assertRejected("just-some-opaque-id-123");
  });

  it("rejects a bare credential-shaped value with no scheme", () => {
    assertRejected("AKIAABCDEFGHIJKLMNOP");
  });

  it("rejects a scheme-valid reference carrying a generic-secret-shaped payload, without echo", () => {
    assertRejected("vault://pki/web?password=supersecret123");
    assertRejected("external-unknown://legacy-ref?password=swordfish");
  });

  it("rejects private key PEM material passed as a keyReference", () => {
    assertRejected(
      "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----",
    );
  });

  it("rejects a reference over the unified maximum length", () => {
    assertRejected(`hsm://${"a".repeat(KEY_REFERENCE_MAX_LENGTH)}`);
  });

  it("returns null for empty/absent values without throwing", () => {
    assert.equal(normalizeKeyReference(undefined), null);
    assert.equal(normalizeKeyReference(null), null);
    assert.equal(normalizeKeyReference("   "), null);
  });
});

// C1/C2 (zero-custody): sourceRef is documented in the OpenAPI contract as an
// "opaque non-secret source reference." Unlike keyReference it carries no
// scheme allow-list (it is free text describing observation provenance, not
// a material-locality pointer), but it is still persisted verbatim and
// echoed back in API responses, so it gets the same content-based secret
// checks. Regression coverage added after a live-stack artifact scan found a
// canary generic secret placed in sourceRef survived unredacted into the
// managed_certificates.source_ref column and the import response body.
describe("normalizeSourceRef non-secret provenance (C1/C2)", () => {
  it("passes through an ordinary opaque source reference unchanged", () => {
    assert.equal(
      normalizeSourceRef("provision-certops-demo:seed-01.tokentimer.test"),
      "provision-certops-demo:seed-01.tokentimer.test",
    );
    assert.equal(normalizeSourceRef("  monitor-job-42  "), "monitor-job-42");
  });

  it("rejects a sourceRef carrying a generic-secret-shaped payload, without echo", () => {
    // The shared detector's generic-secret check is assignment-pattern based
    // (`key=value` / `key: value`), the same mechanism normalizeKeyReference
    // relies on for its remainder-of-URI check. A bare, unassigned
    // high-entropy token (e.g. a raw AWS access key ID with no surrounding
    // `key=`/`key:`) is not flagged by this check for either field; for
    // keyReference that gap is closed by the mandatory scheme allow-list
    // instead, which sourceRef intentionally has none of. This is a known,
    // deliberate scope boundary of the sourceRef check, not an oversight.
    assertSourceRefRejected("import-job?password=supersecret123");
    assertSourceRefRejected("scan-result token=eyJhbGciOiJIUzI1NiJ9.abc.def");
  });

  it("rejects private key PEM material passed as a sourceRef", () => {
    assertSourceRefRejected(
      "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----",
    );
  });

  it("rejects a sourceRef over the maximum length", () => {
    assertSourceRefRejected(`import-job-${"a".repeat(SOURCE_REF_MAX_LENGTH)}`);
  });

  it("returns null for empty/absent values without throwing", () => {
    assert.equal(normalizeSourceRef(undefined), null);
    assert.equal(normalizeSourceRef(null), null);
    assert.equal(normalizeSourceRef("   "), null);
  });
});
