"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { describe, it } = require("node:test");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const {
  MAX_PUBLIC_PEM_BYTES,
  MAX_PUBLIC_SAN_ENTRIES,
  MAX_PUBLIC_SAN_LENGTH,
  MAX_PUBLIC_TEXT_LENGTH,
} = require("../../apps/api/services/certops/controllerObservationLimits");
const {
  _test: apiControllerObservationTest,
} = require("../../apps/api/services/certops/controllerObservations");
const {
  createObservationEnvelope,
} = require("../../apps/k8s-controller/src/observation-envelope");
const {
  MAX_CERTIFICATE_PEM_LENGTH,
  MAX_CERTIFICATE_TEXT_LENGTH,
  MAX_SUBJECT_ALT_NAME_LENGTH,
  MAX_SUBJECT_ALT_NAMES,
  parsePublicCertificateObservation,
} = require("../../apps/k8s-controller/src/public-certificate-parser");
const observationSchema = require("../../packages/contracts/certops/controller-observation.schema.json");

const root = path.resolve(__dirname, "../..");

function certificateLeaf(overrides = {}) {
  return {
    certificatePem: "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----",
    fingerprintSha256: "a".repeat(64),
    issuer: "CN=issuer.example.test",
    notAfter: "2027-07-21T10:00:00.000Z",
    notBefore: "2026-07-21T10:00:00.000Z",
    publicKeyAlgorithm: "rsaEncryption",
    publicKeySize: 2048,
    serialNumber: "01",
    signatureAlgorithm: "sha256WithRSAEncryption",
    subject: "CN=example.test",
    subjectAltNames: ["example.test"],
    ...overrides,
  };
}

function publicObservationFor(leaf) {
  return parsePublicCertificateObservation(Buffer.from("public certificate"), {
    parsePublicCertificateMaterial: () => [leaf],
  });
}

function controllerObservation(publicCertificate) {
  return {
    certificateName: "example-test",
    certificateRequestRef: null,
    certificateUid: "22222222-2222-4222-8222-222222222222",
    clusterId: "controller-a",
    conditions: [{ status: "True", type: "Ready" }],
    dnsNames: ["example.test"],
    issuerRef: { name: "issuer" },
    namespace: "certops",
    publicCertificate,
    ready: true,
    resourceVersion: "42",
    secretName: "example-test-tls",
    workspaceId: "11111111-1111-4111-8111-111111111111",
  };
}

function publicSanAtLength(length) {
  const labels = [];
  let remaining = length;
  while (remaining > 63) {
    labels.push("a".repeat(63));
    remaining -= 64;
  }
  labels.push("a".repeat(remaining));
  return labels.join(".");
}

describe("controller public-certificate observation adapter", () => {
  it("includes normal and exactly bounded PEM without changing it", () => {
    const normalPem = "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----";
    assert.equal(
      publicObservationFor(certificateLeaf({ certificatePem: normalPem })).publicCertificate.certificatePem,
      normalPem,
    );

    const boundedPem = "p".repeat(MAX_PUBLIC_PEM_BYTES);
    const parsed = publicObservationFor(certificateLeaf({ certificatePem: boundedPem }));
    assert.equal(parsed.publicCertificate.certificatePem, boundedPem);
    assert.equal(Buffer.byteLength(parsed.publicCertificate.certificatePem, "utf8"), MAX_PUBLIC_PEM_BYTES);
  });

  it("omits oversized PEM while retaining safe public metadata", () => {
    const parsed = publicObservationFor(certificateLeaf({
      certificatePem: "p".repeat(MAX_PUBLIC_PEM_BYTES + 1),
      subject: "CN=retained.example.test",
    }));
    assert.equal(Object.hasOwn(parsed.publicCertificate, "certificatePem"), false);
    assert.equal(parsed.publicCertificate.fingerprintSha256, "a".repeat(64));
    assert.equal(parsed.publicCertificate.subject, "CN=retained.example.test");
  });

  it("omits overlong public text instead of semantically truncating it", () => {
    const maximum = "s".repeat(MAX_PUBLIC_TEXT_LENGTH);
    const parsed = publicObservationFor(certificateLeaf({
      issuer: "i".repeat(MAX_PUBLIC_TEXT_LENGTH + 1),
      publicKeyAlgorithm: "k".repeat(MAX_PUBLIC_TEXT_LENGTH + 1),
      serialNumber: "r".repeat(MAX_PUBLIC_TEXT_LENGTH + 1),
      signatureAlgorithm: "g".repeat(MAX_PUBLIC_TEXT_LENGTH + 1),
      subject: maximum,
    }));
    assert.equal(parsed.publicCertificate.subject, maximum);
    for (const field of ["issuer", "publicKeyAlgorithm", "serialNumber", "signatureAlgorithm"]) {
      assert.equal(Object.hasOwn(parsed.publicCertificate, field), false);
    }
    const oversizedSubject = publicObservationFor(certificateLeaf({
      issuer: "i".repeat(MAX_PUBLIC_TEXT_LENGTH + 1),
      subject: "s".repeat(MAX_PUBLIC_TEXT_LENGTH + 1),
    }));
    assert.equal(Object.hasOwn(oversizedSubject.publicCertificate, "subject"), false);
    assert.equal(Object.hasOwn(oversizedSubject.publicCertificate, "issuer"), false);
  });

  it("keeps valid SAN forms, accepts 253 characters, and omits 254-character identities", () => {
    const maximumSan = publicSanAtLength(MAX_PUBLIC_SAN_LENGTH);
    const oversizedSan = publicSanAtLength(MAX_PUBLIC_SAN_LENGTH + 1);
    assert.equal(maximumSan.length, MAX_PUBLIC_SAN_LENGTH);
    assert.equal(oversizedSan.length, MAX_PUBLIC_SAN_LENGTH + 1);
    const expected = [
      "*.wild.example.test",
      "192.0.2.1",
      "2001:db8::1",
      "admin@example.test",
      "spiffe://cluster.local/ns/default/sa/controller",
      maximumSan,
    ].sort();
    const parsed = publicObservationFor(certificateLeaf({
      subjectAltNames: [...expected, oversizedSan, "192.0.2.1"],
    }));
    assert.deepEqual(parsed.publicCertificate.subjectAltNames, expected);
    assert.equal(parsed.publicCertificate.subjectAltNames.length <= MAX_PUBLIC_SAN_ENTRIES, true);
    assert.equal(parsed.publicCertificate.subjectAltNames.includes(oversizedSan), false);
  });

  it("produces an envelope accepted by the published controller-observation schema", () => {
    const publicCertificate = publicObservationFor(certificateLeaf({
      subjectAltNames: [
        "*.wild.example.test",
        "192.0.2.1",
        "2001:db8::1",
        "admin@example.test",
        "spiffe://cluster.local/ns/default/sa/controller",
      ],
    })).publicCertificate;
    const envelope = createObservationEnvelope(controllerObservation(publicCertificate), {
      now: () => "2026-07-21T10:00:00.000Z",
    });
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(observationSchema);
    assert.equal(validate(envelope), true, JSON.stringify(validate.errors));
  });

  it("shares producer, API, schema, and OpenAPI public-certificate limits", () => {
    assert.deepEqual(apiControllerObservationTest.limits, {
      MAX_DNS_NAMES: MAX_PUBLIC_SAN_ENTRIES,
      MAX_IDENTITY: MAX_PUBLIC_SAN_LENGTH,
      MAX_PUBLIC_PEM: MAX_PUBLIC_PEM_BYTES,
      MAX_TEXT: MAX_PUBLIC_TEXT_LENGTH,
    });
    assert.deepEqual({
      MAX_CERTIFICATE_PEM_LENGTH,
      MAX_CERTIFICATE_TEXT_LENGTH,
      MAX_SUBJECT_ALT_NAME_LENGTH,
      MAX_SUBJECT_ALT_NAMES,
    }, {
      MAX_CERTIFICATE_PEM_LENGTH: MAX_PUBLIC_PEM_BYTES,
      MAX_CERTIFICATE_TEXT_LENGTH: MAX_PUBLIC_TEXT_LENGTH,
      MAX_SUBJECT_ALT_NAME_LENGTH: MAX_PUBLIC_SAN_LENGTH,
      MAX_SUBJECT_ALT_NAMES: MAX_PUBLIC_SAN_ENTRIES,
    });
    const publicCertificate = observationSchema.definitions.publicCertificate;
    assert.equal(publicCertificate.properties.certificatePem.maxLength, MAX_PUBLIC_PEM_BYTES);
    assert.equal(publicCertificate.properties.subject.maxLength, MAX_PUBLIC_TEXT_LENGTH);
    assert.equal(publicCertificate.properties.issuer.maxLength, MAX_PUBLIC_TEXT_LENGTH);
    assert.equal(publicCertificate.properties.subjectAltNames.maxItems, MAX_PUBLIC_SAN_ENTRIES);
    assert.equal(
      observationSchema.definitions.publicSan.anyOf[1].maxLength,
      MAX_PUBLIC_SAN_LENGTH,
    );

    const openapi = fs.readFileSync(path.join(root, "packages/contracts/openapi/openapi.yaml"), "utf8");
    const publicCertificateSection = openapi.slice(
      openapi.indexOf("        publicCertificate:\n          type: object"),
      openapi.indexOf("        observationSource:", openapi.indexOf("        publicCertificate:\n          type: object")),
    );
    assert.match(publicCertificateSection, /subject: \{ type: string, maxLength: 1024 \}/);
    assert.match(publicCertificateSection, /issuer: \{ type: string, maxLength: 1024 \}/);
    assert.match(publicCertificateSection, /maxItems: 64/);
    assert.match(publicCertificateSection, /maxLength: 253/);
    assert.match(publicCertificateSection, /certificatePem: \{ type: string, maxLength: 65536 \}/);
  });
});
