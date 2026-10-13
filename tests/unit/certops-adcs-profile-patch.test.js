"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_PROFILE_FIELD_IMMUTABLE,
  CERTOPS_PROFILE_INVALID,
  applyRenewalProfilePatch,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/renewalProfileAdmin.js"),
);
const {
  CERTOPS_RENEWAL_PROFILE_INVALID,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/renewalProfile.js"),
);

const TARGET = {
  type: "windows-iis",
  reference: "app.example.com",
  store: "WebHosting",
  binding: { site: "Shop", port: 443 },
};

// The shape createAdcsRenewalProfile stores: no schemaVersion, no ACME fields.
function adcsStored(overrides = {}) {
  return {
    target: TARGET,
    sanPolicy: { sans: ["app.example.com"] },
    keyAlgorithm: "rsa",
    keySize: 2048,
    ...overrides,
  };
}

function expectCode(fn, code) {
  try {
    fn();
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    return;
  }
  assert.fail(`expected a ${code} rejection but the call succeeded`);
}

describe("CertOps AD CS renewal-profile edits", () => {
  it("applies SAN and key edits without requiring ACME fields", () => {
    const result = applyRenewalProfilePatch(adcsStored(), {
      sanPolicy: { sans: ["app.example.com", "www.example.com"] },
      keySize: 3072,
    });
    assert.deepEqual(result.sanPolicy, { sans: ["app.example.com", "www.example.com"] });
    assert.equal(result.keySize, 3072);
    assert.deepEqual(result.target, TARGET);
    assert.equal(result.schemaVersion, undefined);
    assert.equal(result.ca, undefined);
  });

  it("accepts switching the key algorithm when the key size matches it", () => {
    const result = applyRenewalProfilePatch(adcsStored(), {
      keyAlgorithm: "ecdsa",
      keySize: 256,
    });
    assert.equal(result.keyAlgorithm, "ecdsa");
    assert.equal(result.keySize, 256);
  });

  it("refuses to change the Windows/IIS target that decides where the certificate lands", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(adcsStored(), {
          target: { ...TARGET, binding: { site: "Other Site", port: 443 } },
        }),
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
    );
  });

  it("refuses ACME-only fields on an AD CS profile instead of saving them unused", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(adcsStored(), {
          verification: { host: null, port: null, requireMatch: false },
        }),
      CERTOPS_PROFILE_INVALID,
    );
    expectCode(
      () => applyRenewalProfilePatch(adcsStored(), { preferredChain: "lets-encrypt" }),
      CERTOPS_PROFILE_INVALID,
    );
  });

  it("keeps the certificate name in the SAN list", () => {
    expectCode(
      () => applyRenewalProfilePatch(adcsStored(), { sanPolicy: { sans: ["www.example.com"] } }),
      CERTOPS_PROFILE_INVALID,
    );
  });

  it("rejects a SAN that is not a DNS name", () => {
    expectCode(
      () =>
        applyRenewalProfilePatch(adcsStored(), {
          sanPolicy: { sans: ["app.example.com", "not a host!"] },
        }),
      CERTOPS_PROFILE_INVALID,
    );
  });

  it("rejects a key size that does not match the key algorithm", () => {
    expectCode(
      () => applyRenewalProfilePatch(adcsStored(), { keyAlgorithm: "ecdsa", keySize: 2048 }),
      CERTOPS_PROFILE_INVALID,
    );
  });

  it("keeps ACME profiles on the ACME validator", () => {
    const acme = {
      schemaVersion: 1,
      sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
      keyAlgorithm: "ecdsa",
      keySize: 256,
      keyRotationPolicy: { rotateOnRenew: true },
      preferredChain: null,
      ca: { endpoint: "https://acme-v02.api.letsencrypt.org/directory", accountRef: "le-prod", eabRef: null },
      acme: { kind: "certbot", commandRef: "issue.dns" },
      dns: { provider: "cloudflare", zone: "example.com" },
      deploymentTargets: [
        { type: "domain", reference: "app.example.com", certPath: "/etc/ssl/certs/app.pem", reloadService: "nginx", owner: "root" },
      ],
      target: { type: "domain", reference: "app.example.com", certPath: "/etc/ssl/certs/app.pem" },
      verification: { host: null, port: null, requireMatch: false },
    };
    expectCode(
      () => applyRenewalProfilePatch(acme, { keySize: 4096 }),
      CERTOPS_RENEWAL_PROFILE_INVALID,
    );
  });
});
