"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  deriveRenewalProfileFromIssuedCertificate,
  ensureDerivedRenewalProfile,
} = require("../../apps/api/services/certops/renewalProfileDerivation");
const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
} = require("../../apps/api/services/certops/renewalProfile");

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const CERT_ID = "22222222-2222-4222-8222-222222222222";
const PROFILE_ID = "33333333-3333-4333-8333-333333333333";

/**
 * A realistic issue-job payload, i.e. what the scheduler would have to be able
 * to reconstruct in order to renew the certificate the same way it was issued.
 */
function issuePayload(overrides = {}) {
  return {
    certificateId: CERT_ID,
    target: { type: "domain", reference: "web-01.example.com" },
    sans: ["web-01.example.com"],
    caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
    commandRef: "certbot-dns-cloudflare",
    acmeKind: "certbot",
    dnsProvider: "cloudflare",
    dnsZone: "example.com",
    certPath: "/etc/ssl/tokentimer/web-01.example.com.pem",
    keyPath: "/etc/ssl/private/web-01.example.com.key",
    chainPath: "/etc/ssl/tokentimer/web-01.example.com.chain.pem",
    reloadService: "nginx",
    keyAlgorithm: "ecdsa",
    keySize: 256,
    ...overrides,
  };
}

function issuedCertificate(overrides = {}) {
  return {
    commonName: "web-01.example.com",
    subjectAltNames: ["web-01.example.com"],
    ...overrides,
  };
}

describe("renewal profile derivation from an issued certificate", () => {
  it("reproduces the execution contract the issuance actually used", () => {
    const profile = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload(),
      certificate: issuedCertificate(),
    });

    assert.equal(
      profile.ca.endpoint,
      "https://acme-v02.api.letsencrypt.org/directory",
    );
    assert.equal(profile.acme.commandRef, "certbot-dns-cloudflare");
    assert.equal(profile.acme.kind, "certbot");
    assert.equal(profile.dns.provider, "cloudflare");
    assert.equal(profile.dns.zone, "example.com");
    assert.equal(profile.keyAlgorithm, "ecdsa");
    assert.equal(profile.keySize, 256);
    assert.equal(profile.target.certPath, "/etc/ssl/tokentimer/web-01.example.com.pem");
    assert.equal(profile.deploymentTargets.length, 1);
    assert.equal(profile.deploymentTargets[0].reloadService, "nginx");
    assert.equal(
      profile.deploymentTargets[0].chainPath,
      "/etc/ssl/tokentimer/web-01.example.com.chain.pem",
    );
    assert.equal(
      profile.keyRotationPolicy.rotateOnRenew,
      true,
      "an issued certificate is agent-local custody, so renewal can rotate the key",
    );
  });

  it("pins the SAN set to what the CA issued, not what the job requested", () => {
    // If the CA normalised or dropped a name, renewing against the requested
    // set would produce a different certificate than the one on the host.
    const profile = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload({ sans: ["web-01.example.com", "dropped.example.com"] }),
      certificate: issuedCertificate({
        subjectAltNames: ["web-01.example.com", "alt.example.com"],
      }),
    });

    assert.deepEqual(profile.sanPolicy.sans.sort(), [
      "alt.example.com",
      "web-01.example.com",
    ]);
    assert.equal(
      profile.sanPolicy.mode,
      "exact",
      "'inherit' would let a later discovery scan silently change the renewal request",
    );
  });

  it("always covers the common name even when the observed SANs omit it", () => {
    const profile = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload(),
      certificate: issuedCertificate({ subjectAltNames: ["alt.example.com"] }),
    });
    assert.ok(profile.sanPolicy.sans.includes("web-01.example.com"));
  });

  it("allows wildcards only when the issued certificate contains one", () => {
    const plain = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload(),
      certificate: issuedCertificate(),
    });
    assert.equal(plain.sanPolicy.allowWildcards, false);

    const wildcard = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload({
        target: { type: "domain", reference: "*.example.com" },
      }),
      certificate: issuedCertificate({
        commonName: "*.example.com",
        subjectAltNames: ["*.example.com"],
      }),
    });
    assert.equal(wildcard.sanPolicy.allowWildcards, true);
  });

  it("does not require a live verification match when issuance had no verify host", () => {
    const profile = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload(),
      certificate: issuedCertificate(),
    });
    assert.equal(profile.verification.requireMatch, false);
    assert.equal(profile.verification.host, null);
  });

  it("carries the verification host forward when the issuance used one", () => {
    const profile = deriveRenewalProfileFromIssuedCertificate({
      payload: issuePayload({ verifyHost: "web-01.example.com", verifyPort: 443 }),
      certificate: issuedCertificate(),
    });
    assert.equal(profile.verification.host, "web-01.example.com");
    assert.equal(profile.verification.port, 443);
    assert.equal(profile.verification.requireMatch, true);
  });

  it("names each missing field rather than inventing a default", () => {
    // Defaulting any of these would renew the certificate differently from how
    // it was issued, and the divergence would only surface at renewal time.
    for (const [field, pattern] of [
      ["caEndpoint", /caEndpoint/],
      ["commandRef", /commandRef/],
      ["dnsProvider", /dnsProvider/],
      ["dnsZone", /dnsProvider\/dnsZone/],
      ["certPath", /certPath/],
    ]) {
      assert.throws(
        () =>
          deriveRenewalProfileFromIssuedCertificate({
            payload: issuePayload({ [field]: undefined }),
            certificate: issuedCertificate(),
          }),
        (error) => {
          assert.equal(error.code, CERTOPS_RENEWAL_PROFILE_INCOMPLETE);
          assert.match(error.message, pattern);
          return true;
        },
        `missing ${field} must be reported`,
      );
    }
  });

  it("rejects a certificate with no common name", () => {
    assert.throws(
      () =>
        deriveRenewalProfileFromIssuedCertificate({
          payload: issuePayload(),
          certificate: issuedCertificate({ commonName: null }),
        }),
      /no common name/,
    );
  });
});

function createClient({ existingProfileId = null, inserted = true } = {}) {
  const state = { queries: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ sql, params });
      if (sql.includes("SELECT profile_id FROM managed_certificates")) {
        return { rows: [{ profile_id: existingProfileId }] };
      }
      if (sql.includes("INSERT INTO certificate_profiles")) {
        return { rows: [{ id: PROFILE_ID, inserted }] };
      }
      if (sql.includes("UPDATE managed_certificates")) {
        return { rows: [], rowCount: 1 };
      }
      // The real writeAudit is routed through this mock rather than replaced, so
      // the tests prove the event is written on the derivation transaction's own
      // client. A profile granting recurring host authority must not be able to
      // commit while its audit row rolls back.
      if (sql.includes("INSERT INTO audit_events")) {
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  return { state, client };
}

describe("derived renewal profile persistence", () => {
  it("creates the profile and links the certificate to it", async () => {
    const { state, client } = createClient();
    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: issuedCertificate(),
    });

    assert.equal(result.profileId, PROFILE_ID);
    assert.equal(result.created, true);

    const insert = state.queries.find((q) =>
      q.sql.includes("INSERT INTO certificate_profiles"),
    );
    assert.ok(insert, "a profile row is expected");
    const metadata = JSON.parse(insert.params[6]);
    assert.ok(
      metadata.renewalProfile,
      "the scheduler reads public_metadata.renewalProfile",
    );
    assert.equal(metadata.derivedFrom.certificateId, CERT_ID);

    const link = state.queries.find((q) =>
      q.sql.includes("UPDATE managed_certificates"),
    );
    assert.ok(link, "the certificate must be linked to the profile");
    assert.match(
      link.sql,
      /profile_id IS NULL/,
      "linking must not overwrite an operator's own profile",
    );
  });

  it("leaves an already-linked certificate alone", async () => {
    // An operator's hand-authored profile must never be replaced by a
    // derivation, so a re-reconciliation is a no-op here.
    const { state, client } = createClient({ existingProfileId: PROFILE_ID });
    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: issuedCertificate(),
    });

    assert.equal(result.reason, "already_linked");
    assert.equal(result.created, false);
    assert.equal(
      state.queries.filter((q) => q.sql.includes("INSERT INTO")).length,
      0,
      "no profile row should be written",
    );
  });

  it("upserts on the profile name so a re-derivation reuses one row", async () => {
    const { state, client } = createClient({ inserted: false });
    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: issuedCertificate(),
    });

    assert.equal(result.created, false);
    const insert = state.queries.find((q) => q.sql.includes("INSERT INTO"));
    assert.match(insert.sql, /ON CONFLICT \(workspace_id, LOWER\(name\)\)/);
    assert.match(
      insert.sql,
      /renew_before_days = COALESCE\(\s*certificate_profiles\.renew_before_days/,
      "an operator's chosen threshold must survive a re-derivation",
    );
  });

  it("does not fail the issuance when derivation is impossible", async () => {
    // The certificate genuinely exists on the host. Losing that record because
    // renewal config could not be inferred would be strictly worse than an
    // un-auto-renewable certificate the operator can see and fix.
    const { state, client } = createClient();
    const warnings = [];
    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload({ dnsProvider: undefined }),
      certificate: issuedCertificate(),
      logger: { warn: (msg, meta) => warnings.push({ msg, meta }) },
    });

    assert.equal(result.profileId, null);
    assert.equal(result.reason, "derivation_failed");
    assert.equal(
      state.queries.filter((q) => q.sql.includes("INSERT INTO")).length,
      0,
    );
    assert.equal(warnings.length, 1, "the failure must be observable");
    assert.equal(warnings[0].msg, "certops-renewal-profile-derivation-failed");
  });
});
