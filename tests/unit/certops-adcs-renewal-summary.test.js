"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { deriveCertificateRenewalState } =
  require("../../apps/api/routes/certops")._test;
const {
  loadCertificateRenewalRows,
} = require("../../apps/api/services/certops/renewalScheduler");

function certificateRow(profile = {}, overrides = {}) {
  return {
    id: "aaaaaaaa-0000-4000-8000-000000000001",
    status: "discovered",
    key_mode: "os-store-managed",
    not_after: "2027-01-22T00:09:16.000Z",
    common_name: "app.example.test",
    subject_alt_names: ["app.example.test"],
    profile_id: "bbbbbbbb-0000-4000-8000-000000000002",
    profile_name: "IIS renewal",
    profile_status: "active",
    profile_renew_before_days: 30,
    profile_issuer_id: "cccccccc-0000-4000-8000-000000000003",
    profile_issuer_kind: "adcs",
    profile_public_metadata: {
      renewalProfile: {
        target: {
          type: "windows-iis",
          reference: "app.example.test",
          store: "My",
          binding: {
            site: "Example IIS",
            port: 443,
            sniHost: "app.example.test",
          },
        },
        keyAlgorithm: "rsa",
        keySize: 2048,
        sanPolicy: { sans: ["app.example.test"] },
        ...profile,
      },
    },
    ...overrides,
  };
}

describe("AD CS inventory renewal summary", () => {
  it("recognizes a complete native profile without ACME CA fields", () => {
    const state = deriveCertificateRenewalState(certificateRow());
    assert.equal(state.state, "auto");
    assert.equal(state.renewsFrom, "2026-12-23T00:09:16.000Z");
  });

  for (const [name, profile, reason] of [
    ["missing target", { target: null }, /Windows\/IIS deployment target/],
    [
      "wrong DNS policy",
      { sanPolicy: { sans: ["other.example.test"] } },
      /include the certificate name/,
    ],
    ["unsupported key", { keySize: 1024 }, /keySize/],
  ]) {
    it(`refuses a native profile with ${name}`, () => {
      const state = deriveCertificateRenewalState(certificateRow(profile));
      assert.equal(state.state, "not-configured");
      assert.match(state.detail, reason);
    });
  }

  it("refuses an AD CS profile whose issuer relationship is missing", () => {
    const state = deriveCertificateRenewalState(
      certificateRow({}, { profile_issuer_id: null }),
    );
    assert.equal(state.state, "not-configured");
  });

  it("retains disabled intent before validating incomplete native settings", () => {
    assert.equal(
      deriveCertificateRenewalState(
        certificateRow({ target: null }, { profile_status: "disabled" }),
      ).state,
      "disabled",
    );
  });

  it("requires recorded expiration even for a complete native profile", () => {
    const state = deriveCertificateRenewalState(
      certificateRow({}, { not_after: null }),
    );
    assert.equal(state.state, "not-configured");
    assert.match(state.detail, /no expiry date/);
  });

  it("keeps ACME validation when the issuer is not native AD CS", () => {
    const state = deriveCertificateRenewalState(
      certificateRow({}, { profile_issuer_kind: "acme" }),
    );
    assert.equal(state.state, "not-configured");
    assert.match(state.detail, /renewalProfile.ca/);
  });

  it("retains issuer metadata when optional schedule enrichment fails", async () => {
    let calls = 0;
    const loaded = await loadCertificateRenewalRows({
      workspaceId: "workspace",
      certificateIds: [certificateRow().id],
      db: {
        async query(sql) {
          calls += 1;
          assert.match(sql, /cp\.issuer_id AS profile_issuer_id/);
          assert.match(sql, /ci\.kind AS profile_issuer_kind/);
          if (calls === 1) throw new Error("schedule enrichment unavailable");
          return { rows: [certificateRow()] };
        },
      },
    });
    assert.equal(calls, 2);
    assert.equal(loaded.scheduleFacts, false);
    assert.equal(deriveCertificateRenewalState(loaded.rows[0]).state, "auto");
  });
});
