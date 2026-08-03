"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);
const { RENEWAL_PROFILE_SCHEMA_VERSION } = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalProfile.js",
  ),
);

const { deriveCertificateRenewalState, withRenewalState } = certOpsRouter._test;

function completeRenewalProfile(overrides = {}) {
  return {
    schemaVersion: RENEWAL_PROFILE_SCHEMA_VERSION,
    profileId: "profile-1",
    profileName: "web-tls",
    sanPolicy: {
      mode: "exact",
      sans: ["app.example.com"],
      allowWildcards: false,
    },
    keyAlgorithm: "rsa",
    keySize: 2048,
    keyRotationPolicy: { rotateOnRenew: true },
    ca: {
      endpoint: "https://acme-v02.api.letsencrypt.org/directory",
      accountRef: "le-prod",
      eabRef: null,
    },
    acme: { kind: "certbot", commandRef: "renew.web" },
    dns: { provider: "cloudflare", zone: "example.com" },
    deploymentTargets: [
      {
        type: "endpoint",
        reference: "host/web",
        certPath: "/etc/ssl/certs/app.pem",
        reloadService: "nginx",
      },
    ],
    target: {
      type: "endpoint",
      reference: "host/web",
      certPath: "/etc/ssl/certs/app.pem",
    },
    verification: {
      host: "app.example.com",
      port: 443,
      requireMatch: true,
    },
    ...overrides,
  };
}

function certificateRow(overrides = {}) {
  return {
    id: "aaaaaaaa-0000-4000-8000-000000000001",
    status: "active",
    key_mode: "agent-local",
    not_after: new Date("2026-09-30T00:00:00.000Z"),
    common_name: "app.example.com",
    subject_alt_names: ["app.example.com"],
    profile_id: "profile-1",
    profile_name: "web-tls",
    profile_public_metadata: { renewalProfile: completeRenewalProfile() },
    profile_renew_before_days: null,
    ...overrides,
  };
}

describe("CertOps certificate renewal-state derivation", () => {
  it("reports auto with the scheduler's own renewal window for a complete profile", () => {
    const renewal = deriveCertificateRenewalState(certificateRow(), {
      env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
    });

    assert.equal(renewal.state, "auto");
    assert.equal(renewal.renewBeforeDays, 30);
    assert.equal(renewal.renewsFrom, "2026-08-31T00:00:00.000Z");
    assert.equal(renewal.profileId, "profile-1");
    assert.equal(renewal.profileName, "web-tls");
    assert.equal(renewal.keyMode, "agent-local");
  });

  it("prefers the per-profile renew_before_days override over the deployment default", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({ profile_renew_before_days: 45 }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "auto");
    assert.equal(renewal.renewBeforeDays, 45);
    assert.equal(renewal.renewsFrom, "2026-08-16T00:00:00.000Z");
  });

  it("ignores a non-positive profile override and falls back to the deployment threshold", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({ profile_renew_before_days: 0 }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "21" } },
    );

    assert.equal(renewal.state, "auto");
    assert.equal(renewal.renewBeforeDays, 21);
  });

  it("reports not-configured when an agent-deployable certificate has no linked profile", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({
        profile_id: null,
        profile_name: null,
        profile_public_metadata: null,
      }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "not-configured");
    assert.equal(renewal.profileId, null);
    assert.equal(renewal.renewsFrom, null);
    assert.equal(renewal.renewBeforeDays, 30);
    assert.match(renewal.detail, /will not renew automatically/i);
  });

  it("reports not-configured when the linked profile carries an incomplete renewalProfile", () => {
    const incomplete = completeRenewalProfile();
    delete incomplete.acme;

    const renewal = deriveCertificateRenewalState(
      certificateRow({
        profile_public_metadata: { renewalProfile: incomplete },
      }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "not-configured");
    assert.equal(renewal.renewsFrom, null);
    assert.match(renewal.detail, /will not renew automatically/i);
  });

  it("reports not-configured when a complete profile has no recorded expiry to schedule against", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({ not_after: null }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "not-configured");
    assert.equal(renewal.renewsFrom, null);
    assert.match(renewal.detail, /no expiry date is recorded/i);
  });

  it("reports not-eligible for key custody no agent can write back to", () => {
    for (const keyMode of ["vault-managed", "external-unknown", null]) {
      const renewal = deriveCertificateRenewalState(
        certificateRow({ key_mode: keyMode }),
        { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
      );

      assert.equal(renewal.state, "not-eligible", `key_mode=${keyMode}`);
      assert.equal(renewal.renewsFrom, null);
      assert.match(renewal.detail, /monitored only/i);
    }
  });

  it("treats proxy-agent-local custody as renewable", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({ key_mode: "proxy-agent-local" }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "auto");
  });

  it("treats os-store-managed custody as renewable now that the predicate recognizes it", () => {
    // os-store-managed used to sit in the "no agent can write back to" bucket
    // above. The shared custody predicate (jobs.isAgentDeployableKeyMode) now
    // recognizes it as agent-deployable, since the agent (not an external
    // appliance/HSM/vault) is what will rotate a Windows cert store entry.
    // The real store/site/binding deploy path is not wired yet (Windows
    // execution lands separately); this only asserts the eligibility signal
    // agrees with the shared predicate.
    const renewal = deriveCertificateRenewalState(
      certificateRow({ key_mode: "os-store-managed" }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "auto");
  });

  it("reports disabled when the profile switched auto-renewal off", () => {
    for (const profileStatus of ["disabled", "archived"]) {
      const renewal = deriveCertificateRenewalState(
        certificateRow({ profile_status: profileStatus }),
        { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
      );

      assert.equal(renewal.state, "disabled", `status=${profileStatus}`);
      assert.equal(renewal.renewBeforeDays, 30);
      assert.match(renewal.detail, /switched off/i);
    }
  });

  it("reports an active profile as auto rather than disabled", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({ profile_status: "active" }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "auto");
  });

  it("defaults workspacePaused to false and includes it on every state", () => {
    for (const overrides of [
      {},
      { profile_status: "disabled" },
      { profile_id: null, profile_name: null, profile_public_metadata: null },
      { key_mode: "os-store-managed" },
      { status: "revoked" },
    ]) {
      const renewal = deriveCertificateRenewalState(certificateRow(overrides), {
        env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
      });
      assert.equal(renewal.workspacePaused, false);
    }
  });

  it("flags workspacePaused without changing the auto state itself", () => {
    // The profile is genuinely switched on; a paused workspace is a
    // separate, orthogonal fact the badge must be able to show alongside
    // it, not instead of it (13.12 finding, 2026-07-27).
    const renewal = deriveCertificateRenewalState(certificateRow(), {
      env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
      workspacePaused: true,
    });

    assert.equal(renewal.state, "auto");
    assert.equal(renewal.workspacePaused, true);
  });

  it("prefers disabled over not-configured so a switched-off certificate is not called broken", () => {
    // Deliberate intent must win over profile completeness: telling the
    // operator to fix a profile they themselves switched off would send them
    // chasing a non-problem.
    const renewal = deriveCertificateRenewalState(
      certificateRow({
        profile_status: "disabled",
        profile_public_metadata: {},
      }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "disabled");
  });

  it("keeps not-eligible ahead of disabled for custody no agent can renew", () => {
    // Key custody is a hard impossibility; the off switch is a choice. Reporting
    // 'disabled' here would imply re-enabling the profile is enough to make it
    // renew, which is false.
    const renewal = deriveCertificateRenewalState(
      certificateRow({
        key_mode: "external-unknown",
        profile_status: "disabled",
      }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "not-eligible");
  });

  it("does not report disabled for a certificate with no linked profile", () => {
    // profile_status is NULL when the LEFT JOIN matched nothing, which is the
    // incomplete-profile case, mirroring the scheduler's IS NULL branch.
    const renewal = deriveCertificateRenewalState(
      certificateRow({
        profile_id: null,
        profile_status: null,
        profile_public_metadata: null,
      }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "not-configured");
  });

  it("reports not-applicable for lifecycle states the scheduler refuses", () => {
    for (const status of ["revoked", "decommissioned", "provisioning"]) {
      const renewal = deriveCertificateRenewalState(
        certificateRow({ status }),
        { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
      );

      assert.equal(renewal.state, "not-applicable", `status=${status}`);
      assert.equal(renewal.renewsFrom, null);
    }
  });

  it("ranks lifecycle above custody so a revoked observed-only cert is not flagged", () => {
    const renewal = deriveCertificateRenewalState(
      certificateRow({ status: "revoked", key_mode: "os-store-managed" }),
      { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
    );

    assert.equal(renewal.state, "not-applicable");
  });

  it("uses the shared custody predicate rather than its own key-mode list", () => {
    // This route used to keep a hand-copied AGENT_DEPLOYABLE_KEY_MODES set with
    // a "mirrors jobs.js" comment. A comment is not a constraint: the copy is
    // what lets the badge promise "auto" for a certificate the scheduler and
    // job creation both refuse. Assert agreement across every schema-permitted
    // custody mode so a future mode added in one place fails here.
    const { isAgentDeployableKeyMode } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    for (const keyMode of [
      null,
      "agent-local",
      "proxy-agent-local",
      "external-unknown",
      "cert-manager-managed",
      "appliance-managed",
      "hsm-managed",
      "vault-managed",
      "os-store-managed",
    ]) {
      const renewal = deriveCertificateRenewalState(
        certificateRow({ key_mode: keyMode }),
        { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" } },
      );
      assert.equal(
        renewal.state !== "not-eligible",
        isAgentDeployableKeyMode(keyMode),
        `renewal state for key_mode ${String(keyMode)} disagrees with job creation`,
      );
    }
  });
});

describe("CertOps certificate renewal-state projection", () => {
  it("adds renewal to each inventory record without touching existing fields", async () => {
    const queries = [];
    const db = {
      async query(sql, params) {
        queries.push({ sql, params });
        if (/FROM workspaces/.test(sql)) {
          return { rows: [{ certops_paused: false }] };
        }
        return {
          rows: [
            certificateRow({ id: "cert-auto" }),
            certificateRow({
              id: "cert-observed",
              key_mode: "vault-managed",
            }),
          ],
        };
      },
    };

    const items = await withRenewalState({
      db,
      env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
      workspaceId: "workspace-1",
      certificates: [
        { id: "cert-auto", commonName: "app.example.com", status: "active" },
        {
          id: "cert-observed",
          commonName: "obs.example.com",
          status: "active",
        },
      ],
    });

    assert.equal(queries.length, 3);
    assert.match(queries[0].sql, /LEFT JOIN certificate_profiles/);
    assert.deepEqual(queries[0].params, [
      "workspace-1",
      ["cert-auto", "cert-observed"],
    ]);
    assert.match(queries[1].sql, /FROM certops_outbox/);
    assert.deepEqual(queries[1].params, [
      "workspace-1",
      "profile_derivation_requested",
      ["cert-auto", "cert-observed"],
    ]);
    assert.match(queries[2].sql, /SELECT certops_paused FROM workspaces/);
    assert.deepEqual(queries[2].params, ["workspace-1"]);

    assert.equal(items[0].commonName, "app.example.com");
    assert.equal(items[0].renewal.state, "auto");
    assert.equal(items[0].renewal.workspacePaused, false);
    assert.ok(items[0].renewalSetup);
    assert.equal(items[1].commonName, "obs.example.com");
    assert.equal(items[1].renewal.state, "not-eligible");
    assert.ok(items[1].renewalSetup);
  });

  it("flags workspacePaused on an otherwise-auto certificate when the workspace kill switch is paused", async () => {
    const db = {
      async query(sql) {
        if (/FROM workspaces/.test(sql)) {
          return { rows: [{ certops_paused: true }] };
        }
        return { rows: [certificateRow({ id: "cert-auto" })] };
      },
    };

    const [item] = await withRenewalState({
      db,
      env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
      workspaceId: "workspace-1",
      certificates: [{ id: "cert-auto", status: "active" }],
    });

    // State itself must not change: the profile genuinely is switched on,
    // and "will this workspace act" is a separate fact from "is this
    // profile switched on" (13.12).
    assert.equal(item.renewal.state, "auto");
    assert.equal(item.renewal.workspacePaused, true);
  });

  it("does not fail the request when the workspace-pause read errors", async () => {
    const db = {
      async query(sql) {
        if (/FROM workspaces/.test(sql)) {
          throw new Error("boom");
        }
        return { rows: [certificateRow({ id: "cert-auto" })] };
      },
    };

    const [item] = await withRenewalState({
      db,
      env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
      workspaceId: "workspace-1",
      certificates: [{ id: "cert-auto", status: "active" }],
    });

    assert.equal(item.renewal.state, "auto");
    assert.equal(item.renewal.workspacePaused, false);
  });

  it("does not query when there is nothing to enrich", async () => {
    let called = false;
    const db = {
      async query() {
        called = true;
        return { rows: [] };
      },
    };

    assert.deepEqual(
      await withRenewalState({
        db,
        workspaceId: "workspace-1",
        certificates: [],
      }),
      [],
    );
    assert.equal(called, false);
  });

  it("degrades to a non-auto state when the renewal join returns no row", async () => {
    const db = {
      async query() {
        return { rows: [] };
      },
    };

    const [item] = await withRenewalState({
      db,
      env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "30" },
      workspaceId: "workspace-1",
      certificates: [
        {
          id: "cert-missing",
          status: "active",
          keyMode: "agent-local",
          notAfter: "2026-09-30T00:00:00.000Z",
        },
      ],
    });

    assert.equal(item.renewal.state, "not-configured");
  });
});
