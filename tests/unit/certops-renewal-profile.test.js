"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  RENEWAL_PROFILE_SCHEMA_VERSION,
  buildRenewalJobPayload,
  resolveRenewalProfileSnapshot,
  validateRenewalProfile,
  windowsIisTargetAuditFields,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalProfile.js",
  ),
);

function validProfile(overrides = {}) {
  return {
    schemaVersion: RENEWAL_PROFILE_SCHEMA_VERSION,
    profileId: "profile-1",
    profileName: "web-tls",
    sanPolicy: {
      mode: "exact",
      sans: ["app.example.com", "www.example.com"],
      allowWildcards: false,
    },
    keyAlgorithm: "rsa",
    keySize: 2048,
    keyRotationPolicy: { rotateOnRenew: true },
    preferredChain: "ISRG Root X1",
    ca: {
      endpoint: "https://acme-v02.api.letsencrypt.org/directory",
      accountRef: "le-prod",
      eabRef: null,
    },
    acme: {
      kind: "certbot",
      commandRef: "renew.web",
    },
    dns: {
      provider: "cloudflare",
      zone: "example.com",
    },
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

describe("certops renewal profile", () => {
  it("validates a complete schemaVersion 1 profile", () => {
    const profile = validateRenewalProfile(validProfile());
    assert.equal(profile.schemaVersion, 1);
    assert.equal(profile.acme.commandRef, "renew.web");
    assert.equal(profile.dns.provider, "cloudflare");
    assert.deepEqual(profile.sanPolicy.sans, [
      "app.example.com",
      "www.example.com",
    ]);
  });

  it("rejects incomplete profiles", () => {
    assert.throws(
      () => validateRenewalProfile({ schemaVersion: 1 }),
      (error) => error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE ||
        error?.code === "CERTOPS_RENEWAL_PROFILE_INVALID",
    );
    assert.throws(
      () =>
        validateRenewalProfile(
          validProfile({
            sanPolicy: { mode: "exact", sans: [], allowWildcards: false },
          }),
        ),
      (error) => error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  });

  it("accepts a windows-iis target with no certPath (store/binding-based deploy destination)", () => {
    const windowsTarget = {
      type: "windows-iis",
      reference: "iis-01/default-web-site",
      store: "My",
      binding: { site: "Default Web Site", port: 443, sniHost: "app.example.com" },
    };
    const profile = validateRenewalProfile(
      validProfile({
        deploymentTargets: [windowsTarget],
        target: windowsTarget,
      }),
    );
    assert.equal(profile.target.type, "windows-iis");
    assert.equal(profile.target.store, "My");
    assert.deepEqual(profile.target.binding, {
      site: "Default Web Site",
      port: 443,
      sniHost: "app.example.com",
    });
    assert.equal(
      "certPath" in profile.target,
      false,
      "a windows-iis target has no filesystem certPath",
    );
  });

  it("emits keyMode os-store-managed and target.store/binding onto the job payload for a windows-iis profile", () => {
    const windowsTarget = {
      type: "windows-iis",
      reference: "iis-01/default-web-site",
      store: "My",
      binding: { site: "Default Web Site", port: 443, sniHost: "app.example.com" },
      thumbprintSha1: "AA".repeat(20),
    };
    const sourceProfile = validProfile({
      deploymentTargets: [windowsTarget],
      target: windowsTarget,
    });
    const certificate = {
      id: "cert-windows-1",
      profile_id: "profile-1",
      profile_name: "web-tls",
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      key_mode: "os-store-managed",
      not_after: new Date("2026-08-01T00:00:00.000Z"),
      profile_public_metadata: { renewalProfile: sourceProfile },
    };

    const payload = buildRenewalJobPayload({ certificate });

    assert.equal(payload.keyMode, "os-store-managed");
    assert.equal(payload.target.type, "windows-iis");
    assert.equal(payload.target.store, "My");
    assert.deepEqual(payload.target.binding, {
      site: "Default Web Site",
      port: 443,
      sniHost: "app.example.com",
    });
    assert.equal(payload.target.thumbprintSha1, "AA".repeat(20));
    assert.equal(
      "certPath" in payload,
      false,
      "a windows-iis renew payload has no top-level certPath",
    );
    assert.equal(
      "keyPath" in payload,
      false,
      "a windows-iis renew payload has no top-level keyPath",
    );
    assert.equal(
      "chainPath" in payload,
      false,
      "a windows-iis renew payload has no top-level chainPath",
    );
  });

  it("rejects a windows-iis target missing store", () => {
    assert.throws(
      () =>
        validateRenewalProfile(
          validProfile({
            target: {
              type: "windows-iis",
              reference: "iis-01/default-web-site",
              binding: { site: "Default Web Site", port: 443 },
            },
          }),
        ),
      /target\.store/,
    );
  });

  it("rejects a windows-iis target missing binding", () => {
    assert.throws(
      () =>
        validateRenewalProfile(
          validProfile({
            target: {
              type: "windows-iis",
              reference: "iis-01/default-web-site",
              store: "My",
            },
          }),
        ),
      /target\.binding/,
    );
  });

  it("rejects a windows-iis binding with an out-of-range port", () => {
    assert.throws(
      () =>
        validateRenewalProfile(
          validProfile({
            target: {
              type: "windows-iis",
              reference: "iis-01/default-web-site",
              store: "My",
              binding: { site: "Default Web Site", port: 999999 },
            },
          }),
        ),
      /target\.binding\.port/,
    );
  });

  it("windowsIisTargetAuditFields names the store/binding for a windows-iis target", () => {
    const fields = windowsIisTargetAuditFields({
      type: "windows-iis",
      store: "My",
      binding: { site: "Default Web Site", port: 443, sniHost: "app.example.com" },
    });
    assert.deepEqual(fields, {
      targetType: "windows-iis",
      windowsStore: "My",
      windowsBindingSite: "Default Web Site",
      windowsBindingPort: 443,
      windowsBindingSniHost: "app.example.com",
    });
  });

  it("windowsIisTargetAuditFields returns an all-null shape for a non-windows target", () => {
    assert.deepEqual(windowsIisTargetAuditFields({ type: "endpoint" }), {
      targetType: "endpoint",
      windowsStore: null,
      windowsBindingSite: null,
      windowsBindingPort: null,
      windowsBindingSniHost: null,
    });
  });

  it("windowsIisTargetAuditFields tolerates a missing/malformed target without throwing", () => {
    assert.deepEqual(windowsIisTargetAuditFields(undefined), {
      targetType: null,
      windowsStore: null,
      windowsBindingSite: null,
      windowsBindingPort: null,
      windowsBindingSniHost: null,
    });
    assert.deepEqual(
      windowsIisTargetAuditFields({ type: "windows-iis", binding: "not-an-object" }),
      {
        targetType: "windows-iis",
        windowsStore: null,
        windowsBindingSite: null,
        windowsBindingPort: null,
        windowsBindingSniHost: null,
      },
    );
  });

  it("resolves a snapshot from certificate inventory + profile metadata", () => {
    const sourceProfile = validProfile();
    delete sourceProfile.keyRotationPolicy;
    sourceProfile.sanPolicy = {
      mode: "inherit",
      sans: ["ignored.example.com"],
      allowWildcards: false,
    };
    const certificate = {
      id: "cert-1",
      profile_id: "profile-1",
      profile_name: "web-tls",
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      key_mode: "agent-local",
      not_after: new Date("2026-08-01T00:00:00.000Z"),
      profile_public_metadata: {
        renewalProfile: sourceProfile,
      },
    };

    const snapshot = resolveRenewalProfileSnapshot(certificate);
    assert.equal(snapshot.profileId, "profile-1");
    assert.deepEqual(snapshot.sanPolicy.sans, ["app.example.com"]);
    assert.equal(snapshot.keyRotationPolicy.rotateOnRenew, true);

    const payload = buildRenewalJobPayload({ certificate });
    assert.equal(payload.certificateId, "cert-1");
    assert.equal(payload.commandRef, "renew.web");
    assert.equal(payload.caEndpoint, sourceProfile.ca.endpoint);
    assert.equal(payload.dnsProvider, "cloudflare");
    assert.equal(payload.dnsZone, "example.com");
    assert.equal(payload.certPath, "/etc/ssl/certs/app.pem");
    assert.equal(payload.keyRotation, true);
    assert.equal(payload.keyAlgorithm, "rsa");
    assert.equal(payload.keySize, 2048);
    assert.deepEqual(payload.sans, ["app.example.com"]);
    assert.ok(Array.isArray(payload.deploymentTargets));
    assert.ok(payload.deploymentTargets.length >= 1);
    assert.ok(payload.renewalProfile);
  });

  it("flattens per-target keyPath/mode/owner/backup fields onto the job payload", () => {
    const sourceProfile = validProfile({
      deploymentTargets: [
        {
          type: "endpoint",
          reference: "host/web",
          certPath: "/etc/ssl/certs/app.pem",
          keyPath: "/etc/ssl/private/app.key",
          chainPath: "/etc/ssl/certs/app-chain.pem",
          certMode: "0644",
          keyMode: "0600",
          chainMode: "0644",
          owner: "www-data",
          group: "ssl-cert",
          backupDir: "/var/backups/certs",
          backupRetentionCount: 3,
          reloadService: "nginx",
        },
      ],
      target: {
        type: "endpoint",
        reference: "host/web",
        certPath: "/etc/ssl/certs/app.pem",
        keyPath: "/etc/ssl/private/app.key",
        chainPath: "/etc/ssl/certs/app-chain.pem",
      },
    });
    const profile = validateRenewalProfile(sourceProfile);
    assert.equal(profile.deploymentTargets[0].keyPath, "/etc/ssl/private/app.key");
    assert.equal(profile.deploymentTargets[0].certMode, 0o644);
    assert.equal(profile.deploymentTargets[0].keyMode, 0o600);
    assert.equal(profile.deploymentTargets[0].owner, "www-data");
    assert.equal(profile.deploymentTargets[0].backupRetentionCount, 3);

    const certificate = {
      id: "cert-2",
      profile_id: "profile-1",
      profile_name: "web-tls",
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      key_mode: "agent-local",
      not_after: new Date("2026-08-01T00:00:00.000Z"),
      profile_public_metadata: { renewalProfile: sourceProfile },
    };
    const payload = buildRenewalJobPayload({ certificate });
    assert.equal(payload.keyPath, "/etc/ssl/private/app.key");
    assert.equal(payload.chainPath, "/etc/ssl/certs/app-chain.pem");
    assert.equal(payload.deploymentTargets[0].keyPath, "/etc/ssl/private/app.key");
    assert.equal(payload.deploymentTargets[0].owner, "www-data");
    assert.equal(payload.deploymentTargets[0].backupDir, "/var/backups/certs");
  });

  it("rejects world-writable file modes on deployment targets", () => {
    assert.throws(
      () =>
        validateRenewalProfile(
          validProfile({
            deploymentTargets: [
              {
                type: "endpoint",
                reference: "host/web",
                certPath: "/etc/ssl/certs/app.pem",
                certMode: "0666",
                reloadService: "nginx",
              },
            ],
          }),
        ),
      /world-writable/,
    );
  });

  it("refuses certificates without a linked renewal profile", () => {
    assert.throws(
      () =>
        resolveRenewalProfileSnapshot({
          id: "cert-1",
          profile_id: null,
        }),
      (error) => error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  });
});
