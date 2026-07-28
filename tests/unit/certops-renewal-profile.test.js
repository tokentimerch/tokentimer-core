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
