"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { describeRoles, tokenFileConfig, assertRoleMounts } = require("./azure-isolated-role.cjs");

const identity = {
  vaultHost: "ttkv" + "a".repeat(20) + ".vault.azure.net",
  issuerClientId: "11111111-1111-1111-1111-111111111111",
  consumerClientId: "22222222-2222-2222-2222-222222222222",
};
const groupId = "33333333-3333-3333-3333-333333333333";
const workspaceId = "44444444-4444-4444-4444-444444444444";

test("Azure container descriptors select one owned role and one fixed token sink", () => {
  const descriptors = describeRoles(identity);
  const issuer = { descriptor: descriptors.issuer, role: "issuer", name: "issuer",
    groupId, workspaceId, scope: { keyAlgorithm: "ec" } };
  assert.deepEqual(tokenFileConfig(issuer).customer.auth, { type: "token-file", tokenFile: "/run/tt-issuer/token.json" });
  assert.deepEqual(tokenFileConfig({ ...issuer, descriptor: descriptors.consumer, role: "consumer", name: "nginx" }).customer.auth,
    { type: "token-file", tokenFile: "/run/tt-consumer/token.json" });
  assert.throws(() => describeRoles({ ...identity, consumerClientId: identity.issuerClientId }), /separate app/);
  assert.throws(() => describeRoles({ ...identity, vaultHost: "unowned.vault.azure.net" }));
  assert.throws(() => tokenFileConfig({ ...issuer, name: "nginx" }), /outside/);
  assert.throws(() => tokenFileConfig({ ...issuer, descriptor: descriptors.consumer }), /swapped/);
  assert.throws(() => tokenFileConfig({ ...issuer, descriptor: { ...descriptors.issuer, tokenFile: "/run/tt-consumer/token.json" } }));
});

test("an inspected role cannot mount another role, its credentials or a writable sink", () => {
  const project = "tt-wildcard-ux-qual-owned", image = "sha256:" + "a".repeat(64);
  const issuerSink = "/owned/issuer", consumerSink = "/owned/consumer", certificateRoot = "/owned/private";
  const dnsCredential = "/owned/ca/dns.json";
  const options = { role: "issuer", project, image, issuerSink, consumerSink, certificateRoot, dnsCredential };
  const record = {
    Image: image,
    HostConfig: { Privileged: false, PidMode: "", NetworkMode: project + "_default" },
    NetworkSettings: { Networks: { [project + "_default"]: {}, [project + "_operator-ca"]: {} } },
    Config: { Labels: { "com.docker.compose.project": project, "com.docker.compose.service": "issuer" } },
    Mounts: [{ Type: "bind", Source: issuerSink, Destination: "/run/tt-issuer", RW: false }],
  };
  assert.doesNotThrow(() => assertRoleMounts({ ...options, record }));
  for (const source of [consumerSink, certificateRoot, "/owned", "/"]) {
    const Mounts = [...record.Mounts, { Type: "bind", Source: source, Destination: "/alternate", RW: false }];
    assert.throws(() => assertRoleMounts({ ...options, record: { ...record, Mounts } }), /protected host mount/);
  }
  assert.throws(() => assertRoleMounts({ ...options, record: { ...record,
    Mounts: [...record.Mounts, { Type: "bind", Source: "/elsewhere", Destination: "/run", RW: false }],
  } }), /overlaps/);
  assert.throws(() => assertRoleMounts({ ...options, record: { ...record,
    Mounts: [{ ...record.Mounts[0], RW: true }],
  } }), /read-only/);
  assert.throws(() => assertRoleMounts({ ...options, record: { ...record, Image: "sha256:" + "b".repeat(64) } }), /fixture image/);
  assert.throws(() => assertRoleMounts({ ...options, record: { ...record,
    HostConfig: { ...record.HostConfig, Privileged: true },
  } }), /privileged/);
  const consumer = {
    ...record,
    Config: { Labels: { "com.docker.compose.project": project, "com.docker.compose.service": "consumer" } },
    Mounts: [{ Type: "bind", Source: consumerSink, Destination: "/run/tt-consumer", RW: false }],
    NetworkSettings: { Networks: { [project + "_default"]: {} } },
  };
  assert.doesNotThrow(() => assertRoleMounts({ ...options, role: "consumer", record: consumer }));
  assert.throws(() => assertRoleMounts({ ...options, role: "consumer", record: { ...consumer,
    Mounts: [...consumer.Mounts, { Type: "bind", Source: "/owned/ca", Destination: "/ca", RW: false }],
  } }), /protected host mount/);
  assert.throws(() => assertRoleMounts({ ...options, role: "consumer", record: { ...consumer,
    NetworkSettings: record.NetworkSettings,
  } }), /role networks/);
});
