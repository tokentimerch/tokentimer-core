"use strict";
const assert = require("node:assert/strict");
const path = require("node:path");

const VAULT_HOST = /^ttkv[a-f0-9]{20}\.vault\.azure\.net$/;
const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const TOKEN_FILES = Object.freeze({ issuer: "/run/tt-issuer/token.json", consumer: "/run/tt-consumer/token.json" });
const AGENTS = Object.freeze({ issuer: ["issuer"], consumer: ["nginx", "haproxy"] });

function describeRoles({ vaultHost, issuerClientId, consumerClientId }) {
  assert.match(vaultHost || "", VAULT_HOST);
  assert.match(issuerClientId || "", ID);
  assert.match(consumerClientId || "", ID);
  assert.notEqual(issuerClientId, consumerClientId, "Azure lab roles require separate app registrations");
  return {
    issuer: { role: "issuer", vaultHost, clientId: issuerClientId },
    consumer: { role: "consumer", vaultHost, clientId: consumerClientId },
  };
}

function tokenFileConfig({ descriptor, role, name, workspaceId, groupId, scope }) {
  assert.ok(Object.hasOwn(AGENTS, role) && AGENTS[role].includes(name), "agent is outside its committed lab role");
  assert.deepEqual(Object.keys(descriptor).sort(), ["clientId", "role", "vaultHost"]);
  assert.equal(descriptor.role, role, "swapped Azure role descriptor refused");
  assert.match(descriptor.vaultHost || "", VAULT_HOST);
  for (const id of [descriptor.clientId, workspaceId, groupId]) assert.match(id || "", ID);
  return {
    customer: {
      provider: "azure-key-vault",
      address: "https://" + descriptor.vaultHost,
      auth: { type: "token-file", tokenFile: TOKEN_FILES[role] },
      timeoutMs: 10000,
      groups: { [groupId]: { ...scope, workspaceId } },
    },
  };
}

const within = (root, child) => root === child || root === "/" || child.startsWith(root + "/");
function assertRoleMounts({ role, record, project, image, issuerSink, consumerSink, certificateRoot, dnsCredential }) {
  assert.ok(Object.hasOwn(TOKEN_FILES, role));
  assert.equal(record.Config?.Labels?.["com.docker.compose.project"], project);
  assert.equal(record.Config?.Labels?.["com.docker.compose.service"], role);
  assert.equal(record.Image, image, "role container is not from the inspected fixture image");
  assert.equal(record.HostConfig?.Privileged, false, "privileged role container refused");
  assert.ok(!record.HostConfig.PidMode && record.HostConfig.NetworkMode !== "host",
    "role container requires its own process and network namespaces");
  const networks = [project + "_default"];
  if (role === "issuer") networks.push(project + "_operator-ca");
  assert.deepEqual(Object.keys(record.NetworkSettings?.Networks || {}).sort(), networks,
    "role networks differ from the owned lab plan");
  assert.ok(Array.isArray(record.Mounts));
  const own = role === "issuer" ? issuerSink : consumerSink;
  const opposite = role === "issuer" ? consumerSink : issuerSink;
  assert.equal(new Set([issuerSink, consumerSink, certificateRoot]).size, 3);
  const ownTarget = path.posix.dirname(TOKEN_FILES[role]);
  const foreignTarget = path.posix.dirname(TOKEN_FILES[role === "issuer" ? "consumer" : "issuer"]);
  assert.ok(path.posix.isAbsolute(dnsCredential));
  const protectedPaths = role === "consumer" ? [opposite, certificateRoot, dnsCredential] : [opposite, certificateRoot];
  let sinks = 0;
  for (const mount of record.Mounts) {
    for (const location of [mount.Source, mount.Destination])
      assert.ok(path.posix.isAbsolute(location) && path.posix.normalize(location) === location, "unresolved role mount");
    if (mount.Destination === ownTarget) {
      sinks++;
      assert.equal(mount.Type, "bind");
      assert.equal(mount.Source, own);
      assert.equal(mount.RW, false, "role token sink must be read-only");
    } else {
      assert.ok(!within(mount.Destination, ownTarget) && !within(ownTarget, mount.Destination),
        "a role mount overlaps its token sink");
    }
    assert.ok(!within(mount.Destination, foreignTarget) && !within(foreignTarget, mount.Destination),
      "opposite role token sink mount refused");
    for (const forbidden of protectedPaths)
      assert.ok(!within(mount.Source, forbidden) && !within(forbidden, mount.Source), "protected host mount refused");
  }
  assert.equal(sinks, 1, "exactly one role-local token sink mount required");
}

module.exports = { describeRoles, tokenFileConfig, assertRoleMounts };
