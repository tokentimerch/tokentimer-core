"use strict";

const assert = require("node:assert/strict");
const { cleanupCapability } = require("../packages/contracts/certops/material-cleanup.cjs");

const stagingCapability = "material-consumer-staging-v1";
const distribution = Object.freeze({
  directory: "certops-linux-release-distribution",
  buildMode: "release-distribution-candidate",
  capabilities: Object.freeze([
    cleanupCapability("vault-kv2"), cleanupCapability("openbao-kv2"), stagingCapability,
  ]),
});

function linuxCleanupCase(provider = "vault-kv2", staging = false) {
  assert.ok(provider === "vault-kv2" || provider === "openbao-kv2", "Unsupported native Linux cleanup provider");
  const openbao = provider === "openbao-kv2";
  const store = openbao ? "openbao" : "vault";
  if (staging) {
    const scope = openbao ? "openbao-staging" : "staging";
    return {
      provider, store, staging: true, capability: stagingCapability,
      suite: `linux-${scope}-restart`, testName: `installed Linux ${openbao ? "OpenBao " : ""}staging survives restart outside activation`,
      directory: `certops-linux-${scope}`, buildMode: `linux-${scope}-candidate`,
      proofField: "nativeLinuxStagingRestart",
    };
  }
  return {
    provider, store, staging: false, capability: cleanupCapability(provider),
    suite: `linux-${store}-cleanup-restart`,
    testName: `installed Linux ${openbao ? "OpenBao" : "Vault"} cleanup resumes after lost delete response`,
    directory: `certops-linux-${store}-cleanup`,
    buildMode: `linux-${store}-cleanup-candidate`,
    proofField: openbao ? "nativeOpenBaoCleanupRestart" : "nativeVaultCleanupRestart",
  };
}

module.exports = linuxCleanupCase;
module.exports.distribution = distribution;
