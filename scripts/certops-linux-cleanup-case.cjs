"use strict";

const assert = require("node:assert/strict");
const { cleanupCapability } = require("../packages/contracts/certops/material-cleanup.cjs");

module.exports = function linuxCleanupCase(provider = "vault-kv2", staging = false) {
  if (staging) {
    assert.equal(provider, "vault-kv2");
    return {
      provider, store: "vault", staging: true, capability: "material-consumer-staging-v1",
      suite: "linux-staging-restart", testName: "installed Linux staging survives restart outside activation",
      directory: "certops-linux-staging", buildMode: "linux-staging-candidate", proofField: "nativeLinuxStagingRestart",
    };
  }
  assert.ok(provider === "vault-kv2" || provider === "openbao-kv2", "Unsupported native Linux cleanup provider");
  const openbao = provider === "openbao-kv2";
  const store = openbao ? "openbao" : "vault";
  return {
    provider, store, staging: false, capability: cleanupCapability(provider),
    suite: `linux-${store}-cleanup-restart`,
    testName: `installed Linux ${openbao ? "OpenBao" : "Vault"} cleanup resumes after lost delete response`,
    directory: `certops-linux-${store}-cleanup`,
    buildMode: `linux-${store}-cleanup-candidate`,
    proofField: openbao ? "nativeOpenBaoCleanupRestart" : "nativeVaultCleanupRestart",
  };
};
