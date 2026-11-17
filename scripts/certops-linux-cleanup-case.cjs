"use strict";

const assert = require("node:assert/strict");
const { cleanupCapability } = require("../packages/contracts/certops/material-cleanup.cjs");

module.exports = function linuxCleanupCase(provider = "vault-kv2") {
  assert.ok(provider === "vault-kv2" || provider === "openbao-kv2", "Unsupported native Linux cleanup provider");
  const openbao = provider === "openbao-kv2";
  const store = openbao ? "openbao" : "vault";
  return {
    provider, store, capability: cleanupCapability(provider),
    suite: `linux-${store}-cleanup-restart`,
    testName: `installed Linux ${openbao ? "OpenBao" : "Vault"} cleanup resumes after lost delete response`,
    directory: `certops-linux-${store}-cleanup`,
    buildMode: `linux-${store}-cleanup-candidate`,
    proofField: openbao ? "nativeOpenBaoCleanupRestart" : "nativeVaultCleanupRestart",
  };
};
