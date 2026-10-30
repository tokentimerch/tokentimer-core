"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  validate,
} = require("../../packages/contracts/certops/validate-material-distribution.cjs");
const {
  PROVIDERS,
  providerCapability,
  versionOf,
  validProviderVersion,
  providerOf,
} = require("../../packages/contracts/certops/material-provider.cjs");
const {
  evaluateAgentJobEligibility,
} = require("../../apps/api/services/certops/agentJobEligibility");
const id = "11111111-1111-4111-8111-111111111111";
test("cleanup operation identity resolves independently of the pinned provider", () => {
  assert.equal(providerOf({ type: "vault-kv2-soft-delete" }), "vault-kv2");
  assert.equal(providerOf({ operation: "vault-kv2-soft-delete", provider: "vault-kv2" }), "vault-kv2");
  assert.equal(providerOf({ operation: "soft-delete", provider: "vault-kv2" }), "vault-kv2");
  for (const provider of ["openbao-kv2", "azure-key-vault", "unsupported"]) {
    assert.equal(providerOf({ type: "vault-kv2-soft-delete", provider }), null);
    assert.equal(providerOf({ operation: "soft-delete", provider }), null);
  }
  assert.equal(providerOf({ type: "openbao-kv2", provider: "vault-kv2" }), null);
  assert.equal(providerOf({ type: "not-a-provider" }), "not-a-provider");
});
const receipt = {
  schemaVersion: 1,
  workspaceId: id,
  groupId: id,
  materialVersionId: id,
  materialStoreRef: "customer",
  providerVersion: 1,
  fingerprintSha256: "a".repeat(64),
  validTo: "2027-01-01T00:00:00.000Z",
};
test("material provider contracts preserve numeric Vault receipts and reject cross-provider version confusion", () => {
  assert.equal(validate("publicationReceipt", receipt), true);
  for (const provider of PROVIDERS) {
    const value = {
      ...receipt,
      provider,
      providerVersion: provider === "azure-key-vault" ? "f".repeat(32) : 1,
    };
    assert.equal(validate("publicationReceipt", value), true);
    assert.equal(validProviderVersion(provider, value.providerVersion), true);
    assert.equal(
      validate("publicationReceipt", {
        ...value,
        providerVersion: provider === "azure-key-vault" ? 1 : "f".repeat(32),
      }),
      false,
    );
    for (const field of [
      "privateKeyPem",
      "password",
      "accessToken",
      "address",
      "tokenFile",
    ])
      assert.equal(
        validate("publicationReceipt", {
          ...value,
          [field]: "must-not-cross-the-boundary",
        }),
        false,
      );
  }
  assert.equal(
    validate("publicationReceipt", {
      ...receipt,
      providerVersion: "f".repeat(32),
    }),
    false,
  );
  assert.equal(versionOf({ provider_version: 1 }), 1);
  assert.equal(
    versionOf({ provider_version: null, provider_version_ref: "f".repeat(32) }),
    "f".repeat(32),
  );
});
test("dispatch requires fresh provider and Windows connector capabilities before claim", () => {
  for (const provider of PROVIDERS)
    for (const platform of ["linux", "win32"]) {
      const now = Date.now();
      const capabilities = [
        providerCapability(provider),
        "deploy-from-store-v1",
        "evidence-claim-binding-v1",
        ...(platform === "win32"
          ? [
              "windows-material-iis-v1",
              "windows-cert-store-v1",
              "iis-binding-v1",
            ]
          : []),
      ];
      const agent = {
        id,
        agentId: id,
        platform,
        status: "active",
        supportedOperations: ["deploy-from-store"],
        targetSelectors: [id],
        declaredCapabilities: capabilities,
        capabilitiesUpdatedAt: new Date(now).toISOString(),
        dnsProviders: [],
        commandProfiles: [],
      };
      const job = {
        operation: "deploy-from-store",
        assignedAgentId: id,
        payload: {
          keyMode: "vault-managed",
          target: { type: "endpoint", reference: id },
          materialDeployment: { provider },
        },
      };
      const options = {
        agent,
        job,
        compatibility: { compatibilityState: "compatible" },
        now,
        env: {},
      };
      assert.equal(
        evaluateAgentJobEligibility(options).eligible,
        true,
        `${provider}/${platform}`,
      );
      agent.declaredCapabilities = capabilities.filter(
        (capability) => capability !== providerCapability(provider),
      );
      assert.equal(evaluateAgentJobEligibility(options).eligible, false);
      agent.declaredCapabilities = capabilities;
      agent.capabilitiesUpdatedAt = "2020-01-01T00:00:00.000Z";
      assert.equal(evaluateAgentJobEligibility(options).eligible, false);
      if (platform === "win32") {
        agent.capabilitiesUpdatedAt = new Date(now).toISOString();
        agent.declaredCapabilities = capabilities.filter(
          (capability) => capability !== "windows-material-iis-v1",
        );
        assert.equal(evaluateAgentJobEligibility(options).eligible, false);
      }
    }
});
