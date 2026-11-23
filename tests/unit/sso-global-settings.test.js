"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert");

const {
  resolveBoolPolicy,
  resolveProviderSecurityConfig,
  resolveConfigSyncIntervalMs,
  resolveIdpHttpTimeoutMs,
  resolveAllowPrivateIdpUrls,
  resolveAllowedIdpCidrs,
  refreshGlobalSsoSettings,
} = require("../../apps/api/sso/sso-global-settings.js");

describe("sso-global-settings", () => {
  beforeEach(async () => {
    delete process.env.SSO_ALLOW_AUTO_LINK_LOCAL_ACCOUNTS;
    delete process.env.SSO_STRICT_MEMBERSHIP_SYNC;
    delete process.env.SSO_CONFIG_SYNC_INTERVAL_MS;
    delete process.env.SSO_IDP_HTTP_TIMEOUT_MS;
    delete process.env.SSO_ALLOW_PRIVATE_IDP_URLS;
    delete process.env.SSO_ALLOWED_IDP_CIDRS;
    await refreshGlobalSsoSettings(null);
  });

  it("resolveBoolPolicy prefers provider override over global", () => {
    assert.strictEqual(resolveBoolPolicy(true, false, false), true);
    assert.strictEqual(resolveBoolPolicy(false, true, false), false);
    assert.strictEqual(resolveBoolPolicy(undefined, true, false), true);
    assert.strictEqual(resolveBoolPolicy(undefined, undefined, false), false);
  });

  it("resolveProviderSecurityConfig inherits global defaults", () => {
    const resolved = resolveProviderSecurityConfig(
      { security: {} },
      {
        allow_auto_link_local_accounts: true,
        strict_membership_sync: true,
      },
    );
    assert.strictEqual(resolved.allowAutoLinkLocalAccounts, true);
    assert.strictEqual(resolved.strictMembershipSync, true);
  });

  it("resolveProviderSecurityConfig honors provider override", () => {
    const resolved = resolveProviderSecurityConfig(
      {
        security: {
          allow_auto_link_local_accounts: false,
          strict_membership_sync: true,
        },
      },
      {
        allow_auto_link_local_accounts: true,
        strict_membership_sync: false,
      },
    );
    assert.strictEqual(resolved.allowAutoLinkLocalAccounts, false);
    assert.strictEqual(resolved.strictMembershipSync, true);
  });

  it("resolveProviderSecurityConfig defaults strictMembershipSync to false when unset anywhere", () => {
    const resolved = resolveProviderSecurityConfig({ security: {} }, {});
    assert.strictEqual(resolved.strictMembershipSync, false);
  });

  it("uses persisted timeout settings unless the environment overrides them", async () => {
    const pool = {};
    await refreshGlobalSsoSettings(pool, {
      async getJsonSettingValue(receivedPool, column, key) {
        assert.strictEqual(receivedPool, pool);
        assert.strictEqual(column, "sso_global_settings");
        return key === "idp_http_timeout_ms" ? 35_000 : null;
      },
    });

    assert.strictEqual(resolveIdpHttpTimeoutMs({}), 35_000);
    assert.strictEqual(resolveIdpHttpTimeoutMs({ SSO_IDP_HTTP_TIMEOUT_MS: "23000" }), 23_000);
  });

  it("reads the current replica policy even while the ordinary settings cache is warm", async () => {
    const settings = require("../../apps/api/services/systemSettings.js");
    const { SSO_GLOBAL_ENV_MAP } = require("../../apps/api/sso/sso-global-settings-schema.js");
    settings.registerJsonColumn("sso_global_settings", { envMap: SSO_GLOBAL_ENV_MAP });
    let allowAutoLink = true;
    const pool = {
      async query() {
        return { rows: [{ sso_global_settings: { allow_auto_link_local_accounts: allowAutoLink } }] };
      },
    };
    assert.strictEqual(await settings.getJsonSettingValue(pool, "sso_global_settings", "allow_auto_link_local_accounts"), true);
    allowAutoLink = false;
    await refreshGlobalSsoSettings(pool, settings);
    assert.strictEqual(resolveProviderSecurityConfig({}).allowAutoLinkLocalAccounts, false);
    await assert.rejects(refreshGlobalSsoSettings({ query: async () => { throw new Error("database unavailable"); } }, settings));
    settings.invalidateCache();
  });

  it("env wins over defaults for runtime helpers", () => {
    process.env.SSO_CONFIG_SYNC_INTERVAL_MS = "120000";
    process.env.SSO_IDP_HTTP_TIMEOUT_MS = "15000";
    process.env.SSO_ALLOW_PRIVATE_IDP_URLS = "true";
    process.env.SSO_ALLOWED_IDP_CIDRS = "10.0.0.0/8";

    assert.strictEqual(resolveConfigSyncIntervalMs(process.env), 120_000);
    assert.strictEqual(resolveIdpHttpTimeoutMs(process.env), 15_000);
    assert.strictEqual(resolveAllowPrivateIdpUrls(process.env), true);
    assert.strictEqual(resolveAllowedIdpCidrs(process.env), "10.0.0.0/8");
  });
});
