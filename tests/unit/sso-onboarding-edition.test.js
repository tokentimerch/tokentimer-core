"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const capabilities = require("../../apps/api/services/onboarding/capabilities.js");
const summary = require("../../apps/api/services/onboarding/summary.js");
const edition = require("../../apps/api/sso/onboarding-edition.js");
const { setProviderRuntimeStatus, removeProviderRuntimeStatus } = require("../../apps/api/sso/sso-runtime-status.js");

function reset() {
  capabilities.resetRegisteredCapabilities();
  summary.resetSummaryProviders();
}

// Answers the three queries the summary provider makes.
function fakeDb({ providers = [], mappings = [] } = {}) {
  return {
    async query(sql) {
      if (/FROM sso_provider_secrets/.test(sql)) return { rows: [] };
      if (/FROM sso_providers/.test(sql)) {
        return {
          rows: providers.map((p, i) => ({
            id: i + 1,
            slug: p.slug,
            type: p.type || "oidc",
            display_name: p.name || p.slug,
            enabled: p.enabled !== false,
            sort_order: i,
            config: { issuer: "https://idp.example.test", client_id: "c" },
            claim_mapping: {},
            security: {},
            locked_fields: [],
          })),
        };
      }
      if (/FROM sso_group_role_mappings/.test(sql)) return { rows: mappings };
      throw new Error(`unexpected query: ${sql}`);
    },
  };
}

test("registration adds sso.setup for system administrators only", () => {
  reset();
  // A fresh module instance, because registration happens once per process.
  delete require.cache[require.resolve("../../apps/api/sso/onboarding-edition.js")];
  const fresh = require("../../apps/api/sso/onboarding-edition.js");
  assert.equal(fresh.registerSsoOnboarding({ capabilities, summary }), true);
  assert.equal(fresh.registerSsoOnboarding({ capabilities, summary }), false);
  assert.equal(summary.hasSummaryProviders(), true);

  const find = (ctx) => capabilities.evaluateCapabilities(ctx).find((c) => c.id === "sso.setup");
  const admin = find({ workspaceRole: "viewer", isSystemAdmin: true });
  assert.equal(admin.group, "identity");
  assert.equal(admin.authorized, true);
  assert.equal(admin.entitled, true);
  assert.equal(admin.state, "ready");
  const member = find({ workspaceRole: "admin", isSystemAdmin: false });
  assert.equal(member.authorized, false);
  assert.equal(member.state, "role_handoff");
  assert.equal(member.blockers[0].code, "ROLE_REQUIRED");
  assert.match(member.blockers[0].remediation, /system administrator/);
  assert.equal(find({ workspaceRole: "admin" }).state, "unknown");
  reset();
});

test("core's own capabilities are unchanged by the registration", () => {
  reset();
  const before = capabilities.evaluateCapabilities({ workspaceRole: "admin" }).map((c) => c.id);
  delete require.cache[require.resolve("../../apps/api/sso/onboarding-edition.js")];
  require("../../apps/api/sso/onboarding-edition.js").registerSsoOnboarding({ capabilities, summary });
  const after = capabilities.evaluateCapabilities({ workspaceRole: "admin" }).map((c) => c.id);
  assert.deepEqual(after, [...before, "sso.setup"]);
  reset();
});

test("the summary hides everything from anyone who is not a system administrator", async () => {
  const db = fakeDb({ providers: [{ slug: "okta" }] });
  assert.deepEqual(await edition.ssoSummary({ db, user: null }), { applicable: false });
  assert.deepEqual(
    await edition.ssoSummary({ db, user: { id: 2, isSystemAdmin: false, workspaceRole: "admin" } }),
    { applicable: false },
  );
});

test("the summary counts providers that can sign in and mappings on them", async () => {
  setProviderRuntimeStatus("okta", { registered: true, signInReady: true });
  removeProviderRuntimeStatus("keycloak");
  try {
    const db = fakeDb({
      providers: [
        { slug: "okta", name: "Okta" },
        { slug: "keycloak", name: "Keycloak", type: "saml" },
        { slug: "old", name: "Old", enabled: false },
      ],
      mappings: [
        { provider_slug: "okta", n: 2 },
        { provider_slug: "keycloak", n: 3 },
      ],
    });
    const out = await edition.ssoSummary({ db, user: { id: 1, isSystemAdmin: true } });
    assert.deepEqual(out, {
      applicable: true,
      providers: {
        total: 3,
        enabled: 2,
        signInReady: 1,
        items: [
          { slug: "okta", type: "oidc", displayName: "Okta", enabled: true, signInReady: true },
          { slug: "keycloak", type: "saml", displayName: "Keycloak", enabled: true, signInReady: false },
          { slug: "old", type: "oidc", displayName: "Old", enabled: false, signInReady: false },
        ],
      },
      mappings: { total: 5, forReadyProviders: 2 },
    });
    // Nothing configuration-like or secret-like is reported.
    assert.doesNotMatch(JSON.stringify(out), /issuer|client_id|secret/i);
  } finally {
    removeProviderRuntimeStatus("okta");
  }
});

test("the summary gates same-protocol conflicts even with previously ready strategies", async (t) => {
  setProviderRuntimeStatus("one", { registered: true, signInReady: true });
  setProviderRuntimeStatus("saml", { registered: true, signInReady: true });
  t.after(() => {
    removeProviderRuntimeStatus("one");
    removeProviderRuntimeStatus("saml");
  });
  const db = fakeDb({ providers: [{ slug: "one" }, { slug: "two" }, { slug: "saml", type: "saml" }] });
  const out = await edition.ssoSummary({ db, user: { id: 1, isSystemAdmin: true } });
  assert.deepEqual(out.providers.items.map((provider) => provider.signInReady), [false, false, true]);
});

test("an empty deployment reports zero everywhere", async () => {
  const out = await edition.ssoSummary({ db: fakeDb(), user: { id: 1, isSystemAdmin: true } });
  assert.deepEqual(out.providers, { total: 0, enabled: 0, signInReady: 0, items: [] });
  assert.deepEqual(out.mappings, { total: 0, forReadyProviders: 0 });
});
