"use strict";

const { listProviders } = require("./provider-registry.js");

const SSO_CAPABILITY = "sso.setup";
const SSO_SUMMARY_ID = "sso";
const MAX_ITEMS = 50;

// Expose readiness and mapping counts without provider configuration or secrets.
async function ssoSummary({ db, user } = {}) {
  if (!user || user.isSystemAdmin !== true) return { applicable: false };

  const [providers, mappingRows] = await Promise.all([
    listProviders(db),
    db.query(
      "SELECT provider_slug, COUNT(*)::int AS n FROM sso_group_role_mappings GROUP BY provider_slug",
    ),
  ]);

  const items = providers.map((p) => ({
    slug: p.slug,
    type: p.type,
    displayName: p.displayName,
    enabled: p.enabled === true,
    signInReady: p.enabled === true && p.runtime?.signInReady === true,
  }));
  const readySlugs = new Set(items.filter((i) => i.signInReady).map((i) => i.slug));
  let total = 0;
  let forReady = 0;
  for (const row of mappingRows.rows) {
    total += row.n;
    if (readySlugs.has(row.provider_slug)) forReady += row.n;
  }

  return {
    applicable: true,
    providers: {
      total: items.length,
      enabled: items.filter((i) => i.enabled).length,
      signInReady: readySlugs.size,
      items: items.slice(0, MAX_ITEMS),
    },
    mappings: { total, forReadyProviders: forReady },
  };
}

let registered = false;

/**
 * @param {{ capabilities: object, summary: object }} services Core's
 *   `services/onboarding/capabilities` and `services/onboarding/summary`.
 */
function registerSsoOnboarding({ capabilities, summary }) {
  if (registered) return false;
  // Only a system administrator may start it; the facts that decide whether it
  // is finished come from the summary provider below.
  capabilities.registerCapability({
    id: SSO_CAPABILITY,
    group: "identity",
    scope: "system_admin",
  });
  summary.registerSummaryProvider(SSO_SUMMARY_ID, ssoSummary);
  registered = true;
  return true;
}

module.exports = {
  SSO_CAPABILITY,
  SSO_SUMMARY_ID,
  ssoSummary,
  registerSsoOnboarding,
};
