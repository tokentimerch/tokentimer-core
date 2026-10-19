"use strict";

// "Reality" side of the onboarding model: what verifiably exists in the
// backend right now. Stored session flags never count as completion.

const MAX_REF_IDS = 100;
const MAX_MONITORS = 20;

function intIds(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => Number(v))
    .filter((v) => Number.isInteger(v) && v > 0)
    .slice(0, MAX_REF_IDS);
}

function uuidIds(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v))
    .slice(0, MAX_REF_IDS);
}

function splitExisting(wanted, found) {
  const foundSet = new Set(found.map(String));
  return {
    existing: wanted.filter((id) => foundSet.has(String(id))),
    missing: wanted.filter((id) => !foundSet.has(String(id))),
  };
}

function summarizeContactGroups(settings, contacts) {
  const groups = Array.isArray(settings?.contact_groups)
    ? settings.contact_groups
    : [];
  const emailById = new Set(
    contacts
      .filter((c) => c.details && typeof c.details.email === "string" && c.details.email)
      .map((c) => String(c.id)),
  );
  const hasEmailRecipient = (g) =>
    Array.isArray(g.email_contact_ids) &&
    g.email_contact_ids.some((id) => emailById.has(String(id)));
  const groupsWithEmail = groups.filter(hasEmailRecipient);
  // A webhook only counts if it still exists; a group can name one that was deleted.
  const webhookNames = new Set(
    (Array.isArray(settings?.webhook_urls) ? settings.webhook_urls : [])
      .filter((w) => w && typeof w.name === "string" && w.name && w.url)
      .map((w) => w.name),
  );
  const hasWebhookRecipient = (g) =>
    Array.isArray(g.webhook_names) && g.webhook_names.some((n) => webhookNames.has(n));
  const hasRecipient = (g) => hasEmailRecipient(g) || hasWebhookRecipient(g);
  const defaultId = settings?.default_contact_group_id || null;
  const defaultGroup = defaultId
    ? groups.find((g) => String(g.id) === String(defaultId))
    : null;
  return {
    count: groups.length,
    defaultId,
    defaultHasEmailRecipient: Boolean(defaultGroup && hasEmailRecipient(defaultGroup)),
    defaultHasWebhookRecipient: Boolean(defaultGroup && hasWebhookRecipient(defaultGroup)),
    defaultHasRecipient: Boolean(defaultGroup && hasRecipient(defaultGroup)),
    withEmailRecipient: groupsWithEmail.length,
    webhookCount: webhookNames.size,
    emailAlertsEnabled: settings ? settings.email_alerts_enabled !== false : null,
  };
}

/**
 * Resolves expected assets by verified identity. Used by resume to adopt
 * work that succeeded before the session recorded it.
 */
async function findMonitorByUrl(pool, workspaceId, url) {
  const { rows } = await pool.query(
    `SELECT id, url, token_id, validated, health_check_enabled,
            last_health_status, last_health_check_at, ssl_valid_to
       FROM domain_monitors
      WHERE workspace_id = $1 AND lower(url) = lower($2)
      LIMIT 1`,
    [workspaceId, url],
  );
  return rows[0] || null;
}

async function buildSummary(
  pool,
  { workspaceId, refs = {}, smtpConfigured, certops = null },
) {
  const tokenIds = intIds(refs.tokenIds);
  const monitorIds = uuidIds(refs.monitorIds);

  const [tokenCount, monitors, settings, contacts, tokenRefs, monitorRefs] =
    await Promise.all([
      pool.query("SELECT COUNT(*)::int AS n FROM tokens WHERE workspace_id = $1", [
        workspaceId,
      ]),
      pool.query(
        `SELECT id, url, token_id, validated, health_check_enabled,
                last_health_status, last_health_check_at, ssl_valid_to
           FROM domain_monitors
          WHERE workspace_id = $1
          ORDER BY created_at DESC
          LIMIT ${MAX_MONITORS}`,
        [workspaceId],
      ),
      pool.query(
        `SELECT contact_groups, default_contact_group_id, email_alerts_enabled,
                webhook_urls
           FROM workspace_settings WHERE workspace_id = $1`,
        [workspaceId],
      ),
      pool.query(
        "SELECT id, details FROM workspace_contacts WHERE workspace_id = $1",
        [workspaceId],
      ),
      tokenIds.length
        ? pool.query(
            "SELECT id FROM tokens WHERE workspace_id = $1 AND id = ANY($2::int[])",
            [workspaceId, tokenIds],
          )
        : { rows: [] },
      monitorIds.length
        ? pool.query(
            "SELECT id FROM domain_monitors WHERE workspace_id = $1 AND id = ANY($2::uuid[])",
            [workspaceId, monitorIds],
          )
        : { rows: [] },
    ]);

  return {
    generatedAt: new Date().toISOString(),
    assets: { total: tokenCount.rows[0].n },
    monitors: {
      total: monitors.rows.length,
      items: monitors.rows.map((m) => ({
        id: m.id,
        url: m.url,
        tokenId: m.token_id,
        validated: m.validated,
        healthCheckEnabled: m.health_check_enabled,
        lastHealthStatus: m.last_health_status,
        lastHealthCheckAt: m.last_health_check_at,
        certificateExpiresAt: m.ssl_valid_to,
      })),
    },
    certops: certops === null ? "unknown" : certops,
    alerts: {
      smtpConfigured: smtpConfigured === undefined ? "unknown" : smtpConfigured,
      contactGroups: summarizeContactGroups(settings.rows[0], contacts.rows),
    },
    references: {
      tokenIds: splitExisting(tokenIds, tokenRefs.rows.map((r) => r.id)),
      monitorIds: splitExisting(monitorIds, monitorRefs.rows.map((r) => r.id)),
    },
  };
}

module.exports = {
  buildSummary,
  findMonitorByUrl,
  summarizeContactGroups,
  splitExisting,
};
