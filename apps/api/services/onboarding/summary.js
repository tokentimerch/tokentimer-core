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

function recipientChecks(settings, contacts) {
  const emailById = new Set(
    contacts
      .filter((c) => c.details && typeof c.details.email === "string" && c.details.email)
      .map((c) => String(c.id)),
  );
  const hasEmailRecipient = (g) =>
    Array.isArray(g.email_contact_ids) &&
    g.email_contact_ids.some((id) => emailById.has(String(id)));
  // A webhook only counts if it still exists; a group can name one that was deleted.
  const webhookNames = new Set(
    (Array.isArray(settings?.webhook_urls) ? settings.webhook_urls : [])
      .filter((w) => w && typeof w.name === "string" && w.name && w.url)
      .map((w) => w.name),
  );
  const hasWebhookRecipient = (g) =>
    Array.isArray(g.webhook_names) && g.webhook_names.some((n) => webhookNames.has(n));
  const hasRecipient = (g) => hasEmailRecipient(g) || hasWebhookRecipient(g);
  return { hasEmailRecipient, hasWebhookRecipient, hasRecipient, webhookNames };
}

/** Ids of the groups that exist and can reach at least one recipient. */
function reachableGroupIds(settings, contacts) {
  const groups = Array.isArray(settings?.contact_groups)
    ? settings.contact_groups
    : [];
  const { hasRecipient } = recipientChecks(settings, contacts);
  return new Set(groups.filter(hasRecipient).map((g) => String(g.id)));
}

/**
 * The reachable contact groups carried by each token, by token id. A token
 * with no group row uses the workspace default and maps to an empty list.
 */
function tokenGroupMap(tokenIds, rows, reachable) {
  const out = {};
  for (const id of tokenIds) out[String(id)] = [];
  for (const row of rows) {
    const key = String(row.token_id);
    const group = String(row.contact_group_id);
    if (out[key] && reachable.has(group) && !out[key].includes(group)) {
      out[key].push(group);
    }
  }
  return out;
}

function summarizeContactGroups(settings, contacts) {
  const groups = Array.isArray(settings?.contact_groups)
    ? settings.contact_groups
    : [];
  const { hasEmailRecipient, hasWebhookRecipient, hasRecipient, webhookNames } =
    recipientChecks(settings, contacts);
  const groupsWithEmail = groups.filter(hasEmailRecipient);
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
  // Asset-step ids are looked up with the rest in one query.
  const assetTokenIds = intIds(refs.assetTokenIds);
  const allTokenIds = Array.from(new Set([...tokenIds, ...assetTokenIds]));
  const monitorIds = uuidIds(refs.monitorIds);

  const [
    tokenCount,
    monitors,
    settings,
    contacts,
    tokenRefs,
    monitorRefs,
    autoSync,
    syncLinked,
  ] = await Promise.all([
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
      allTokenIds.length
        ? pool.query(
            "SELECT id FROM tokens WHERE workspace_id = $1 AND id = ANY($2::int[])",
            [workspaceId, allTokenIds],
          )
        : { rows: [] },
      monitorIds.length
        ? pool.query(
            "SELECT id FROM domain_monitors WHERE workspace_id = $1 AND id = ANY($2::uuid[])",
            [workspaceId, monitorIds],
          )
        : { rows: [] },
      // Names and outcomes only. Credentials and scan parameters can hold
      // secrets and are never selected.
      pool.query(
        `SELECT id, provider, connection_key, enabled, frequency,
                last_sync_at, last_sync_status, last_sync_items_count,
                consecutive_failures, active_run_id
           FROM auto_sync_configs
          WHERE workspace_id = $1
          ORDER BY created_at DESC
          LIMIT 20`,
        [workspaceId],
      ),
      pool.query(
        `SELECT COUNT(DISTINCT l.token_id)::int AS n
           FROM auto_sync_token_links l
           JOIN auto_sync_configs c ON c.id = l.config_id
          WHERE c.workspace_id = $1`,
        [workspaceId],
      ),
    ]);

  const syncRows = autoSync.rows;

  // Groups carried by the items this session created, so the recipients step
  // can tell "a group is attached" from "a default group exists". Monitor
  // certificates that are not in the stored ids yet are read too.
  const reachable = reachableGroupIds(settings.rows[0], contacts.rows);
  const sessionMonitors = new Set(monitorRefs.rows.map((r) => String(r.id)));
  const monitorTokenIds = monitors.rows
    .filter((m) => sessionMonitors.has(String(m.id)) && m.token_id != null)
    .map((m) => Number(m.token_id))
    .filter((id) => Number.isInteger(id) && id > 0);
  const groupTokenIds = Array.from(new Set([...allTokenIds, ...monitorTokenIds]));
  const membership = groupTokenIds.length
    ? await pool.query(
        `SELECT token_id, contact_group_id
           FROM token_contact_groups
          WHERE workspace_id = $1 AND token_id = ANY($2::int[])`,
        [workspaceId, groupTokenIds],
      )
    : { rows: [] };
  const tokenGroups = tokenGroupMap(groupTokenIds, membership.rows, reachable);

  return {
    generatedAt: new Date().toISOString(),
    assets: {
      total: tokenCount.rows[0].n,
      syncManaged: syncLinked.rows[0]?.n || 0,
    },
    autoSync: {
      total: syncRows.length,
      items: syncRows.map((c) => ({
        id: c.id,
        provider: c.provider,
        name: c.connection_key,
        enabled: c.enabled === true,
        frequency: c.frequency,
        lastSyncAt: c.last_sync_at,
        lastStatus: c.last_sync_status || null,
        lastItems: c.last_sync_items_count ?? null,
        failures: c.consecutive_failures || 0,
        running: Boolean(c.active_run_id),
      })),
    },
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
      assetTokenIds: splitExisting(
        assetTokenIds,
        tokenRefs.rows.map((r) => r.id),
      ),
      monitorIds: splitExisting(monitorIds, monitorRefs.rows.map((r) => r.id)),
      tokenGroups,
    },
  };
}

module.exports = {
  buildSummary,
  findMonitorByUrl,
  summarizeContactGroups,
  reachableGroupIds,
  tokenGroupMap,
  splitExisting,
};
