/**
 * Contact Group Resolution Utilities
 *
 * Shared functions for resolving contact groups from workspace settings,
 * handling fallbacks between token-level and workspace default groups.
 *
 * Keep in sync with apps/api/src/shared/contactGroups.js.
 */

/**
 * Resolves a contact group from an array of contact groups based on token-level
 * or workspace default contact group ID.
 *
 * @param {Object} options - Resolution options
 * @param {Array<Object>} options.contactGroups - Array of contact group objects from workspace settings
 * @param {string|null} options.contactGroupId - Token-level contact group ID (optional)
 * @param {string|null} options.defaultContactGroupId - Workspace default contact group ID (optional)
 * @returns {Object|null} The resolved contact group object, or null if not found
 *
 * @example
 * const group = resolveContactGroup({
 *   contactGroups: workspaceSettings.contact_groups,
 *   contactGroupId: token.contact_group_id,
 *   defaultContactGroupId: workspaceSettings.default_contact_group_id
 * });
 */
function resolveContactGroup({
  contactGroups,
  contactGroupId,
  defaultContactGroupId,
}) {
  try {
    const groups = Array.isArray(contactGroups) ? contactGroups : [];

    // Determine which group ID to use: token-level takes precedence, fallback to workspace default
    const pickId =
      contactGroupId && String(contactGroupId).trim().length > 0
        ? String(contactGroupId)
        : defaultContactGroupId
          ? String(defaultContactGroupId)
          : null;

    if (!pickId) {
      return null;
    }

    // Find the group by ID
    let resolvedGroup = groups.find((g) => String(g.id) === pickId) || null;

    // Fallback: if token-level group was deleted, try workspace default
    if (!resolvedGroup && contactGroupId && defaultContactGroupId) {
      resolvedGroup =
        groups.find((g) => String(g.id) === String(defaultContactGroupId)) ||
        null;
    }

    return resolvedGroup;
  } catch (_err) {
    // Return null on any error to allow graceful degradation
    return null;
  }
}

/**
 * Checks if a contact group has email contacts configured.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {boolean} True if the group has email contact IDs
 */
function hasEmailContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.email_contact_ids) &&
    contactGroup.email_contact_ids.length > 0
  );
}

/**
 * Checks if a contact group has WhatsApp contacts configured.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {boolean} True if the group has WhatsApp contact IDs
 */
function hasWhatsAppContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.whatsapp_contact_ids) &&
    contactGroup.whatsapp_contact_ids.length > 0
  );
}

/**
 * Checks if a contact group has webhook names configured.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {boolean} True if the group has webhook names configured
 */
function hasWebhookNames(contactGroup) {
  if (!contactGroup) return false;
  return (
    contactGroup.webhook_name ||
    (Array.isArray(contactGroup.webhook_names) &&
      contactGroup.webhook_names.length > 0)
  );
}

/**
 * Gets webhook names from a contact group.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {Array<string>} Array of webhook names (trimmed)
 */
function getWebhookNames(contactGroup) {
  if (!contactGroup) return [];

  if (Array.isArray(contactGroup.webhook_names)) {
    return contactGroup.webhook_names
      .filter(Boolean)
      .map((n) => String(n).trim());
  }

  if (contactGroup.webhook_name) {
    return [String(contactGroup.webhook_name).trim()];
  }

  return [];
}

const MIN_GROUP_THRESHOLD_DAYS = -365;
const MAX_GROUP_THRESHOLD_DAYS = 730;

function compareContactGroupIdsUtf8Bytes(left, right) {
  const a = Buffer.from(String(left), "utf8");
  const b = Buffer.from(String(right), "utf8");
  return Buffer.compare(a, b);
}

function normalizeAssignedGroupIds(ids) {
  if (!Array.isArray(ids)) return [];
  const unique = [];
  const seen = new Set();
  for (const raw of ids) {
    if (typeof raw !== "string") continue;
    const id = raw.trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    unique.push(id);
  }
  unique.sort(compareContactGroupIdsUtf8Bytes);
  return unique;
}

function canonicalLegacyContactGroupId(ids) {
  const normalized = normalizeAssignedGroupIds(ids);
  return normalized.length > 0 ? normalized[0] : null;
}

function resolveContactGroupsForAsset({
  contactGroups,
  assignedIds,
  defaultContactGroupId,
}) {
  const groups = Array.isArray(contactGroups) ? contactGroups : [];

  const findGroup = (id) => {
    if (id == null) return null;
    const pickId = String(id).trim();
    if (!pickId) return null;
    return groups.find((g) => g && String(g.id) === pickId) || null;
  };

  const resolveDefault = () => {
    const fallback = findGroup(defaultContactGroupId);
    return fallback ? [fallback] : [];
  };

  const assigned = normalizeAssignedGroupIds(assignedIds);
  if (assigned.length === 0) {
    return resolveDefault();
  }

  const resolved = [];
  const seen = new Set();
  for (const id of assigned) {
    const group = findGroup(id);
    if (!group) continue;
    const gid = String(group.id);
    if (seen.has(gid)) continue;
    seen.add(gid);
    resolved.push(group);
  }

  // All assigned ids missing from JSON: same as "no join rows" for routing.
  if (resolved.length === 0) {
    return resolveDefault();
  }

  resolved.sort((a, b) => compareContactGroupIdsUtf8Bytes(a.id, b.id));
  return resolved;
}

function validGroupThresholds(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of values) {
    const n = typeof raw === "number" ? raw : Number(raw);
    if (
      !Number.isFinite(n) ||
      n < MIN_GROUP_THRESHOLD_DAYS ||
      n > MAX_GROUP_THRESHOLD_DAYS
    ) {
      continue;
    }
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

function effectiveThresholds(group, workspaceThresholds) {
  const fromGroup = validGroupThresholds(group && group.thresholds);
  if (fromGroup.length > 0) return fromGroup;
  return Array.isArray(workspaceThresholds) ? workspaceThresholds.slice() : [];
}

function groupFiresForWindow(group, workspaceThresholds, thresholdDays) {
  const windowDays = Number(thresholdDays);
  if (!Number.isFinite(windowDays)) return false;
  return effectiveThresholds(group, workspaceThresholds).some(
    (value) => Number(value) === windowDays,
  );
}

function unionGroupsForThresholdWindow(
  groups,
  workspaceThresholds,
  thresholdDays,
) {
  return (Array.isArray(groups) ? groups : []).filter((group) =>
    groupFiresForWindow(group, workspaceThresholds, thresholdDays),
  );
}

function unionEffectiveThresholds(groups, workspaceThresholds) {
  const unionList = [];
  const seen = new Set();
  for (const group of Array.isArray(groups) ? groups : []) {
    for (const threshold of effectiveThresholds(group, workspaceThresholds)) {
      if (seen.has(threshold)) continue;
      seen.add(threshold);
      unionList.push(threshold);
    }
  }
  return unionList;
}

function unionContactIds(groups, field) {
  const ids = [];
  const seen = new Set();
  for (const group of Array.isArray(groups) ? groups : []) {
    const list = Array.isArray(group?.[field]) ? group[field] : [];
    for (const raw of list) {
      if (raw == null) continue;
      const key = String(raw);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      ids.push(raw);
    }
  }
  return ids;
}

function dedupeNormalizedDestinations(values, kind) {
  const list = Array.isArray(values) ? values : [];
  const seen = new Set();
  const out = [];
  for (const raw of list) {
    if (raw == null) continue;
    let value = String(raw).trim();
    if (kind === "email") value = value.toLowerCase();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function whatsAppAllowedForAlertKey(alertKey) {
  const key = String(alertKey || "");
  return !(
    key.startsWith("cert_renewal_failed:") || key.startsWith("agent_health:")
  );
}

function deliveryChannelsFromEligibleGroups(
  eligibleGroups,
  { emailAlertsEnabled = true, alertKey = "" } = {},
) {
  const groups = Array.isArray(eligibleGroups) ? eligibleGroups : [];
  if (groups.length === 0) return [];
  const channels = [];
  if (emailAlertsEnabled !== false && groups.some(hasEmailContacts)) {
    channels.push("email");
  }
  if (groups.some(hasWebhookNames)) {
    channels.push("webhooks");
  }
  if (
    whatsAppAllowedForAlertKey(alertKey) &&
    groups.some(hasWhatsAppContacts)
  ) {
    channels.push("whatsapp");
  }
  return channels;
}

function parseQueuedChannels(value) {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value !== "string" || value.trim() === "") return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

function channelsForDeliveryAttempt(
  liveChannels,
  queuedChannels,
  { isRetry = false } = {},
) {
  const live = Array.isArray(liveChannels) ? liveChannels.map(String) : [];
  if (!isRetry) return live;
  const queued = new Set(parseQueuedChannels(queuedChannels));
  return live.filter((channel) => queued.has(channel));
}

export {
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
  compareContactGroupIdsUtf8Bytes,
  canonicalLegacyContactGroupId,
  normalizeAssignedGroupIds,
  resolveContactGroupsForAsset,
  effectiveThresholds,
  groupFiresForWindow,
  unionGroupsForThresholdWindow,
  unionEffectiveThresholds,
  unionContactIds,
  dedupeNormalizedDestinations,
  whatsAppAllowedForAlertKey,
  deliveryChannelsFromEligibleGroups,
  channelsForDeliveryAttempt,
};
