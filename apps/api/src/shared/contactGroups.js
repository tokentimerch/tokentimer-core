"use strict";

const {
  isContactGroupPluralWritesEnabled,
} = require("./contactGroupPluralWrites");

const MIN_THRESHOLD = -365;
const MAX_THRESHOLD = 730;

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

function findGroupById(groups, groupId) {
  if (!groupId) return null;
  const id = String(groupId);
  return groups.find((g) => g && String(g.id) === id) || null;
}

/**
 * Join-table ids are the membership source of truth. Empty assigned set
 * means workspace default; do not consult the singular column.
 */
function resolveContactGroupsForAsset({
  contactGroups,
  assignedIds,
  defaultContactGroupId,
}) {
  const groups = Array.isArray(contactGroups) ? contactGroups : [];
  const assigned = normalizeAssignedGroupIds(assignedIds);
  const defaultId =
    defaultContactGroupId && String(defaultContactGroupId).trim()
      ? String(defaultContactGroupId).trim()
      : null;

  const pickDefault = () => {
    if (!defaultId) return [];
    const resolved = findGroupById(groups, defaultId);
    return resolved ? [resolved] : [];
  };

  if (assigned.length === 0) {
    return pickDefault();
  }

  const valid = [];
  for (const id of assigned) {
    const group = findGroupById(groups, id);
    if (group) valid.push(group);
  }

  if (valid.length === 0) {
    return pickDefault();
  }
  valid.sort((left, right) =>
    compareContactGroupIdsUtf8Bytes(left.id, right.id),
  );
  return valid;
}

function resolveContactGroup({
  contactGroups,
  contactGroupId,
  defaultContactGroupId,
}) {
  try {
    const groups = Array.isArray(contactGroups) ? contactGroups : [];
    const pickId =
      contactGroupId && String(contactGroupId).trim().length > 0
        ? String(contactGroupId)
        : defaultContactGroupId
          ? String(defaultContactGroupId)
          : null;
    if (!pickId) return null;
    let resolvedGroup = groups.find((g) => String(g.id) === pickId) || null;
    if (!resolvedGroup && contactGroupId && defaultContactGroupId) {
      resolvedGroup =
        groups.find((g) => String(g.id) === String(defaultContactGroupId)) ||
        null;
    }
    return resolvedGroup;
  } catch (_err) {
    return null;
  }
}

function hasEmailContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.email_contact_ids) &&
    contactGroup.email_contact_ids.length > 0
  );
}

function hasWhatsAppContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.whatsapp_contact_ids) &&
    contactGroup.whatsapp_contact_ids.length > 0
  );
}

function hasWebhookNames(contactGroup) {
  if (!contactGroup) return false;
  return (
    contactGroup.webhook_name ||
    (Array.isArray(contactGroup.webhook_names) &&
      contactGroup.webhook_names.length > 0)
  );
}

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

function validGroupThresholds(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of values) {
    const n = typeof raw === "number" ? raw : Number(raw);
    if (!Number.isFinite(n) || n < MIN_THRESHOLD || n > MAX_THRESHOLD) {
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
  const window = Number(thresholdDays);
  if (!Number.isFinite(window)) return false;
  return effectiveThresholds(group, workspaceThresholds).some(
    (n) => Number(n) === window,
  );
}

function unionGroupsForThresholdWindow(
  groups,
  workspaceThresholds,
  thresholdDays,
) {
  if (!Array.isArray(groups)) return [];
  return groups.filter((g) =>
    groupFiresForWindow(g, workspaceThresholds, thresholdDays),
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
  const seen = new Set();
  const out = [];
  if (!Array.isArray(values)) return out;
  for (const raw of values) {
    if (raw == null) continue;
    let next = String(raw).trim();
    if (!next) continue;
    if (kind === "email") next = next.toLowerCase();
    if (seen.has(next)) continue;
    seen.add(next);
    out.push(next);
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

function invalidMembershipWriteError(fieldName, { array = false } = {}) {
  const err = new Error(
    array
      ? `${fieldName} must be an array of strings`
      : `${fieldName} must be a string`,
  );
  err.code = "VALIDATION_ERROR";
  return err;
}

/**
 * @returns {{ action: 'omit' } | { action: 'set', ids: string[] }}
 */
function interpretContactGroupWrite({
  contactGroupIds,
  contactGroupId,
  hasPlural,
  hasSingular,
  pluralFieldName = "contact_group_ids",
  singularFieldName = "contact_group_id",
}) {
  if (hasPlural) {
    if (!Array.isArray(contactGroupIds)) {
      throw invalidMembershipWriteError(pluralFieldName, { array: true });
    }
    for (const raw of contactGroupIds) {
      if (typeof raw !== "string") {
        throw invalidMembershipWriteError(pluralFieldName, { array: true });
      }
    }
    const ids = normalizeAssignedGroupIds(contactGroupIds);
    if (ids.length > 1 && !isContactGroupPluralWritesEnabled()) {
      const err = new Error(
        `${pluralFieldName} cannot assign more than one group until CONTACT_GROUP_PLURAL_WRITES is enabled`,
      );
      err.code = "VALIDATION_ERROR";
      throw err;
    }
    return { action: "set", ids };
  }
  if (!hasSingular) {
    return { action: "omit" };
  }
  if (contactGroupId == null) {
    return { action: "set", ids: [] };
  }
  if (typeof contactGroupId !== "string") {
    throw invalidMembershipWriteError(singularFieldName);
  }
  if (contactGroupId.trim() === "") {
    return { action: "set", ids: [] };
  }
  return {
    action: "set",
    ids: normalizeAssignedGroupIds([contactGroupId]),
  };
}

function membershipAfterContactGroupMove(assignedIds, fromId, toId) {
  const current = normalizeAssignedGroupIds(assignedIds);
  const from = fromId != null ? String(fromId).trim() : "";
  const to = toId != null ? String(toId).trim() : "";
  const next = current.filter((id) => id !== from);
  if (to && !next.includes(to)) next.push(to);
  return normalizeAssignedGroupIds(next);
}

module.exports = {
  compareContactGroupIdsUtf8Bytes,
  canonicalLegacyContactGroupId,
  normalizeAssignedGroupIds,
  membershipAfterContactGroupMove,
  resolveContactGroupsForAsset,
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
  effectiveThresholds,
  groupFiresForWindow,
  unionGroupsForThresholdWindow,
  unionEffectiveThresholds,
  unionContactIds,
  dedupeNormalizedDestinations,
  whatsAppAllowedForAlertKey,
  deliveryChannelsFromEligibleGroups,
  channelsForDeliveryAttempt,
  interpretContactGroupWrite,
  isContactGroupPluralWritesEnabled,
};
