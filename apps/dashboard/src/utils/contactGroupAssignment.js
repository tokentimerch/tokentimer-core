/**
 * Dashboard helpers for multi-group contact assignment.
 * Empty `contact_group_ids` means "use the workspace default".
 */

function compareContactGroupIdsUtf8Bytes(left, right) {
  const encoder = new TextEncoder();
  const a = encoder.encode(String(left));
  const b = encoder.encode(String(right));
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export function normalizeContactGroupIds(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of value) {
    if (raw == null) continue;
    const id = String(raw).trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  out.sort(compareContactGroupIdsUtf8Bytes);
  return out;
}

/**
 * Prefer the plural array when present (including `[]`).
 * Fall back to the legacy singular id, then to no assignment.
 */
export function hydrateContactGroupIds(source) {
  if (!source || typeof source !== 'object') return [];
  if (Array.isArray(source.contact_group_ids)) {
    return normalizeContactGroupIds(source.contact_group_ids);
  }
  if (Array.isArray(source.contactGroupIds)) {
    return normalizeContactGroupIds(source.contactGroupIds);
  }
  const singular = source.contact_group_id ?? source.contactGroupId;
  if (singular != null && String(singular).trim() !== '') {
    return [String(singular).trim()];
  }
  return [];
}

export function canonicalContactGroupFields(ids) {
  const contact_group_ids = normalizeContactGroupIds(ids);
  return {
    contact_group_ids,
    contact_group_id: contact_group_ids[0] ?? null,
  };
}

/**
 * Top-level import defaults. An empty picker omits both fields so a
 * re-import does not clear membership that was set on an earlier run.
 */
export function contactGroupFieldsForImportDefaults(ids) {
  const normalized = normalizeContactGroupIds(ids);
  return normalized.length > 0 ? canonicalContactGroupFields(normalized) : {};
}

export function canonicalAgentContactGroupFields(ids) {
  const { contact_group_ids, contact_group_id } =
    canonicalContactGroupFields(ids);
  return {
    contactGroupIds: contact_group_ids,
    contactGroupId: contact_group_id,
  };
}

export function formatContactGroupNames(
  ids,
  contactGroups = [],
  emptyLabel = 'Use workspace default'
) {
  const groups = Array.isArray(contactGroups) ? contactGroups : [];
  const names = normalizeContactGroupIds(ids).map(id => {
    const group = groups.find(item => String(item?.id) === id);
    return group?.name || id;
  });
  return names.length ? names.join(', ') : emptyLabel;
}

export function joinContactGroupIdsForExport(token) {
  return hydrateContactGroupIds(token).join(';');
}
