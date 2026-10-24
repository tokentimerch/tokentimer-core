import { normalizeContactGroupIds } from '../../utils/contactGroupAssignment.js';

/**
 * One line that says where alerts for assets found by later syncs go. A sync
 * has its own group choice: the groups picked while importing apply only to
 * what was imported then.
 */
export function describeSyncGroups(groupIds, groups, defaultGroupId) {
  const list = Array.isArray(groups) ? groups : [];
  const nameOf = id => list.find(g => String(g.id) === String(id))?.name;
  const chosen = normalizeContactGroupIds(groupIds).map(nameOf).filter(Boolean);
  if (chosen.length) return chosen.join(', ');
  const fallback = defaultGroupId ? nameOf(defaultGroupId) : '';
  return fallback
    ? `the workspace default group (${fallback})`
    : 'the workspace default group';
}

export const SYNC_GROUP_EXPLANATION =
  'Applies to assets a sync adds from now on. Assets you already imported keep the group chosen at import.';

/** When the next scan runs, in the reader's locale. */
export function formatNextSync(value) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString();
}
