// Pure rules for the recipients step: who a group reaches and what deleting
// a group does. No React, so it is testable.

const same = (a, b) => String(a) === String(b);

/** True if the group has an email contact or a webhook that still exists. */
export function groupReaches(group, webhookNames, emailIds) {
  return (
    (group.email_contact_ids || []).some(id => emailIds.has(String(id))) ||
    (group.webhook_names || []).some(n => webhookNames.has(n))
  );
}

/**
 * Whether a group can be deleted from the guide. Alert Preferences lets the
 * default be deleted and silently promotes another group. Here the default
 * must be handed over first (in Alert Preferences, since this step no longer
 * changes it), so the default never moves behind the operator's back. Any
 * other group can go: the server drops it from assets and websites, and those
 * fall back to the default.
 */
export function planGroupDelete({ group, groups, defaultId }) {
  const list = Array.isArray(groups) ? groups : [];
  const remaining = list.filter(g => !same(g.id, group.id));
  const isDefault = Boolean(defaultId) && same(group.id, defaultId);
  let reason = '';
  if (isDefault) {
    reason = remaining.length
      ? 'It is the default group. Make another group the default in Alert Preferences first.'
      : 'It is the default and only group. Create another group, then make it the default in Alert Preferences.';
  }
  return { allowed: !reason, reason, remaining, isDefault };
}
