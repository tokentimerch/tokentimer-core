// Pure rules for the recipients step: what deleting a group does and which
// group receives the alerts for the chosen goal. No React, so it is testable.

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
 * must be handed over first, so the default never changes behind the
 * operator's back. Any other group can go: the server drops it from assets and
 * websites, and those fall back to the default.
 */
export function planGroupDelete({ group, groups, defaultId }) {
  const list = Array.isArray(groups) ? groups : [];
  const remaining = list.filter(g => !same(g.id, group.id));
  const isDefault = Boolean(defaultId) && same(group.id, defaultId);
  let reason = '';
  if (isDefault) {
    reason = remaining.length
      ? 'It is the default group. Make another group the default first.'
      : 'It is the default and only group. Create another group and make it the default first.';
  }
  return { allowed: !reason, reason, remaining, isDefault };
}

/**
 * Goals where an asset can carry its own group. The wizard cannot see what the
 * operator picks there (the asset form, or an import dialog), so it states no
 * rule for them and shows no "Used for this setup" block.
 */
const OWN_GROUP_GOALS = new Set([
  'track_asset',
  'import_file',
  'import_integration',
]);

export const usesDefaultOnly = goal => !OWN_GROUP_GOALS.has(goal);

/**
 * Which group receives the alerts for what is being set up, in plain words.
 * Only meaningful for goals where usesDefaultOnly is true.
 */
export function describeSetupUse({ goal, groups, defaultId, defaultReaches }) {
  const list = Array.isArray(groups) ? groups : [];
  const def = defaultId ? list.find(g => same(g.id, defaultId)) : null;
  const quoted = def ? `"${def.name}"` : '';
  const lines = [];
  const usedIds = def ? [String(def.id)] : [];

  if (goal === 'monitor_https') {
    lines.push(
      def
        ? `Websites you add here use the default group ${quoted}. This setup attaches no group to a website, so the default applies.`
        : 'Websites you add here use the default group, but none is set.'
    );
  } else if (String(goal || '').startsWith('certops_')) {
    lines.push(
      def
        ? `Alerts about your agents and their certificates use the default group ${quoted}. This setup attaches no group to them.`
        : 'Alerts about your agents and their certificates use the default group, but none is set.'
    );
  } else {
    lines.push(
      def
        ? `Anything without a group of its own uses the default group ${quoted}.`
        : 'Anything without a group of its own uses the default group, but none is set.'
    );
  }

  let warning = '';
  if (!def) {
    warning =
      'Nothing without its own group has a recipient yet. Make one of the groups below the default.';
  } else if (!defaultReaches) {
    warning = `${quoted} reaches nobody yet. Add a recipient or a webhook to it, or make another group the default.`;
  }
  return { lines, warning, usedIds };
}
