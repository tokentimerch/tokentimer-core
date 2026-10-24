// Decides the smallest safe change that gives the workspace a default contact
// group with an email recipient. Pure, so the reasoning is testable without a
// browser. The caller performs the writes through the existing endpoints.

function emailOf(contact) {
  const email = contact?.details?.email;
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

export function findContactByEmail(contacts, email) {
  const wanted = String(email || '')
    .trim()
    .toLowerCase();
  if (!wanted) return null;
  return (contacts || []).find(c => emailOf(c) === wanted) || null;
}

function groupHasEmailRecipient(group, emailIds) {
  return (group?.email_contact_ids || []).some(id => emailIds.has(String(id)));
}

/**
 * @returns {{kind:'ready'|'set_default'|'add_to_default'|'create', groupId?:string, groups?:Array}}
 */
export function planContactSetup({ groups, contacts, defaultGroupId }) {
  const emailIds = new Set(
    (contacts || []).filter(c => emailOf(c)).map(c => String(c.id))
  );
  const all = Array.isArray(groups) ? groups : [];
  const defaultGroup = defaultGroupId
    ? all.find(g => String(g.id) === String(defaultGroupId))
    : null;

  if (defaultGroup && groupHasEmailRecipient(defaultGroup, emailIds)) {
    return { kind: 'ready', groupId: String(defaultGroup.id) };
  }
  const usable = all.filter(g => groupHasEmailRecipient(g, emailIds));
  if (usable.length > 0) {
    return {
      kind: 'set_default',
      groupId: String(usable[0].id),
      groups: usable,
    };
  }
  if (defaultGroup) {
    return { kind: 'add_to_default', groupId: String(defaultGroup.id) };
  }
  return { kind: 'create' };
}

/** Stable id, so a retried create finds the group it already made. */
export function onboardingGroupId(email) {
  const slug = String(email || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `onboarding-${slug || 'default'}`;
}

export function splitName(fullName, email) {
  const cleaned = String(fullName || '').trim();
  if (cleaned) {
    const [first, ...rest] = cleaned.split(/\s+/);
    return { first_name: first, last_name: rest.join(' ') || 'Contact' };
  }
  const local = String(email || '').split('@')[0] || 'Alert';
  return { first_name: local, last_name: 'Contact' };
}
