// Builds contact groups and webhooks for the setup guide. Pure, so the rules
// are testable without a browser. The shapes match what the alert-settings
// endpoint and the existing Alert Preferences page read and write.

import { parseThresholds } from './thresholds.js';

export const WEBHOOK_KINDS = {
  slack: { label: 'Slack', help: 'Incoming webhook URL' },
  teams: { label: 'Microsoft Teams', help: 'Incoming webhook connector URL' },
  discord: { label: 'Discord', help: 'Channel webhook URL' },
  pagerduty: { label: 'PagerDuty', help: 'Events API v2', needsRouting: true },
  generic: { label: 'Generic', help: 'Any HTTPS endpoint' },
};

const NAME = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$/;
const MAX_WEBHOOKS = 5;

/** Fields the user can set on a webhook, validated before any call. */
export function validateWebhookDraft(draft, existing = []) {
  const problems = [];
  const name = String(draft?.name || '').trim();
  const url = String(draft?.url || '').trim();
  const kind = draft?.kind || 'generic';
  if (!WEBHOOK_KINDS[kind]) problems.push('Choose a webhook type.');
  if (!NAME.test(name))
    problems.push(
      'Give it a short name (letters, numbers, spaces, dot, dash, underscore).'
    );
  if (
    existing.some(
      w => String(w.name).toLowerCase() === name.toLowerCase() && name
    )
  )
    problems.push('A webhook with this name already exists.');
  let parsed = null;
  try {
    parsed = new URL(url);
  } catch (_) {
    /* reported below */
  }
  if (!parsed || parsed.protocol !== 'https:')
    problems.push('The URL must start with https://.');
  if (kind === 'pagerduty' && !String(draft?.routingKey || '').trim())
    problems.push('PagerDuty needs a routing key.');
  if (existing.length >= MAX_WEBHOOKS)
    problems.push(`A workspace can hold up to ${MAX_WEBHOOKS} webhooks.`);
  return { ok: problems.length === 0, problems };
}

/**
 * The stored shape. Only call after the test succeeded: the product refuses to
 * persist a webhook that was not verified against its current URL.
 */
export function toStoredWebhook(draft) {
  const url = String(draft.url).trim();
  return {
    name: String(draft.name).trim(),
    url,
    kind: draft.kind || 'generic',
    severity: draft.severity || '',
    template: draft.template || '',
    routingKey: draft.routingKey || '',
    verified: true,
    verifiedUrl: url,
  };
}

/** Appends without disturbing the others; the PUT replaces the whole list. */
export function appendWebhook(existing, draft) {
  const list = Array.isArray(existing) ? existing : [];
  return [...list, toStoredWebhook(draft)];
}

const slug = text =>
  String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);

/** Stable id from the name, so a retried create finds the group it made. */
export function groupIdFor(name) {
  return `onboarding-${slug(name) || 'group'}`;
}

/**
 * A complete group. Needs at least one way to reach someone, as the product
 * requires. Thresholds are stored only when they differ from the workspace.
 */
export function buildGroup({
  id,
  name,
  emailContactIds = [],
  whatsappContactIds = [],
  webhookNames = [],
  thresholdsText = '',
  workspaceThresholds = [],
  weeklyDigestEmail = false,
  weeklyDigestWhatsapp = false,
  weeklyDigestWebhooks = false,
}) {
  const problems = [];
  const cleanName = String(name || '').trim();
  if (!cleanName) problems.push('Name the group.');
  const email = Array.from(new Set(emailContactIds.filter(Boolean)));
  const whatsapp = Array.from(new Set(whatsappContactIds.filter(Boolean)));
  const hooks = Array.from(new Set(webhookNames.filter(Boolean)));
  if (!email.length && !whatsapp.length && !hooks.length)
    problems.push('Add at least one recipient or webhook.');

  let thresholds;
  if (String(thresholdsText || '').trim()) {
    const parsed = parseThresholds(thresholdsText);
    if (parsed.problems.length) problems.push(...parsed.problems);
    else if (
      JSON.stringify(parsed.values) !== JSON.stringify(workspaceThresholds)
    )
      thresholds = parsed.values;
  }
  if (problems.length) return { ok: false, problems };

  const group = {
    id: id || groupIdFor(cleanName),
    name: cleanName,
    email_contact_ids: email,
    whatsapp_contact_ids: whatsapp,
    webhook_names: hooks,
    weekly_digest_email: weeklyDigestEmail,
    weekly_digest_whatsapp: weeklyDigestWhatsapp,
    weekly_digest_webhooks: weeklyDigestWebhooks,
  };
  if (thresholds) group.thresholds = thresholds;
  return { ok: true, group };
}

/** Adds or replaces one group by id; every other group is left as it was. */
export function upsertGroup(groups, group) {
  const list = Array.isArray(groups) ? groups : [];
  const index = list.findIndex(g => String(g.id) === String(group.id));
  if (index === -1) return [...list, group];
  return list.map((g, i) => (i === index ? { ...g, ...group } : g));
}

/** Short human summary of who a group reaches. */
export function describeGroup(group, contacts = []) {
  const byId = new Map(contacts.map(c => [String(c.id), c]));
  const label = id => {
    const c = byId.get(String(id));
    return c?.details?.email || c?.details?.phone || 'a contact';
  };
  const parts = [];
  (group.email_contact_ids || []).forEach(id => parts.push(label(id)));
  (group.whatsapp_contact_ids || []).forEach(id =>
    parts.push(`${label(id)} (WhatsApp)`)
  );
  (group.webhook_names || []).forEach(n => parts.push(`${n} (webhook)`));
  return parts;
}
