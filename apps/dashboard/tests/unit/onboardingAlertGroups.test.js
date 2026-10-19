import { describe, expect, it } from 'vitest';
import {
  appendWebhook,
  buildGroup,
  describeGroup,
  groupIdFor,
  toStoredWebhook,
  upsertGroup,
  validateWebhookDraft,
} from '../../src/components/onboarding/alertGroups.js';

const hook = {
  name: 'Ops Slack',
  url: 'https://hooks.slack.com/services/T000/B000/XXXX',
  kind: 'slack',
};

describe('validateWebhookDraft', () => {
  it('accepts a complete https webhook', () => {
    expect(validateWebhookDraft(hook).ok).toBe(true);
  });

  it('requires https, a name and a known type', () => {
    expect(validateWebhookDraft({ ...hook, url: 'http://x.example' }).ok).toBe(
      false
    );
    expect(validateWebhookDraft({ ...hook, url: 'not a url' }).ok).toBe(false);
    expect(validateWebhookDraft({ ...hook, name: '' }).ok).toBe(false);
    expect(validateWebhookDraft({ ...hook, kind: 'fax' }).ok).toBe(false);
  });

  it('requires a routing key for PagerDuty only', () => {
    const pd = { ...hook, kind: 'pagerduty' };
    expect(validateWebhookDraft(pd).ok).toBe(false);
    expect(validateWebhookDraft({ ...pd, routingKey: 'abc123' }).ok).toBe(true);
    expect(validateWebhookDraft(hook).ok).toBe(true);
  });

  it('rejects a duplicate name regardless of case', () => {
    const r = validateWebhookDraft({ ...hook, name: 'ops slack' }, [hook]);
    expect(r.ok).toBe(false);
    expect(r.problems.join(' ')).toMatch(/already exists/);
  });

  it('stops at the workspace limit', () => {
    const five = Array.from({ length: 5 }, (_, i) => ({ name: `h${i}` }));
    expect(validateWebhookDraft(hook, five).ok).toBe(false);
  });
});

describe('stored webhook', () => {
  it('is marked verified against its own URL', () => {
    const stored = toStoredWebhook({ ...hook, url: ` ${hook.url} ` });
    expect(stored).toMatchObject({
      verified: true,
      verifiedUrl: hook.url,
      url: hook.url,
    });
  });

  it('keeps existing webhooks when appending', () => {
    const existing = [
      { name: 'Old', url: 'https://a.example', kind: 'generic' },
    ];
    const next = appendWebhook(existing, hook);
    expect(next).toHaveLength(2);
    expect(next[0]).toBe(existing[0]);
    expect(next[1].name).toBe('Ops Slack');
  });
});

describe('buildGroup', () => {
  it('needs a name and at least one way to reach someone', () => {
    expect(buildGroup({ name: '', emailContactIds: ['a'] }).ok).toBe(false);
    expect(buildGroup({ name: 'Ops' }).ok).toBe(false);
  });

  it('accepts a webhook-only group, as the product does', () => {
    const r = buildGroup({ name: 'Ops', webhookNames: ['Ops Slack'] });
    expect(r.ok).toBe(true);
    expect(r.group.webhook_names).toEqual(['Ops Slack']);
    expect(r.group.email_contact_ids).toEqual([]);
  });

  it('builds the full stored shape and removes duplicates', () => {
    const r = buildGroup({
      name: ' Platform team ',
      emailContactIds: ['1', '1', '2'],
      whatsappContactIds: ['2'],
      webhookNames: ['Ops Slack', 'Ops Slack'],
      weeklyDigestEmail: true,
    });
    expect(r.group).toMatchObject({
      id: 'onboarding-platform-team',
      name: 'Platform team',
      email_contact_ids: ['1', '2'],
      whatsapp_contact_ids: ['2'],
      webhook_names: ['Ops Slack'],
      weekly_digest_email: true,
      weekly_digest_whatsapp: false,
      weekly_digest_webhooks: false,
    });
  });

  it('stores thresholds only when they differ from the workspace', () => {
    const base = {
      name: 'Ops',
      emailContactIds: ['1'],
      workspaceThresholds: [30, 14, 7, 1, 0],
    };
    expect(
      buildGroup({ ...base, thresholdsText: '30,14,7,1,0' }).group.thresholds
    ).toBeUndefined();
    expect(
      buildGroup({ ...base, thresholdsText: '60, 7' }).group.thresholds
    ).toEqual([60, 7]);
    expect(
      buildGroup({ ...base, thresholdsText: '' }).group.thresholds
    ).toBeUndefined();
  });

  it('reports invalid thresholds', () => {
    const r = buildGroup({
      name: 'Ops',
      emailContactIds: ['1'],
      thresholdsText: 'soon',
    });
    expect(r.ok).toBe(false);
    expect(r.problems.join(' ')).toMatch(/whole number/);
  });
});

describe('upsertGroup', () => {
  const a = { id: 'a', name: 'A', email_contact_ids: ['1'] };
  const b = { id: 'b', name: 'B', email_contact_ids: ['2'] };

  it('adds a new group and leaves the others untouched', () => {
    const out = upsertGroup([a, b], { id: 'c', name: 'C' });
    expect(out).toHaveLength(3);
    expect(out[0]).toBe(a);
    expect(out[1]).toBe(b);
  });

  it('replaces by id, so a retry cannot create a second copy', () => {
    const out = upsertGroup([a, b], { id: 'a', name: 'A2' });
    expect(out).toHaveLength(2);
    expect(out[0].name).toBe('A2');
    expect(out[1]).toBe(b);
  });
});

describe('groupIdFor and describeGroup', () => {
  it('is stable for the same name', () => {
    expect(groupIdFor('Platform Team!')).toBe(groupIdFor('platform team'));
  });

  it('describes who a group reaches', () => {
    const parts = describeGroup(
      {
        email_contact_ids: ['1'],
        whatsapp_contact_ids: ['2'],
        webhook_names: ['Ops Slack'],
      },
      [
        { id: '1', details: { email: 'a@example.com' } },
        { id: '2', details: { phone: '+41790000000' } },
      ]
    );
    expect(parts).toEqual([
      'a@example.com',
      '+41790000000 (WhatsApp)',
      'Ops Slack (webhook)',
    ]);
  });
});
