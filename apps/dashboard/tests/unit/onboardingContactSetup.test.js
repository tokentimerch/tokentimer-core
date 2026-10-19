import { describe, expect, it } from 'vitest';
import {
  findContactByEmail,
  onboardingGroupId,
  planContactSetup,
  splitName,
} from '../../src/components/onboarding/contactSetup.js';
import {
  addRecipientToGroup,
  appendContactGroup,
} from '../../src/utils/onboardingActions.js';

const ana = { id: 'c1', details: { email: 'Ana@Example.com' } };
const phoneOnly = { id: 'c2', details: {} };

describe('planContactSetup', () => {
  it('is ready when the default group already reaches an email recipient', () => {
    expect(
      planContactSetup({
        groups: [{ id: 'g1', email_contact_ids: ['c1'] }],
        contacts: [ana],
        defaultGroupId: 'g1',
      })
    ).toEqual({ kind: 'ready', groupId: 'g1' });
  });

  it('only changes the default when a usable group already exists', () => {
    const plan = planContactSetup({
      groups: [
        { id: 'g0', email_contact_ids: ['c2'] },
        { id: 'g1', email_contact_ids: ['c1'] },
      ],
      contacts: [ana, phoneOnly],
      defaultGroupId: 'g0',
    });
    expect(plan.kind).toBe('set_default');
    expect(plan.groupId).toBe('g1');
  });

  it('adds a recipient to a default group that has none', () => {
    expect(
      planContactSetup({
        groups: [{ id: 'g0', email_contact_ids: [] }],
        contacts: [],
        defaultGroupId: 'g0',
      })
    ).toEqual({ kind: 'add_to_default', groupId: 'g0' });
  });

  it('creates a group only when there is nothing to reuse', () => {
    expect(
      planContactSetup({ groups: [], contacts: [], defaultGroupId: null })
    ).toEqual({ kind: 'create' });
    expect(
      planContactSetup({
        groups: [{ id: 'g9', webhook_names: ['x'] }],
        contacts: [ana],
        defaultGroupId: null,
      }).kind
    ).toBe('create');
  });
});

describe('contact helpers', () => {
  it('reuses an existing contact regardless of email case', () => {
    expect(findContactByEmail([ana], ' ana@example.com ')).toBe(ana);
    expect(findContactByEmail([ana], '')).toBeNull();
    expect(findContactByEmail([phoneOnly], 'x@y.z')).toBeNull();
  });

  it('derives a stable group id from the email', () => {
    expect(onboardingGroupId('Ana@Example.com')).toBe(
      onboardingGroupId(' ana@example.com ')
    );
    expect(onboardingGroupId('ana@example.com')).toMatch(/^onboarding-/);
  });

  it('splits names with a safe fallback', () => {
    expect(splitName('Ana Maria Lopez', 'a@b.c')).toEqual({
      first_name: 'Ana',
      last_name: 'Maria Lopez',
    });
    expect(splitName('Ana', 'a@b.c').last_name).toBe('Contact');
    expect(splitName('', 'ops@example.com').first_name).toBe('ops');
  });
});

describe('group writes preserve existing data', () => {
  const existing = [
    {
      id: 'g1',
      name: 'Platform',
      email_contact_ids: ['c1'],
      thresholds: [90, 30],
      webhook_names: ['slack'],
      weekly_digest_email: true,
    },
  ];

  it('appends without altering existing groups', () => {
    const next = appendContactGroup(existing, {
      id: 'new',
      name: 'Ops',
      emailContactIds: ['c9'],
    });
    expect(next).toHaveLength(2);
    expect(next[0]).toEqual(existing[0]);
    expect(next[1]).toMatchObject({ id: 'new', email_contact_ids: ['c9'] });
    expect(existing).toHaveLength(1);
  });

  it('adds a recipient while keeping members and settings', () => {
    const next = addRecipientToGroup(existing, 'g1', 'c2');
    expect(next[0].email_contact_ids).toEqual(['c1', 'c2']);
    expect(next[0].thresholds).toEqual([90, 30]);
    expect(next[0].webhook_names).toEqual(['slack']);
    expect(
      addRecipientToGroup(existing, 'g1', 'c1')[0].email_contact_ids
    ).toEqual(['c1']);
  });
});
