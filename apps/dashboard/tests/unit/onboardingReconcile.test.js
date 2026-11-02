import { describe, expect, it } from 'vitest';
import { reconcilePending } from '../../src/components/onboarding/reconcile.js';

const marker = (kind, identity) => ({
  id: 'op-1',
  kind,
  identityKey: JSON.stringify(identity),
});

describe('reconcilePending', () => {
  it('does nothing without a pending operation or a summary', () => {
    expect(
      reconcilePending({ session: { progress: {} }, summary: {} })
    ).toBeNull();
    expect(
      reconcilePending({
        session: {
          progress: { pending: marker('monitor', { url: 'https://a.b' }) },
        },
        summary: null,
      })
    ).toBeNull();
  });

  it('adopts a monitor that exists and clears the marker', () => {
    const patch = reconcilePending({
      session: {
        progress: {
          skipped: ['recipients'],
          pending: marker('monitor', { url: 'https://Example.com' }),
        },
        operationRefs: { tokenIds: [1] },
      },
      summary: {
        monitors: {
          items: [{ id: 'm1', url: 'https://example.com', tokenId: 7 }],
        },
      },
    });
    expect(patch.progress).toEqual({ skipped: ['recipients'] });
    expect(patch.operation_refs).toMatchObject({
      monitorUrl: 'https://Example.com',
      monitorIds: ['m1'],
      tokenIds: [1, 7],
    });
  });

  it('keeps the marker when the monitor does not exist yet', () => {
    expect(
      reconcilePending({
        session: {
          progress: {
            pending: marker('monitor', { url: 'https://a.example' }),
          },
        },
        summary: { monitors: { items: [] } },
      })
    ).toBeNull();
  });

  it('closes a contact-group operation only when a usable default exists', () => {
    const session = {
      progress: {
        pending: marker('contact_group', {
          email: 'a@b.c',
          groupId: 'onboarding-a',
        }),
      },
      operationRefs: {},
    };
    expect(
      reconcilePending({
        session,
        summary: {
          alerts: { contactGroups: { defaultHasEmailRecipient: false } },
        },
      })
    ).toBeNull();
    const patch = reconcilePending({
      session,
      summary: {
        alerts: { contactGroups: { defaultHasEmailRecipient: true } },
      },
    });
    expect(patch.progress.pending).toBeUndefined();
    expect(patch.operation_refs.contactGroupId).toBe('onboarding-a');
  });

  it('leaves unverifiable operations for the step to reconcile', () => {
    expect(
      reconcilePending({
        session: { progress: { pending: marker('asset', { name: 'Key' }) } },
        summary: { monitors: { items: [] } },
      })
    ).toBeNull();
  });

  it('survives a corrupt marker', () => {
    expect(
      reconcilePending({
        session: {
          progress: { pending: { id: 'x', kind: 'monitor', identityKey: '{' } },
        },
        summary: { monitors: { items: [] } },
      })
    ).toBeNull();
  });
});
