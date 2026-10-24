import { describe, expect, it } from 'vitest';
import {
  MAX_ITEMS,
  canTickGoal,
  describeNoToken,
  describeNoCertificate,
  describeTicks,
  describeUngrouped,
  isDefaultOnlyGoal,
  itemsToChange,
  nextGroupIds,
  planSessionItems,
  tickState,
} from '../../src/components/onboarding/groupAttachment.js';

const item = (id, groupIds, kind = 'website') => ({ id, kind, groupIds });

describe('tickState', () => {
  it('is all, some or none by how many items carry the group', () => {
    const items = [item('1', ['a']), item('2', ['a', 'b']), item('3', [])];
    expect(tickState('a', items.slice(0, 2))).toBe('all');
    expect(tickState('a', items)).toBe('some');
    expect(tickState('c', items)).toBe('none');
    expect(tickState('a', [])).toBe('none');
  });

  it('compares ids as text', () => {
    expect(tickState(7, [item('1', ['7'])])).toBe('all');
  });
});

describe('nextGroupIds and itemsToChange', () => {
  it('adds in canonical order and removes without touching the rest', () => {
    expect(nextGroupIds(['ops'], 'billing', true)).toEqual(['billing', 'ops']);
    expect(nextGroupIds(['billing', 'ops'], 'ops', false)).toEqual(['billing']);
    expect(nextGroupIds(['ops'], 'ops', true)).toEqual(['ops']);
  });

  it('holds one group per item when plural writes are off', () => {
    expect(nextGroupIds(['ops'], 'billing', true, false)).toEqual(['billing']);
    expect(nextGroupIds(['ops', 'x'], 'ops', false, false)).toEqual(['x']);
  });

  it('lists only the items that need a write', () => {
    const items = [item('1', ['a']), item('2', [])];
    expect(itemsToChange('a', items, true).map(i => i.id)).toEqual(['2']);
    expect(itemsToChange('a', items, false).map(i => i.id)).toEqual(['1']);
  });
});

describe('planSessionItems', () => {
  const summary = ids => ({
    references: {
      tokenIds: { existing: ids },
      assetTokenIds: { existing: [] },
      monitorIds: { existing: [] },
    },
    monitors: { items: [] },
  });

  it('offers nothing for goals that create no attachable items', () => {
    for (const goal of ['alerting', 'import_file', 'import_integration']) {
      expect(canTickGoal(goal)).toBe(false);
      const plan = planSessionItems({
        goal,
        refs: { tokenIds: [1] },
        summary: summary([1]),
      });
      expect(plan).toEqual({
        websites: [],
        assets: [],
        certificates: [],
        noToken: 0,
        blocked: null,
      });
    }
  });

  it('plans a CertOps pick from the certificates of its own source', () => {
    const certops = {
      sessionCertificates: [
        { certificateId: 'c1', tokenId: 31, source: 'issue' },
        { certificateId: 'c2', tokenId: 32, source: 'issue' },
        { certificateId: 'c3', tokenId: null, source: 'issue' },
        { certificateId: 'c4', tokenId: 33, source: 'publish' },
        { certificateId: 'c5', tokenId: 34, source: 'enrollment' },
      ],
    };
    const plan = goal =>
      planSessionItems({ goal, refs: {}, summary: { certops } });
    expect(plan('certops_automate')).toEqual({
      websites: [],
      assets: [],
      certificates: ['31', '32'],
      noToken: 1,
      blocked: null,
    });
    expect(plan('certops_vault').certificates).toEqual(['33']);
    expect(plan('certops_adcs').certificates).toEqual(['34']);
  });

  it('plans nothing for a CertOps pick that created no certificate', () => {
    for (const summary of [
      null,
      { certops: 'unknown' },
      { certops: { sessionCertificates: [] } },
    ]) {
      expect(
        planSessionItems({ goal: 'certops_automate', refs: {}, summary })
      ).toEqual({
        websites: [],
        assets: [],
        certificates: [],
        noToken: 0,
        blocked: null,
      });
    }
  });

  it('ignores website refs for a CertOps pick and repeats no token', () => {
    const plan = planSessionItems({
      goal: 'certops_automate',
      refs: { tokenIds: [1], monitorIds: ['m1'] },
      summary: {
        certops: {
          sessionCertificates: [
            { certificateId: 'c1', tokenId: 5, source: 'issue' },
            { certificateId: 'c2', tokenId: 5, source: 'issue' },
          ],
        },
      },
    });
    expect(plan.certificates).toEqual(['5']);
    expect(plan.websites).toEqual([]);
  });

  it('blocks a CertOps pick past the cap', () => {
    const many = Array.from({ length: MAX_ITEMS + 1 }, (_, i) => ({
      certificateId: `c${i}`,
      tokenId: i + 1,
      source: 'issue',
    }));
    expect(
      planSessionItems({
        goal: 'certops_automate',
        refs: {},
        summary: { certops: { sessionCertificates: many } },
      }).blocked
    ).toBe('cap');
  });

  it('keeps only the alerting goal out of the ticking goals', () => {
    expect(canTickGoal('alerting')).toBe(false);
    expect(isDefaultOnlyGoal('alerting')).toBe(true);
    expect(isDefaultOnlyGoal('certops_observe')).toBe(false);
    expect(isDefaultOnlyGoal('import_file')).toBe(false);
    for (const goal of [
      'certops_observe',
      'certops_automate',
      'certops_adcs',
      'certops_vault',
    ]) {
      expect(canTickGoal(goal)).toBe(true);
    }
  });

  it('splits website certificates from asset-step ids', () => {
    const plan = planSessionItems({
      goal: 'track_asset',
      refs: { tokenIds: [1, 2, 3], assetTokenIds: [3] },
      summary: {
        ...summary([1, 2, 3]),
        references: {
          tokenIds: { existing: [1, 2, 3] },
          assetTokenIds: { existing: [3] },
          monitorIds: { existing: [] },
        },
      },
    });
    expect(plan.websites).toEqual(['1', '2']);
    expect(plan.assets).toEqual(['3']);
    expect(plan.blocked).toBeNull();
  });

  it('drops ids that no longer exist', () => {
    const plan = planSessionItems({
      goal: 'monitor_https',
      refs: { tokenIds: [1, 2], monitorIds: ['m1', 'm2'] },
      summary: {
        ...summary([1]),
        references: {
          tokenIds: { existing: [1] },
          monitorIds: { existing: ['m1'] },
        },
      },
    });
    expect(plan.websites).toEqual(['1']);
    expect(plan.blocked).toBeNull();
  });

  it('adds the certificate of a listed session monitor', () => {
    const plan = planSessionItems({
      goal: 'monitor_https',
      refs: { monitorIds: ['m1'] },
      summary: {
        references: { monitorIds: { existing: ['m1'] } },
        monitors: { items: [{ id: 'm1', tokenId: 41 }] },
      },
    });
    expect(plan.websites).toEqual(['41']);
  });

  it('blocks past the cap', () => {
    const many = Array.from({ length: MAX_ITEMS + 1 }, (_, i) => i + 1);
    expect(
      planSessionItems({
        goal: 'track_asset',
        refs: { tokenIds: many, assetTokenIds: many },
        summary: {
          references: {
            tokenIds: { existing: many },
            assetTokenIds: { existing: many },
          },
        },
      }).blocked
    ).toBe('cap');
  });

  it('counts session websites that have no certificate record', () => {
    const plan = planSessionItems({
      goal: 'monitor_https',
      refs: { tokenIds: [1], monitorIds: ['m1', 'm2'] },
      summary: {
        references: { tokenIds: { existing: [1] } },
        monitors: {
          items: [
            { id: 'm1', tokenId: 1 },
            { id: 'm2', tokenId: null },
            { id: 'other', tokenId: null },
          ],
        },
      },
    });
    expect(plan.noToken).toBe(1);
    expect(plan.websites).toEqual(['1']);
    expect(plan.blocked).toBeNull();
  });

  it('reads a session saved before assetTokenIds as website certificates', () => {
    const plan = planSessionItems({
      goal: 'monitor_https',
      refs: { tokenIds: [1, 2], monitorIds: ['m1'] },
      summary: {
        references: { tokenIds: { existing: [1, 2] } },
        monitors: { items: [{ id: 'm1', tokenId: 1 }] },
      },
    });
    expect(plan.websites).toEqual(['1', '2']);
    expect(plan.assets).toEqual([]);
  });
  it('splits a legacy asset-goal session by which tokens a monitor points at', () => {
    const plan = planSessionItems({
      goal: 'track_asset',
      refs: { tokenIds: [1, 2, 3], monitorIds: ['m1'] },
      summary: {
        references: { tokenIds: { existing: [1, 2, 3] } },
        monitors: { items: [{ id: 'm1', tokenId: 1 }] },
      },
    });
    expect(plan.websites).toEqual(['1']);
    expect(plan.assets).toEqual(['2', '3']);
  });

  it('treats a legacy session without monitors as assets only', () => {
    const plan = planSessionItems({
      goal: 'track_asset',
      refs: { tokenIds: [5] },
      summary: { references: { tokenIds: { existing: [5] } } },
    });
    expect(plan.assets).toEqual(['5']);
    expect(plan.websites).toEqual([]);
  });
});
describe('sentences', () => {
  const sites = [item('1', [])];
  const assets = [item('2', [], 'asset')];
  const grouped = [item('3', ['a'])];

  it('describes what a tick means per kind of item', () => {
    expect(
      describeTicks({ goal: 'monitor_https', items: sites, defaultName: 'Ops' })
    ).toBe(
      'Ticked groups receive alerts for the websites you added in this guide. 1 website has no group and uses the workspace default group "Ops".'
    );
    expect(
      describeTicks({
        goal: 'monitor_https',
        items: grouped,
        defaultName: 'Ops',
      })
    ).toBe(
      'Ticked groups receive alerts for the websites you added in this guide. Anything without a group uses the workspace default group "Ops".'
    );
    expect(
      describeTicks({ goal: 'track_asset', items: assets, defaultName: 'Ops' })
    ).toMatch(/for the assets you added/);
    expect(
      describeTicks({
        goal: 'track_asset',
        items: [...sites, ...assets],
        defaultName: 'Ops',
      })
    ).toMatch(/for the websites and assets you added/);
  });

  it('never invents a default group', () => {
    expect(
      describeTicks({ goal: 'monitor_https', items: grouped, defaultName: '' })
    ).toMatch(/No default group is set/);
    expect(
      describeUngrouped({ items: [sites[0], sites[0]], defaultName: '' })
    ).toMatch(/no recipient until a group is set/);
  });

  it('words the missing certificate note for one and many', () => {
    expect(describeNoToken(0)).toBe('');
    expect(describeNoToken(1)).toMatch(
      /^1 website you added has no certificate record yet, so its groups/
    );
    expect(describeNoToken(2)).toMatch(
      /^2 websites you added have no certificate record yet, so their groups/
    );
  });

  it('words the ungrouped note for one and many', () => {
    expect(describeUngrouped({ items: sites, defaultName: 'Ops' })).toBe(
      '1 website has no group and uses the workspace default group "Ops".'
    );
    expect(
      describeUngrouped({
        items: [...assets, ...assets, ...assets],
        defaultName: 'Ops',
      })
    ).toBe('3 assets have no group and use the workspace default group "Ops".');
    expect(describeUngrouped({ items: [], defaultName: 'Ops' })).toBe('');
    expect(
      describeUngrouped({ items: [...sites, ...assets], defaultName: 'Ops' })
    ).toBe('2 items have no group and use the workspace default group "Ops".');
  });

  it('explains websites without a certificate record instead of asking to add something', () => {
    expect(
      describeTicks({
        goal: 'monitor_https',
        items: [],
        defaultName: 'Ops',
        noToken: 2,
      })
    ).toMatch(/^2 websites you added have no certificate record yet/);
  });

  it('makes no tick claim for goals without attachable items', () => {
    const text = describeTicks({
      goal: 'alerting',
      items: [],
      defaultName: 'Ops',
    });
    expect(text).not.toMatch(/Ticked/);
  });

  it('words certificates for the CertOps picks', () => {
    const certs = [item('9', [], 'certificate')];
    expect(
      describeTicks({
        goal: 'certops_automate',
        items: certs,
        defaultName: 'Ops',
      })
    ).toBe(
      'Ticked groups receive alerts for the certificates you added in this guide. 1 certificate has no group and uses the workspace default group "Ops".'
    );
  });

  it('says nothing carries a group yet when a CertOps pick made no certificate', () => {
    expect(
      describeTicks({ goal: 'certops_vault', items: [], defaultName: 'Ops' })
    ).toBe(
      'Nothing was created yet that could carry a group: the workspace default group "Ops" is used.'
    );
    expect(describeNoCertificate('')).toMatch(/no default group is set/);
    expect(
      describeTicks({
        goal: 'certops_adcs',
        items: [],
        defaultName: 'Ops',
        noToken: 2,
      })
    ).toBe(
      '2 certificates from this setup have no inventory record yet, so their groups cannot be set here.'
    );
  });

  it('tells a website without a certificate record which group it uses', () => {
    expect(describeNoToken(1, 'monitor_https', 'Ops')).toBe(
      '1 website you added has no certificate record yet, so its groups cannot be set here. Until then it uses the workspace default group "Ops"; you can change that in Alert Preferences.'
    );
  });
});
