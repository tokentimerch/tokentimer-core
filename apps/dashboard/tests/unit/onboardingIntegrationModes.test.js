import { describe, expect, it } from 'vitest';
import {
  defaultMode,
  describeSync,
  diffImport,
  providerModes,
  syncFor,
} from '../../src/components/onboarding/integrationModes.js';

const cap = (id, state = 'ready', blockers = []) => ({ id, state, blockers });

describe('providerModes', () => {
  it('offers both paths where the deployment supports auto-sync', () => {
    const m = providerModes(
      { items: [cap('integrations.github'), cap('autosync.github')] },
      'github'
    );
    expect(m.once.available).toBe(true);
    expect(m.sync.available).toBe(true);
  });

  it('offers only one-time import where there is no auto-sync', () => {
    const m = providerModes({ items: [cap('integrations.aws')] }, 'aws');
    expect(m.once.available).toBe(true);
    expect(m.sync).toBe(null);
  });

  it('carries the reason when a path is blocked', () => {
    const m = providerModes(
      {
        items: [
          cap('integrations.gitlab'),
          cap('autosync.gitlab', 'not_entitled', [
            { code: 'PLAN', remediation: 'Upgrade to use auto-sync.' },
          ]),
        ],
      },
      'gitlab'
    );
    expect(m.sync.available).toBe(false);
    expect(m.sync.blocker.remediation).toMatch(/Upgrade/);
    expect(m.once.available).toBe(true);
  });

  it('treats unknown capability data as available rather than blocking', () => {
    expect(providerModes(null, 'github').once.available).toBe(true);
  });
});

describe('defaultMode', () => {
  it('prefers sync only when it is usable', () => {
    expect(defaultMode({ once: {}, sync: { available: true } })).toBe('sync');
    expect(defaultMode({ once: {}, sync: { available: false } })).toBe('once');
    expect(defaultMode({ once: {}, sync: null })).toBe('once');
  });
});

describe('describeSync', () => {
  const base = { enabled: true, frequency: 'daily', failures: 0 };

  it('reports each state in plain words', () => {
    expect(describeSync({ ...base, running: true }).label).toMatch(/Scanning/);
    expect(describeSync({ ...base, enabled: false }).label).toBe('Paused');
    expect(describeSync(base).label).toMatch(/first run/);
    expect(
      describeSync({
        ...base,
        lastStatus: 'success',
        lastSyncAt: 'x',
        lastItems: 12,
      }).detail
    ).toMatch(/12 items/);
    expect(
      describeSync({ ...base, lastStatus: 'partial', lastSyncAt: 'x' }).tone
    ).toBe('orange');
  });

  it('says how many times in a row a connection failed', () => {
    const r = describeSync({
      ...base,
      lastStatus: 'failed',
      lastSyncAt: 'x',
      failures: 3,
    });
    expect(r.tone).toBe('red');
    expect(r.detail).toMatch(/3 times/);
  });

  it('is safe with nothing', () => {
    expect(describeSync(null)).toBe(null);
  });
});

describe('diffImport', () => {
  const before = {
    assets: { total: 2 },
    autoSync: { items: [{ id: 'a', lastSyncAt: 't1' }] },
  };

  it('counts new assets from the server totals', () => {
    expect(
      diffImport(before, {
        assets: { total: 7 },
        autoSync: { items: before.autoSync.items },
      }).assets
    ).toBe(5);
    expect(diffImport(before, { assets: { total: 1 } }).assets).toBe(0);
  });

  it('finds a connection created while the modal was open', () => {
    const after = {
      assets: { total: 2 },
      autoSync: { items: [{ id: 'a', lastSyncAt: 't1' }, { id: 'b' }] },
    };
    expect(diffImport(before, after).newConnections.map(c => c.id)).toEqual([
      'b',
    ]);
  });

  it('finds a run that finished while the modal was open', () => {
    const after = {
      assets: { total: 2 },
      autoSync: { items: [{ id: 'a', lastSyncAt: 't2' }] },
    };
    expect(diffImport(before, after).ranSince.map(c => c.id)).toEqual(['a']);
  });

  it('reports nothing when nothing happened', () => {
    const r = diffImport(before, before);
    expect(r).toEqual({ assets: 0, newConnections: [], ranSince: [] });
  });
});

describe('syncFor', () => {
  it('filters by provider', () => {
    const s = {
      autoSync: { items: [{ provider: 'github' }, { provider: 'gitlab' }] },
    };
    expect(syncFor(s, 'github')).toHaveLength(1);
    expect(syncFor(null, 'github')).toEqual([]);
  });
});
