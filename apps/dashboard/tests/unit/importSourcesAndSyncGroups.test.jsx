import { describe, expect, it } from 'vitest';

import {
  isSourceVisible,
  resolveStartSource,
} from '../../src/components/imports/importSources.jsx';
import {
  describeSyncGroups,
  formatNextSync,
} from '../../src/components/imports/syncGroupLine.js';

describe('visible import sources', () => {
  it('shows everything by default and starts on File', () => {
    expect(isSourceVisible('file')).toBe(true);
    expect(resolveStartSource()).toBe('file');
  });

  it('hides sources and starts on the first visible one', () => {
    const hidden = ['file', 'cert-pem'];
    expect(isSourceVisible('file', { hiddenSources: hidden })).toBe(false);
    expect(isSourceVisible('github', { hiddenSources: hidden })).toBe(true);
    expect(resolveStartSource({ hiddenSources: hidden })).toBe('vault');
  });

  it('honours an allow list and a requested start', () => {
    expect(isSourceVisible('aws', { sourceChoices: ['file'] })).toBe(false);
    expect(resolveStartSource({ initialSource: 'gcp' })).toBe('gcp');
    expect(
      resolveStartSource({ initialSource: 'gcp', hiddenSources: ['gcp'] })
    ).toBe('file');
  });
});

describe('alerts for synced items', () => {
  const groups = [
    { id: 'g1', name: 'Platform' },
    { id: 'g2', name: 'Security' },
  ];

  it('names the groups chosen at import', () => {
    expect(describeSyncGroups(['g2', 'g1'], groups, 'g1')).toBe(
      'Platform, Security'
    );
  });

  it('says it is the workspace default when none is chosen', () => {
    expect(describeSyncGroups([], groups, 'g1')).toBe(
      'the workspace default group (Platform)'
    );
    expect(describeSyncGroups(undefined, [], '')).toBe(
      'the workspace default group'
    );
  });

  it('ignores a group that no longer exists', () => {
    expect(describeSyncGroups(['gone'], groups, 'g2')).toBe(
      'the workspace default group (Security)'
    );
  });

  it('formats the next scan or nothing', () => {
    expect(formatNextSync(null)).toBe('');
    expect(formatNextSync('nope')).toBe('');
    expect(formatNextSync('2030-01-02T09:00:00.000Z')).not.toBe('');
  });
});
