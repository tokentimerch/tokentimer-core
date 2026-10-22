import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import {
  IMPORT_SOURCE_LOGOS,
  IMPORT_SOURCE_NAMES,
  ImportSourceLogo,
  isSourceVisible,
  resolveStartSource,
} from '../../src/components/imports/importSources.jsx';
import {
  describeSyncGroups,
  formatNextSync,
} from '../../src/components/imports/syncGroupLine.js';

const PUBLIC = resolve(__dirname, '../../public');

describe('provider logos', () => {
  const entries = Object.entries(IMPORT_SOURCE_LOGOS);

  it('covers every provider and names each one', () => {
    expect(Object.keys(IMPORT_SOURCE_NAMES).sort()).toEqual(
      entries.map(([k]) => k).sort()
    );
  });

  for (const [key, src] of entries) {
    it(`${key} points at a file that ships with the app`, () => {
      expect(src.startsWith('/')).toBe(true);
      expect(existsSync(resolve(PUBLIC, src.slice(1)))).toBe(true);
    });
  }

  it.each(['azure', 'azure-ad'])(
    '%s has its own crisp SVG with a viewBox and no remote fetch',
    key => {
      const file = resolve(PUBLIC, IMPORT_SOURCE_LOGOS[key].slice(1));
      const svg = readFileSync(file, 'utf8');
      expect(file.endsWith('.svg')).toBe(true);
      expect(svg).toMatch(/viewBox="0 0 48 48"/);
      expect(svg).not.toMatch(/https?:\/\/(?!www\.w3\.org)/);
      expect(svg).not.toMatch(/<image/);
    }
  );

  it('the two Azure sources no longer share a logo or a badge', () => {
    expect(IMPORT_SOURCE_LOGOS.azure).not.toBe(IMPORT_SOURCE_LOGOS['azure-ad']);
    const { container } = render(
      <ChakraProvider>
        <ImportSourceLogo sourceKey='azure-ad' />
      </ChakraProvider>
    );
    expect(container.querySelectorAll('img')).toHaveLength(1);
    expect(container.querySelector('svg')).toBeNull();
    expect(container.querySelector('img').getAttribute('alt')).toBe('');
  });

  it('renders nothing for an unknown source', () => {
    const { container } = render(
      <ChakraProvider>
        <ImportSourceLogo sourceKey='nope' />
      </ChakraProvider>
    );
    expect(container.textContent).toBe('');
    expect(screen.queryByRole('img')).toBeNull();
  });
});

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
