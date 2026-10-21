import { describe, expect, it } from 'vitest';
import {
  ALERT_AFTER_MAX,
  CHECK_INTERVALS,
  DEFAULT_MONITOR_SETTINGS,
  DISCOVERY_PAGE_SIZE,
  MAX_STAGED_WEBSITES,
  MAX_SAVED_REFS,
  MAX_WEBSITE_LENGTH,
  discoveredHostnames,
  discoveryErrorMessage,
  discoveryNotices,
  filterHostnames,
  hostToUrl,
  mergeRefs,
  normalizeRootDomain,
  paginate,
  parseSections,
  selectableHosts,
  stageMany,
  stageWebsite,
  validateMonitorSettings,
} from '../../src/components/onboarding/monitorModel.js';

describe('monitor settings', () => {
  it('offers exactly the intervals the API accepts', () => {
    expect(CHECK_INTERVALS.map(i => i.value)).toEqual([
      '1min',
      '5min',
      '30min',
      'hourly',
      'daily',
    ]);
  });

  it('defaults to what the wizard always used, so nothing changes silently', () => {
    expect(DEFAULT_MONITOR_SETTINGS).toEqual({
      checkInterval: 'hourly',
      healthCheckEnabled: true,
      alertAfterFailures: 2,
    });
    expect(validateMonitorSettings().ok).toBe(true);
  });

  it('rejects an interval the API would store unchecked', () => {
    const r = validateMonitorSettings({ checkInterval: 'every-second' });
    expect(r.ok).toBe(false);
    expect(r.errors.checkInterval).toBeTruthy();
  });

  it('requires a whole number of failures from 1 to 10 when alerts are on', () => {
    for (const bad of [0, 11, 2.5, 'x', null]) {
      expect(
        validateMonitorSettings({ alertAfterFailures: bad }).ok,
        String(bad)
      ).toBe(false);
    }
    expect(validateMonitorSettings({ alertAfterFailures: 1 }).ok).toBe(true);
    expect(
      validateMonitorSettings({ alertAfterFailures: ALERT_AFTER_MAX }).ok
    ).toBe(true);
  });

  it('ignores the failure count when down alerts are off', () => {
    const r = validateMonitorSettings({
      healthCheckEnabled: false,
      alertAfterFailures: 99,
    });
    expect(r.ok).toBe(true);
    expect(r.value.healthCheckEnabled).toBe(false);
  });
});

describe('stageWebsite', () => {
  it('normalizes an address and adds it', () => {
    const r = stageWebsite([], 'Example.com/');
    expect(r.ok).toBe(true);
    expect(r.list).toEqual(['https://example.com']);
  });

  it('refuses a non-HTTPS or empty address', () => {
    expect(stageWebsite([], 'http://example.com').ok).toBe(false);
    expect(stageWebsite([], '   ').ok).toBe(false);
    expect(stageWebsite([], 'not a url').ok).toBe(false);
  });

  it('refuses a duplicate regardless of case or trailing slash', () => {
    const r = stageWebsite(['https://example.com'], 'HTTPS://EXAMPLE.COM/');
    expect(r.ok).toBe(false);
    expect(r.duplicate).toBe(true);
  });

  it('stops at the batch limit with a message', () => {
    const full = Array.from(
      { length: MAX_STAGED_WEBSITES },
      (_, i) => `https://s${i}.example.com`
    );
    const r = stageWebsite(full, 'https://more.example.com');
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/up to 50/);
  });

  it('refuses an address too long to be saved with the setup progress', () => {
    const long = `https://example.com/${'a'.repeat(MAX_WEBSITE_LENGTH)}`;
    const r = stageWebsite([], long);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/too long/);
    const edge = `https://example.com/${'a'.repeat(MAX_WEBSITE_LENGTH - 20)}`;
    expect(edge.length).toBe(MAX_WEBSITE_LENGTH);
    expect(stageWebsite([], edge).ok).toBe(true);
  });
});

describe('mergeRefs', () => {
  it('adds new ids without repeats and ignores empty ones', () => {
    expect(mergeRefs(['a', 'b'], ['b', null, 'c', undefined])).toEqual([
      'a',
      'b',
      'c',
    ]);
    expect(mergeRefs(undefined, ['a'])).toEqual(['a']);
  });

  it('keeps the newest ids within what the saved progress can hold', () => {
    const old = Array.from({ length: 90 }, (_, i) => `old-${i}`);
    const added = Array.from({ length: 50 }, (_, i) => `new-${i}`);
    const merged = mergeRefs(old, added);
    expect(merged).toHaveLength(MAX_SAVED_REFS);
    expect(merged.at(-1)).toBe('new-49');
    expect(merged).not.toContain('old-0');
    expect(merged).toContain('old-40');
  });
});

describe('stageMany', () => {
  it('reports what was added, duplicated and left out', () => {
    const start = ['https://a.example.com'];
    const r = stageMany(start, [
      'a.example.com',
      'b.example.com',
      'b.example.com',
    ]);
    expect(r.list).toEqual(['https://a.example.com', 'https://b.example.com']);
    expect(r.added).toBe(1);
    expect(r.duplicates).toBe(2);
    expect(r.overLimit).toBe(0);
  });

  it('counts how many did not fit under the limit', () => {
    const inputs = Array.from(
      { length: MAX_STAGED_WEBSITES + 5 },
      (_, i) => `s${i}.example.com`
    );
    const r = stageMany([], inputs);
    expect(r.list).toHaveLength(MAX_STAGED_WEBSITES);
    expect(r.overLimit).toBe(5);
  });
});

describe('domain discovery helpers', () => {
  it('reduces whatever the user pasted to a root domain', () => {
    expect(normalizeRootDomain('https://www.Example.com/path?x=1')).toBe(
      'example.com'
    );
    expect(normalizeRootDomain('example.com.')).toBe('example.com');
    expect(normalizeRootDomain('localhost')).toBeNull();
    expect(normalizeRootDomain('')).toBeNull();
    expect(normalizeRootDomain('bad domain.com')).toBeNull();
  });

  it('keeps only hostnames inside the root domain, without wildcards', () => {
    const hosts = discoveredHostnames(
      [
        {
          name: 'api.example.com',
          domains: ['api.example.com', '*.example.com'],
        },
        { name: 'example.com' },
        { name: 'evilexample.com' },
        { name: 'x.other.org' },
        'WWW.example.com.',
        { domains: ['b.example.com', 'a.example.com'] },
      ],
      'example.com'
    );
    expect(hosts).toEqual([
      'a.example.com',
      'api.example.com',
      'b.example.com',
      'example.com',
      'www.example.com',
    ]);
  });

  it('returns nothing for an unusable root or response', () => {
    expect(discoveredHostnames([{ name: 'a.example.com' }], 'nope')).toEqual(
      []
    );
    expect(discoveredHostnames(null, 'example.com')).toEqual([]);
  });

  it('turns a hostname into an https address', () => {
    expect(hostToUrl('a.example.com')).toBe('https://a.example.com');
  });
});

describe('section labels', () => {
  it('splits, trims and de-duplicates comma separated labels', () => {
    expect(parseSections(' prod, public ,prod,, ').labels).toEqual([
      'prod',
      'public',
    ]);
    expect(parseSections('').labels).toEqual([]);
  });

  it('refuses more labels than the API accepts', () => {
    const many = Array.from({ length: 51 }, (_, i) => `s${i}`).join(',');
    expect(parseSections(many).ok).toBe(false);
    const r = validateMonitorSettings({ section: many });
    expect(r.ok).toBe(false);
    expect(r.errors.section).toBeTruthy();
  });

  it('only sends sections when some were given', () => {
    expect(validateMonitorSettings({}).value).not.toHaveProperty('section');
    expect(validateMonitorSettings({ section: 'a, b' }).value.section).toEqual([
      'a',
      'b',
    ]);
  });
});

describe('found website list', () => {
  const hosts = ['api.example.com', 'www.example.com', 'mail.example.com'];

  it('filters by a case insensitive fragment', () => {
    expect(filterHostnames(hosts, ' API ')).toEqual(['api.example.com']);
    expect(filterHostnames(hosts, '')).toEqual(hosts);
    expect(filterHostnames(hosts, 'zzz')).toEqual([]);
    expect(filterHostnames(null, 'a')).toEqual([]);
  });

  it('pages in blocks of 50 and clamps the page', () => {
    const many = Array.from({ length: 120 }, (_, i) => `h${i}.example.com`);
    const first = paginate(many, 0);
    expect(DISCOVERY_PAGE_SIZE).toBe(50);
    expect(first).toMatchObject({ pages: 3, from: 1, to: 50, total: 120 });
    expect(first.items).toHaveLength(50);
    const last = paginate(many, 99);
    expect(last).toMatchObject({ page: 2, from: 101, to: 120 });
    expect(last.items).toHaveLength(20);
    expect(paginate([], 0)).toMatchObject({ pages: 1, from: 0, to: 0 });
  });

  it('selects across the whole filtered list, skipping taken hosts, within the room left', () => {
    const taken = h => h === 'www.example.com';
    expect(selectableHosts(hosts, taken, 10)).toEqual([
      'api.example.com',
      'mail.example.com',
    ]);
    expect(selectableHosts(hosts, taken, 1)).toEqual(['api.example.com']);
    expect(selectableHosts(hosts, taken, 0)).toEqual([]);
  });
});

describe('discovery wording', () => {
  it('words a missing tool without naming tools or paths', () => {
    const m = discoveryErrorMessage({
      code: 'DOMAIN_CHECKER_TOOL_MISSING',
      message: 'spawn subfinder ENOENT',
    });
    expect(m).toBe(
      'Website discovery is not available on this server. Add websites by address instead.'
    );
    expect(m).not.toMatch(/subfinder|ENOENT/i);
  });

  it('words busy, timeout, rate limit and invalid domain', () => {
    expect(
      discoveryErrorMessage({
        code: 'DOMAIN_CHECKER_BUSY',
        retryAfterSeconds: 60,
      })
    ).toMatch(/already running.*in about 60s/);
    expect(discoveryErrorMessage({ code: 'DOMAIN_CHECKER_BUSY' })).toMatch(
      /in a minute/
    );
    expect(discoveryErrorMessage({ code: 'DOMAIN_CHECKER_TIMEOUT' })).toMatch(
      /took too long/
    );
    expect(
      discoveryErrorMessage({
        code: 'DOMAIN_CHECKER_RATE_LIMITED',
        retryAfterSeconds: 12.2,
      })
    ).toMatch(/Too many searches.*about 13s/);
    expect(discoveryErrorMessage({ status: 429 })).toMatch(/Too many searches/);
    expect(discoveryErrorMessage({ code: 'INVALID_DOMAIN' })).toBe(
      'Enter a domain such as example.com.'
    );
    expect(discoveryErrorMessage({ code: 'DOMAIN_CHECKER_FAILED' })).toMatch(
      /could not finish/
    );
  });

  it('falls back to the error message, then to a generic line', () => {
    expect(discoveryErrorMessage(new Error('Network error.'))).toBe(
      'Network error.'
    );
    expect(discoveryErrorMessage(null)).toMatch(/lookup failed/);
  });

  it('explains a cut or partial result in plain words', () => {
    expect(discoveryNotices({ truncated: true, cap: 500 })[0]).toMatch(
      /cut at 500/
    );
    expect(discoveryNotices({ partial: true, failedCodes: [] })[0]).toMatch(
      /Some sources did not answer/
    );
    expect(
      discoveryNotices({
        partial: true,
        failedCodes: ['DOMAIN_CHECKER_TOOL_TIMEOUT'],
      })[0]
    ).toMatch(/ran out of time/);
    expect(discoveryNotices({ partial: false, truncated: false })).toEqual([]);
    const text = discoveryNotices({ partial: true, failedCodes: ['x'] }).join();
    expect(text).not.toMatch(/subfinder/i);
  });
});
