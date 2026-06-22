import { describe, it, expect } from 'vitest';
import {
  applyInventoryUrlPatch,
  categoriesEqual,
  getActiveFilterSummaryLabels,
  getClearAllFiltersPatch,
  hasActiveInventoryFilters,
  normalizeCategories,
  parseInventoryUrlState,
} from '../../src/hooks/useInventoryUrlState.js';

describe('useInventoryUrlState helpers', () => {
  it('normalizes and compares category arrays bidirectionally', () => {
    expect(normalizeCategories(['cert', 'cert', '', 'key_secret'])).toEqual([
      'cert',
      'key_secret',
    ]);
    expect(
      categoriesEqual(['key_secret', 'cert'], ['cert', 'key_secret'])
    ).toBe(true);
    expect(categoriesEqual(['cert'], ['license'])).toBe(false);
  });

  it('parses repeated category params from the URL', () => {
    const state = parseInventoryUrlState(
      '?category=cert&category=key_secret&status=critical&q=acme&section=prod'
    );

    expect(state.categories).toEqual(['cert', 'key_secret']);
    expect(state.status).toBe('critical');
    expect(state.search).toBe('acme');
    expect(state.section).toBe('prod');
  });

  it('writes categories back to URL params and clears filters', () => {
    const params = new URLSearchParams(
      'section=prod&q=acme&category=cert&status=critical&offset=50&sort=name'
    );

    applyInventoryUrlPatch(params, getClearAllFiltersPatch());

    expect(params.get('section')).toBeNull();
    expect(params.get('q')).toBeNull();
    expect(params.getAll('category')).toEqual([]);
    expect(params.get('status')).toBeNull();
    expect(params.get('offset')).toBeNull();
    expect(params.get('sort')).toBe('name');
  });

  it('builds active filter summary labels', () => {
    const labels = getActiveFilterSummaryLabels({
      section: 'prod,staging',
      search: 'acme',
      categories: ['cert', 'license'],
      status: 'critical',
    });

    expect(labels).toEqual([
      { key: 'section', label: 'Section', value: 'prod, staging' },
      { key: 'search', label: 'Search', value: 'acme' },
      {
        key: 'category',
        label: 'Categories',
        value: 'Certificate, License',
      },
      { key: 'status', label: 'Status', value: 'Critical' },
    ]);
    expect(
      hasActiveInventoryFilters({
        section: '__all__',
        search: '',
        categories: [],
        status: 'all',
      })
    ).toBe(false);
  });
});
