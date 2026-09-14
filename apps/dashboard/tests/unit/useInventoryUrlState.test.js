import { describe, it, expect } from 'vitest';
import {
  applyInventoryUrlPatch,
  categoriesEqual,
  clearInventoryFiltersForWorkspaceSwitch,
  getActiveFilterSummaryLabels,
  getClearAllFiltersPatch,
  hasActiveInventoryFilters,
  isInventoryDashboardPath,
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

  it('treats /dashboard as the inventory route', () => {
    expect(isInventoryDashboardPath('/dashboard')).toBe(true);
    expect(isInventoryDashboardPath('/dashboard/')).toBe(true);
    expect(isInventoryDashboardPath('/control-center')).toBe(false);
  });

  it('clears list filters and token deep-links but keeps sort and mode', () => {
    const params = new URLSearchParams(
      'workspace=ws-a&section=prod&status=critical&q=acme&category=cert&offset=20&sort=name&mode=certs&token-id=99'
    );

    clearInventoryFiltersForWorkspaceSwitch(params);

    expect(params.get('workspace')).toBe('ws-a');
    expect(params.get('section')).toBeNull();
    expect(params.get('status')).toBeNull();
    expect(params.get('q')).toBeNull();
    expect(params.getAll('category')).toEqual([]);
    expect(params.get('offset')).toBeNull();
    expect(params.get('token-id')).toBeNull();
    expect(params.get('sort')).toBe('name');
    expect(params.get('mode')).toBe('certs');
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
