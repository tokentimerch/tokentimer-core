import { useCallback, useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * @typedef {object} InventoryUrlState
 * @property {string} section - Section filter token (`__all__`, `__none__`, or comma list).
 * @property {string} search - Free-text inventory search query.
 * @property {string} sort - Server sort key.
 * @property {string[]} categories - Selected category filters.
 * @property {string} status - Expiry status filter.
 * @property {number} offset - Pagination offset.
 * @property {string} mode - Inventory table mode (e.g. all, certs, keys).
 */

/**
 * @typedef {object} ActiveFilterLabel
 * @property {'section' | 'search' | 'category' | 'status'} key
 * @property {string} label - Human-readable filter name.
 * @property {string} value - Human-readable active value.
 */

/** @type {Record<string, string>} */
export const INVENTORY_STATUS_LABELS = {
  all: 'All',
  critical: 'Critical',
  due: 'Due Soon',
  healthy: 'Healthy',
  expired: 'Expired',
};

/** @type {Record<string, string>} */
export const INVENTORY_SECTION_LABELS = {
  __all__: 'All sections',
  __none__: 'No section',
};

/** @type {Record<string, string>} */
export const INVENTORY_CATEGORY_LABELS = {
  cert: 'Certificate',
  key_secret: 'Key/Secret',
  license: 'License',
  general: 'General',
};

export const DEFAULT_INVENTORY_FILTERS = {
  section: '__all__',
  search: '',
  categories: [],
  status: 'all',
  offset: 0,
};

/**
 * Normalize a category list for stable URL/state comparison.
 *
 * @param {string[] | null | undefined} values
 * @returns {string[]}
 */
export function normalizeCategories(values) {
  if (!Array.isArray(values)) return [];

  const seen = new Set();
  const normalized = [];

  for (const entry of values) {
    const value = String(entry || '').trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    normalized.push(value);
  }

  return normalized.sort();
}

/**
 * Compare two category arrays after normalization.
 *
 * @param {string[] | null | undefined} left
 * @param {string[] | null | undefined} right
 * @returns {boolean}
 */
export function categoriesEqual(left, right) {
  const a = normalizeCategories(left);
  const b = normalizeCategories(right);
  if (a.length !== b.length) return false;
  return a.every((value, index) => value === b[index]);
}

/**
 * Read inventory URL state from search params.
 *
 * @param {URLSearchParams | string} input
 * @returns {InventoryUrlState}
 */
export function parseInventoryUrlState(input) {
  const params = typeof input === 'string' ? new URLSearchParams(input) : input;

  return {
    section: params.get('section') || DEFAULT_INVENTORY_FILTERS.section,
    search: params.get('q') || DEFAULT_INVENTORY_FILTERS.search,
    sort: params.get('sort') || '',
    categories: normalizeCategories(params.getAll('category')),
    status: params.get('status') || DEFAULT_INVENTORY_FILTERS.status,
    offset: Number(params.get('offset') || DEFAULT_INVENTORY_FILTERS.offset),
    mode: params.get('mode') || 'all',
  };
}

function applyParam(params, key, value) {
  if (
    value === null ||
    value === undefined ||
    value === '' ||
    (key === 'section' && value === '__all__') ||
    (key === 'status' && value === 'all') ||
    (key === 'mode' && value === 'all') ||
    (key === 'offset' && (!value || Number(value) <= 0)) ||
    (key === 'sort' && !value)
  ) {
    params.delete(key);
    return;
  }

  params.set(key, String(value));
}

/**
 * Apply inventory filter updates to URL search params.
 *
 * @param {URLSearchParams} params
 * @param {Record<string, unknown>} updates
 */
export function applyInventoryUrlPatch(params, updates) {
  for (const [key, value] of Object.entries(updates)) {
    if (key === 'category' || key === 'categories') {
      params.delete('category');
      const categories = normalizeCategories(
        Array.isArray(value) ? value : value ? [value] : []
      );
      categories.forEach(entry => params.append('category', entry));
      continue;
    }

    if (key === 'search') {
      applyParam(params, 'q', value);
      continue;
    }

    applyParam(params, key, value);
  }
}

/**
 * Patch object that clears inventory list filters while preserving sort/mode.
 *
 * @returns {Record<string, unknown>}
 */
export function getClearAllFiltersPatch() {
  return {
    section: DEFAULT_INVENTORY_FILTERS.section,
    search: DEFAULT_INVENTORY_FILTERS.search,
    category: DEFAULT_INVENTORY_FILTERS.categories,
    status: DEFAULT_INVENTORY_FILTERS.status,
    offset: DEFAULT_INVENTORY_FILTERS.offset,
  };
}

/**
 * Resolve a section token to a display label.
 *
 * @param {string} section
 * @param {Record<string, string>} [sectionLabels]
 * @returns {string}
 */
export function getSectionFilterLabel(
  section,
  sectionLabels = INVENTORY_SECTION_LABELS
) {
  const value = section || DEFAULT_INVENTORY_FILTERS.section;
  if (sectionLabels[value]) return sectionLabels[value];
  if (value === DEFAULT_INVENTORY_FILTERS.section) {
    return sectionLabels.__all__;
  }

  return value
    .split(',')
    .map(part => part.trim())
    .filter(Boolean)
    .join(', ');
}

/**
 * Resolve a category value to a display label.
 *
 * @param {string} category
 * @param {Record<string, string>} [categoryLabels]
 * @returns {string}
 */
export function getCategoryFilterLabel(
  category,
  categoryLabels = INVENTORY_CATEGORY_LABELS
) {
  return categoryLabels[category] || category;
}

/**
 * Resolve a status token to a display label.
 *
 * @param {string} status
 * @param {Record<string, string>} [statusLabels]
 * @returns {string}
 */
export function getStatusFilterLabel(
  status,
  statusLabels = INVENTORY_STATUS_LABELS
) {
  return statusLabels[status] || status;
}

/**
 * Build human-readable labels for active inventory filters.
 *
 * @param {Partial<InventoryUrlState>} state
 * @param {{
 *   statusLabels?: Record<string, string>,
 *   sectionLabels?: Record<string, string>,
 *   categoryLabels?: Record<string, string>,
 * }} [options]
 * @returns {ActiveFilterLabel[]}
 */
export function getActiveFilterSummaryLabels(state, options = {}) {
  const {
    statusLabels = INVENTORY_STATUS_LABELS,
    sectionLabels = INVENTORY_SECTION_LABELS,
    categoryLabels = INVENTORY_CATEGORY_LABELS,
  } = options;

  const labels = [];
  const section = state.section || DEFAULT_INVENTORY_FILTERS.section;
  const search = state.search || DEFAULT_INVENTORY_FILTERS.search;
  const categories = normalizeCategories(state.categories);
  const status = state.status || DEFAULT_INVENTORY_FILTERS.status;

  if (section !== DEFAULT_INVENTORY_FILTERS.section) {
    labels.push({
      key: 'section',
      label: 'Section',
      value: getSectionFilterLabel(section, sectionLabels),
    });
  }

  if (search) {
    labels.push({
      key: 'search',
      label: 'Search',
      value: search,
    });
  }

  if (categories.length > 0) {
    labels.push({
      key: 'category',
      label: categories.length === 1 ? 'Category' : 'Categories',
      value: categories
        .map(category => getCategoryFilterLabel(category, categoryLabels))
        .join(', '),
    });
  }

  if (status !== DEFAULT_INVENTORY_FILTERS.status) {
    labels.push({
      key: 'status',
      label: 'Status',
      value: getStatusFilterLabel(status, statusLabels),
    });
  }

  return labels;
}

/**
 * Whether any inventory list filters are active.
 *
 * @param {Partial<InventoryUrlState>} state
 * @returns {boolean}
 */
export function hasActiveInventoryFilters(state) {
  return getActiveFilterSummaryLabels(state).length > 0;
}

/**
 * Read and write inventory list state via URL search params.
 *
 * @param {{
 *   categories?: string[],
 *   onCategoriesChange?: (values: string[]) => void,
 * }} [options]
 * @returns {InventoryUrlState & {
 *   setSection: (value: string) => void,
 *   setSearch: (value: string) => void,
 *   setSort: (value: string) => void,
 *   setCategories: (values: string[]) => void,
 *   setStatus: (value: string) => void,
 *   setOffset: (value: number) => void,
 *   setMode: (value: string) => void,
 *   clearAllFilters: () => void,
 *   activeFilterLabels: ActiveFilterLabel[],
 *   hasActiveFilters: boolean,
 * }}
 */
export function useInventoryUrlState(options = {}) {
  const { categories: controlledCategories, onCategoriesChange } = options;
  const [searchParams, setSearchParams] = useSearchParams();
  const categoriesWriteSourceRef = useRef('init');

  const state = useMemo(
    () => parseInventoryUrlState(searchParams),
    [searchParams]
  );

  const patchParams = useCallback(
    updates => {
      if (Object.prototype.hasOwnProperty.call(updates, 'category')) {
        categoriesWriteSourceRef.current = 'url';
      }

      setSearchParams(
        prev => {
          const next = new URLSearchParams(prev);
          applyInventoryUrlPatch(next, updates);
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );

  const setSection = useCallback(
    value => patchParams({ section: value }),
    [patchParams]
  );
  const setSearch = useCallback(
    value => patchParams({ search: value }),
    [patchParams]
  );
  const setSort = useCallback(
    value => patchParams({ sort: value }),
    [patchParams]
  );
  const setCategories = useCallback(
    values => {
      categoriesWriteSourceRef.current = 'url';
      patchParams({ category: normalizeCategories(values) });
    },
    [patchParams]
  );
  const setStatus = useCallback(
    value => patchParams({ status: value }),
    [patchParams]
  );
  const setOffset = useCallback(
    value => patchParams({ offset: value }),
    [patchParams]
  );
  const setMode = useCallback(
    value => patchParams({ mode: value }),
    [patchParams]
  );
  const clearAllFilters = useCallback(
    () => patchParams(getClearAllFiltersPatch()),
    [patchParams]
  );

  useEffect(() => {
    if (typeof onCategoriesChange !== 'function') return;
    if (categoriesWriteSourceRef.current === 'url') {
      categoriesWriteSourceRef.current = 'synced';
      return;
    }

    const urlCategories = normalizeCategories(state.categories);
    const localCategories = normalizeCategories(controlledCategories);

    if (!categoriesEqual(urlCategories, localCategories)) {
      onCategoriesChange(urlCategories);
    }
  }, [controlledCategories, onCategoriesChange, state.categories]);

  useEffect(() => {
    if (controlledCategories === undefined) return;
    if (categoriesWriteSourceRef.current === 'url') {
      categoriesWriteSourceRef.current = 'synced';
      return;
    }

    const urlCategories = normalizeCategories(state.categories);
    const localCategories = normalizeCategories(controlledCategories);

    if (!categoriesEqual(urlCategories, localCategories)) {
      patchParams({ category: localCategories });
    }
  }, [controlledCategories, patchParams, state.categories]);

  const activeFilterLabels = useMemo(
    () => getActiveFilterSummaryLabels(state),
    [state]
  );
  const hasActiveFilters = activeFilterLabels.length > 0;

  return {
    ...state,
    setSection,
    setSearch,
    setSort,
    setCategories,
    setStatus,
    setOffset,
    setMode,
    clearAllFilters,
    activeFilterLabels,
    hasActiveFilters,
  };
}
