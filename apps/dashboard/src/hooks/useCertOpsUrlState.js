import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router';

/**
 * URL state for the CertOps lists: filters and page position live in search
 * params so a filtered, paged view can be linked to and pasted into a chat
 * during an incident, and so a reload lands on the same rows.
 *
 * Conventions are the token inventory's (see useInventoryUrlState): default
 * values are omitted from the query string, writes replace the current history
 * entry so paging does not fill the back button, and a repeatable filter is
 * read with getAll.
 *
 * A tab showing two lists scopes the second one's params with a prefix
 * (`profileOffset`), so the two page positions cannot overwrite each other.
 */

/** Page sizes offered by every CertOps list control. */
export const CERTOPS_PAGE_SIZE_OPTIONS = [10, 20, 50, 100];

/** Rows per page when the URL says nothing. */
export const CERTOPS_DEFAULT_PAGE_SIZE = 20;

/**
 * @typedef {object} CertOpsFilterSpec
 * @property {string} label - Human-readable filter name.
 * @property {string|string[]} default - Value that is omitted from the URL. An
 *   array default marks the filter repeatable.
 */

/** Shared empty spec so unfiltered lists keep a stable hook identity. */
const NO_FILTERS = Object.freeze({});

/** Filters the job list accepts; the server takes the same names. */
export const CERTOPS_JOB_FILTERS = {
  status: { label: 'Status', default: '' },
  operation: { label: 'Operation', default: '' },
  source: { label: 'Source', default: '' },
};

/**
 * Prefixed param name for a scoped list, e.g. ('profile', 'offset') is
 * `profileOffset`. An unscoped list keeps the bare name.
 */
export function certOpsParamName(scope, key) {
  if (!scope) return key;
  return `${scope}${key.charAt(0).toUpperCase()}${key.slice(1)}`;
}

function normalizeRepeatable(values) {
  if (!Array.isArray(values)) return [];
  const seen = new Set();
  for (const entry of values) {
    const value = String(entry || '').trim();
    if (value) seen.add(value);
  }
  return Array.from(seen).sort();
}

function positiveInt(raw, fallback) {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.floor(parsed);
}

/**
 * Read one list's page position and filters from search params.
 *
 * @param {URLSearchParams|string} input
 * @param {{ scope?: string, filters?: Record<string, CertOpsFilterSpec>, defaultLimit?: number }} [options]
 * @returns {{ limit: number, offset: number, filters: Record<string, string|string[]> }}
 */
export function parseCertOpsListUrlState(input, options = {}) {
  const {
    scope = '',
    filters = {},
    defaultLimit = CERTOPS_DEFAULT_PAGE_SIZE,
  } = options;
  const params = typeof input === 'string' ? new URLSearchParams(input) : input;

  const parsedFilters = {};
  for (const [key, spec] of Object.entries(filters)) {
    const name = certOpsParamName(scope, key);
    if (Array.isArray(spec?.default)) {
      parsedFilters[key] = normalizeRepeatable(params.getAll(name));
      continue;
    }
    parsedFilters[key] = params.get(name) || spec?.default || '';
  }

  return {
    limit: positiveInt(
      params.get(certOpsParamName(scope, 'limit')),
      defaultLimit
    ),
    offset: positiveInt(params.get(certOpsParamName(scope, 'offset')), 0),
    filters: parsedFilters,
  };
}

function applyValue(params, name, value, defaultValue) {
  if (Array.isArray(defaultValue)) {
    params.delete(name);
    normalizeRepeatable(
      Array.isArray(value) ? value : value ? [value] : []
    ).forEach(entry => params.append(name, entry));
    return;
  }

  const isNumericDefault = typeof defaultValue === 'number';
  const isDefault = isNumericDefault
    ? !Number.isFinite(Number(value)) || Number(value) === defaultValue
    : String(value ?? '') === String(defaultValue ?? '');

  if (value === null || value === undefined || value === '' || isDefault) {
    params.delete(name);
    return;
  }

  params.set(name, String(value));
}

/**
 * Apply a page/filter patch to search params, dropping anything at its default.
 *
 * @param {URLSearchParams} params
 * @param {Record<string, unknown>} updates
 * @param {{ scope?: string, filters?: Record<string, CertOpsFilterSpec>, defaultLimit?: number }} [options]
 */
export function applyCertOpsListUrlPatch(params, updates, options = {}) {
  const {
    scope = '',
    filters = {},
    defaultLimit = CERTOPS_DEFAULT_PAGE_SIZE,
  } = options;

  for (const [key, value] of Object.entries(updates)) {
    const name = certOpsParamName(scope, key);
    if (key === 'limit') {
      applyValue(params, name, value, defaultLimit);
      continue;
    }
    if (key === 'offset') {
      applyValue(params, name, value, 0);
      continue;
    }
    applyValue(params, name, value, filters[key]?.default ?? '');
  }
}

/**
 * Human-readable labels for whatever filters are currently applied, so a view
 * arrived at through a link can say why it is showing a subset.
 *
 * @param {Record<string, string|string[]>} values
 * @param {Record<string, CertOpsFilterSpec>} specs
 * @returns {{ key: string, label: string, value: string }[]}
 */
export function certOpsActiveFilterLabels(values, specs) {
  const labels = [];
  for (const [key, spec] of Object.entries(specs || {})) {
    const value = values?.[key];
    if (Array.isArray(spec?.default)) {
      const list = normalizeRepeatable(value);
      if (list.length > 0) {
        labels.push({ key, label: spec.label || key, value: list.join(', ') });
      }
      continue;
    }
    if (value && value !== spec?.default) {
      labels.push({ key, label: spec?.label || key, value: String(value) });
    }
  }
  return labels;
}

/**
 * Read and write one CertOps list's page position and filters via the URL.
 *
 * @param {{ scope?: string, filters?: Record<string, CertOpsFilterSpec>, defaultLimit?: number }} [options]
 * @returns {{
 *   limit: number,
 *   offset: number,
 *   filters: Record<string, string|string[]>,
 *   setPage: (next: { limit?: number, offset?: number }) => void,
 *   setFilter: (key: string, value: unknown) => void,
 *   clearFilters: () => void,
 *   activeFilterLabels: { key: string, label: string, value: string }[],
 *   hasActiveFilters: boolean,
 * }}
 */
export function useCertOpsListUrlState(options = {}) {
  const {
    scope = '',
    filters: filterSpecs = NO_FILTERS,
    defaultLimit = CERTOPS_DEFAULT_PAGE_SIZE,
  } = options;
  const [searchParams, setSearchParams] = useSearchParams();

  const parseOptions = useMemo(
    () => ({ scope, filters: filterSpecs, defaultLimit }),
    [scope, filterSpecs, defaultLimit]
  );

  const state = useMemo(
    () => parseCertOpsListUrlState(searchParams, parseOptions),
    [searchParams, parseOptions]
  );

  const patchParams = useCallback(
    updates => {
      setSearchParams(
        prev => {
          const next = new URLSearchParams(prev);
          applyCertOpsListUrlPatch(next, updates, parseOptions);
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams, parseOptions]
  );

  const setPage = useCallback(
    ({ limit, offset } = {}) => {
      patchParams({
        limit: limit === undefined ? state.limit : limit,
        offset: offset === undefined ? state.offset : offset,
      });
    },
    [patchParams, state.limit, state.offset]
  );

  // Narrowing the list can only shrink it, so the page the reader was on may no
  // longer exist. Landing on an empty page reads as "nothing matches", which is
  // the wrong answer, so a filter change always returns to the first page.
  const setFilter = useCallback(
    (key, value) => patchParams({ [key]: value, offset: 0 }),
    [patchParams]
  );

  const clearFilters = useCallback(() => {
    const cleared = { offset: 0 };
    for (const [key, spec] of Object.entries(filterSpecs)) {
      cleared[key] = Array.isArray(spec?.default) ? [] : (spec?.default ?? '');
    }
    patchParams(cleared);
  }, [patchParams, filterSpecs]);

  const activeFilterLabels = useMemo(
    () => certOpsActiveFilterLabels(state.filters, filterSpecs),
    [state.filters, filterSpecs]
  );

  return {
    ...state,
    setPage,
    setFilter,
    clearFilters,
    activeFilterLabels,
    hasActiveFilters: activeFilterLabels.length > 0,
  };
}
