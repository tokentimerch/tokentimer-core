import { useCallback, useMemo } from 'react';
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
 * Read and write inventory list state via URL search params.
 *
 * @returns {InventoryUrlState & {
 *   setSection: (value: string) => void,
 *   setSearch: (value: string) => void,
 *   setSort: (value: string) => void,
 *   setCategories: (values: string[]) => void,
 *   setStatus: (value: string) => void,
 *   setOffset: (value: number) => void,
 *   setMode: (value: string) => void,
 * }}
 */
export function useInventoryUrlState() {
  const [searchParams, setSearchParams] = useSearchParams();

  const state = useMemo(
    () => ({
      section: searchParams.get('section') || '__all__',
      search: searchParams.get('q') || '',
      sort: searchParams.get('sort') || '',
      categories: searchParams.getAll('category'),
      status: searchParams.get('status') || 'all',
      offset: Number(searchParams.get('offset') || 0),
      mode: searchParams.get('mode') || 'all',
    }),
    [searchParams]
  );

  const patchParams = useCallback(
    updates => {
      setSearchParams(
        prev => {
          const next = new URLSearchParams(prev);

          for (const [key, value] of Object.entries(updates)) {
            if (key === 'category') {
              next.delete('category');
              if (Array.isArray(value) && value.length > 0) {
                value.forEach(entry => next.append('category', entry));
              }
              continue;
            }

            if (key === 'search') {
              applyParam(next, 'q', value);
              continue;
            }

            applyParam(next, key, value);
          }

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
    values => patchParams({ category: values }),
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

  return {
    ...state,
    setSection,
    setSearch,
    setSort,
    setCategories,
    setStatus,
    setOffset,
    setMode,
  };
}
