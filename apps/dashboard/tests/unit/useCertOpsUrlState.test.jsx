import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router';

import {
  CERTOPS_DEFAULT_PAGE_SIZE,
  CERTOPS_JOB_FILTERS,
  applyCertOpsListUrlPatch,
  certOpsActiveFilterLabels,
  certOpsParamName,
  parseCertOpsListUrlState,
  useCertOpsListUrlState,
} from '../../src/hooks/useCertOpsUrlState.js';

const REPEATABLE = {
  status: { label: 'Status', default: [] },
};

function Probe({ options }) {
  const state = useCertOpsListUrlState(options);
  const location = useLocation();
  return (
    <div>
      <span data-testid='search'>{location.search}</span>
      <span data-testid='limit'>{state.limit}</span>
      <span data-testid='offset'>{state.offset}</span>
      <span data-testid='filters'>{JSON.stringify(state.filters)}</span>
      <button onClick={() => state.setPage({ offset: state.offset + 20 })}>
        next
      </button>
      <button onClick={() => state.setPage({ limit: 50, offset: 0 })}>
        resize
      </button>
      <button onClick={() => state.setFilter('status', 'failed')}>
        filter
      </button>
      <button onClick={state.clearFilters}>clear</button>
    </div>
  );
}

function renderProbe(entries = ['/'], options = {}) {
  return render(
    <MemoryRouter initialEntries={entries}>
      <Routes>
        <Route path='/' element={<Probe options={options} />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('certOpsParamName', () => {
  it('leaves an unscoped list on the bare parameter name', () => {
    expect(certOpsParamName('', 'offset')).toBe('offset');
  });

  it('prefixes a scoped list so two lists on one tab cannot collide', () => {
    expect(certOpsParamName('profile', 'offset')).toBe('profileOffset');
    expect(certOpsParamName('schedule', 'limit')).toBe('scheduleLimit');
  });
});

describe('parseCertOpsListUrlState', () => {
  it('falls back to the default page size and the first page', () => {
    const state = parseCertOpsListUrlState('');
    expect(state.limit).toBe(CERTOPS_DEFAULT_PAGE_SIZE);
    expect(state.offset).toBe(0);
  });

  it('reads a page position out of the query string', () => {
    const state = parseCertOpsListUrlState('?limit=50&offset=100');
    expect(state).toMatchObject({ limit: 50, offset: 100 });
  });

  it('ignores a nonsense page position rather than requesting it', () => {
    expect(parseCertOpsListUrlState('?limit=0&offset=-5')).toMatchObject({
      limit: CERTOPS_DEFAULT_PAGE_SIZE,
      offset: 0,
    });
    expect(parseCertOpsListUrlState('?limit=abc')).toMatchObject({
      limit: CERTOPS_DEFAULT_PAGE_SIZE,
    });
  });

  it('reads scoped parameters for a second list on the same tab', () => {
    const state = parseCertOpsListUrlState('?offset=20&profileOffset=40', {
      scope: 'profile',
    });
    expect(state.offset).toBe(40);
  });

  it('reads single-value filters', () => {
    const state = parseCertOpsListUrlState('?status=failed&source=scheduler', {
      filters: CERTOPS_JOB_FILTERS,
    });
    expect(state.filters).toEqual({
      status: 'failed',
      operation: '',
      source: 'scheduler',
    });
  });

  it('reads a repeatable filter with getAll, deduplicated and ordered', () => {
    const state = parseCertOpsListUrlState(
      '?status=queued&status=failed&status=queued',
      { filters: REPEATABLE }
    );
    expect(state.filters.status).toEqual(['failed', 'queued']);
  });
});

describe('applyCertOpsListUrlPatch', () => {
  it('omits a default page size and the first page from the query string', () => {
    const params = new URLSearchParams();
    applyCertOpsListUrlPatch(params, {
      limit: CERTOPS_DEFAULT_PAGE_SIZE,
      offset: 0,
    });
    expect(params.toString()).toBe('');
  });

  it('writes a non-default page position', () => {
    const params = new URLSearchParams();
    applyCertOpsListUrlPatch(params, { limit: 50, offset: 100 });
    expect(params.get('limit')).toBe('50');
    expect(params.get('offset')).toBe('100');
  });

  it('drops a filter set back to its default', () => {
    const params = new URLSearchParams('?status=failed');
    applyCertOpsListUrlPatch(
      params,
      { status: '' },
      {
        filters: CERTOPS_JOB_FILTERS,
      }
    );
    expect(params.has('status')).toBe(false);
  });

  it('replaces rather than appends a repeatable filter', () => {
    const params = new URLSearchParams('?status=queued&status=failed');
    applyCertOpsListUrlPatch(
      params,
      { status: ['running'] },
      {
        filters: REPEATABLE,
      }
    );
    expect(params.getAll('status')).toEqual(['running']);
  });

  it('leaves the other list parameters untouched', () => {
    const params = new URLSearchParams('?offset=20');
    applyCertOpsListUrlPatch(params, { offset: 40 }, { scope: 'profile' });
    expect(params.get('offset')).toBe('20');
    expect(params.get('profileOffset')).toBe('40');
  });
});

describe('certOpsActiveFilterLabels', () => {
  it('names only the filters that are actually applied', () => {
    expect(
      certOpsActiveFilterLabels(
        { status: 'failed', operation: '', source: '' },
        CERTOPS_JOB_FILTERS
      )
    ).toEqual([{ key: 'status', label: 'Status', value: 'failed' }]);
  });

  it('joins a repeatable filter into one label', () => {
    expect(
      certOpsActiveFilterLabels({ status: ['failed', 'queued'] }, REPEATABLE)
    ).toEqual([{ key: 'status', label: 'Status', value: 'failed, queued' }]);
  });
});

describe('useCertOpsListUrlState', () => {
  it('writes the page position into the URL and reads it back', () => {
    renderProbe();

    fireEvent.click(screen.getByText('next'));

    expect(screen.getByTestId('offset').textContent).toBe('20');
    expect(screen.getByTestId('search').textContent).toBe('?offset=20');
  });

  it('keeps a default value out of the query string', () => {
    renderProbe();

    fireEvent.click(screen.getByText('resize'));
    // 50 is not the default, so it is written; offset 0 is, so it is not.
    expect(screen.getByTestId('search').textContent).toBe('?limit=50');
  });

  it('round-trips a filtered, paged view', () => {
    renderProbe(['/?status=failed&limit=50&offset=50'], {
      filters: CERTOPS_JOB_FILTERS,
    });

    expect(screen.getByTestId('limit').textContent).toBe('50');
    expect(screen.getByTestId('offset').textContent).toBe('50');
    expect(JSON.parse(screen.getByTestId('filters').textContent)).toMatchObject(
      { status: 'failed' }
    );
  });

  it('returns to the first page whenever a filter changes', () => {
    renderProbe(['/?offset=60'], { filters: CERTOPS_JOB_FILTERS });
    expect(screen.getByTestId('offset').textContent).toBe('60');

    fireEvent.click(screen.getByText('filter'));

    expect(screen.getByTestId('offset').textContent).toBe('0');
    expect(screen.getByTestId('search').textContent).toBe('?status=failed');
  });

  it('returns to the first page when the filters are cleared', () => {
    renderProbe(['/?status=failed&offset=60'], {
      filters: CERTOPS_JOB_FILTERS,
    });

    fireEvent.click(screen.getByText('clear'));

    expect(screen.getByTestId('offset').textContent).toBe('0');
    expect(screen.getByTestId('search').textContent).toBe('');
  });

  it('does not add a history entry when paging', () => {
    // A page-forward that pushed would mean the back button walks the reader
    // through every page they visited instead of leaving the list.
    renderProbe(['/']);
    const before = window.history.length;

    fireEvent.click(screen.getByText('next'));
    fireEvent.click(screen.getByText('next'));

    expect(window.history.length).toBe(before);
  });
});
