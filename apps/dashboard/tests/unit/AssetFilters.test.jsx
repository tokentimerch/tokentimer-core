import { ChakraProvider } from '@chakra-ui/react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import AssetFilters, {
  ASSET_SEARCH_DEBOUNCE_MS,
} from '../../src/components/AssetFilters.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const originalMatchMedia = window.matchMedia;

function renderFilters(overrides = {}) {
  const props = {
    statusFilter: 'all',
    setStatusFilter: vi.fn(),
    selectedCategories: [],
    setSelectedCategories: vi.fn(),
    panelQueries: { __global: '', __section: '__all__' },
    setPanelQueries: vi.fn(),
    onGlobalSearchChange: vi.fn(),
    onFilterReset: vi.fn(),
    ...overrides,
  };

  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AssetFilters {...props} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

  return props;
}

describe('AssetFilters search', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: originalMatchMedia,
    });
  });

  it('keeps rapid typing local and commits one search update after the pause', () => {
    const props = renderFilters();
    const input = screen.getByPlaceholderText(
      'Search assets, domains, owners...'
    );

    for (const value of ['t', 'to', 'tok', 'toke', 'token']) {
      fireEvent.change(input, { target: { value } });
      expect(input).toHaveValue(value);
    }

    expect(props.setPanelQueries).not.toHaveBeenCalled();
    expect(props.onGlobalSearchChange).not.toHaveBeenCalled();
    expect(props.onFilterReset).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(ASSET_SEARCH_DEBOUNCE_MS);
    });

    expect(props.setPanelQueries).toHaveBeenCalledTimes(1);
    const update = props.setPanelQueries.mock.calls[0][0];
    expect(update(props.panelQueries)).toEqual({
      __global: 'token',
      __section: '__all__',
    });
    expect(props.onGlobalSearchChange).toHaveBeenCalledTimes(1);
    expect(props.onGlobalSearchChange).toHaveBeenCalledWith('token');
    expect(props.onFilterReset).toHaveBeenCalledTimes(1);
  });
});
