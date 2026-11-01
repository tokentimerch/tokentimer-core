import { it, expect, afterEach, vi } from 'vitest';
import {
  render,
  screen,
  cleanup,
  fireEvent,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AutoSyncRecentRuns from '../../src/components/imports/AutoSyncRecentRuns.jsx';
afterEach(cleanup);
const run = {
  run_id: 'run',
  started_at: '2026-10-30T12:00:00Z',
  trigger: 'scheduled',
  status: 'partial',
  discovered_count: 12,
  created_count: 3,
  updated_count: 4,
  detached_count: 1,
  deleted_count: 0,
  error_count: 1,
  error: 'One project was inaccessible',
};
it('shows structured history with separate outcomes and inventory columns', () => {
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns runs={[run]} />
    </ChakraProvider>
  );
  expect(
    screen.getByRole('table', { name: 'Recent auto-sync runs' })
  ).toBeVisible();
  expect(screen.getByRole('columnheader', { name: 'Detached' })).toBeVisible();
  expect(screen.getByText('Partial')).toBeVisible();
  expect(screen.getByText('Scheduled · 12 found')).toBeVisible();
  expect(
    screen.queryByText('One project was inaccessible')
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /Details for/ }));
  expect(screen.getByText('One project was inaccessible')).toBeVisible();
});
it('hides previous history while the selected configuration is loading', () => {
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns runs={[run]} loading />
    </ChakraProvider>
  );
  expect(screen.getByText('Loading run history…')).toBeVisible();
  expect(screen.queryByText('Partial')).not.toBeInTheDocument();
});
it('does not invent zero counts for missing fields and loads earlier records', () => {
  const load = vi.fn();
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns
        runs={[{ run_id: 'old', status: 'success' }]}
        hasEarlier
        onLoadEarlier={load}
      />
    </ChakraProvider>
  );
  expect(screen.getByText('Unknown start')).toBeVisible();
  expect(screen.getByText('Succeeded')).toBeVisible();
  expect(screen.getAllByText('—').length).toBe(5);
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  expect(load).toHaveBeenCalledOnce();
});
it('shows an empty state', () => {
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns />
    </ChakraProvider>
  );
  expect(screen.getByText('No runs yet')).toBeVisible();
});

it('shows at most five runs per page and navigates cached pages in both directions', () => {
  const runs = Array.from({ length: 12 }, (_, i) => ({
    ...run,
    run_id: `run-${i}`,
    started_at: new Date(Date.UTC(2026, 9, 30 - i)).toISOString(),
  }));
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns runs={runs} />
    </ChakraProvider>
  );
  expect(screen.getAllByRole('button', { name: /Details for/ })).toHaveLength(
    5
  );
  expect(screen.getByRole('button', { name: 'Newer runs' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  expect(screen.getByText('Page 2 · Up to 5 runs')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  expect(screen.getAllByRole('button', { name: /Details for/ })).toHaveLength(
    2
  );
  expect(screen.getByRole('button', { name: 'Earlier runs' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Newer runs' }));
  expect(screen.getAllByRole('button', { name: /Details for/ })).toHaveLength(
    5
  );
});
it('opens saved details for successful runs without an error', () => {
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns
        runs={[
          {
            ...run,
            status: 'success',
            error: null,
            finished_at: '2026-10-30T12:02:00Z',
            generation: 7,
            scan_version: 3,
            settings_snapshot: { cleanup_obsolete: false },
          },
        ]}
      />
    </ChakraProvider>
  );
  fireEvent.click(screen.getByRole('button', { name: /Details for/ }));
  expect(screen.getByText('Run ID: run')).toBeVisible();
  expect(screen.getByText(/Generation: 7/)).toBeVisible();
  expect(screen.getByText(/cleanup_obsolete/)).toBeVisible();
  expect(screen.getByRole('button', { name: /Details for/ })).toHaveAttribute(
    'aria-expanded',
    'true'
  );
});
it('keeps the current page and allows retry after a page request fails', async () => {
  const load = vi
    .fn()
    .mockRejectedValueOnce(new Error('offline'))
    .mockResolvedValueOnce(false);
  render(
    <ChakraProvider>
      <AutoSyncRecentRuns runs={[run]} hasEarlier onLoadEarlier={load} />
    </ChakraProvider>
  );
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load');
  expect(screen.getByText('Page 1 · Up to 5 runs')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  await waitFor(() => expect(load).toHaveBeenCalledTimes(2));
  expect(screen.getByText('Page 1 · Up to 5 runs')).toBeVisible();
});
it('fetches a cursor page only once and uses cached pages when going back', async () => {
  const first = Array.from({ length: 5 }, (_, i) => ({
    ...run,
    run_id: `first-${i}`,
  }));
  const load = vi.fn(() => {
    view.rerender(
      <ChakraProvider>
        <AutoSyncRecentRuns
          runs={[...first, { ...run, run_id: 'last' }]}
          onLoadEarlier={load}
        />
      </ChakraProvider>
    );
    return Promise.resolve(true);
  });
  const view = render(
    <ChakraProvider>
      <AutoSyncRecentRuns runs={first} hasEarlier onLoadEarlier={load} />
    </ChakraProvider>
  );
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  await screen.findByText('Page 2 · Up to 5 runs');
  expect(screen.getAllByRole('button', { name: /Details for/ })).toHaveLength(
    1
  );
  fireEvent.click(screen.getByRole('button', { name: 'Newer runs' }));
  fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
  expect(load).toHaveBeenCalledOnce();
});
