import React from 'react';
import { it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent } from '@testing-library/react';
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
