import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AutoSyncProvenance from '../../src/components/AutoSyncProvenance.jsx';

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../src/utils/apiClient.js', () => ({ default: { get } }));

describe('association provenance API contract', () => {
  beforeEach(() => {
    cleanup();
    get.mockReset();
  });
  it('loads and pages the registered token route, retaining earlier events', async () => {
    get.mockImplementation(url => {
      if (url === '/api/tokens/71/auto-sync-provenance')
        return Promise.resolve({
          data: {
            configurations: [{ config_id: 'config-a', name: 'Production' }],
            items: [
              {
                id: '26',
                config_name: 'Production',
                event: 'attached',
                occurred_at: '2026-10-01T00:00:00Z',
              },
            ],
            next_before: '26',
          },
        });
      if (url === '/api/tokens/71/auto-sync-provenance?before=26')
        return Promise.resolve({
          data: {
            configurations: [{ config_id: 'config-a', name: 'Production' }],
            items: [
              {
                id: '25',
                config_name: 'Former config',
                event: 'detached',
                reason: 'configuration_deleted',
                occurred_at: '2026-09-01T00:00:00Z',
              },
            ],
            next_before: null,
          },
        });
      return Promise.reject(new Error('404: unregistered route'));
    });
    render(
      <ChakraProvider>
        <AutoSyncProvenance tokenId={71} />
      </ChakraProvider>
    );
    expect(await screen.findByText('Production')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Show history' }));
    fireEvent.click(screen.getByRole('button', { name: 'Earlier history' }));
    expect(await screen.findByText('Removed from Former config')).toBeTruthy();
    expect(
      screen.getByText('Configuration deleted; inventory retained.')
    ).toBeTruthy();
    expect(screen.getByText('Added to Production')).toBeTruthy();
    await waitFor(() =>
      expect(
        screen.queryByRole('button', { name: 'Earlier history' })
      ).toBeNull()
    );
  });
});
