import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import CertificateObservationHistory from '../../src/components/certops/CertificateObservationHistory.jsx';
import apiClient from '../../src/utils/apiClient';

vi.mock('../../src/utils/apiClient', () => ({ default: { get: vi.fn() } }));
const access = vi.hoisted(() => ({ canManage: true, workspaceId: 'w' }));
vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: () => access.canManage,
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: access.workspaceId }),
}));
const props = {
  workspaceId: 'w',
  certificateId: 'c',
  fingerprintSha256: 'abc',
};
const view = extra => (
  <ChakraProvider>
    <CertificateObservationHistory {...props} {...extra} />
  </ChakraProvider>
);
beforeEach(() => {
  vi.resetAllMocks();
  access.canManage = true;
  access.workspaceId = 'w';
});
it('shows only existing fingerprint-scoped history and clears it for another certificate', async () => {
  apiClient.get
    .mockResolvedValueOnce({
      data: {
        items: [
          { id: '1', metadata: { observedRevocationVerdict: 'revoked' } },
        ],
      },
    })
    .mockResolvedValueOnce({ data: { items: [] } });
  const rendered = render(view());
  fireEvent.click(
    await screen.findByRole('button', { name: 'Observation history' })
  );
  expect(
    screen.getByRole('dialog', { name: 'Observation history' })
  ).toBeTruthy();
  expect(apiClient.get.mock.calls[0][1].params).toEqual({
    limit: 10,
    offset: 0,
    fingerprint: 'abc',
  });
  rendered.rerender(view({ certificateId: 'other' }));
  await waitFor(() =>
    expect(
      screen.queryByRole('button', { name: 'Observation history' })
    ).toBeNull()
  );
  expect(screen.queryByRole('dialog')).toBeNull();
});
it('hides the action when access is denied', async () => {
  apiClient.get.mockRejectedValueOnce({ response: { status: 403 } });
  render(view());
  await waitFor(() => expect(apiClient.get).toHaveBeenCalled());
  expect(
    screen.queryByRole('button', { name: 'Observation history' })
  ).toBeNull();
});

it('hides the action for empty history', async () => {
  apiClient.get.mockResolvedValueOnce({ data: { items: [] } });
  render(view());
  await waitFor(() => expect(apiClient.get).toHaveBeenCalled());
  expect(
    screen.queryByRole('button', { name: 'Observation history' })
  ).toBeNull();
});

it('paginates, recovers from a failed page, and explains an empty page', async () => {
  apiClient.get
    .mockResolvedValueOnce({
      data: {
        items: Array.from({ length: 10 }, (_, id) => ({ id, metadata: {} })),
      },
    })
    .mockRejectedValueOnce({ response: { status: 409 } })
    .mockResolvedValueOnce({ data: { items: [] } });
  render(view());
  fireEvent.click(
    await screen.findByRole('button', { name: 'Observation history' })
  );
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  expect((await screen.findByRole('alert')).textContent).toContain(
    'Certificate changed'
  );
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  expect(await screen.findByText('No more observations.')).toBeTruthy();
  expect(apiClient.get.mock.calls[2][1].params.offset).toBe(10);
  expect(screen.getByRole('button', { name: 'Next' }).disabled).toBe(true);
  expect(screen.getByRole('button', { name: 'Previous' }).disabled).toBe(false);
});

it('requests a server sort across pages and resets pagination when sorting changes', async () => {
  apiClient.get.mockResolvedValue({
    data: {
      items: Array.from({ length: 10 }, (_, id) => ({ id, metadata: {} })),
    },
  });
  render(view());
  fireEvent.click(
    await screen.findByRole('button', { name: 'Observation history' })
  );
  fireEvent.click(
    screen.getByRole('button', { name: 'Sort by Observer / source' })
  );
  await waitFor(() =>
    expect(apiClient.get.mock.calls.at(-1)[1].params).toMatchObject({
      offset: 0,
      sortBy: 'source',
      sortDirection: 'asc',
    })
  );
  fireEvent.click(await screen.findByRole('button', { name: 'Next' }));
  await waitFor(() =>
    expect(apiClient.get.mock.calls.at(-1)[1].params).toMatchObject({
      offset: 10,
      sortBy: 'source',
      sortDirection: 'asc',
    })
  );
  fireEvent.click(
    await screen.findByRole('button', { name: 'Sort by Observer / source' })
  );
  await waitFor(() =>
    expect(apiClient.get.mock.calls.at(-1)[1].params).toMatchObject({
      offset: 0,
      sortBy: 'source',
      sortDirection: 'desc',
    })
  );
  fireEvent.change(await screen.findByLabelText('Sort observations by'), {
    target: { value: 'location' },
  });
  await waitFor(() =>
    expect(apiClient.get.mock.calls.at(-1)[1].params).toMatchObject({
      offset: 0,
      sortBy: 'location',
      sortDirection: 'asc',
    })
  );
});

it('allows date sorting for readers without exposing topology sorting', async () => {
  access.canManage = false;
  apiClient.get.mockResolvedValue({
    data: { items: [{ id: '1', metadata: {} }] },
  });
  render(view());
  fireEvent.click(
    await screen.findByRole('button', { name: 'Observation history' })
  );
  expect(
    screen.queryByRole('button', { name: 'Sort by Observer / source' })
  ).toBeNull();
  expect(screen.queryByRole('button', { name: 'Sort by Location' })).toBeNull();
  expect(screen.queryByRole('option', { name: 'Location' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Sort by Observed' }));
  await waitFor(() =>
    expect(apiClient.get.mock.calls.at(-1)[1].params).toMatchObject({
      sortBy: 'observedAt',
      sortDirection: 'desc',
    })
  );
});
