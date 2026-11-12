import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import CertificateObservationHistory from '../../src/components/certops/CertificateObservationHistory.jsx';
import apiClient from '../../src/utils/apiClient';

vi.mock('../../src/utils/apiClient', () => ({ default: { get: vi.fn() } }));
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
beforeEach(() => vi.resetAllMocks());
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
