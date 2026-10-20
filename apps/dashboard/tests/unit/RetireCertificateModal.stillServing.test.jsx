import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

// A plain function (not vi.fn) so a rejection is only observed by the modal.
const deleteCalls = [];
let deleteResult = () => {};
vi.mock('../../src/components/certops/certopsApi.js', () => ({
  deleteEndpointMonitor: (...args) => {
    deleteCalls.push(args);
    return deleteResult(...args);
  },
}));

import RetireCertificateModal from '../../src/components/certops/RetireCertificateModal.jsx';

const certificate = {
  id: 'cert-1',
  commonName: 'app.example',
  fingerprintSha256: 'a'.repeat(64),
  status: 'active',
  source: 'endpoint_monitor',
  notAfter: '2027-01-12',
};

const stillServing = {
  response: {
    status: 409,
    data: {
      code: 'CERTOPS_CERTIFICATE_STILL_SERVING',
      error:
        'Certificate is still serving at 1 location(s): https://app.example',
      locations: [
        {
          id: 'obs-1',
          source: 'endpoint_monitor',
          sourceRef: 'a399363a-4a6a-4403-84ea-2f25458ee059',
          domainMonitorId: 'a399363a-4a6a-4403-84ea-2f25458ee059',
          url: 'https://app.example',
        },
      ],
    },
  },
};

function show(onRetire) {
  render(
    <ChakraProvider>
      <RetireCertificateModal
        isOpen
        onClose={vi.fn()}
        onRetire={onRetire}
        certificate={certificate}
        workspaceId='ws-1'
      />
    </ChakraProvider>
  );
}

function submitDecommission() {
  fireEvent.change(screen.getByPlaceholderText(/Reason/), {
    target: { value: 'Replaced' },
  });
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Decommission' }));
}

describe('retiring a certificate that an endpoint checker still sees', () => {
  beforeEach(() => {
    deleteCalls.length = 0;
    deleteResult = () => {};
  });

  it('lists the serving location and removes the checker before retrying', async () => {
    const onRetire = vi
      .fn()
      .mockRejectedValueOnce(stillServing)
      .mockResolvedValueOnce(undefined);
    show(onRetire);
    submitDecommission();

    const list = await screen.findByTestId('serving-locations');
    expect(list).toHaveTextContent('https://app.example');
    expect(list).toHaveTextContent('endpoint checker');

    fireEvent.click(
      screen.getByRole('button', {
        name: /Remove endpoint checker and decommission/,
      })
    );
    await waitFor(() => expect(onRetire).toHaveBeenCalledTimes(2));
    expect(deleteCalls).toEqual([
      ['ws-1', 'a399363a-4a6a-4403-84ea-2f25458ee059'],
    ]);
  });

  it('keeps the modal open and explains a permission failure without retrying', async () => {
    const onRetire = vi.fn().mockRejectedValue(stillServing);
    deleteResult = () => {
      return Promise.reject(
        Object.assign(new Error('forbidden'), { response: { status: 403 } })
      );
    };
    show(onRetire);
    submitDecommission();
    await screen.findByTestId('serving-locations');
    fireEvent.click(
      screen.getByRole('button', {
        name: /Remove endpoint checker and decommission/,
      })
    );
    expect(
      await screen.findByText(/requires the workspace manager role/)
    ).toBeInTheDocument();
    expect(onRetire).toHaveBeenCalledTimes(1);
  });

  it('offers no removal for locations that are not endpoint checkers', async () => {
    const onRetire = vi.fn().mockRejectedValue({
      response: {
        status: 409,
        data: {
          code: 'CERTOPS_CERTIFICATE_STILL_SERVING',
          error: 'Certificate is still serving at 1 location(s): iis',
          locations: [
            {
              id: 'o2',
              source: 'agent_slot',
              sourceRef: 'iis:443',
              domainMonitorId: null,
              url: null,
            },
          ],
        },
      },
    });
    show(onRetire);
    submitDecommission();
    await screen.findByTestId('serving-locations');
    expect(
      screen.queryByRole('button', { name: /Remove endpoint checker/ })
    ).not.toBeInTheDocument();
  });
});
