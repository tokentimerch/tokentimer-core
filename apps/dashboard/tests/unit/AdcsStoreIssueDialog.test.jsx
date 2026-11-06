import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import AdcsStoreIssueDialog from '../../src/components/certops/AdcsStoreIssueDialog.jsx';

const { listAgentsMock, createJobMock } = vi.hoisted(() => ({
  listAgentsMock: vi.fn(),
  createJobMock: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsAgentsApi', () => ({
  listAgents: listAgentsMock,
}));
vi.mock('../../src/components/certops/certopsJobsApi', () => ({
  createJob: createJobMock,
}));

const issuer = { id: 'issuer-1', name: 'CA', kind: 'adcs', currentVersion: 1 };
const qualifiedAgent = {
  id: 'agent-1',
  name: 'Server',
  status: 'active',
  platform: 'win32',
  livenessState: 'live',
  declaredCapabilities: ['adcs-enroll-v1', 'windows-store-only-adcs-v1'],
};

beforeEach(() => {
  listAgentsMock.mockReset().mockResolvedValue({
    items: [
      qualifiedAgent,
      {
        id: 'old-agent',
        name: 'Old server',
        status: 'active',
        declaredCapabilities: ['adcs-enroll-v1'],
      },
    ],
  });
  createJobMock.mockReset();
});

function mount() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AdcsStoreIssueDialog
          isOpen
          onClose={vi.fn()}
          workspaceId='workspace-1'
          issuers={[issuer]}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

it('issues only on a qualified agent with an explicit store and renewal off', async () => {
  createJobMock.mockResolvedValue({ job: { id: 'job-1' } });
  mount();
  await screen.findByRole('option', { name: 'Server' });
  expect(screen.queryByRole('option', { name: 'Old server' })).toBeNull();
  fireEvent.change(screen.getByLabelText('Confirmed AD CS issuer'), {
    target: { value: issuer.id },
  });
  fireEvent.change(screen.getByLabelText('Windows agent'), {
    target: { value: qualifiedAgent.id },
  });
  fireEvent.change(screen.getByLabelText('Certificate DNS name'), {
    target: { value: 'host.example.com' },
  });
  fireEvent.change(screen.getByLabelText('Change ticket reference'), {
    target: { value: 'CHG-1' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await waitFor(() => expect(createJobMock).toHaveBeenCalledTimes(1));
  expect(createJobMock.mock.calls[0][1]).toMatchObject({
    operation: 'issue',
    assignedAgentId: 'agent-1',
    changeTicketReference: 'CHG-1',
    payload: {
      issuerId: 'issuer-1',
      target: {
        type: 'windows-cert-store',
        reference: 'host.example.com',
        store: 'My',
      },
      automationEnabled: false,
    },
  });
  expect(await screen.findByText(/Issuance requested/)).toBeInTheDocument();
  expect(screen.queryByLabelText('IIS site')).toBeNull();
});

it('reuses the idempotency key when a request fails and is retried unchanged', async () => {
  createJobMock
    .mockRejectedValueOnce(new Error('offline'))
    .mockResolvedValueOnce({ job: { id: 'job-1' } });
  mount();
  await screen.findByRole('option', { name: 'Server' });
  fireEvent.change(screen.getByLabelText('Confirmed AD CS issuer'), {
    target: { value: issuer.id },
  });
  fireEvent.change(screen.getByLabelText('Windows agent'), {
    target: { value: qualifiedAgent.id },
  });
  fireEvent.change(screen.getByLabelText('Certificate DNS name'), {
    target: { value: 'host.example.com' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await screen.findByText(/outcome is unknown/);
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await waitFor(() => expect(createJobMock).toHaveBeenCalledTimes(2));
  expect(createJobMock.mock.calls[1][1].idempotencyKey).toBe(
    createJobMock.mock.calls[0][1].idempotencyKey
  );
});
