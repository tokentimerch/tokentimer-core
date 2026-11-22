import { ChakraProvider } from '@chakra-ui/react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  AdcsStoreIssueAttemptsProvider,
  useAdcsStoreIssueAttemptStore,
} from '../../src/components/certops/AdcsStoreIssueAttempts.jsx';
import RenewalProfilesPanel from '../../src/components/certops/RenewalProfilesPanel.jsx';
import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';

const { createJob, listAgents, listIssuers } = vi.hoisted(() => ({
  createJob: vi.fn(),
  listAgents: vi.fn(),
  listIssuers: vi.fn(),
}));

vi.mock('../../src/components/certops/certopsJobsApi', async original => ({
  ...(await original()),
  createJob,
}));
vi.mock('../../src/components/certops/certopsAgentsApi', async original => ({
  ...(await original()),
  listAgents,
}));
vi.mock(
  '../../src/components/certops/certopsEnrollmentsApi',
  async original => ({
    ...(await original()),
    listIssuers,
  })
);
vi.mock('../../src/components/certops/certopsApi.js', async original => ({
  ...(await original()),
  getWorkspaceCertOpsPauseState: async () => ({}),
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'workspace-1' }),
}));
vi.mock('../../src/components/certops/useCertOps.js', async original => ({
  ...(await original()),
  useCertOpsCanManage: () => true,
}));
vi.mock('../../src/components/certops/useCertOpsRenewals.js', () => ({
  useCertOpsRenewalProfiles: () => ({
    profiles: [],
    loading: false,
    refresh: () => {},
  }),
  useUpdateRenewalProfile: () => ({ errors: {}, savingIds: new Set() }),
}));
vi.mock('../../src/components/certops/RenewalProfileDetailsModal.jsx', () => ({
  default: () => null,
  namesForProfile: () => [],
  useBoundCertificates: () => ({ certificates: [] }),
}));

const issuer = {
  id: 'issuer-1',
  name: 'Corp CA',
  kind: 'adcs',
  currentVersion: 1,
  confirmed: true,
  safe: true,
};
const agent = {
  id: 'agent-1',
  name: 'Server',
  status: 'active',
  livenessState: 'live',
  platform: 'win32',
  declaredCapabilities: [
    'windows-store-only-adcs-v1',
    'adcs-enroll-v1',
    'evidence-claim-binding-v1',
  ],
};

function onboardingContext(agents = [agent]) {
  return {
    workspaceId: 'workspace-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    session: {
      progress: { certops: { chosenIssuerId: issuer.id } },
    },
    summary: {
      certops: {
        agents: { items: agents },
        adcs: { issuers: [issuer], profiles: 1 },
      },
    },
  };
}

function TestAccount({ children }) {
  const attempts = useAdcsStoreIssueAttemptStore('account-1');
  return (
    <AdcsStoreIssueAttemptsProvider attempts={attempts}>
      {children}
    </AdcsStoreIssueAttemptsProvider>
  );
}

function show(children) {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <TestAccount>{children}</TestAccount>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

beforeEach(() => {
  listAgents.mockReset().mockResolvedValue({ items: [agent] });
  listIssuers.mockReset().mockResolvedValue({ items: [issuer] });
  createJob
    .mockReset()
    .mockRejectedValueOnce(new Error('response lost'))
    .mockResolvedValueOnce({ job: { id: 'job-1' } });
});

const tryUnload = () =>
  window.dispatchEvent(new Event('beforeunload', { cancelable: true }));

async function submitFrom(openLabel) {
  fireEvent.click(screen.getByRole('button', { name: openLabel }));
  const dialog = within(await screen.findByRole('dialog'));
  await dialog.findByRole('option', { name: agent.name });
  await dialog.findByRole('option', { name: issuer.name });
  fireEvent.change(dialog.getByLabelText('Confirmed AD CS issuer'), {
    target: { value: issuer.id },
  });
  fireEvent.change(dialog.getByLabelText('Windows agent'), {
    target: { value: agent.id },
  });
  fireEvent.change(dialog.getByLabelText('Certificate DNS name'), {
    target: { value: 'store.example.test' },
  });
  fireEvent.change(dialog.getByLabelText('Change ticket reference'), {
    target: { value: 'CHG-1' },
  });
  fireEvent.click(dialog.getByRole('button', { name: 'Issue certificate' }));
  await dialog.findByText(/outcome is unknown/i);
  fireEvent.click(dialog.getByRole('button', { name: 'Close for now' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(tryUnload()).toBe(false);
}

async function resumeFrom(label) {
  fireEvent.click(screen.getByRole('button', { name: label }));
  const dialog = within(await screen.findByRole('dialog'));
  await dialog.findByText(/outcome is unknown for store.example.test/i);
  expect(dialog.queryByLabelText('Certificate DNS name')).toBeNull();
  fireEvent.click(
    dialog.getByRole('button', { name: 'Retry original request' })
  );
  await dialog.findByText(/Issuance requested/);
  expect(tryUnload()).toBe(true);
  expect(createJob).toHaveBeenCalledTimes(2);
  expect(createJob.mock.calls[1][0]).toBe('workspace-1');
  expect(createJob.mock.calls[1][1]).toBe(createJob.mock.calls[0][1]);
}

it('resumes an unknown request after the Renewal profiles modal unmounts', async () => {
  render(show(<RenewalProfilesPanel />));
  await submitFrom('Issue from Microsoft CA');
  await resumeFrom('Resume Microsoft CA request');
});

it('resumes an unknown request in onboarding even after the agent disappears', async () => {
  const { rerender } = render(show(<AdcsStep ctx={onboardingContext()} />));
  await submitFrom('Issue into Windows store');
  listAgents.mockResolvedValue({ items: [] });
  rerender(show(<AdcsStep ctx={onboardingContext([])} />));
  await resumeFrom('Resume Windows store request');
});

it('shares the original request with the other surface in the same account', async () => {
  const { rerender } = render(show(<RenewalProfilesPanel />));
  await submitFrom('Issue from Microsoft CA');
  rerender(show(<AdcsStep ctx={onboardingContext([])} />));
  await resumeFrom('Resume Windows store request');
});
