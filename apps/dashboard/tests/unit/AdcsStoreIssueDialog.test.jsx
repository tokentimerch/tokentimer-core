import {
  act,
  render,
  renderHook,
  screen,
  fireEvent,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import AdcsStoreIssueDialog from '../../src/components/certops/AdcsStoreIssueDialog.jsx';
import {
  AdcsStoreIssueAttemptsProvider,
  useAdcsStoreIssueAttemptStore,
} from '../../src/components/certops/AdcsStoreIssueAttempts.jsx';

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
const requiredCapabilities = [
  'windows-store-only-adcs-v1',
  'adcs-enroll-v1',
  'evidence-claim-binding-v1',
];
const qualifiedAgent = {
  id: 'agent-1',
  name: 'Server',
  status: 'active',
  platform: 'win32',
  livenessState: 'live',
  declaredCapabilities: requiredCapabilities,
};

beforeEach(() => {
  listAgentsMock.mockReset().mockResolvedValue({
    items: [
      qualifiedAgent,
      ...requiredCapabilities.map(missing => ({
        ...qualifiedAgent,
        id: missing,
        name: 'Missing ' + missing,
        declaredCapabilities: requiredCapabilities.filter(
          capability => capability !== missing
        ),
      })),
    ],
  });
  createJobMock.mockReset();
});

function TestAccount({ accountId, children }) {
  const attempts = useAdcsStoreIssueAttemptStore(accountId);
  return (
    <AdcsStoreIssueAttemptsProvider attempts={attempts}>
      {children}
    </AdcsStoreIssueAttemptsProvider>
  );
}

function show(workspaceId, onCreated, accountId = 'account-1') {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <TestAccount accountId={accountId}>
          <AdcsStoreIssueDialog
            isOpen
            onClose={vi.fn()}
            onCreated={onCreated}
            workspaceId={workspaceId}
            issuers={[issuer]}
          />
        </TestAccount>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function mount() {
  return render(show('workspace-1'));
}

async function fillForm() {
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
}

it('issues only on a qualified agent with an explicit store and renewal off', async () => {
  createJobMock.mockResolvedValue({ job: { id: 'job-1' } });
  mount();
  await screen.findByRole('option', { name: 'Server' });
  for (const capability of requiredCapabilities) {
    expect(
      screen.queryByRole('option', { name: 'Missing ' + capability })
    ).toBeNull();
  }
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

it('uses the unpaginated fleet and can select a qualified agent at the end', async () => {
  const otherAgents = Array.from({ length: 120 }, (_, index) => ({
    ...qualifiedAgent,
    id: 'other-agent-' + index,
    name: 'Other server ' + index,
    declaredCapabilities: ['windows-store-only-adcs-v1', 'adcs-enroll-v1'],
  }));
  listAgentsMock.mockResolvedValueOnce({
    items: [...otherAgents, qualifiedAgent],
    pagination: { limit: null, offset: 0, total: otherAgents.length + 1 },
  });

  mount();
  expect(await screen.findByRole('option', { name: 'Server' })).toHaveValue(
    qualifiedAgent.id
  );
  expect(listAgentsMock).toHaveBeenCalledExactlyOnceWith('workspace-1');
});

it('reuses the idempotency key when a request fails and is retried unchanged', async () => {
  createJobMock
    .mockRejectedValueOnce(new Error('offline'))
    .mockRejectedValueOnce({
      response: { status: 400, data: { code: 'CERTOPS_JOB_INVALID' } },
    })
    .mockResolvedValueOnce({ job: { id: 'job-1' } });
  mount();
  await fillForm();
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await screen.findByText(/outcome is unknown/i);
  fireEvent.click(
    screen.getByRole('button', { name: 'Retry original request' })
  );
  await screen.findByText(/outcome is unknown/i);
  fireEvent.click(
    screen.getByRole('button', { name: 'Retry original request' })
  );
  await screen.findByText(/Issuance requested/);
  expect(createJobMock).toHaveBeenCalledTimes(3);
  const original = createJobMock.mock.calls[0][1];
  expect(createJobMock.mock.calls[1][1]).toBe(original);
  expect(createJobMock.mock.calls[2][1]).toBe(original);
  expect(Object.isFrozen(original.payload.sans)).toBe(true);
});

it('lets the operator correct a first explicit validation rejection', async () => {
  createJobMock
    .mockRejectedValueOnce({
      response: {
        status: 400,
        data: { code: 'CERTOPS_JOB_INVALID', error: 'Invalid DNS name' },
      },
    })
    .mockResolvedValueOnce({ job: { id: 'job-1' } });
  mount();
  await fillForm();
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await screen.findByText('Invalid DNS name');
  fireEvent.change(screen.getByLabelText('Certificate DNS name'), {
    target: { value: 'updated.example.com' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await screen.findByText(/Issuance requested/);
  expect(createJobMock).toHaveBeenCalledTimes(2);
  expect(createJobMock.mock.calls[1][1].idempotencyKey).not.toBe(
    createJobMock.mock.calls[0][1].idempotencyKey
  );
});

it('separates workspace views and ignores callbacks from a stale view', async () => {
  let finishFirst;
  const onCreated = vi.fn();
  createJobMock.mockImplementationOnce(
    () =>
      new Promise(resolve => {
        finishFirst = resolve;
      })
  );
  const { rerender } = render(show('workspace-1', onCreated));
  const tryUnload = () =>
    window.dispatchEvent(new Event('beforeunload', { cancelable: true }));
  expect(tryUnload()).toBe(true);
  await fillForm();
  const issue = screen.getByRole('button', { name: 'Issue certificate' });
  act(() => {
    fireEvent.click(issue);
    fireEvent.click(issue);
  });
  expect(createJobMock).toHaveBeenCalledTimes(1);
  expect(tryUnload()).toBe(false);

  rerender(show('workspace-2', onCreated));
  expect(createJobMock.mock.calls[0][2].signal.aborted).toBe(false);
  expect(tryUnload()).toBe(false);
  expect(screen.getByLabelText('Certificate DNS name')).toHaveValue('');
  rerender(show('workspace-1', onCreated));
  expect(screen.getByText(/request in progress/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Close for now' })).toBeDisabled();
  await act(async () => finishFirst({ job: { id: 'job-1' } }));
  await screen.findByText(/Issuance requested/);
  expect(tryUnload()).toBe(true);
  expect(onCreated).not.toHaveBeenCalled();
  expect(createJobMock).toHaveBeenCalledTimes(1);
});

it('does not carry a request from a previous account into the same workspace', async () => {
  createJobMock.mockRejectedValueOnce(new Error('offline'));
  const { rerender } = render(show('workspace-1'));
  await fillForm();
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await screen.findByText(/outcome is unknown/i);
  rerender(show('workspace-1', undefined, 'account-2'));
  expect(screen.getByLabelText('Certificate DNS name')).toHaveValue('');
  expect(screen.queryByText(/outcome is unknown/i)).toBeNull();
});

it('cancels the previous account transport when the authenticated account changes', async () => {
  createJobMock.mockImplementation(
    (_workspace, _body, { signal }) =>
      new Promise((_, reject) =>
        signal.addEventListener('abort', () => reject(signal.reason), {
          once: true,
        })
      )
  );
  const { rerender } = render(show('workspace-1'));
  await fillForm();
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  const { signal } = createJobMock.mock.calls[0][2];
  expect(signal.aborted).toBe(false);
  rerender(show('workspace-1', undefined, 'account-2'));
  expect(signal.aborted).toBe(true);
  expect(screen.getByLabelText('Certificate DNS name')).toHaveValue('');
});

it('requires confirmation before signing out with a pending or unknown request', () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { result } = renderHook(() =>
    useAdcsStoreIssueAttemptStore('account-1')
  );
  try {
    expect(result.current.confirmSignOut()).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
    result.current.set('workspace-2', { status: 'pending' });
    expect(result.current.confirmSignOut()).toBe(false);
    expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining('may already have reached the server')
    );
    result.current.set('workspace-2', { status: 'unknown' });
    expect(result.current.confirmSignOut()).toBe(false);
    confirm.mockReturnValue(true);
    expect(result.current.confirmSignOut()).toBe(true);
    result.current.set('workspace-2', { status: 'accepted' });
    expect(result.current.confirmSignOut()).toBe(true);
    expect(confirm).toHaveBeenCalledTimes(3);
  } finally {
    confirm.mockRestore();
  }
});

it('shows a clear error without making a request when the session provider is missing', () => {
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AdcsStoreIssueDialog
          isOpen
          onClose={vi.fn()}
          workspaceId='workspace-1'
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  expect(screen.getByRole('alert')).toHaveTextContent(
    /could not load the AD CS request session/i
  );
  expect(
    screen.queryByRole('button', { name: 'Issue certificate' })
  ).toBeNull();
  expect(createJobMock).not.toHaveBeenCalled();
  expect(listAgentsMock).not.toHaveBeenCalled();
});
