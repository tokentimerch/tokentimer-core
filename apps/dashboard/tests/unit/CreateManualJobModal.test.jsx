import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CreateManualJobModal from '../../src/components/certops/CreateManualJobModal.jsx';

const {
  useWorkspaceMock,
  useCertOpsAgentsMock,
  useCertOpsControllerClustersMock,
  createJobMock,
  createControllerProvisionIntentMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  useCertOpsControllerClustersMock: vi.fn(),
  createJobMock: vi.fn(),
  createControllerProvisionIntentMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsAgents: useCertOpsAgentsMock,
}));

vi.mock('../../src/components/certops/useCertOpsControllerClusters.js', () => ({
  useCertOpsControllerClusters: useCertOpsControllerClustersMock,
}));

vi.mock('../../src/components/certops/certopsJobsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsJobsApi.js'
  );
  return {
    ...actual,
    createJob: createJobMock,
  };
});

vi.mock('../../src/components/certops/certopsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsApi.js'
  );
  return {
    ...actual,
    createControllerProvisionIntent: createControllerProvisionIntentMock,
  };
});

function renderModal(props = {}) {
  return render(
    <ChakraProvider>
      <MemoryRouter>
        <CreateManualJobModal
          isOpen
          onClose={vi.fn()}
          onCreated={vi.fn()}
          {...props}
        />
      </MemoryRouter>
    </ChakraProvider>
  );
}

function selectOperation(label) {
  fireEvent.change(screen.getByLabelText(/^Operation/), {
    target: { value: label },
  });
}

beforeEach(() => {
  useWorkspaceMock.mockReset();
  useCertOpsAgentsMock.mockReset();
  useCertOpsControllerClustersMock.mockReset();
  createJobMock.mockReset();
  createControllerProvisionIntentMock.mockReset();
  useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  useCertOpsAgentsMock.mockReturnValue({ agents: [] });
  useCertOpsControllerClustersMock.mockReturnValue({
    enabled: true,
    clusters: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
  });
});

describe('CreateManualJobModal executor toggle', () => {
  it('does not show an Executor control for a non-issue operation', () => {
    renderModal();

    selectOperation('renew');

    expect(screen.queryByText('Executor')).not.toBeInTheDocument();
  });

  it('shows the Executor toggle for issue, defaulting to Agent', () => {
    renderModal();

    selectOperation('issue');

    expect(screen.getByText('Executor')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Agent' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Controller (cluster)' })
    ).toBeInTheDocument();
    // Agent path fields are visible by default.
    expect(screen.getByText('Payload')).toBeInTheDocument();
  });

  it('switches to the controller fields and hides the agent-only sections', () => {
    useCertOpsControllerClustersMock.mockReturnValue({
      enabled: true,
      clusters: ['cluster-a'],
      loading: false,
      error: '',
      refresh: vi.fn(),
    });

    renderModal();
    selectOperation('issue');
    fireEvent.click(screen.getByRole('button', { name: 'Controller (cluster)' }));

    expect(screen.getByText('Cluster')).toBeInTheDocument();
    expect(screen.getByText('Namespace')).toBeInTheDocument();
    expect(screen.getByText('Certificate name')).toBeInTheDocument();
    expect(screen.getByText('Secret name')).toBeInTheDocument();
    expect(screen.getByText('Issuer kind')).toBeInTheDocument();
    expect(screen.getByText('Issuer name')).toBeInTheDocument();
    expect(screen.getByText('DNS names')).toBeInTheDocument();

    // Agent-only sections disappear.
    expect(screen.queryByText('Payload')).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Agent$/)).not.toBeInTheDocument();
    expect(
      screen.queryByText('Require approval before this job can run')
    ).not.toBeInTheDocument();
  });

  it('lists only clusters returned by useCertOpsControllerClusters, and disables the picker when there are none', () => {
    useCertOpsControllerClustersMock.mockReturnValue({
      enabled: true,
      clusters: [],
      loading: false,
      error: '',
      refresh: vi.fn(),
    });

    renderModal();
    selectOperation('issue');
    fireEvent.click(screen.getByRole('button', { name: 'Controller (cluster)' }));

    expect(
      screen.getByText('Create an API token scoped to a cluster on the API Tokens tab first, then come back here.')
    ).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: /^Cluster/ })).toBeDisabled();
  });

  it('reverts to the Agent executor when the operation changes away from issue', () => {
    renderModal();
    selectOperation('issue');
    fireEvent.click(screen.getByRole('button', { name: 'Controller (cluster)' }));

    selectOperation('renew');
    selectOperation('issue');

    // Back to issue: executor state was reset to agent, so Payload (agent
    // path) is visible again instead of the controller fields.
    expect(screen.getByText('Payload')).toBeInTheDocument();
  });
});

describe('CreateManualJobModal controller provisioning submission', () => {
  function fillControllerFields() {
    fireEvent.change(screen.getByRole('combobox', { name: /^Cluster/ }), {
      target: { value: 'cluster-a' },
    });
    fireEvent.change(screen.getByLabelText(/^Namespace/), {
      target: { value: 'team-a' },
    });
    fireEvent.change(screen.getByLabelText(/^Certificate name/), {
      target: { value: 'web-tls' },
    });
    fireEvent.change(screen.getByLabelText(/^Secret name/), {
      target: { value: 'web-tls-secret' },
    });
    fireEvent.change(screen.getByLabelText(/^Issuer name/), {
      target: { value: 'letsencrypt-prod' },
    });
    fireEvent.change(screen.getByLabelText(/^DNS names/), {
      target: { value: 'example.com, www.example.com' },
    });
    fireEvent.change(screen.getByLabelText(/^Idempotency key/), {
      target: { value: 'req-123' },
    });
  }

  beforeEach(() => {
    useCertOpsControllerClustersMock.mockReturnValue({
      enabled: true,
      clusters: ['cluster-a'],
      loading: false,
      error: '',
      refresh: vi.fn(),
    });
  });

  it('disables submit until the required controller fields are filled', () => {
    renderModal();
    selectOperation('issue');
    fireEvent.click(screen.getByRole('button', { name: 'Controller (cluster)' }));

    expect(
      screen.getByRole('button', { name: 'Create provisioning intent' })
    ).toBeDisabled();

    fillControllerFields();

    expect(
      screen.getByRole('button', { name: 'Create provisioning intent' })
    ).toBeEnabled();
  });

  it('calls createControllerProvisionIntent (not createJob) with the built request, and closes on success', async () => {
    const onClose = vi.fn();
    const onCreated = vi.fn();
    createControllerProvisionIntentMock.mockResolvedValue({
      job: { id: 'job-1' },
      managedCertificateId: 'cert-1',
      targetId: 'target-1',
      duplicate: false,
    });

    renderModal({ onClose, onCreated });
    selectOperation('issue');
    fireEvent.click(screen.getByRole('button', { name: 'Controller (cluster)' }));
    fillControllerFields();

    fireEvent.click(
      screen.getByRole('button', { name: 'Create provisioning intent' })
    );

    await waitFor(() => {
      expect(createControllerProvisionIntentMock).toHaveBeenCalledWith('ws-1', {
        idempotencyKey: 'req-123',
        clusterId: 'cluster-a',
        namespace: 'team-a',
        certificateName: 'web-tls',
        secretName: 'web-tls-secret',
        issuerRef: {
          group: 'cert-manager.io',
          kind: 'ClusterIssuer',
          name: 'letsencrypt-prod',
        },
        dnsNames: ['example.com', 'www.example.com'],
      });
    });
    expect(createJobMock).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onCreated).toHaveBeenCalledTimes(1);
  });

  it('surfaces the terminal-identity error with a friendly message', async () => {

    createControllerProvisionIntentMock.mockRejectedValue({
      response: {
        status: 409,
        data: {
          error: 'Provisioning cannot reactivate a terminal managed certificate',
          code: 'CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY',
        },
      },
    });

    renderModal();
    selectOperation('issue');
    fireEvent.click(screen.getByRole('button', { name: 'Controller (cluster)' }));
    fillControllerFields();

    fireEvent.click(
      screen.getByRole('button', { name: 'Create provisioning intent' })
    );

    await waitFor(() => {
      expect(createControllerProvisionIntentMock).toHaveBeenCalledTimes(1);
    });
  });
});

describe('CreateManualJobModal renew payload fields', () => {
  it('shows only a Reason field for renew, not the execution fields renew jobs reject', () => {
    renderModal();
    selectOperation('renew');

    expect(screen.getByLabelText(/^Reason/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/^Target domain/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^SANs/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Command ref/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^CA endpoint/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^DNS zone/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^DNS provider/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Cert file path/)).not.toBeInTheDocument();
  });

  it('submits only { reason } as the payload for a renew job, never the execution fields', async () => {
    createJobMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderModal();
    selectOperation('renew');
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'managed_certificate' },
    });
    fireEvent.change(screen.getByLabelText(/^Subject ID/), {
      target: { value: 'cert-1' },
    });
    fireEvent.change(screen.getByLabelText(/^Reason/), {
      target: { value: 'manual renewal requested by ops' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Create job' }));

    await waitFor(() => {
      expect(createJobMock).toHaveBeenCalledWith('ws-1', {
        operation: 'renew',
        subjectType: 'managed_certificate',
        subjectId: 'cert-1',
        payload: { reason: 'manual renewal requested by ops' },
      });
    });
  });

  it('omits payload entirely for a renew job when reason is left blank', async () => {
    createJobMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderModal();
    selectOperation('renew');
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'managed_certificate' },
    });
    fireEvent.change(screen.getByLabelText(/^Subject ID/), {
      target: { value: 'cert-1' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Create job' }));

    await waitFor(() => {
      expect(createJobMock).toHaveBeenCalledWith('ws-1', {
        operation: 'renew',
        subjectType: 'managed_certificate',
        subjectId: 'cert-1',
      });
    });
  });
});
