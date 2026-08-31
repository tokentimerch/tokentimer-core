import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CreateManualJobModal from '../../src/components/certops/CreateManualJobModal.jsx';

const {
  useWorkspaceMock,
  useCertOpsAgentsMock,
  useCertOpsControllerClustersMock,
  useCertOpsIsWorkspaceAdminMock,
  createJobMock,
  createControllerProvisionIntentMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  useCertOpsControllerClustersMock: vi.fn(),
  useCertOpsIsWorkspaceAdminMock: vi.fn(),
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

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsIsWorkspaceAdmin: useCertOpsIsWorkspaceAdminMock,
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
  useCertOpsIsWorkspaceAdminMock.mockReset();
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
  useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
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

describe('CreateManualJobModal trustOp mode', () => {
  const AGENT_A = { id: 'agent-a', name: 'Agent A', status: 'active' };
  const AGENT_B = { id: 'agent-b', name: 'Agent B', status: 'active' };

  const distributeTrustOp = {
    anchorId: 'anchor-1',
    anchorName: 'Internal Root CA',
    anchorFingerprint: 'aa'.repeat(32),
    operation: 'distribute-trust',
    installations: [
      {
        id: 'install-1',
        agentId: 'agent-a',
        owner: 'team-a',
        host: 'host-a',
        store: 'root',
        transitionState: 'installed',
      },
    ],
  };

  const revokeTrustOp = {
    ...distributeTrustOp,
    operation: 'revoke-trust',
  };

  beforeEach(() => {
    useCertOpsAgentsMock.mockReturnValue({ agents: [AGENT_A, AGENT_B] });
  });

  it('renders the trust-op header instead of the generic manual-job form', () => {
    renderModal({ trustOp: distributeTrustOp });

    expect(
      screen.getByText('Distribute trust trust anchor')
    ).toBeInTheDocument();
    expect(screen.queryByText('Operation')).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Subject type/)).not.toBeInTheDocument();
  });

  it('disables submit until an agent and owner are chosen on distribute', () => {
    renderModal({ trustOp: distributeTrustOp });

    const submit = screen.getByRole('button', { name: 'Distribute trust' });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'agent-b' },
    });
    fireEvent.change(screen.getByLabelText(/^Owner/), {
      target: { value: 'team-a' },
    });

    expect(submit).toBeEnabled();
  });

  it('submits distribute-trust with agentId/owner/subjectType trust_anchor and an auto-generated idempotency key', async () => {
    createJobMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderModal({ trustOp: distributeTrustOp });
    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'agent-b' },
    });
    fireEvent.change(screen.getByLabelText(/^Owner/), {
      target: { value: 'team-a' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Distribute trust' }));

    await waitFor(() => {
      expect(createJobMock).toHaveBeenCalledTimes(1);
    });
    const [workspaceId, body] = createJobMock.mock.calls[0];
    expect(workspaceId).toBe('ws-1');
    expect(body.operation).toBe('distribute-trust');
    expect(body.subjectType).toBe('trust_anchor');
    expect(body.subjectId).toBe('anchor-1');
    expect(body.agentId).toBe('agent-b');
    expect(body.owner).toBe('team-a');
    expect(body.idempotencyKey).toBeTruthy();
  });

  it("offers only the anchor's existing owners on distribute, from the installations the panel passed in", () => {
    renderModal({ trustOp: distributeTrustOp });

    const ownerSelect = screen.getByLabelText(/^Owner/);
    expect(ownerSelect.tagName).toBe('SELECT');
    expect(screen.getByRole('option', { name: 'team-a' })).toBeInTheDocument();
  });

  it('switches to a free-text new-owner input and submits the typed value', async () => {
    createJobMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderModal({ trustOp: distributeTrustOp });
    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'agent-b' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'New owner' }));
    fireEvent.change(
      screen.getByPlaceholderText('e.g. a team or system label'),
      { target: { value: 'team-b' } }
    );

    fireEvent.click(screen.getByRole('button', { name: 'Distribute trust' }));

    await waitFor(() => {
      expect(createJobMock).toHaveBeenCalledTimes(1);
    });
    expect(createJobMock.mock.calls[0][1].owner).toBe('team-b');
  });

  it('warns on a case-only near-duplicate of an existing owner without blocking submit', () => {
    renderModal({ trustOp: distributeTrustOp });
    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'agent-b' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'New owner' }));
    fireEvent.change(
      screen.getByPlaceholderText('e.g. a team or system label'),
      { target: { value: 'Team-A' } }
    );

    expect(
      screen.getByText(/Close to existing owner "team-a"/)
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Distribute trust' })
    ).toBeEnabled();
  });

  it('on revoke, only lists live installations and derives agentId/owner from the one selected', async () => {
    createJobMock.mockResolvedValue({ ownershipReleased: true });

    renderModal({ trustOp: revokeTrustOp });

    expect(
      screen.getByRole('option', {
        name: /team-a — Agent A \(agent-a\) \(root\)/,
      })
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'install-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Revoke trust' }));

    await waitFor(() => {
      expect(createJobMock).toHaveBeenCalledTimes(1);
    });
    const body = createJobMock.mock.calls[0][1];
    expect(body.operation).toBe('revoke-trust');
    expect(body.agentId).toBe('agent-a');
    expect(body.owner).toBe('team-a');
  });

  it('excludes a removed installation from the revoke picker', () => {
    renderModal({
      trustOp: {
        ...revokeTrustOp,
        installations: [
          {
            ...distributeTrustOp.installations[0],
            transitionState: 'removed',
          },
        ],
      },
    });

    expect(
      screen.queryByRole('option', { name: /team-a/ })
    ).not.toBeInTheDocument();
  });

  it('requires workspace admin to submit', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);
    renderModal({ trustOp: distributeTrustOp });

    expect(
      screen.getByText('Trust-anchor operations require workspace admin.')
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'agent-b' },
    });
    fireEvent.change(screen.getByLabelText(/^Owner/), {
      target: { value: 'team-a' },
    });
    expect(
      screen.getByRole('button', { name: 'Distribute trust' })
    ).toBeDisabled();
  });

  it('maps CERTOPS_TRUST_JOB_IDEMPOTENCY_CONFLICT to a friendly retry message', async () => {
    createJobMock.mockRejectedValue({
      response: {
        status: 409,
        data: {
          error: 'idempotency conflict',
          code: 'CERTOPS_TRUST_JOB_IDEMPOTENCY_CONFLICT',
        },
      },
    });

    renderModal({ trustOp: distributeTrustOp });
    fireEvent.change(screen.getByLabelText(/^Target agent/), {
      target: { value: 'agent-b' },
    });
    fireEvent.change(screen.getByLabelText(/^Owner/), {
      target: { value: 'team-a' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Distribute trust' }));

    await waitFor(() => {
      expect(createJobMock).toHaveBeenCalledTimes(1);
    });
  });
});
