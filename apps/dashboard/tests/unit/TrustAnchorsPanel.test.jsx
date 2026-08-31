import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import TrustAnchorsPanel from '../../src/components/certops/TrustAnchorsPanel.jsx';

const {
  useWorkspaceMock,
  useCertOpsTrustAnchorsMock,
  useCertOpsTrustAnchorInstallationsMock,
  useCertOpsAgentsMock,
  createTrustAnchorMock,
  retireTrustAnchorMock,
  createJobMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsTrustAnchorsMock: vi.fn(),
  useCertOpsTrustAnchorInstallationsMock: vi.fn(),
  useCertOpsAgentsMock: vi.fn(),
  createTrustAnchorMock: vi.fn(),
  retireTrustAnchorMock: vi.fn(),
  createJobMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOpsTrustAnchors.js', () => ({
  useCertOpsTrustAnchors: useCertOpsTrustAnchorsMock,
  useCertOpsTrustAnchorInstallations: useCertOpsTrustAnchorInstallationsMock,
}));

vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsAgents: useCertOpsAgentsMock,
}));

vi.mock('../../src/components/certops/certopsTrustAnchorsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsTrustAnchorsApi.js'
  );
  return {
    ...actual,
    createTrustAnchor: createTrustAnchorMock,
    retireTrustAnchor: retireTrustAnchorMock,
  };
});

vi.mock('../../src/components/certops/certopsJobsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsJobsApi.js'
  );
  return {
    ...actual,
    createJob: createJobMock,
  };
});

function renderPanel() {
  return render(
    <ChakraProvider>
      <MemoryRouter>
        <TrustAnchorsPanel />
      </MemoryRouter>
    </ChakraProvider>
  );
}

function anchorsState(overrides = {}) {
  return {
    enabled: true,
    isAdmin: true,
    anchors: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

function installationsState(overrides = {}) {
  return {
    installations: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

function sampleAnchor(overrides = {}) {
  return {
    id: 'anchor-1',
    name: 'Internal Root CA',
    anchorType: 'root',
    fingerprintSha256: 'aa'.repeat(32),
    status: 'active',
    source: 'api',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe('TrustAnchorsPanel', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsTrustAnchorsMock.mockReset();
    useCertOpsTrustAnchorInstallationsMock.mockReset();
    useCertOpsAgentsMock.mockReset();
    createTrustAnchorMock.mockReset();
    retireTrustAnchorMock.mockReset();
    createJobMock.mockReset();

    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    useCertOpsTrustAnchorInstallationsMock.mockReturnValue(
      installationsState()
    );
    useCertOpsAgentsMock.mockReturnValue({
      agents: [{ id: 'agent-a', name: 'Agent A', status: 'active' }],
    });
  });

  it('renders nothing while disabled or for a non-admin', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ enabled: false })
    );
    const { container: disabledContainer } = renderPanel();
    expect(disabledContainer.textContent).toBe('');

    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ isAdmin: false })
    );
    const { container: nonAdminContainer } = renderPanel();
    expect(nonAdminContainer.textContent).toBe('');
  });

  it('shows an empty state pointing to the approve action', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(anchorsState());

    renderPanel();

    expect(screen.getByText('No trust anchors approved yet.')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Approve a trust anchor' })
    ).toBeInTheDocument();
  });

  it('lists anchors with type, fingerprint, and status', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor()] })
    );

    renderPanel();

    expect(screen.getByText('Internal Root CA')).toBeInTheDocument();
    expect(screen.getByText('Root')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('hides the Retire action for an already-revoked anchor', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor({ status: 'revoked' })] })
    );

    renderPanel();

    expect(screen.getByText('Revoked')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Retire' })
    ).not.toBeInTheDocument();
  });

  it('expands a row to show its installations, empty state included', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor()] })
    );

    renderPanel();
    fireEvent.click(screen.getByText('Internal Root CA'));

    expect(
      screen.getByText('Not distributed to any agent yet.')
    ).toBeInTheDocument();
  });

  it('renders installation rows with owner, host, store, and state', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor()] })
    );
    useCertOpsTrustAnchorInstallationsMock.mockReturnValue(
      installationsState({
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
      })
    );

    renderPanel();
    fireEvent.click(screen.getByText('Internal Root CA'));

    expect(screen.getByText('team-a')).toBeInTheDocument();
    expect(screen.getByText('host-a')).toBeInTheDocument();
    expect(screen.getByText('Installed')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Revoke', hidden: true })
    ).toBeInTheDocument();
  });

  it('opens the trust-op modal in distribute mode with the anchor pre-set', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor()] })
    );

    renderPanel();
    fireEvent.click(screen.getByText('Internal Root CA'));
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Distribute to an agent',
        hidden: true,
      })
    );

    expect(
      screen.getByText('Distribute trust trust anchor')
    ).toBeInTheDocument();
  });

  it('opens the trust-op modal in revoke mode from an installation row', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor()] })
    );
    useCertOpsTrustAnchorInstallationsMock.mockReturnValue(
      installationsState({
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
      })
    );

    renderPanel();
    fireEvent.click(screen.getByText('Internal Root CA'));
    fireEvent.click(
      screen.getByRole('button', { name: 'Revoke', hidden: true })
    );

    expect(screen.getByText('Revoke trust trust anchor')).toBeInTheDocument();
  });

  it('disables distribute for a retired anchor', () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor({ status: 'revoked' })] })
    );

    renderPanel();
    fireEvent.click(screen.getByText('Internal Root CA'));

    expect(
      screen.getByRole('button', {
        name: 'Distribute to an agent',
        hidden: true,
      })
    ).toBeDisabled();
  });

  it('approves a new trust anchor and refreshes the list', async () => {
    const refresh = vi.fn();
    useCertOpsTrustAnchorsMock.mockReturnValue(anchorsState({ refresh }));
    createTrustAnchorMock.mockResolvedValue({
      trustAnchor: sampleAnchor(),
    });

    renderPanel();
    fireEvent.click(
      screen.getByRole('button', { name: 'Approve a trust anchor' })
    );

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'Internal Root CA' },
    });
    fireEvent.change(screen.getByLabelText(/^CA certificate/), {
      target: { value: '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Approve anchor' }));

    await waitFor(() => {
      expect(createTrustAnchorMock).toHaveBeenCalledWith('ws-1', {
        name: 'Internal Root CA',
        anchorType: 'root',
        pem: '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----',
      });
      expect(refresh).toHaveBeenCalled();
    });
  });

  it('surfaces a friendly message for an invalid PEM', async () => {
    useCertOpsTrustAnchorsMock.mockReturnValue(anchorsState());
    createTrustAnchorMock.mockRejectedValue({
      response: {
        status: 400,
        data: { code: 'CERTOPS_TRUST_ANCHOR_PEM_INVALID' },
      },
    });

    renderPanel();
    fireEvent.click(
      screen.getByRole('button', { name: 'Approve a trust anchor' })
    );
    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'Bad cert' },
    });
    fireEvent.change(screen.getByLabelText(/^CA certificate/), {
      target: { value: 'not a cert' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Approve anchor' }));

    expect(
      await screen.findByText(/does not look like a single CA certificate/)
    ).toBeInTheDocument();
  });

  it('retires an anchor through the confirm modal and refreshes', async () => {
    const refresh = vi.fn();
    useCertOpsTrustAnchorsMock.mockReturnValue(
      anchorsState({ anchors: [sampleAnchor()], refresh })
    );
    retireTrustAnchorMock.mockResolvedValue({
      trustAnchor: sampleAnchor({ status: 'revoked' }),
      retiredNow: true,
    });

    renderPanel();
    fireEvent.click(screen.getByRole('button', { name: 'Retire' }));
    expect(
      await screen.findByText(/no longer approved for new distribute-trust/)
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retire anchor' }));

    await waitFor(() => {
      expect(retireTrustAnchorMock).toHaveBeenCalledWith('ws-1', 'anchor-1', {
        reason: undefined,
      });
      expect(refresh).toHaveBeenCalled();
    });
  });
});
