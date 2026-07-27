import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import ApiTokenList from '../../src/components/certops/ApiTokenList.jsx';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsApiTokensMock,
  revokeApiTokenMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsApiTokensMock: vi.fn(),
  revokeApiTokenMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/useCertOpsJobs.js', () => ({
  useCertOpsApiTokens: useCertOpsApiTokensMock,
}));

vi.mock('../../src/components/certops/certopsTokensApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsTokensApi.js'
  );
  return {
    ...actual,
    revokeApiToken: revokeApiTokenMock,
  };
});

function renderWithProviders(ui, { initialEntries = ['/'] } = {}) {
  return render(
    <ChakraProvider>
      <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

function tokensState(overrides = {}) {
  const { pagination, ...rest } = overrides;
  const state = {
    enabled: true,
    tokens: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...rest,
  };
  return {
    ...state,
    pagination:
      pagination === undefined
        ? { limit: 20, offset: 0, total: state.tokens.length }
        : pagination,
  };
}

describe('ApiTokenList', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsApiTokensMock.mockReset();
    revokeApiTokenMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('renders nothing while CertOps availability is unresolved or disabled', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState({ enabled: false }));

    const { container } = renderWithProviders(<ApiTokenList />);

    expect(container.textContent).toBe('');
  });

  it('shows a loading state distinct from the empty and populated states', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState({ loading: true }));

    renderWithProviders(<ApiTokenList />);

    expect(screen.getByText('Loading API tokens...')).toBeInTheDocument();
    expect(screen.queryByText('No machine tokens yet.')).not.toBeInTheDocument();
  });

  it('shows an empty state with manager-only helper copy', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<ApiTokenList />);

    expect(screen.getByText('No machine tokens yet.')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Create one to let an external executor report certificate lifecycle events, or a cert-manager controller drive provisioning.'
      )
    ).toBeInTheDocument();
  });

  it('hides the manager-only helper copy for a viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<ApiTokenList />);

    expect(screen.getByText('No machine tokens yet.')).toBeInTheDocument();
    expect(
      screen.queryByText(/Create one to let an external executor/)
    ).not.toBeInTheDocument();
  });

  it('shows an error alert distinct from the empty/loading states', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({ error: 'Could not load certificate operations API tokens.' })
    );

    renderWithProviders(<ApiTokenList />);

    expect(
      screen.getByText('Could not load certificate operations API tokens.')
    ).toBeInTheDocument();
  });

  it('renders active, revoked and expired tokens with distinct status badges', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({
        tokens: [
          {
            id: 'tok-active',
            name: 'active-token',
            tokenPrefix: 'ttx_ab12ab12ab12ab12',
            status: 'active',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
          {
            id: 'tok-revoked',
            name: 'revoked-token',
            tokenPrefix: 'ttx_cd34cd34cd34cd34',
            status: 'revoked',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
          {
            id: 'tok-expired',
            name: 'expired-token',
            tokenPrefix: 'ttx_ef56ef56ef56ef56',
            status: 'active',
            expiresAt: '2020-01-01T00:00:00.000Z',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      })
    );

    renderWithProviders(<ApiTokenList />);

    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('revoked')).toBeInTheDocument();
    expect(screen.getByText('expired')).toBeInTheDocument();

    const revokeButtons = screen.getAllByRole('button', { name: 'Revoke' });
    expect(revokeButtons).toHaveLength(1);
  });

  it('shows a controller cluster badge for controller-scoped tokens', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({
        tokens: [
          {
            id: 'tok-controller',
            name: 'controller-token',
            tokenPrefix: 'ttx_ab12ab12ab12ab12',
            status: 'active',
            scopes: ['certops:provision:execute'],
            controllerClusterId: 'prod-eu-west-1',
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      })
    );

    renderWithProviders(<ApiTokenList />);

    expect(screen.getByText('provision:execute')).toBeInTheDocument();
    expect(screen.getByText('cluster: prod-eu-west-1')).toBeInTheDocument();
  });

  it('revokes a token via confirmation dialog with the correct token id', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const refresh = vi.fn();
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({
        refresh,
        tokens: [
          {
            id: 'tok-1',
            name: 'certbot-prod-hook',
            tokenPrefix: 'ttx_ab12ab12ab12ab12',
            status: 'active',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      })
    );
    revokeApiTokenMock.mockResolvedValue({ token: { id: 'tok-1', status: 'revoked' } });

    renderWithProviders(<ApiTokenList />);

    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(screen.getByText('Revoke API token')).toBeInTheDocument();

    const dialog = screen.getByRole('alertdialog');
    fireEvent.click(
      screen.getAllByRole('button', { name: 'Revoke' }).find(btn => dialog.contains(btn))
    );

    await waitFor(() => expect(revokeApiTokenMock).toHaveBeenCalledTimes(1));
    expect(revokeApiTokenMock).toHaveBeenCalledWith('ws-1', 'tok-1');
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('renders the shared pagination control from the server envelope', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({
        tokens: [
          {
            id: 'tok-1',
            name: 'certbot-prod-hook',
            tokenPrefix: 'ttx_ab12ab12ab12ab12',
            status: 'active',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
        pagination: { limit: 20, offset: 0, total: 42 },
      })
    );

    renderWithProviders(<ApiTokenList />);

    expect(
      screen.getByRole('navigation', { name: 'API tokens pagination' })
    ).toBeInTheDocument();
    expect(screen.getByText('1-20 of 42')).toBeInTheDocument();
  });

  it('offers a way back to the first page when the offset lands past the end', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({
        tokens: [],
        pagination: { limit: 20, offset: 40, total: 5 },
      })
    );

    renderWithProviders(<ApiTokenList />, {
      initialEntries: ['/certops/settings?tokenOffset=40'],
    });

    expect(
      screen.getByText('This page is past the end of the list.')
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Back to the first page' })
    ).toBeInTheDocument();
  });
});
