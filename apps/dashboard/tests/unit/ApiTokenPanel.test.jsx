import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import ApiTokenPanel from '../../src/components/certops/ApiTokenPanel.jsx';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsApiTokensMock,
  createApiTokenMock,
  revokeApiTokenMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsApiTokensMock: vi.fn(),
  createApiTokenMock: vi.fn(),
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
    createApiToken: createApiTokenMock,
    revokeApiToken: revokeApiTokenMock,
  };
});

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

function tokensState(overrides = {}) {
  return {
    enabled: true,
    tokens: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

describe('ApiTokenPanel', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsApiTokensMock.mockReset();
    createApiTokenMock.mockReset();
    revokeApiTokenMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('renders nothing while CertOps availability is unresolved or disabled', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState({ enabled: false }));

    const { container } = renderWithProviders(<ApiTokenPanel />);

    expect(container.textContent).toBe('');
  });

  it('does not show the create form for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<ApiTokenPanel />);

    expect(
      screen.queryByRole('heading', { name: 'Create token' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('textbox', { name: 'Name' })
    ).not.toBeInTheDocument();
  });

  it('shows the create form with accessible labels for a manager', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<ApiTokenPanel />);

    expect(screen.getByLabelText(/^Name/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Expires \(optional\)/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Create token' })
    ).toBeInTheDocument();
  });

  it('shows a loading state distinct from the empty and populated states', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState({ loading: true }));

    renderWithProviders(<ApiTokenPanel />);

    expect(screen.getByText('Loading API tokens...')).toBeInTheDocument();
    expect(screen.queryByText('No machine tokens yet.')).not.toBeInTheDocument();
  });

  it('shows an empty state with manager-only helper copy', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<ApiTokenPanel />);

    expect(screen.getByText('No machine tokens yet.')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Create one to let an external executor report certificate lifecycle events.'
      )
    ).toBeInTheDocument();
  });

  it('shows an error alert distinct from the empty/loading states', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(
      tokensState({ error: 'Could not load certificate operations API tokens.' })
    );

    renderWithProviders(<ApiTokenPanel />);

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
            tokenPrefix: 'cop_ab12',
            status: 'active',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
          {
            id: 'tok-revoked',
            name: 'revoked-token',
            tokenPrefix: 'cop_cd34',
            status: 'revoked',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
          {
            id: 'tok-expired',
            name: 'expired-token',
            tokenPrefix: 'cop_ef56',
            status: 'active',
            expiresAt: '2020-01-01T00:00:00.000Z',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      })
    );

    renderWithProviders(<ApiTokenPanel />);

    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('revoked')).toBeInTheDocument();
    expect(screen.getByText('expired')).toBeInTheDocument();

    expect(
      screen.queryByRole('button', { name: /Revoke/i })
    ).toBeInTheDocument();
    const revokeButtons = screen.getAllByRole('button', { name: 'Revoke' });
    expect(revokeButtons).toHaveLength(1);
  });

  it('lets a manager toggle scope checkboxes and requires at least one scope to submit', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());

    renderWithProviders(<ApiTokenPanel />);

    const createButton = screen.getByRole('button', { name: 'Create token' });
    expect(createButton).toBeDisabled();

    const nameInput = screen.getByLabelText(/^Name/);
    fireEvent.change(nameInput, {
      target: { value: 'certbot-prod-hook' },
    });
    fireEvent.click(screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i }));
    expect(createButton).not.toBeDisabled();

    fireEvent.click(screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i }));
    expect(createButton).toBeDisabled();
  });

  it('creates a token, shows the plaintext exactly once, then hides it after acknowledgement', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    const refresh = vi.fn();
    useCertOpsApiTokensMock.mockReturnValue(tokensState({ refresh }));
    createApiTokenMock.mockResolvedValue({
      token: { id: 'tok-1', name: 'certbot-prod-hook' },
      plaintextToken: 'copsk_live_supersecretvalue',
    });

    renderWithProviders(<ApiTokenPanel />);

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'certbot-prod-hook' },
    });
    fireEvent.click(screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));

    await waitFor(() => expect(createApiTokenMock).toHaveBeenCalledTimes(1));
    expect(createApiTokenMock).toHaveBeenCalledWith('ws-1', {
      name: 'certbot-prod-hook',
      scopes: ['certops:read'],
    });

    expect(
      await screen.findByText('copsk_live_supersecretvalue')
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'I stored the token' }));

    await waitFor(() =>
      expect(
        screen.queryByText('copsk_live_supersecretvalue')
      ).not.toBeInTheDocument()
    );
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('submits an expiry timestamp as ISO when one is set', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue(tokensState());
    createApiTokenMock.mockResolvedValue({
      token: { id: 'tok-1' },
      plaintextToken: 'copsk_live_secret',
    });

    renderWithProviders(<ApiTokenPanel />);

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'expiring-token' },
    });
    fireEvent.click(screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i }));
    fireEvent.change(screen.getByLabelText(/^Expires \(optional\)/), {
      target: { value: '2030-06-01T10:00' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));

    await waitFor(() => expect(createApiTokenMock).toHaveBeenCalledTimes(1));
    const [, payload] = createApiTokenMock.mock.calls[0];
    expect(payload.expiresAt).toBe(new Date('2030-06-01T10:00').toISOString());
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
            tokenPrefix: 'cop_ab12',
            status: 'active',
            scopes: ['certops:read'],
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      })
    );
    revokeApiTokenMock.mockResolvedValue({ token: { id: 'tok-1', status: 'revoked' } });

    renderWithProviders(<ApiTokenPanel />);

    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));

    expect(screen.getByText('Revoke API token')).toBeInTheDocument();

    const dialog = screen.getByRole('alertdialog');
    fireEvent.click(
      within(dialog).getByRole('button', { name: 'Revoke' })
    );

    await waitFor(() => expect(revokeApiTokenMock).toHaveBeenCalledTimes(1));
    expect(revokeApiTokenMock).toHaveBeenCalledWith('ws-1', 'tok-1');
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
