import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import BootstrapTokenList from '../../src/components/certops/BootstrapTokenList.jsx';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsBootstrapTokensMock,
  revokeBootstrapTokenMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsBootstrapTokensMock: vi.fn(),
  revokeBootstrapTokenMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsBootstrapTokens: useCertOpsBootstrapTokensMock,
}));

vi.mock('../../src/components/certops/certopsAgentsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsAgentsApi.js'
  );
  return {
    ...actual,
    revokeBootstrapToken: revokeBootstrapTokenMock,
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

describe('BootstrapTokenList', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsBootstrapTokensMock.mockReset();
    revokeBootstrapTokenMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('renders nothing while CertOps availability is unresolved or disabled', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(
      tokensState({ enabled: false })
    );

    const { container } = renderWithProviders(<BootstrapTokenList />);

    expect(container.textContent).toBe('');
  });

  it('renders nothing for a viewer without manager permission', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsBootstrapTokensMock.mockReturnValue(tokensState());

    const { container } = renderWithProviders(<BootstrapTokenList />);

    expect(container.textContent).toBe('');
  });

  it('lists bootstrap tokens and revokes an active one', async () => {
    const refresh = vi.fn();
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(
      tokensState({
        refresh,
        tokens: [
          {
            id: 'bt-1',
            name: 'active-token',
            tokenPrefix: 'ttboot_abc',
            status: 'active',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            createdAt: new Date().toISOString(),
          },
          {
            id: 'bt-2',
            name: 'used-token',
            tokenPrefix: 'ttboot_def',
            status: 'used',
            usedAt: new Date().toISOString(),
            createdAt: new Date().toISOString(),
          },
        ],
      })
    );
    revokeBootstrapTokenMock.mockResolvedValue({ token: { id: 'bt-1' } });

    renderWithProviders(<BootstrapTokenList />);

    expect(screen.getByText('active-token')).toBeInTheDocument();
    expect(screen.getByText('used-token')).toBeInTheDocument();
    const revokeButtons = screen.getAllByRole('button', { name: 'Revoke' });
    expect(revokeButtons).toHaveLength(1);

    fireEvent.click(revokeButtons[0]);
    expect(
      await screen.findByText('Revoke bootstrap token')
    ).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: 'Revoke' }).at(-1));

    await waitFor(() => {
      expect(revokeBootstrapTokenMock).toHaveBeenCalledWith('ws-1', 'bt-1');
      expect(refresh).toHaveBeenCalled();
    });
  });

  it('renders the shared pagination control from the server envelope', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(
      tokensState({
        tokens: [
          {
            id: 'bt-1',
            name: 'active-token',
            tokenPrefix: 'ttboot_abc',
            status: 'active',
            createdAt: new Date().toISOString(),
          },
        ],
        pagination: { limit: 20, offset: 0, total: 42 },
      })
    );

    renderWithProviders(<BootstrapTokenList />);

    expect(
      screen.getByRole('navigation', { name: 'bootstrap tokens pagination' })
    ).toBeInTheDocument();
    expect(screen.getByText('1-20 of 42')).toBeInTheDocument();
  });

  it('offers a way back to the first page when the offset lands past the end', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsBootstrapTokensMock.mockReturnValue(
      tokensState({
        tokens: [],
        pagination: { limit: 20, offset: 40, total: 5 },
      })
    );

    renderWithProviders(<BootstrapTokenList />, {
      initialEntries: ['/certops/agents?bootstrapOffset=40'],
    });

    expect(
      screen.getByText('This page is past the end of the list.')
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Back to the first page' })
    ).toBeInTheDocument();
  });
});
