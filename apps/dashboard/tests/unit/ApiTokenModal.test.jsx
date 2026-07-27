import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import ApiTokenModal from '../../src/components/certops/ApiTokenModal.jsx';

const {
  useWorkspaceMock,
  createApiTokenMock,
  createTokenMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  createApiTokenMock: vi.fn(),
  createTokenMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/utils/apiClient', async () => {
  const actual = await vi.importActual('../../src/utils/apiClient');
  return {
    ...actual,
    tokenAPI: { createToken: createTokenMock },
  };
});

vi.mock('../../src/components/certops/certopsTokensApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsTokensApi.js'
  );
  return {
    ...actual,
    createApiToken: createApiTokenMock,
  };
});

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

describe('ApiTokenModal', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    createApiTokenMock.mockReset();
    createTokenMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('renders nothing when closed', () => {
    const { container } = renderWithProviders(
      <ApiTokenModal isOpen={false} onClose={vi.fn()} />
    );
    expect(container.textContent).toBe('');
  });

  it('shows the create form with accessible labels', () => {
    renderWithProviders(<ApiTokenModal isOpen onClose={vi.fn()} />);

    expect(screen.getByLabelText(/^Name/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Expires \(optional\)/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Create token' })
    ).toBeInTheDocument();
  });

  it('requires at least one scope to submit', () => {
    renderWithProviders(<ApiTokenModal isOpen onClose={vi.fn()} />);

    const createButton = screen.getByRole('button', { name: 'Create token' });
    expect(createButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'certbot-prod-hook' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i })
    );
    expect(createButton).not.toBeDisabled();

    fireEvent.click(
      screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i })
    );
    expect(createButton).toBeDisabled();
  });

  it('requires a cluster id once a controller scope is selected, and clears it when deselected', () => {
    renderWithProviders(<ApiTokenModal isOpen onClose={vi.fn()} />);

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'controller-token' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: /provision:execute/i })
    );

    expect(screen.getByLabelText(/^Cluster ID/)).toBeInTheDocument();
    const createButton = screen.getByRole('button', { name: 'Create token' });
    expect(createButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Cluster ID/), {
      target: { value: 'prod-eu-west-1' },
    });
    expect(createButton).not.toBeDisabled();

    fireEvent.click(
      screen.getByRole('checkbox', { name: /provision:execute/i })
    );
    expect(screen.queryByLabelText(/^Cluster ID/)).not.toBeInTheDocument();
  });

  it('creates a token with the cluster id and shows the plaintext exactly once', async () => {
    createApiTokenMock.mockResolvedValue({
      token: { id: 'tok-1', name: 'controller-token' },
      plaintextToken:
        'ttx_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    });
    const onCreated = vi.fn();

    renderWithProviders(
      <ApiTokenModal isOpen onClose={vi.fn()} onCreated={onCreated} />
    );

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'controller-token' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: /provision:execute/i })
    );
    fireEvent.change(screen.getByLabelText(/^Cluster ID/), {
      target: { value: 'prod-eu-west-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));

    await waitFor(() => expect(createApiTokenMock).toHaveBeenCalledTimes(1));
    expect(createApiTokenMock).toHaveBeenCalledWith('ws-1', {
      name: 'controller-token',
      scopes: ['certops:provision:execute'],
      controllerClusterId: 'prod-eu-west-1',
    });

    const plaintext =
      'ttx_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    expect(await screen.findByText(plaintext)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'I stored the token' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
  });

  it('does not dismiss the modal or destroy the secret on Escape', async () => {
    createApiTokenMock.mockResolvedValue({
      token: { id: 'tok-1', name: 'certbot-prod-hook' },
      plaintextToken:
        'ttx_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    });
    const onClose = vi.fn();

    renderWithProviders(<ApiTokenModal isOpen onClose={onClose} />);

    fireEvent.change(screen.getByLabelText(/^Name/), {
      target: { value: 'certbot-prod-hook' },
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: /read.*read certificates and jobs/i })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));

    const plaintext =
      'ttx_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    expect(await screen.findByText(plaintext)).toBeInTheDocument();

    const dialog = screen.getByRole('dialog');
    fireEvent.keyDown(dialog, { key: 'Escape', code: 'Escape' });

    expect(screen.getByText(plaintext)).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });
});
