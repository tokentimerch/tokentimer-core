import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CertopsSetupBanner from '../../src/components/onboarding/CertopsSetupBanner.jsx';

const { canManageMock, workspaceRef } = vi.hoisted(() => ({
  canManageMock: vi.fn(),
  workspaceRef: { id: 'ws-1' },
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: canManageMock,
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: workspaceRef.id }),
}));

const empty = {
  certops: {
    agents: { total: 0 },
    certificates: { total: 0 },
    adcs: { issuers: [], profiles: 0 },
  },
};

function makeApi({ session, summary = empty } = {}) {
  return {
    getSession: vi
      .fn()
      .mockResolvedValue(
        session || { revision: 0, status: 'in_progress', intent: {} }
      ),
    getSummary: vi.fn().mockResolvedValue(summary),
    putSession: vi.fn().mockResolvedValue({}),
  };
}

function Where() {
  const l = useLocation();
  return <div data-testid='where'>{l.pathname + l.search}</div>;
}

const show = (api, props = {}) =>
  render(
    <ChakraProvider>
      <MemoryRouter initialEntries={['/certops/jobs']}>
        <Routes>
          <Route
            path='*'
            element={
              <>
                <CertopsSetupBanner
                  enabled={props.enabled ?? true}
                  paused={props.paused ?? false}
                  api={api}
                />
                <Where />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </ChakraProvider>
  );

describe('CertopsSetupBanner', () => {
  beforeEach(() => {
    canManageMock.mockReset();
    canManageMock.mockReturnValue(true);
    workspaceRef.id = 'ws-1';
  });

  it('shows for an empty CertOps workspace and reads the certops flow', async () => {
    const api = makeApi();
    show(api);
    expect(await screen.findByTestId('certops-setup-banner')).toBeTruthy();
    expect(api.getSession).toHaveBeenCalledWith('ws-1', 'certops');
    expect(api.getSummary).toHaveBeenCalledWith('ws-1', 'certops');
  });

  it('opens the quickstart on the certificate management goals', async () => {
    show(makeApi());
    fireEvent.click(await screen.findByText('Start the CertOps quickstart'));
    expect(screen.getByTestId('where').textContent).toBe(
      '/onboarding?area=certops'
    );
  });

  it('hides for good on the certops flow, not the dashboard prompt flow', async () => {
    const api = makeApi({
      session: { revision: 4, status: 'in_progress', intent: {} },
    });
    show(api);
    fireEvent.click(await screen.findByText('Hide'));
    await waitFor(() => expect(api.putSession).toHaveBeenCalledTimes(1));
    expect(api.putSession.mock.calls[0][0]).toBe('ws-1');
    expect(api.putSession.mock.calls[0][1]).toBe('certops');
    expect(api.putSession.mock.calls[0][2]).toEqual({
      status: 'dismissed',
      expectedRevision: 4,
    });
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
  });

  it('shows nothing once an agent, certificate or issuer exists', async () => {
    const api = makeApi({
      summary: {
        certops: { ...empty.certops, agents: { total: 1 } },
      },
    });
    show(api);
    await waitFor(() => expect(api.getSummary).toHaveBeenCalled());
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
  });

  it('shows nothing when paused, for non managers, or when not enabled', async () => {
    const paused = makeApi();
    show(paused, { paused: true });
    await waitFor(() => expect(paused.getSummary).toHaveBeenCalled());
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();

    canManageMock.mockReturnValue(false);
    const viewer = makeApi();
    show(viewer);
    await new Promise(r => setTimeout(r, 30));
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
    // Nobody who cannot act on it is asked to wait for the check.
    expect(viewer.getSession).not.toHaveBeenCalled();

    canManageMock.mockReturnValue(true);
    const off = makeApi();
    show(off, { enabled: false });
    await new Promise(r => setTimeout(r, 30));
    expect(off.getSession).not.toHaveBeenCalled();
  });

  it('shows nothing when the check fails', async () => {
    const api = makeApi();
    api.getSummary.mockRejectedValue(new Error('boom'));
    show(api);
    await waitFor(() => expect(api.getSummary).toHaveBeenCalled());
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
  });
});

describe('CertopsSetupBanner when the workspace changes', () => {
  beforeEach(() => {
    canManageMock.mockReset();
    canManageMock.mockReturnValue(true);
    workspaceRef.id = 'ws-a';
  });

  // ws-a is empty, ws-b already has an agent.
  const apiByWorkspace = () => ({
    getSession: vi
      .fn()
      .mockResolvedValue({ revision: 0, status: 'in_progress', intent: {} }),
    getSummary: vi
      .fn()
      .mockImplementation(async ws =>
        ws === 'ws-a'
          ? empty
          : { certops: { ...empty.certops, agents: { total: 1 } } }
      ),
    putSession: vi.fn().mockResolvedValue({}),
  });

  const tree = api => (
    <ChakraProvider>
      <MemoryRouter>
        <CertopsSetupBanner enabled paused={false} api={api} />
      </MemoryRouter>
    </ChakraProvider>
  );

  it('drops the banner at once for a workspace that is set up', async () => {
    const api = apiByWorkspace();
    const { rerender } = render(tree(api));
    expect(await screen.findByTestId('certops-setup-banner')).toBeTruthy();

    workspaceRef.id = 'ws-b';
    rerender(tree(api));
    // Immediately, not after the new workspace's answer arrives.
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
    await waitFor(() =>
      expect(api.getSummary).toHaveBeenCalledWith('ws-b', 'certops')
    );
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
  });

  it('drops the banner when the new workspace cannot be managed', async () => {
    const api = apiByWorkspace();
    const { rerender } = render(tree(api));
    await screen.findByTestId('certops-setup-banner');

    workspaceRef.id = 'ws-b';
    canManageMock.mockReturnValue(false);
    rerender(tree(api));
    await new Promise(r => setTimeout(r, 30));
    expect(screen.queryByTestId('certops-setup-banner')).toBeNull();
  });

  it('shows the banner again when switching back to the empty workspace', async () => {
    const api = apiByWorkspace();
    const { rerender } = render(tree(api));
    await screen.findByTestId('certops-setup-banner');

    workspaceRef.id = 'ws-b';
    rerender(tree(api));
    await waitFor(() =>
      expect(api.getSummary).toHaveBeenCalledWith('ws-b', 'certops')
    );
    workspaceRef.id = 'ws-a';
    rerender(tree(api));
    expect(await screen.findByTestId('certops-setup-banner')).toBeTruthy();
  });
});
