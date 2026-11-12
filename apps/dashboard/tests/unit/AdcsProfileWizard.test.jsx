import { render, screen, within, fireEvent, waitFor, act } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import AdcsProfileWizard from '../../src/components/certops/AdcsProfileWizard.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { ADCS_DOCS } from '../../src/utils/docsUrls.js';
import { createAdcsRenewalProfile } from '../../src/components/certops/certopsRenewalApi';
import { listCertificates, replaceManagingSource } from '../../src/components/certops/certopsApi';

const { listAgentsMock } = vi.hoisted(() => ({ listAgentsMock: vi.fn() }));

vi.mock('../../src/components/certops/certopsAgentsApi', () => ({
  listAgents: listAgentsMock,
}));
vi.mock('../../src/components/certops/certopsApi', () => ({
  listCertificates: vi.fn().mockResolvedValue({ items: [] }),
  replaceManagingSource: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsRenewalApi', () => ({
  createAdcsRenewalProfile: vi.fn(),
}));

const ISSUER = {
  id: 'issuer-1',
  kind: 'adcs',
  name: 'Issuing CA',
  currentVersion: 2,
  revalidationRequired: false,
};

function mount() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AdcsProfileWizard
          isOpen
          onClose={vi.fn()}
          workspaceId='ws-1'
          issuers={[ISSUER]}
          onCreated={vi.fn()}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('AdcsProfileWizard docs panel', () => {
  beforeEach(() => {
    createAdcsRenewalProfile.mockReset();
    replaceManagingSource.mockReset();
    listCertificates.mockReset().mockResolvedValue({ items: [] });
    listAgentsMock.mockReset().mockResolvedValue({ items: [] });
  });

  it('shows one compact panel per step, each with a single renewal link', async () => {
    mount();
    await screen.findByLabelText('Profile name');

    let panel = screen.getByRole('note', { name: 'Learn more' });
    expect(within(panel).getAllByRole('link')).toHaveLength(1);
    expect(
      within(panel).getByRole('link', {
        name: 'What a renewal profile records',
      })
    ).toHaveAttribute('href', ADCS_DOCS.renewalProfile);

    fireEvent.change(screen.getByLabelText('Profile name'), {
      target: { value: 'Web renewals' },
    });
    fireEvent.change(screen.getByLabelText('AD CS issuer'), {
      target: { value: ISSUER.id },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await screen.findByLabelText('Certificate name');
    panel = screen.getByRole('note', { name: 'Learn more' });
    expect(within(panel).getAllByRole('link')).toHaveLength(1);
    expect(
      within(panel).getByRole('link', { name: 'Renewal profile' })
    ).toHaveAttribute('href', ADCS_DOCS.renewalProfile);
    expect(screen.getAllByRole('note', { name: 'Learn more' })).toHaveLength(1);
  });

  it.each(['success', 'failure'])('discards a pending profile %s when the workspace changes', async outcome => {
    let finishCreate;
    createAdcsRenewalProfile.mockReturnValue(new Promise((resolve, reject) => { finishCreate = outcome === 'success' ? () => resolve({ id: 'old-profile' }) : () => reject(new Error('old creation failure')); }));
    const onCreated = vi.fn();
    const view = workspaceId => <ChakraProvider><DashboardThemeProvider><AdcsProfileWizard isOpen onClose={vi.fn()} workspaceId={workspaceId} issuers={[ISSUER]} onCreated={onCreated} /></DashboardThemeProvider></ChakraProvider>;
    const { rerender } = render(view('ws-1'));
    fireEvent.change(screen.getByLabelText('Profile name'), { target: { value: 'Old workspace profile' } });
    fireEvent.change(screen.getByLabelText('AD CS issuer'), { target: { value: ISSUER.id } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText('Certificate name'), { target: { value: 'app.example' } });
    fireEvent.change(screen.getByLabelText('IIS site'), { target: { value: 'Site' } });
    fireEvent.change(screen.getByLabelText('IIS port'), { target: { value: '443' } });
    fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
    await waitFor(() => expect(createAdcsRenewalProfile).toHaveBeenCalledWith('ws-1', expect.anything()));
    rerender(view('ws-2'));
    await act(async () => { finishCreate(); await Promise.resolve(); });
    expect(await screen.findByLabelText('Profile name')).toHaveValue('');
    expect(onCreated).not.toHaveBeenCalled();
    expect(screen.queryByText(/old creation failure/)).not.toBeInTheDocument();
  });

  it.each(['success', 'failure'])('discards an attachment %s from the previous workspace', async outcome => {
    createAdcsRenewalProfile.mockResolvedValue({ id: 'profile-1' });
    listCertificates.mockResolvedValue({ items: [{ identityId: 'identity-1', commonName: 'app.example', sources: [{ managedCertificateId: 'mc-1', currentIdentityId: 'identity-1', source: 'agent_windows', periodEndedAt: '2026-01-01T00:00:00Z' }] }] });
    let finishAttach;
    replaceManagingSource.mockReturnValue(new Promise((resolve, reject) => { finishAttach = outcome === 'success' ? () => resolve({}) : () => reject(new Error('old workspace failure')); }));
    const view = workspaceId => <ChakraProvider><DashboardThemeProvider><AdcsProfileWizard isOpen onClose={vi.fn()} workspaceId={workspaceId} issuers={[ISSUER]} /></DashboardThemeProvider></ChakraProvider>;
    const { rerender } = render(view('ws-1'));
    fireEvent.change(screen.getByLabelText('Profile name'), { target: { value: 'Old workspace profile' } });
    fireEvent.change(screen.getByLabelText('AD CS issuer'), { target: { value: ISSUER.id } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText('Certificate name'), { target: { value: 'app.example' } });
    fireEvent.change(screen.getByLabelText('IIS site'), { target: { value: 'Site' } });
    fireEvent.change(screen.getByLabelText('IIS port'), { target: { value: '443' } });
    fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Attach and enable automation' }));
    await waitFor(() => expect(replaceManagingSource).toHaveBeenCalled());
    rerender(view('ws-2'));
    await act(async () => { finishAttach(); await Promise.resolve(); });
    expect(await screen.findByLabelText('Profile name')).toHaveValue('');
    expect(screen.queryByText(/old workspace failure/)).not.toBeInTheDocument();
  });

  it.each(['close', 'unmount'])('ignores profile creation after %s', async action => {
    let resolveCreate;
    createAdcsRenewalProfile.mockReturnValue(new Promise(resolve => { resolveCreate = resolve; }));
    const onCreated = vi.fn();
    const view = isOpen => <ChakraProvider><DashboardThemeProvider><AdcsProfileWizard isOpen={isOpen} onClose={vi.fn()} workspaceId='ws-1' issuers={[ISSUER]} onCreated={onCreated} /></DashboardThemeProvider></ChakraProvider>;
    const { rerender, unmount } = render(view(true));
    fireEvent.change(screen.getByLabelText('Profile name'), { target: { value: 'Old profile' } });
    fireEvent.change(screen.getByLabelText('AD CS issuer'), { target: { value: ISSUER.id } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText('Certificate name'), { target: { value: 'app.example' } });
    fireEvent.change(screen.getByLabelText('IIS site'), { target: { value: 'Site' } });
    fireEvent.change(screen.getByLabelText('IIS port'), { target: { value: '443' } });
    fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
    await waitFor(() => expect(createAdcsRenewalProfile).toHaveBeenCalledWith('ws-1', expect.anything()));
    if (action === 'close') rerender(view(false)); else unmount();
    await act(async () => { resolveCreate({ id: 'old-profile' }); await Promise.resolve(); });
    expect(onCreated).not.toHaveBeenCalled();
  });
});
