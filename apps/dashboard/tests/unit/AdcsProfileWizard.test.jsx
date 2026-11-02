import { render, screen, within, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import AdcsProfileWizard from '../../src/components/certops/AdcsProfileWizard.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { ADCS_DOCS } from '../../src/utils/docsUrls.js';

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
});
