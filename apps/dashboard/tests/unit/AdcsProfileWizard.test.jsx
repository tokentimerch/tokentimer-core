import { act, render, screen, within, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import AdcsProfileWizard from '../../src/components/certops/AdcsProfileWizard.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { ADCS_DOCS } from '../../src/utils/docsUrls.js';

const { listAgentsMock, createProfileMock } = vi.hoisted(() => ({
  listAgentsMock: vi.fn(),
  createProfileMock: vi.fn(),
}));

vi.mock('../../src/components/certops/certopsAgentsApi', () => ({
  listAgents: listAgentsMock,
}));
vi.mock('../../src/components/certops/certopsApi', () => ({
  listCertificates: vi.fn().mockResolvedValue({ items: [] }),
  replaceManagingSource: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsRenewalApi', () => ({
  createAdcsRenewalProfile: createProfileMock,
}));

const ISSUER = {
  id: 'issuer-1',
  kind: 'adcs',
  name: 'Issuing CA',
  currentVersion: 2,
  revalidationRequired: false,
};

function wizard(workspaceId = 'ws-1', onCreated = vi.fn()) {
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <AdcsProfileWizard
          isOpen
          onClose={vi.fn()}
          workspaceId={workspaceId}
          issuers={[ISSUER]}
          onCreated={onCreated}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

it('ignores profile creation that completes after a workspace switch', async () => {
  let finishCreation;
  createProfileMock.mockReturnValueOnce(
    new Promise(resolve => {
      finishCreation = resolve;
    })
  );
  listAgentsMock.mockResolvedValue({ items: [] });
  const onCreated = vi.fn();
  const { rerender } = render(wizard('ws-1', onCreated));

  fireEvent.change(await screen.findByLabelText('Profile name'), {
    target: { value: 'First workspace profile' },
  });
  fireEvent.change(screen.getByLabelText('AD CS issuer'), {
    target: { value: ISSUER.id },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  fireEvent.change(await screen.findByLabelText('Certificate name'), {
    target: { value: 'one.example.test' },
  });
  const review = screen.getByRole('button', { name: 'Review' });
  const site = screen.getByLabelText('IIS site');
  const port = screen.getByLabelText('IIS port');
  expect(site).toHaveValue('');
  expect(port).toHaveValue('');
  expect(review).toBeDisabled();
  fireEvent.change(site, { target: { value: 'Public Site' } });
  fireEvent.change(port, { target: { value: '443' } });
  fireEvent.click(review);
  fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
  expect(createProfileMock).toHaveBeenCalledWith(
    'ws-1',
    expect.objectContaining({ name: 'First workspace profile' })
  );

  rerender(wizard('ws-2'));
  await act(async () => finishCreation({ id: 'created-in-first-workspace' }));

  expect(onCreated).not.toHaveBeenCalled();
  expect(await screen.findByLabelText('Profile name')).toHaveValue('');
});

describe('AdcsProfileWizard docs panel', () => {
  beforeEach(() => {
    listAgentsMock.mockReset().mockResolvedValue({ items: [] });
  });

  it('shows one compact panel per step, each with a single renewal link', async () => {
    render(wizard());
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
