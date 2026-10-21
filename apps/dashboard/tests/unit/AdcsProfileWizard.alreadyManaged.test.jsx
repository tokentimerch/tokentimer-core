import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

const replaceCalls = [];
let replaceResults = [];
vi.mock('../../src/components/certops/certopsApi.js', () => ({
  listCertificates: vi.fn(),
  replaceManagingSource: (...args) => {
    replaceCalls.push(args);
    const next = replaceResults.shift();
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  },
}));
vi.mock('../../src/components/certops/certopsAgentsApi.js', () => ({
  listAgents: vi.fn().mockResolvedValue({ items: [] }),
}));
vi.mock('../../src/components/certops/certopsRenewalApi.js', () => ({
  createAdcsRenewalProfile: vi.fn().mockResolvedValue({ id: 'profile-1' }),
}));
vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: vi.fn(),
  showError: vi.fn(),
}));

import { listCertificates } from '../../src/components/certops/certopsApi.js';
import AdcsProfileWizard from '../../src/components/certops/AdcsProfileWizard.jsx';

const OPEN_PERIOD = '11111111-1111-4111-8111-111111111111';

function conflict(data) {
  return Object.assign(new Error('conflict'), {
    response: { status: 409, data },
  });
}

const alreadyOpen = conflict({
  code: 'CERTOPS_MANAGEMENT_ALREADY_OPEN',
  reason: 'period_id_required',
  error: `This certificate is already managed since 2026-10-01T00:00:00.000Z (automatic renewal with profile "Edge IIS"), period ${OPEN_PERIOD}. Retry replace-management with that periodId.`,
  currentPeriod: { periodId: OPEN_PERIOD, managementMode: 'automatic' },
});

async function openAtAttachStep(sources) {
  listCertificates.mockResolvedValue({
    items: [
      {
        commonName: 'app.example',
        sources,
      },
    ],
  });
  render(
    <ChakraProvider>
      <WizardHost />
    </ChakraProvider>
  );
  fireEvent.change(screen.getByLabelText('Profile name'), {
    target: { value: 'Edge IIS 2' },
  });
  fireEvent.change(screen.getByLabelText('AD CS issuer'), {
    target: { value: 'issuer-1' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  fireEvent.change(screen.getByLabelText('Certificate name'), {
    target: { value: 'app.example' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
  return screen.findByRole('button', { name: 'Attach and enable automation' });
}

function WizardHost() {
  return (
    <AdcsProfileWizard
      isOpen
      onClose={vi.fn()}
      workspaceId='ws-1'
      issuers={[
        {
          id: 'issuer-1',
          name: 'Corp CA',
          kind: 'adcs',
          currentVersion: 1,
          revalidationRequired: false,
        },
      ]}
      onCreated={vi.fn()}
    />
  );
}

// The inventory still shows an ended registration, so the wizard sends no
// periodId; the server knows a newer period is open.
const staleInventory = [
  {
    managedCertificateId: 'mc-1',
    source: 'agent_filesystem',
    startedAt: '2026-09-01T00:00:00Z',
    periodStartedAt: '2026-09-01T00:00:00Z',
    periodEndedAt: '2026-09-02T00:00:00Z',
    periodId: null,
  },
];

describe('AD CS wizard when the certificate is already managed', () => {
  beforeEach(() => {
    replaceCalls.length = 0;
    replaceResults = [];
  });

  it('shows the server explanation and replaces the named open period only after an explicit click', async () => {
    replaceResults = [alreadyOpen, { stopped: {}, readded: {} }];
    const attach = await openAtAttachStep(staleInventory);
    fireEvent.click(attach);

    expect(
      await screen.findByText(/automatic renewal with profile "Edge IIS"/)
    ).toBeInTheDocument();
    expect(replaceCalls).toHaveLength(1);
    expect(replaceCalls[0][2].periodId).toBeNull();

    fireEvent.click(
      screen.getByRole('button', {
        name: /Replace the current management with this profile/,
      })
    );
    await waitFor(() => expect(replaceCalls).toHaveLength(2));
    expect(replaceCalls[1][1]).toBe('mc-1');
    expect(replaceCalls[1][2]).toMatchObject({
      periodId: OPEN_PERIOD,
      renewalProfileId: 'profile-1',
      automationEnabled: true,
    });
    expect(
      await screen.findByText(/Automatic renewal is on for/)
    ).toBeInTheDocument();
  });

  it('falls back to the manual steps when an older API gives no open period', async () => {
    replaceResults = [
      conflict({
        code: 'CERTOPS_MANAGEMENT_ALREADY_OPEN',
        error: 'Source is already managed',
      }),
    ];
    const attach = await openAtAttachStep(staleInventory);
    fireEvent.click(attach);
    expect(
      await screen.findByText(/stop managing, then start managing again/)
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Replace the current management/ })
    ).not.toBeInTheDocument();
  });
});
