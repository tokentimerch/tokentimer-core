import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

const replaceCalls = [];
let replaceResults = [];
vi.mock('../../src/components/certops/certopsApi.js', () => ({
  listCertificates: vi.fn(),
  getWindowsRenewal: vi.fn(),
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

import {
  listCertificates,
  getWindowsRenewal,
} from '../../src/components/certops/certopsApi.js';
import { createAdcsRenewalProfile } from '../../src/components/certops/certopsRenewalApi.js';
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

async function openAtAttachStep(sources, expectAttach = true) {
  listCertificates.mockResolvedValue({
    items: [
      {
        identityId: 'identity-1',
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
  fireEvent.change(screen.getByLabelText('IIS site'), {
    target: { value: 'Default Web Site' },
  });
  fireEvent.change(screen.getByLabelText('IIS port'), {
    target: { value: '443' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
  if (!expectAttach) {
    await screen.findByText(/No certificate in inventory uses app.example/);
    expect(
      screen.queryByRole('button', { name: 'Attach and enable automation' })
    ).not.toBeInTheDocument();
    return null;
  }
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

  it('attaches an ended period returned by the grouped certificate API', async () => {
    replaceResults = [{ stopped: null, readded: {} }];
    const attach = await openAtAttachStep([
      {
        managedCertificateId: 'mc-1',
        source: 'agent_windows',
        currentIdentityId: 'identity-1',
        startedAt: '2026-09-01T00:00:00Z',
        endedAt: '2026-09-02T00:00:00Z',
        periodEndedAt: '2026-09-02T00:00:00Z',
        periodId: OPEN_PERIOD,
      },
    ]);
    fireEvent.click(attach);
    await waitFor(() => expect(replaceCalls).toHaveLength(1));
    expect(replaceCalls[0]).toEqual([
      'ws-1',
      'mc-1',
      {
        periodId: null,
        renewalProfileId: 'profile-1',
        automationEnabled: true,
      },
    ]);
  });

  it.each([
    { endedAt: '2026-09-02T00:00:00Z', periodEndedAt: null },
    {
      endedAt: '2026-09-02T00:00:00Z',
      periodEndedAt: '2026-09-02T00:00:00Z',
      currentIdentityId: 'other-identity',
    },
    {
      endedAt: '2026-09-02T00:00:00Z',
      periodEndedAt: '2026-09-02T00:00:00Z',
      endedReason: 'endpoint_monitor_deleted',
    },
  ])(
    'does not attach a superseded, foreign or deleted source: %j',
    async fields => {
      await openAtAttachStep(
        [
          {
            managedCertificateId: 'mc-1',
            source: 'agent_windows',
            currentIdentityId: 'identity-1',
            startedAt: '2026-09-01T00:00:00Z',
            periodId: OPEN_PERIOD,
            ...fields,
          },
        ],
        false
      );
      expect(replaceCalls).toHaveLength(0);
    }
  );

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

it('creates a Store renewal without IIS fields and offers only confirmed Store registrations', async () => {
  listCertificates.mockResolvedValue({
    items: [
      {
        identityId: 'identity-store',
        commonName: 'app.example',
        sources: [
          {
            managedCertificateId: 'store',
            periodId: OPEN_PERIOD,
            source: 'agent_windows',
            sourceRef: 'agent/host/windows_store/LocalMachine/My/app.example',
            currentIdentityId: 'identity-store',
          },
          {
            managedCertificateId: 'iis',
            periodId: 'iis-period',
            source: 'agent_windows',
            sourceRef: 'agent/host/iis_binding/Site:443',
            currentIdentityId: 'identity-store',
          },
        ],
      },
    ],
  });
  getWindowsRenewal.mockResolvedValue({
    groups: [{ managedCertificateId: 'store' }],
  });
  render(
    <ChakraProvider>
      <WizardHost />
    </ChakraProvider>
  );
  fireEvent.change(screen.getByLabelText('Profile name'), {
    target: { value: 'Store AD CS' },
  });
  fireEvent.change(screen.getByLabelText('AD CS issuer'), {
    target: { value: 'issuer-1' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  fireEvent.change(screen.getByLabelText('Certificate name'), {
    target: { value: 'app.example' },
  });
  fireEvent.change(screen.getByLabelText('Renewal destination'), {
    target: { value: 'windows-cert-store' },
  });
  expect(screen.queryByLabelText('IIS site')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
  await waitFor(() =>
    expect(createAdcsRenewalProfile).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.objectContaining({
        target: {
          type: 'windows-cert-store',
          reference: 'app.example',
          store: 'My',
        },
      })
    )
  );
  await screen.findByRole('button', { name: 'Attach and enable automation' });
  expect(
    screen.queryAllByRole('option').some(option => option.value === 'iis')
  ).toBe(false);
});
