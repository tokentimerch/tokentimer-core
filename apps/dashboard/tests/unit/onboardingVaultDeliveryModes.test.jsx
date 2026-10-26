import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import {
  VaultAgentTest,
  VaultRolloutGuide,
} from '../../src/components/onboarding/VaultGuidedOperations.jsx';
import { DoneCard } from '../../src/components/onboarding/OnboardingPage.jsx';
import {
  buildVaultConfigs,
  buildVaultConsumerAssignment,
} from '../../src/components/onboarding/certopsConfig.js';
import {
  evaluateVerification,
  CHECK_STATUS,
} from '../../src/components/onboarding/verification.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  combineDeploymentSummaries,
  consumerDeploymentStatus,
} from '../../src/components/certops/distributionFormat.js';

const api = vi.hoisted(() => ({
  readDistribution: vi.fn(),
  assignConsumer: vi.fn(),
  requestRollout: vi.fn(),
  retryDeployment: vi.fn(),
  getJob: vi.fn(),
  createJob: vi.fn(),
}));
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => api);
vi.mock('../../src/components/certops/certopsJobsApi.js', () => api);
vi.mock('../../src/components/onboarding/JobActivity.jsx', () => ({
  default: () => <div>Actual job evidence</div>,
  JobTimelineList: () => null,
}));
vi.mock(
  '../../src/components/onboarding/approvalPolicy.jsx',
  async original => ({
    ...(await original()),
    useJobApprovalPolicy: () => ({ required: false }),
  })
);
const WS = '11111111-1111-4111-8111-111111111111';
const GROUP = '22222222-2222-4222-8222-222222222222';
const BINDING = '33333333-3333-4333-8333-333333333333';
const agents = [
  {
    id: 'issuer',
    wireAgentId: 'issuer-wire',
    platform: 'linux',
    commandProfiles: ['certbot'],
  },
  {
    id: 'consumer',
    wireAgentId: 'consumer-wire',
    name: 'Consumer',
    platform: 'linux',
  },
];
const base = {
  vaultAddress: 'https://vault.example.com',
  workspaceId: WS,
  groupId: GROUP,
  names: ['web.example.com'],
  zone: 'example.com',
  dnsProvider: 'rfc2136',
  consumerBindingId: BINDING,
};
function context(saved = {}) {
  const session = {
    intent: { goal: 'certops_vault' },
    progress: {
      certops: {
        objective: 'vault',
        infrastructure: 'linux',
        names: 'web.example.com',
        zone: 'example.com',
        vaultAddress: base.vaultAddress,
        groupId: GROUP,
        vaultBindingId: BINDING,
        ...saved,
      },
    },
  };
  return {
    session,
    workspaceId: WS,
    apiUrl: 'https://tt.example.com',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(),
    controller: {
      update: vi.fn(async change => Object.assign(session, change(session))),
    },
    summary: {
      alerts: {},
      certops: {
        agents: { items: agents },
        distribution: { groups: 0, items: [] },
      },
    },
  };
}
function show(element) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>{element}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  api.readDistribution.mockResolvedValue({ versions: [], consumers: [] });
});

describe('Vault consumer delivery choices', () => {
  it('never adopts or passes the issuer job for an empty consumer selection', async () => {
    const ctx = context({ dryRunJobId: 'issuer-test' });
    api.getJob.mockResolvedValue({
      job: { id: 'issuer-test', status: 'dry_run_complete', operation: 'noop' },
    });
    await act(async () => show(<VaultAgentTest ctx={ctx} agent={undefined} />));
    expect(api.getJob).not.toHaveBeenCalled();
    expect(screen.queryByText('Signed dry run completed')).toBeNull();
    expect(screen.queryByText('Actual job evidence')).toBeNull();
  });
  it('shows only the issuer test during publication preparation, even before a consumer is registered', () => {
    const ctx = context();
    ctx.summary.certops.agents.items = [agents[0]];
    show(<VaultStep ctx={ctx} />);
    expect(
      screen.getAllByRole('button', { name: /^Send a test job to/ })
    ).toHaveLength(1);
  });
  it('can create publication with an issuer alone after the issuer-stop confirmation', async () => {
    const ctx = context();
    ctx.summary.certops.agents.items = [agents[0]];
    api.createJob.mockResolvedValue({
      job: {
        id: 'publication',
        status: 'pending',
        payload: { publication: { groupId: GROUP } },
      },
    });
    show(<VaultStep ctx={ctx} />);
    const publish = screen.getByRole('button', {
      name: 'Create the publish job',
    });
    expect(publish).toBeDisabled();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'The issuing TokenTimer agent is stopped while I prepare Vault',
      })
    );
    expect(publish).toBeEnabled();
    fireEvent.click(publish);
    await waitFor(() =>
      expect(api.createJob).toHaveBeenCalledWith(
        WS,
        expect.objectContaining({
          operation: 'issue',
          assignedAgentId: 'issuer',
        })
      )
    );
  });
  it('generates actual file-only configuration without reload commands, probes or NGINX paths', () => {
    const result = buildVaultConfigs({
      ...base,
      consumerDeliveryMode: 'files',
      deployPath: '/srv/certificates',
      probeTrustCaFile: 'not-needed-for-files',
    });
    expect(result.ok).toBe(true);
    const binding = result.consumer.materialBindings[BINDING];
    expect(binding).toMatchObject({
      verificationPolicy: 'installed',
      probes: [],
      target: {
        certPath: '/srv/certificates/fullchain.pem',
        keyPath: '/srv/certificates/privkey.pem',
      },
    });
    expect(binding).not.toHaveProperty('reloadService');
    expect(binding).not.toHaveProperty('reloadCommandRefs');
    expect(result.consumer.policy.allowedCommands).toEqual({});
    expect(JSON.stringify(result.consumer)).not.toMatch(/nginx|trustCaFile/);
    expect(
      buildVaultConsumerAssignment({
        agentRowId: 'consumer',
        consumerDeliveryMode: 'files',
      }).verificationPolicy
    ).toBe('installed');
  });
  it.each(['nginx', 'apache', 'haproxy'])(
    'retains reload and live TLS assurance for %s',
    service => {
      const result = buildVaultConfigs({
        ...base,
        consumerDeliveryMode: 'service',
        consumerReloadService: service,
      });
      const binding = result.consumer.materialBindings[BINDING];
      expect(binding).toMatchObject({
        verificationPolicy: 'trust',
        reloadService: service,
        reloadCommandRefs: {
          validate: `${service}-validate`,
          reload: `${service}-reload`,
        },
      });
      expect(binding.probes).toHaveLength(1);
      expect(
        result.consumer.policy.allowedCommands[`${service}-reload`]
      ).toBeDefined();
      if (service === 'haproxy')
        expect(binding.target.keyPath).toBe(`${binding.target.certPath}.key`);
    }
  );
  it.each(['/srv/../keys', '/srv/./keys', '/srv/bad path', 'relative', '/'])(
    'rejects unsafe destination %s before generating host commands',
    deployPath => {
      expect(buildVaultConfigs({ ...base, deployPath }).ok).toBe(false);
    }
  );
  it('keeps the six numbered parts but defaults new setup to files, with no service prerequisites', async () => {
    const ctx = context();
    show(<VaultStep ctx={ctx} />);
    expect(
      screen.getByRole('radio', { name: 'Distribute certificate files only' })
    ).toBeChecked();
    for (let n = 1; n <= 6; n++)
      expect(screen.getByTestId(`vault-part-${n}`)).toBeVisible();
    expect(screen.queryByLabelText('Service to reload')).toBeNull();
    expect(screen.queryByTestId('vault-reload-prerequisite')).toBeNull();
    expect(document.body.textContent).not.toMatch(
      /Install nginx|nginx server block|One-time nginx setup|--reload-service/
    );
    expect(
      screen.getByLabelText('Certificate destination directory')
    ).toHaveValue('/etc/tokentimer/certificates');
    fireEvent.click(
      screen.getByRole('radio', { name: 'Distribute and reload a service' })
    );
    await screen.findByLabelText('Service to reload');
    expect(screen.getByTestId('vault-reload-prerequisite')).toHaveTextContent(
      'Ubuntu 24.04'
    );
    fireEvent.change(screen.getByLabelText('Service to reload'), {
      target: { value: 'apache' },
    });
    await waitFor(() =>
      expect(ctx.session.progress.certops.vaultConsumerReloadService).toBe(
        'apache'
      )
    );
    expect(document.body.textContent).toContain('SSLCertificateFile');
    expect(document.body.textContent).not.toContain('One-time nginx setup');
    expect(ctx.session.progress.certops.vaultConsumerDeliveryMode).toBe(
      'service'
    );
  });
  it('keeps an invalid destination editable and suppresses unsafe generated host commands', () => {
    show(<VaultStep ctx={context()} />);
    const destination = screen.getByLabelText(
      'Certificate destination directory'
    );
    fireEvent.change(destination, { target: { value: '/srv/bad;command' } });
    expect(destination).toBeVisible();
    expect(
      screen.getByText(/Use an absolute destination directory/)
    ).toBeVisible();
    expect(
      screen.queryByRole('button', { name: 'Assign Consumer' })
    ).toBeNull();
    expect(document.body.textContent).not.toContain('-keyout /srv/bad;command');
    fireEvent.change(destination, { target: { value: '/srv/certificates' } });
    expect(
      screen.getByRole('button', { name: 'Assign Consumer' })
    ).toBeVisible();
  });
  it('does not silently change existing consumer assignments from service assurance to files', async () => {
    await act(async () =>
      show(
        <VaultStep
          ctx={context({
            vaultConsumers: [{ agentId: 'consumer', bindingId: BINDING }],
          })}
        />
      )
    );
    expect(
      screen.getByRole('radio', { name: 'Distribute and reload a service' })
    ).toBeChecked();
    expect(
      screen.getByRole('radio', { name: 'Distribute certificate files only' })
    ).toBeDisabled();
  });
  it('reports file installation completion without requiring a service verification panel', async () => {
    const ctx = context({
      vaultConsumerDeliveryMode: 'files',
      vaultMaterialVersionId: 'version',
    });
    api.readDistribution.mockResolvedValue({
      versions: [
        {
          id: 'version',
          state: 'published',
          provider_version: 1,
          valid_to: '2099-01-01',
        },
      ],
      consumers: [
        {
          binding_id: BINDING,
          assigned_agent_id: 'consumer',
          binding_state: 'active',
          verification_policy: 'installed',
          authorization_revision: 1,
          deployment_profile_ref: 'certificate-files',
          profile_revision: 1,
          converged: true,
          desired_material_version_id: 'version',
        },
      ],
    });
    show(
      <VaultRolloutGuide
        ctx={ctx}
        groupId={GROUP}
        firstAgentId='consumer'
        firstBindingId={BINDING}
        agents={agents}
        config={{
          ...base,
          consumerDeliveryMode: 'files',
          deployPath: '/srv/certificates',
        }}
        approvalRequired={false}
      />
    );
    expect(
      await screen.findByText(
        'Certificate files installed on all selected consumers'
      )
    ).toBeVisible();
    expect(screen.queryByText('All selected consumers verified')).toBeNull();
    expect(document.body.textContent).toContain(
      'this does not prove the certificate is in use'
    );
  });
  it('accepts only selected backend completion evidence in final verification and completion', () => {
    const ctx = context();
    ctx.summary.certops.distribution = {
      items: [{ id: GROUP, completed: true, verified: false }],
    };
    const result = evaluateVerification({
      goal: 'certops_vault',
      summary: ctx.summary,
      distributionId: GROUP,
    });
    expect(
      result.checks.find(check => check.id === 'distribution')
    ).toMatchObject({
      status: CHECK_STATUS.PASS,
      label: 'Certificate files distributed',
    });
    const view = show(<DoneCard ctx={ctx} />);
    expect(screen.getByText('You are set up')).toBeVisible();
    expect(document.body.textContent).toContain('does not reload a service');
    view.unmount();
    ctx.summary.certops.distribution.items[0].id = 'unrelated';
    show(<DoneCard ctx={ctx} />);
    expect(screen.getByText('Setup finished, not verified yet')).toBeVisible();
  });
  it('keeps inventory file installations separate from live verification', () => {
    expect(
      consumerDeploymentStatus({
        binding_state: 'active',
        verification_policy: 'installed',
        converged: true,
      })
    ).toBe('installed');
    expect(
      combineDeploymentSummaries([
        { summary: { total: 2, installed: 1, verified: 1 } },
      ])
    ).toMatchObject({ status: 'completed', installed: 1, verified: 1 });
    expect(
      combineDeploymentSummaries([
        { summary: { total: 2, installed: 2, verified: 0 } },
      ])
    ).toMatchObject({ status: 'installed', verified: 0 });
  });
});
