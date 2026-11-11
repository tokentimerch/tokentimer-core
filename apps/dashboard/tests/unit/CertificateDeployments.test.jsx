import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import CertificateDeployments from '../../src/components/certops/CertificateDeployments.jsx';
import {
  consumerDeploymentStatus,
  consumerVersionComparison,
  combineDeploymentSummaries,
  formatFreshnessDuration,
  freshnessDeadline,
  verificationDeadline,
} from '../../src/components/certops/distributionFormat.js';

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../src/utils/apiClient', () => ({ default: { get } }));

const group = {
  id: 'group-a',
  managed_certificate_id: 'cert-a',
  current_identity_id: 'identity-a',
  management_period_id: 'period-a',
  active: true,
  material_store_ref: 'production',
  created_at: '2026-01-01',
};
const row = (extra = {}) => ({
  binding_id: 'binding-a',
  agent_name: 'Edge proxy',
  deployment_profile_ref: 'https-edge',
  binding_state: 'active',
  assigned_agent_id: 'agent-a',
  desired_material_version_id: 'version-a',
  observed_material_version_id: 'version-a',
  desired_version: 2,
  observed_version: 2,
  desired_generation: 3,
  accepted_generation: 3,
  verification_policy: 'served',
  observed_at: new Date().toISOString(),
  freshness_seconds: 3600,
  verification_method: 'served',
  observed_valid_to: '2027-01-01',
  converged: true,
  latest_deployment: { stage: 'served_verified', jobId: 'job-a' },
  ...extra,
});
const version = {
  id: 'version-a',
  state: 'published',
  provider_version: 2,
  certificate_identity_id: 'identity-a',
  publishing_job_id: 'publication-a',
  published_at: '2026-10-17',
};

function mockData(consumers = [row()], groups = [group], versions = [version]) {
  get.mockImplementation(async url => ({
    data: url.endsWith('/consumers')
      ? { consumers }
      : url.endsWith('/versions')
        ? { versions }
        : { groups },
  }));
}
function view(props = {}) {
  return (
    <ChakraProvider>
      <MemoryRouter>
        <CertificateDeployments
          workspaceId='workspace-a'
          managedCertificateId='cert-a'
          isOpen
          {...props}
        />
      </MemoryRouter>
    </ChakraProvider>
  );
}
beforeEach(() => {
  get.mockReset();
  mockData();
});

it('identifies Azure secret versions and Windows IIS consumers', async () => {
  const id = 'a'.repeat(32);
  mockData(
    [
      row({
        agent_platform: 'win32',
        desired_version: id,
        observed_version: id,
      }),
    ],
    [{ ...group, material_store_provider: 'azure-key-vault' }],
    [{ ...version, provider_version: id }]
  );
  render(view());
  expect(await screen.findByText('Edge proxy')).toBeInTheDocument();
  expect(screen.getAllByText(/Azure Key Vault/).length).toBeGreaterThan(0);
  expect(
    screen.getAllByText(`Azure secret version ${id}`).length
  ).toBeGreaterThan(0);
  expect(screen.getByText(/Windows \/ IIS/)).toBeInTheDocument();
});

it('loads only when opened and shows publication separately from current deployment', async () => {
  const { rerender } = render(view({ isOpen: false }));
  expect(get).not.toHaveBeenCalled();
  rerender(view());
  expect(await screen.findByText('Edge proxy')).toBeInTheDocument();
  expect(screen.getByText('1/1 verified')).toBeInTheDocument();
  expect(
    screen.getByRole('button', {
      name: 'About Certificate publication',
    })
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Details', exact: true }));
  expect(
    within(screen.getByRole('table')).getByRole('link', {
      name: 'View job and evidence',
    })
  ).toHaveAttribute('href', '/certops/jobs?workspace=workspace-a&job=job-a');
  expect(
    screen.getAllByText('Advanced diagnostics')[0].closest('details')
  ).not.toHaveAttribute('open');
  expect(screen.getByText('Matches expected')).toBeInTheDocument();
  expect(
    screen.getAllByText('KV v2 provider revision 2').length
  ).toBeGreaterThan(0);
  expect(screen.queryByText(/bindingId/)).not.toBeInTheDocument();
  expect(screen.getByText('binding-a').closest('details')).not.toHaveAttribute(
    'open'
  );
});

describe.each([
  [
    { converged: false, stale: true },
    'Verification outdated',
    /last verification is no longer current/,
  ],
  [
    {
      converged: false,
      latest_deployment: {
        stage: 'failed',
        failureCode: 'service_unavailable',
      },
    },
    'Deployment failed',
    /latest deployment failed/,
  ],
  [
    {
      converged: false,
      latest_deployment: { stage: 'orphaned_unknown_effect' },
    },
    'Deployment outcome uncertain',
    /deployment outcome is uncertain/,
  ],
  [{ converged: false }, 'Pending verification', /awaiting verification/],
  [
    {
      converged: false,
      desired_material_version_id: null,
      desired_version: null,
      latest_deployment: null,
    },
    'Not deployed',
    /No expected version is assigned/,
  ],
])('consumer explanation', (extra, label, explanation) => {
  it(`shows ${label} despite published material`, async () => {
    mockData([row(extra)]);
    render(view());
    const table = await screen.findByRole('table', {
      name: 'Certificate deployment consumers',
    });
    expect(within(table).getByText(label)).toBeInTheDocument();
    fireEvent.click(
      within(table).getByRole('button', { name: 'Details', exact: true })
    );
    expect(screen.getByText(explanation)).toBeInTheDocument();
    if (extra.latest_deployment === null)
      expect(screen.getByText('No execution recorded')).toBeInTheDocument();
    expect(screen.getByText(/0\/1 verified/)).toBeInTheDocument();
  });
});

it('keeps a successful historic job from becoming current proof', () => {
  expect(consumerDeploymentStatus(row({ converged: false }))).toBe('pending');
  expect(
    consumerDeploymentStatus(
      row({ latest_deployment: { stage: 'orphaned_unknown_effect' } })
    )
  ).toBe('uncertain');
  expect(
    consumerDeploymentStatus(row({ latest_deployment: { stage: 'failed' } }))
  ).toBe('failed');
  expect(combineDeploymentSummaries([]).status).toBe('not_distributed');
  expect(
    combineDeploymentSummaries([
      { summary: { total: 5, verified: 3, pending: 2 } },
    ])
  ).toMatchObject({ total: 5, verified: 3, status: 'partial' });
});

it('handles absent distribution, missing consumers, failures and retry', async () => {
  mockData([], []);
  const { rerender } = render(view());
  expect(await screen.findByText('Not distributed')).toBeInTheDocument();
  get.mockRejectedValueOnce(new Error('offline'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Deployment information unavailable'
  );
  mockData([]);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
  expect(
    await screen.findByText(/No consumer assignments/)
  ).toBeInTheDocument();
  rerender(view({ workspaceId: 'workspace-b' }));
  expect(screen.queryByText('No consumer assignments')).not.toBeInTheDocument();
});

it('shows ended periods as historical, and never reads another identity’s current consumers', async () => {
  mockData([row()], [{ ...group, current_identity_id: 'identity-b' }]);
  render(view({ identityId: 'identity-a' }));
  expect(
    await screen.findByText(/registration currently tracks another certificate/)
  ).toBeInTheDocument();
  await screen.findByText('Publication history');
  expect(get.mock.calls.some(([url]) => url.endsWith('/consumers'))).toBe(
    false
  );
  expect(screen.queryByText(/1\/1 verified/)).not.toBeInTheDocument();
});

it('does not count historical assignments as currently verified', async () => {
  mockData([row()], [{ ...group, active: false }]);
  render(view());
  await screen.findByText('Edge proxy');
  expect(screen.getByText(/0\/1 verified/)).toBeInTheDocument();
});

it('paginates hundreds of bindings without per-consumer fetches', async () => {
  mockData(
    Array.from({ length: 105 }, (_, i) =>
      row({ binding_id: `binding-${i}`, agent_name: `Proxy ${i}` })
    )
  );
  render(view());
  const table = await screen.findByRole('table');
  expect(within(table).getAllByRole('row')).toHaveLength(21);
  expect(screen.getByText('105/105 verified')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Next consumers' }));
  expect(screen.getByText('Proxy 20')).toBeInTheDocument();
  expect(screen.queryByText('Proxy 0')).not.toBeInTheDocument();
  expect(get).toHaveBeenCalledTimes(3);
});

it('drops late responses when switching workspace and certificate', async () => {
  let resolveOld;
  get.mockImplementationOnce(
    () =>
      new Promise(resolve => {
        resolveOld = resolve;
      })
  );
  const { rerender } = render(view());
  await waitFor(() => expect(resolveOld).toBeTypeOf('function'));
  rerender(
    view({ workspaceId: 'workspace-b', managedCertificateId: 'cert-b' })
  );
  mockData([], []);
  resolveOld({ data: { groups: [group] } });
  await waitFor(() =>
    expect(screen.queryByText('Edge proxy')).not.toBeInTheDocument()
  );
  expect(
    get.mock.calls.filter(([url]) => url.endsWith('/consumers')).length
  ).toBe(0);
});

it('keeps readable destination details and the same table mounted during manual refresh', async () => {
  render(view());
  const table = await screen.findByRole('table');
  fireEvent.click(
    within(table).getByRole('button', { name: 'Details', exact: true })
  );
  const evidence = within(table).getByRole('link', {
    name: 'View job and evidence',
  });
  expect(screen.getByText('Consumer ID')).toBeInTheDocument();
  expect(screen.getByText('binding-a').closest('details')).not.toHaveAttribute(
    'open'
  );
  expect(screen.getByText('Last confirmed version')).toBeInTheDocument();
  const pending = [];
  get.mockImplementation(() => new Promise(resolve => pending.push(resolve)));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
  await waitFor(() => expect(pending.length).toBe(3));
  expect(screen.getByRole('table')).toBe(table);
  expect(
    within(table).getByRole('link', { name: 'View job and evidence' })
  ).toBe(evidence);
  expect(screen.queryByText('Loading consumers…')).not.toBeInTheDocument();
});

it('does not confuse provider revisions, material identity or uncertain last-confirmed evidence', async () => {
  mockData([
    row({
      observed_material_version_id: 'different-material',
      observed_version: 2,
      latest_deployment: {
        stage: 'orphaned_unknown_effect',
        jobId: 'job-uncertain',
      },
    }),
  ]);
  render(view());
  const table = await screen.findByRole('table');
  expect(within(table).getByText('Unknown')).toBeInTheDocument();
  expect(within(table).queryByText('Matches expected')).not.toBeInTheDocument();
  fireEvent.click(
    within(table).getByRole('button', { name: 'Details', exact: true })
  );
  expect(
    screen.getByText(/historical, current state unknown/)
  ).toBeInTheDocument();
  expect(
    screen.getByText(/signed retry and approval workflow/)
  ).toBeInTheDocument();
  expect(
    screen.getByText(/Versions are compared using TokenTimer material IDs/)
  ).toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: /Retry/ })
  ).not.toBeInTheDocument();
});

it('compares immutable material IDs even when provider revision labels are equal', () => {
  expect(
    consumerVersionComparison(
      row({ observed_material_version_id: 'different', observed_version: 2 }),
      'pending'
    )
  ).toBe('Different version');
  expect(
    consumerDeploymentStatus(
      row({ observed_at: '2026-01-01', freshness_seconds: 60 }),
      Date.parse('2026-10-19')
    )
  ).toBe('stale');
  expect(
    consumerDeploymentStatus(
      row({ observed_valid_to: '2026-01-01' }),
      Date.parse('2026-10-19')
    )
  ).toBe('stale');
});

it('does not retain green evidence when the registration advances to another rollout generation', async () => {
  let generation = 1;
  let holdConsumers = false;
  get.mockImplementation(async url => {
    if (url.endsWith('/consumers'))
      return holdConsumers
        ? new Promise(() => {})
        : { data: { consumers: [row()] } };
    if (url.endsWith('/versions')) return { data: { versions: [version] } };
    return { data: { groups: [{ ...group, generation }] } };
  });
  render(view());
  await screen.findByText('1/1 verified');
  generation = 2;
  holdConsumers = true;
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
  await waitFor(() =>
    expect(screen.queryByText('1/1 verified')).not.toBeInTheDocument()
  );
  expect(screen.getByText('Loading consumers…')).toBeInTheDocument();
});

it('organizes all publication diagnostics in one Technical information section and omits the latest event from history', async () => {
  const older = {
    ...version,
    id: 'older-material',
    provider_version: 1,
    publishing_job_id: 'old-job',
    fingerprint_sha256: 'a'.repeat(64),
    profile_revision: 4,
    published_at: '2026-10-16',
  };
  mockData([row()], [{ ...group, generation: 3 }], [version, older]);
  render(view());
  await screen.findByRole('table');
  const history = screen.getByText('Publication history').closest('details');
  fireEvent.click(within(history).getByText('Publication history'));
  expect(
    within(history).getByText('KV v2 provider revision 1')
  ).toBeInTheDocument();
  expect(
    within(history).queryByText('KV v2 provider revision 2')
  ).not.toBeInTheDocument();
  expect(
    within(history).queryByText('Advanced diagnostics')
  ).not.toBeInTheDocument();
  expect(
    within(history).getByRole('link', { name: 'View job and evidence' })
  ).toHaveAttribute('href', '/certops/jobs?workspace=workspace-a&job=old-job');
  expect(screen.getAllByText('Technical information')).toHaveLength(1);
  const technical = screen
    .getByText('Technical information')
    .closest('details');
  fireEvent.click(within(technical).getByText('Technical information'));
  expect(
    within(technical).getByRole('heading', { name: 'Certificate publication' })
  ).toBeInTheDocument();
  expect(
    within(technical).getByRole('heading', {
      name: 'Distribution configuration',
    })
  ).toBeInTheDocument();
  for (const value of [
    'version-a',
    'older-material',
    'identity-a',
    'a'.repeat(64),
    'group-a',
    'period-a',
    'cert-a',
    'old-job',
  ])
    expect(within(technical).getAllByText(value).length).toBeGreaterThan(0);
  expect(
    within(technical).getAllByRole('button', { name: 'Copy to clipboard' })
      .length
  ).toBeGreaterThan(8);
  expect(
    within(technical).queryByText('Advanced diagnostics')
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Details', exact: true }));
  expect(screen.getAllByText('Advanced diagnostics')).toHaveLength(1);
  expect(screen.getByText('binding-a').closest('details')).not.toHaveAttribute(
    'open'
  );
});

it('explains a GET-only Refresh status next to the heading and keeps existing details while revalidating', async () => {
  render(view());
  const table = await screen.findByRole('table');
  const refresh = screen.getByRole('button', {
    name: 'Refresh status',
    exact: true,
  });
  expect(
    screen
      .getByRole('heading', { name: 'Deployments' })
      .closest('[data-compact-section-heading]')
  ).toContainElement(refresh);
  fireEvent.focus(refresh);
  expect(await screen.findByRole('tooltip')).toHaveTextContent(
    'Reload the latest deployment status and evidence recorded by TokenTimer.'
  );
  const readsBefore = get.mock.calls.length;
  const pending = [];
  get.mockImplementation(
    url => new Promise(resolve => pending.push({ url, resolve }))
  );
  fireEvent.click(refresh);
  await waitFor(() => expect(pending).toHaveLength(3));
  expect(screen.getByRole('table')).toBe(table);
  expect(screen.getByText('1/1 verified')).toBeInTheDocument();
  expect(
    get.mock.calls
      .slice(readsBefore)
      .every(([url]) =>
        /distribution-groups(?:\/group-a\/(?:consumers|versions))?$/.test(url)
      )
  ).toBe(true);
});

it.each([
  [
    'served',
    'served_verified',
    'Certificate served and fingerprint verified',
    'Certificate served successfully',
  ],
  [
    'trust',
    'trust_validated',
    'Certificate and TLS trust verified',
    'Certificate and TLS trust validated',
  ],
])(
  'separates %s verification policy and accepted observations from execution stage labels',
  async (method, stage, observation, execution) => {
    mockData([
      row({
        verification_method: method,
        verification_policy: method,
        freshness_seconds: 86400,
        required: true,
        latest_deployment: { stage, jobId: 'job-a' },
      }),
    ]);
    render(view());
    await screen.findByRole('table');
    fireEvent.click(
      screen.getByRole('button', { name: 'Details', exact: true })
    );
    expect(screen.getAllByText(observation)).toHaveLength(2);
    expect(screen.getByText(execution)).toBeInTheDocument();
    for (const label of [
      'Deployment profile',
      'Expected version',
      'Last confirmed version',
      'Last verification',
      'Verification freshness',
      'Deployment status',
      'Certificate expiry on destination',
    ])
      expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText('24 hours')).toBeInTheDocument();
    expect(screen.getByText('24 hours')).toHaveAttribute('title', '86400');
    expect(screen.queryByText('86400')).not.toBeInTheDocument();
    expect(screen.getByText('Verification policy code')).toBeInTheDocument();
    expect(screen.getByText(stage).closest('details')).not.toHaveAttribute(
      'open'
    );
    expect(screen.getByText(/Valid until/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'About Verification freshness' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'About Required destination' })
    ).toBeInTheDocument();
  }
);

it('keeps an uncertain latest publication visible once without hiding the previous successful publication', async () => {
  const attempt = {
    ...version,
    id: 'uncertain-material',
    provider_version: 3,
    state: 'orphaned_unknown_effect',
    publishing_job_id: 'uncertain-publish',
    published_at: null,
    created_at: '2026-10-18',
  };
  mockData([row()], [group], [attempt, version]);
  render(view());
  await screen.findByRole('table');
  expect(screen.getByText('Publication outcome uncertain')).toBeInTheDocument();
  expect(screen.getByText('Last published:')).toBeInTheDocument();
  expect(
    screen.getByRole('link', { name: 'Attempt evidence' })
  ).toHaveAttribute(
    'href',
    '/certops/jobs?workspace=workspace-a&job=uncertain-publish'
  );
  const history = screen.getByText('Publication history').closest('details');
  expect(
    within(history).queryByText('KV v2 provider revision 3')
  ).not.toBeInTheDocument();
  expect(
    within(history).getByText('KV v2 provider revision 2')
  ).toBeInTheDocument();
});

it('formats exact policy durations and keeps freshness policy expiry distinct from certificate expiry', () => {
  expect(formatFreshnessDuration(86400)).toBe('24 hours');
  expect(formatFreshnessDuration(3600)).toBe('1 hour');
  expect(formatFreshnessDuration(3661)).toBe('1 hour 1 minute 1 second');
  expect(formatFreshnessDuration(90)).toBe('1 minute 30 seconds');
  expect(formatFreshnessDuration(null)).toBe('Unavailable');
  const c = row({
    observed_at: '2026-10-19T00:00:00Z',
    freshness_seconds: 86400,
    observed_valid_to: '2026-10-19T12:00:00Z',
  });
  expect(freshnessDeadline(c)).toBe(Date.parse('2026-10-20T00:00:00Z'));
  expect(verificationDeadline(c)).toBe(Date.parse('2026-10-19T12:00:00Z'));
});
