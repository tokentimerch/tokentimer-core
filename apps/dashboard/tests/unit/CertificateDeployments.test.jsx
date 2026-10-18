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
  combineDeploymentSummaries,
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
  observed_at: '2026-10-18T10:00:00Z',
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

function mockData(consumers = [row()], groups = [group]) {
  get.mockImplementation(async url => ({
    data: url.endsWith('/consumers')
      ? { consumers }
      : url.endsWith('/versions')
        ? { versions: [version] }
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

it('loads only when opened and shows publication separately from current deployment', async () => {
  const { rerender } = render(view({ isOpen: false }));
  expect(get).not.toHaveBeenCalled();
  rerender(view());
  expect(await screen.findByText('Edge proxy')).toBeInTheDocument();
  expect(
    screen.getByText('1/1 verified · Verified and current')
  ).toBeInTheDocument();
  expect(
    screen.getByText(/It does not prove that consumers currently serve it/)
  ).toBeInTheDocument();
  expect(
    within(screen.getByRole('table')).getByRole('link', {
      name: 'View job and evidence',
    })
  ).toHaveAttribute('href', '/certops/jobs?workspace=workspace-a&job=job-a');
  expect(
    screen.getByText('Technical details').closest('details')
  ).not.toHaveAttribute('open');
  expect(screen.getByText('Desired: Version 2')).toBeInTheDocument();
  expect(screen.getByText('Observed: Version 2')).toBeInTheDocument();
});

describe.each([
  [
    { converged: false, stale: true },
    'Verification outdated',
    /older than the consumer freshness policy/,
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
    'Execution uncertain',
    /result is unconfirmed/,
  ],
  [
    { converged: false },
    'Pending verification',
    /has not been verified as currently served/,
  ],
  [
    {
      converged: false,
      desired_material_version_id: null,
      desired_version: null,
    },
    'Not deployed',
    /No desired version is assigned/,
  ],
])('consumer explanation', (extra, label, explanation) => {
  it(`shows ${label} despite published material`, async () => {
    mockData([row(extra)]);
    render(view());
    const table = await screen.findByRole('table', {
      name: 'Certificate deployment consumers',
    });
    expect(within(table).getByText(label)).toBeInTheDocument();
    expect(screen.getByText(explanation)).toBeInTheDocument();
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
  fireEvent.click(screen.getByRole('button', { name: 'Refresh deployments' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Deployment information unavailable'
  );
  mockData([]);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh deployments' }));
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
    await screen.findByText(/registration now tracks another identity/)
  ).toBeInTheDocument();
  await screen.findByText('Publication technical details and history');
  expect(get.mock.calls.some(([url]) => url.endsWith('/consumers'))).toBe(
    false
  );
  expect(screen.queryByText(/1\/1 verified/)).not.toBeInTheDocument();
});

it('does not count historical assignments as currently verified', async () => {
  mockData([row()], [{ ...group, active: false }]);
  render(view());
  await screen.findByText('Edge proxy');
  expect(
    screen.getByText(/0\/1 verified · Management ended/)
  ).toBeInTheDocument();
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
  expect(
    screen.getByText('105/105 verified · Verified and current')
  ).toBeInTheDocument();
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
