import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, within, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  WorkspaceProvider,
  useWorkspace,
} from '../../src/utils/WorkspaceContext.jsx';
import { writeLastWorkspaceId } from '../../src/utils/lastWorkspacePreference.js';
import CertOpsDistribution from '../../src/pages/certops/CertOpsDistribution.jsx';

const { api, list } = vi.hoisted(() => ({
  api: { groups: vi.fn(), management: vi.fn(), retention: vi.fn() },
  list: vi.fn(),
}));
vi.mock('../../src/utils/apiClient', () => ({ workspaceAPI: { list } }));
vi.mock('../../src/components/certops/distributionApi.js', () => ({
  distributionApi: api,
}));
vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: () => true,
  useCertOpsIsWorkspaceAdmin: () => true,
}));
const version = '11111111-1111-4111-8111-111111111111',
  job = '22222222-2222-4222-8222-222222222222';
const policy = {
  mode: 'manual',
  maxParallel: 1,
  verification: {
    enabled: false,
    intervalSeconds: 300,
    maxBackoffSeconds: 1200,
    staleJobSeconds: 3600,
    failureThreshold: 2,
  },
  alerts: {
    enabled: false,
    offlineSeconds: 900,
    stuckSeconds: 3600,
    convergenceSeconds: 3600,
    expiryWarningDays: 14,
    repeatSeconds: 3600,
    contactGroupIds: [],
  },
  retention: {
    minimumSeconds: 86400,
    minimumVersions: 2,
    rollbackSeconds: 86400,
    cleanupEnabled: false,
    reportOnly: true,
    requiresApproval: true,
  },
};
function Destination() {
  const { workspaceId } = useWorkspace();
  const location = useLocation();
  return (
    <output data-testid='destination'>
      {workspaceId}|{location.pathname}
      {location.search}
    </output>
  );
}
function tab(workspace) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter
          initialEntries={[`/certops/distribution?workspace=${workspace}`]}
        >
          <WorkspaceProvider accountId='operator'>
            <Routes>
              <Route
                path='/certops/distribution'
                element={<CertOpsDistribution />}
              />
              <Route path='/certops/jobs' element={<Destination />} />
              <Route path='/onboarding' element={<Destination />} />
            </Routes>
          </WorkspaceProvider>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  list.mockResolvedValue({
    items: [
      { id: 'alpha', name: 'Alpha' },
      { id: 'beta', name: 'Beta' },
    ],
  });
  api.groups.mockImplementation(workspace =>
    Promise.resolve({
      groups: [
        {
          id: `group-${workspace}`,
          state: 'active',
          material_store_ref: 'customer',
        },
      ],
    })
  );
  api.management.mockImplementation(workspace =>
    Promise.resolve({
      evaluated_at: new Date().toISOString(),
      group: {
        id: `group-${workspace}`,
        state: 'active',
        generation: 1,
        material_store_ref: 'customer',
        latest_material_version_id: version,
      },
      policy: null,
      defaults: structuredClone(policy),
      consumers: [],
      versions: [],
      rollouts: [],
      approvals: [],
      incidents: [],
      discoveries: [],
      agents: [],
      contactGroups: [],
    })
  );
  api.retention.mockResolvedValue({
    cleanupAvailable: false,
    versions: [
      {
        id: version,
        provider_version: 1,
        retainedReasons: ['cleanup_fenced'],
        cleanup_job_id: job,
        cleanup_state: 'fenced',
        cleanup_job_status: 'failed',
      },
    ],
  });
});
describe('Distribution links retain explicit workspace across saved selections and tabs', () => {
  it.each(['alpha', 'beta'])(
    'keeps %s on cleanup approval navigation even when another workspace is saved',
    async workspace => {
      writeLastWorkspaceId(
        'operator',
        workspace === 'alpha' ? 'beta' : 'alpha'
      );
      const view = tab(workspace),
        page = within(view.container);
      fireEvent.click(
        await page.findByRole('button', { name: 'Preview retained versions' })
      );
      const link = await page.findByRole('link', {
        name: 'View cleanup job and approval',
      });
      expect(link).toHaveAttribute(
        'href',
        `/certops/jobs?workspace=${workspace}&job=${job}`
      );
      fireEvent.click(link);
      await waitFor(() =>
        expect(page.getByTestId('destination')).toHaveTextContent(
          `${workspace}|/certops/jobs?workspace=${workspace}&job=${job}`
        )
      );
    }
  );
  it('keeps onboarding workspace independent in two tabs with conflicting saved selections', async () => {
    writeLastWorkspaceId('operator', 'beta');
    const first = tab('alpha');
    const firstPage = within(first.container);
    await firstPage.findByRole('button', { name: 'Preview retained versions' });
    writeLastWorkspaceId('operator', 'alpha');
    const second = tab('beta'),
      secondPage = within(second.container);
    const secondLink = await secondPage.findByRole('link', {
      name: 'Open first-distribution setup guide',
    });
    expect(
      firstPage.getByRole('link', {
        name: 'Open first-distribution setup guide',
      })
    ).toHaveAttribute('href', '/onboarding?workspace=alpha&area=certops');
    expect(secondLink).toHaveAttribute(
      'href',
      '/onboarding?workspace=beta&area=certops'
    );
    fireEvent.click(secondLink);
    await waitFor(() =>
      expect(secondPage.getByTestId('destination')).toHaveTextContent(
        'beta|/onboarding?workspace=beta&area=certops'
      )
    );
    fireEvent.click(
      firstPage.getByRole('link', {
        name: 'Open first-distribution setup guide',
      })
    );
    await waitFor(() =>
      expect(firstPage.getByTestId('destination')).toHaveTextContent(
        'alpha|/onboarding?workspace=alpha&area=certops'
      )
    );
  });
});
