import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, waitFor, act } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import ApprovalDecisionModal from '../../src/components/certops/ApprovalDecisionModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { getJobMock } = vi.hoisted(() => ({ getJobMock: vi.fn() }));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  getJob: getJobMock,
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'review-workspace' }),
}));
beforeEach(() => {
  getJobMock.mockReset();
});

const cleanup = {
  groupId: 'cleanup-group',
  managementPeriodId: 'owned-period',
  materialVersionId: 'a7de2e19-a22f-5195-9ff5-e4d3e5ef0df7',
  provider: 'vault-kv2',
  providerVersion: 1,
  materialStoreRef: 'vault-retention',
  profileRevision: 2,
  policyRevision: 3,
  scopeHash: 'frozen-cleanup-scope',
  expiresAt: '2026-11-04T07:17:20.114Z',
  operation: 'soft-delete',
  retentionPolicy: {
    minimumSeconds: 0,
    minimumVersions: 2,
    rollbackSeconds: 0,
    cleanupEnabled: true,
    reportOnly: false,
    requiresApproval: true,
  },
};
const binding = {
  bindingId: 'destination-file',
  agentId: 'agent-file',
  profileRef: 'file-profile',
  profileRevision: 4,
  authorizationRevision: 7,
  required: false,
  wave: 0,
  verificationPolicy: 'installed',
  freshnessSeconds: 3600,
  activationPolicy: {
    method: 'none',
    disruptive: false,
    requiresApproval: true,
    timezone: 'Europe/Berlin',
    windows: [{ days: [0, 1], start: '01:00', end: '03:00' }],
    blackouts: [{ start: '2026-11-05T00:00:00Z', end: '2026-11-06T00:00:00Z' }],
    validUntil: '2026-11-20T00:00:00Z',
    emergency: {
      start: '2026-11-03T09:00:00Z',
      end: '2026-11-03T10:00:00Z',
      reference: 'incident-42',
    },
  },
};
async function show(
  payload,
  { operation = 'noop', decision = 'approve', load } = {}
) {
  const onDecide = vi.fn();
  getJobMock.mockImplementation(
    load ||
      (() =>
        Promise.resolve({
          job: {
            id: 'review-job',
            workspaceId: 'review-workspace',
            operation,
            status: 'pending_approval',
            payload,
          },
        }))
  );
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <ApprovalDecisionModal
          isOpen
          onClose={vi.fn()}
          job={{ id: 'review-job', operation, payload }}
          decision={decision}
          onDecide={onDecide}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  const dialog = within(screen.getByRole('dialog'));
  await waitFor(() =>
    expect(
      dialog.queryByText('Loading approval scope...')
    ).not.toBeInTheDocument()
  );
  return dialog;
}

describe('immutable distribution approval review', () => {
  it('shows the exact cleanup object, provider reference and all authorization bounds before approval', async () => {
    const dialog = await show(
      { materialCleanup: cleanup },
      { operation: 'cleanup-from-store' }
    );
    for (const value of [
      cleanup.materialVersionId,
      cleanup.scopeHash,
      cleanup.expiresAt,
      cleanup.materialStoreRef,
      cleanup.managementPeriodId,
      'Soft delete one store version',
      'Provider version',
      'Local profile revision',
      'Policy revision',
      'Minimum retained versions',
      'Minimum age (seconds)',
      'Rollback protection (seconds)',
      'Report only',
    ]) {
      expect(dialog.getByText(value, { exact: true })).toBeInTheDocument();
    }
    expect(dialog.getByRole('button', { name: 'Approve' })).toBeEnabled();
  });

  it('reviews frozen rollout destinations, exact Azure version, wave zero and local activation calendars', async () => {
    const dialog = await show({
      distributionRollout: {
        workspaceId: 'rollout-workspace',
        groupId: 'rollout-group',
        materialVersionId: 'retained-version',
        managementPeriodId: 'rollout-period',
        materialStoreRef: 'azure-store',
        provider: 'azure-key-vault',
        providerVersion: '00112233445566778899aabbccddeeff',
        fingerprintSha256: 'exact-fingerprint',
        issuanceProfileRevision: 3,
        generation: 8,
        maxParallel: 1,
        verificationOnly: true,
        bindings: [
          binding,
          {
            ...binding,
            bindingId: 'destination-web',
            agentId: 'agent-web',
            profileRef: 'web-profile',
            required: true,
            wave: 2,
            activationPolicy: null,
          },
        ],
      },
    });
    for (const value of [
      'Verification only',
      'retained-version',
      '00112233445566778899aabbccddeeff',
      'exact-fingerprint',
      'destination-file',
      'destination-web',
      'agent-file',
      'web-profile',
      'Europe/Berlin',
      'Sun, Mon: 01:00–03:00',
      '2026-11-05T00:00:00Z – 2026-11-06T00:00:00Z',
      'incident-42',
      '2026-11-20T00:00:00Z',
    ])
      expect(dialog.getByText(value, { exact: true })).toBeInTheDocument();
    expect(dialog.getAllByText('0', { exact: true }).length).toBeGreaterThan(0);
    expect(dialog.getAllByText('No', { exact: true }).length).toBeGreaterThan(
      0
    );
  });

  it('exposes the standing grant scope, source authority, reviewer membership and fixed failure behavior', async () => {
    const dialog = await show({
      distributionPolicyApproval: {
        groupId: 'standing-group',
        revision: 6,
        scopeHash: 'standing-scope',
        expiresAt: '2026-11-21T00:00:00Z',
        scope: {
          workspaceId: 'standing-workspace',
          groupId: 'standing-group',
          managementPeriodId: 'standing-period',
          materialStoreRef: 'approved-store',
          issuerAgentId: 'approved-issuer',
          issuanceProfileRef: 'approved-source',
          profileRevision: 9,
          workspaceAuthorizationRevision: '12',
          workspaceRequiresApproval: true,
          workspaceOwner: 10,
          reviewers: [{ user_id: 11, role: 'workspace_manager' }],
          policy: {
            mode: 'preauthorized',
            maxParallel: 2,
            authorizationExpiresAt: '2026-11-21T00:00:00Z',
          },
          bindings: [binding],
          rolloutBehavior: {
            requiredFailure: 'pause',
            optionalFailure: 'degraded',
            waveOrder: 'ascending',
            rollback: 'explicit_approval',
            verificationBeforeNextWave: true,
          },
        },
      },
    });
    for (const value of [
      'Standing distribution authorization',
      'standing-scope',
      'approved-store',
      'approved-issuer',
      'approved-source',
      'Workspace authorization revision',
      'workspace_manager',
      'preauthorized',
      'pause',
      'degraded',
      'ascending',
      'explicit_approval',
      'destination-file',
    ]) {
      expect(dialog.getByText(value, { exact: true })).toBeInTheDocument();
    }
  });

  it('never dumps arbitrary job or store fields', async () => {
    const dialog = await show(
      {
        privateKey: 'TOP-LEVEL-SECRET',
        materialCleanup: {
          ...cleanup,
          credentials: 'STORE-SECRET',
          retentionPolicy: {
            ...cleanup.retentionPolicy,
            token: 'NESTED-SECRET',
          },
        },
      },
      { operation: 'cleanup-from-store' }
    );
    expect(dialog.getByText(cleanup.materialVersionId)).toBeInTheDocument();
    expect(
      screen.queryByText(/TOP-LEVEL-SECRET|STORE-SECRET|NESTED-SECRET/)
    ).not.toBeInTheDocument();
  });

  it('does not expose unrecognized destination or calendar fields in a standing grant', async () => {
    const dialog = await show({
      distributionPolicyApproval: {
        groupId: 'standing-group',
        scopeHash: 'frozen-scope',
        scope: {
          credentials: 'SOURCE-SECRET',
          policy: { mode: 'preauthorized', token: 'POLICY-SECRET' },
          bindings: [
            {
              ...binding,
              tokenFile: 'BINDING-SECRET',
              activationPolicy: {
                ...binding.activationPolicy,
                credentials: 'CALENDAR-SECRET',
                windows: [
                  {
                    ...binding.activationPolicy.windows[0],
                    token: 'WINDOW-SECRET',
                  },
                ],
              },
            },
          ],
        },
      },
    });
    expect(dialog.getByText('destination-file')).toBeInTheDocument();
    expect(dialog.getByText('Sun, Mon: 01:00–03:00')).toBeInTheDocument();
    expect(
      screen.queryByText(
        /SOURCE-SECRET|POLICY-SECRET|BINDING-SECRET|CALENDAR-SECRET|WINDOW-SECRET/
      )
    ).not.toBeInTheDocument();
  });

  it('refuses approval when the exact cleanup intent is unavailable, but still permits rejection', async () => {
    const dialog = await show({}, { operation: 'cleanup-from-store' });
    expect(dialog.getByRole('button', { name: 'Approve' })).toBeDisabled();
    expect(
      dialog.getByText(/Exact cleanup scope is unavailable/)
    ).toBeInTheDocument();
  });

  it('keeps rejection available when cleanup scope is unavailable', async () => {
    const dialog = await show(
      {},
      { operation: 'cleanup-from-store', decision: 'reject' }
    );
    expect(dialog.getByRole('button', { name: 'Reject' })).toBeEnabled();
  });

  it('does not enable approval while detail is loading and ignores a late response for another job', async () => {
    let resolveOld, resolveNew;
    getJobMock.mockImplementation(
      (workspace, id) =>
        new Promise(resolve => {
          if (id === 'old-job') resolveOld = resolve;
          else resolveNew = resolve;
        })
    );
    const view = id => (
      <ChakraProvider>
        <DashboardThemeProvider>
          <ApprovalDecisionModal
            isOpen
            onClose={vi.fn()}
            job={{ id, operation: 'cleanup-from-store' }}
            decision='approve'
            onDecide={vi.fn()}
          />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    const rendered = render(view('old-job'));
    expect(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Approve',
      })
    ).toBeDisabled();
    rendered.rerender(view('new-job'));
    await act(async () =>
      resolveOld({
        job: {
          id: 'old-job',
          workspaceId: 'review-workspace',
          status: 'pending_approval',
          payload: {
            materialCleanup: { ...cleanup, materialVersionId: 'stale-version' },
          },
        },
      })
    );
    expect(screen.queryByText('stale-version')).not.toBeInTheDocument();
    expect(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Approve',
      })
    ).toBeDisabled();
    await act(async () =>
      resolveNew({
        job: {
          id: 'new-job',
          workspaceId: 'review-workspace',
          status: 'pending_approval',
          payload: { materialCleanup: cleanup },
        },
      })
    );
    expect(screen.getByText(cleanup.materialVersionId)).toBeInTheDocument();
    expect(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Approve',
      })
    ).toBeEnabled();
  });

  it.each(['unavailable', 'wrong workspace', 'already decided'])(
    'refuses approval when detail is %s',
    async scenario => {
      const load = () =>
        scenario === 'unavailable'
          ? Promise.reject(new Error('offline'))
          : Promise.resolve({
              job: {
                id: 'review-job',
                workspaceId:
                  scenario === 'wrong workspace'
                    ? 'other-workspace'
                    : 'review-workspace',
                status:
                  scenario === 'already decided'
                    ? 'rejected'
                    : 'pending_approval',
                payload: { materialCleanup: cleanup },
              },
            });
      const dialog = await show({}, { operation: 'cleanup-from-store', load });
      expect(dialog.getByRole('button', { name: 'Approve' })).toBeDisabled();
      expect(dialog.getByRole('alert')).toBeInTheDocument();
    }
  );
});
