import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  waitFor,
  screen,
  fireEvent,
  cleanup,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import ImportTokensModal from '../../src/components/ImportTokensModal.jsx';

const { apiGetMock, apiDeleteMock, gitlabFormProps, githubFormProps } =
  vi.hoisted(() => ({
    apiGetMock: vi.fn(),
    apiDeleteMock: vi.fn(),
    gitlabFormProps: [],
    githubFormProps: [],
  }));

vi.mock('../../src/utils/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), log: vi.fn() },
}));

vi.mock('../../src/utils/toast.js', () => ({
  showWarning: vi.fn(),
  showError: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: {
    get: apiGetMock,
    post: vi.fn().mockResolvedValue({ data: {} }),
    put: vi.fn().mockResolvedValue({ data: {} }),
    delete: apiDeleteMock,
  },
  tokenAPI: { createToken: vi.fn() },
  workspaceAPI: {
    get: vi.fn().mockResolvedValue({}),
    getAlertSettings: vi.fn().mockResolvedValue({}),
  },
  authAPI: { getPlan: vi.fn().mockResolvedValue({}) },
  azureADAPI: { scan: vi.fn() },
  integrationAPI: {
    checkDuplicates: vi
      .fn()
      .mockResolvedValue({ duplicate_count: 0, duplicates: [] }),
    import: vi.fn(),
  },
  formatDate: d => String(d),
  showSuccessMessage: vi.fn(),
}));

vi.mock('../../src/components/IntegrationImportTable', () => ({
  default: () => <div>import-table</div>,
}));
vi.mock('../../src/components/BulkIntegrationAssignment', () => ({
  default: () => <div>bulk-assignment</div>,
}));
vi.mock('../../src/components/CopyableCodeBlock', () => ({
  default: () => <div>code-block</div>,
}));

vi.mock('../../src/components/imports/ImportVaultForm', () => ({
  default: React.forwardRef(function VaultMock(_props, _ref) {
    return <div>vault-form</div>;
  }),
}));
vi.mock('../../src/components/imports/ImportGitLabForm', () => ({
  default: React.forwardRef(function GitLabMock(props, _ref) {
    gitlabFormProps.push(props.initialScanParams);
    return (
      <div>
        gitlab-form
        <button onClick={() => props.onError('GitLab scan failed')}>
          Fail GitLab scan
        </button>
        {props.errorContent}
      </div>
    );
  }),
}));
vi.mock('../../src/components/imports/ImportGitHubForm', () => ({
  default: React.forwardRef(function GitHubMock(props, _ref) {
    githubFormProps.push(props.initialScanParams);
    return <div>github-form{props.errorContent}</div>;
  }),
}));
vi.mock('../../src/components/imports/ImportAWSForm', () => ({
  default: React.forwardRef(function AwsMock(_props, _ref) {
    return <div>aws-form</div>;
  }),
  buildAwsAutoSyncPayload: () => ({ credentials: {}, scanParams: {} }),
}));
vi.mock('../../src/components/imports/ImportAzureForm', () => ({
  default: React.forwardRef(function AzureMock(_props, _ref) {
    return <div>azure-form</div>;
  }),
}));
vi.mock('../../src/components/imports/ImportGCPForm', () => ({
  default: React.forwardRef(function GcpMock(_props, _ref) {
    return <div>gcp-form</div>;
  }),
}));
vi.mock('../../src/components/certops/ImportCertificateForm.jsx', () => ({
  default: React.forwardRef(function CertMock(_props, _ref) {
    return <div>cert-form</div>;
  }),
}));
vi.mock('../../src/components/certops/certopsApi.js', () => ({
  invalidateCertOpsInventoryCache: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsFormat.js', () => ({
  describeCertificateImportOutcome: vi.fn(),
}));
vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsAvailability: () => ({ ready: true, enabled: false, error: null }),
  useCertOpsCanManage: () => false,
}));
vi.mock('../../src/hooks/useDashboardTheme.js', () => ({
  useDashboardTheme: () => ({ border: 'gray.200', muted: 'gray.500' }),
}));
vi.mock('../../src/components/DashboardModalFrame.jsx', () => ({
  DashboardModalFrame: ({ children }) => <div>{children}</div>,
  DashboardModalDescription: ({ children }) => <div>{children}</div>,
  DashboardModalTitle: ({ children }) => <div>{children}</div>,
  useDashboardModalProps: () => ({
    overlayProps: {},
    headerProps: {},
    bodyProps: {},
    footerProps: {},
    closeButtonProps: {},
    fieldProps: {},
    outlineButtonProps: {},
    primaryButtonProps: {},
    dangerButtonProps: {},
    tokens: {},
  }),
}));
vi.mock('../../src/styles/theme.js', () => ({
  dashboardModalInlineActionButtonProps: {},
}));

const GITLAB_SELF_HOSTED = 'https://gitlab.selfhosted.example';

function renderModal(openRequest) {
  return (
    <ChakraProvider>
      <ImportTokensModal
        isOpen
        onClose={vi.fn()}
        onImported={vi.fn()}
        openRequest={openRequest}
        onOpenRequestHandled={vi.fn()}
      />
    </ChakraProvider>
  );
}

describe('ImportTokensModal restored scan params provider scoping', () => {
  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    apiDeleteMock.mockReset().mockResolvedValue({ data: {} });
    gitlabFormProps.length = 0;
    githubFormProps.length = 0;
    // Only GitLab has an auto-sync config with saved scan params.
    apiGetMock.mockImplementation(url => {
      if (String(url).includes('/auto-sync')) {
        return Promise.resolve({
          data: {
            items: [
              {
                id: 'as-gitlab-1',
                provider: 'gitlab',
                frequency: 'daily',
                scan_params: {
                  baseUrl: GITLAB_SELF_HOSTED,
                  filters: { includePATs: true },
                },
              },
            ],
          },
        });
      }
      return Promise.resolve({ data: {} });
    });
  });

  it.each([true, false])(
    'refreshes provider configuration selection after disabling (remaining: %s)',
    async hasRemaining => {
      const removed = {
        id: 'as-gitlab-1',
        provider: 'gitlab',
        name: 'Removed configuration',
        scan_params: { baseUrl: GITLAB_SELF_HOSTED },
      };
      const remaining = {
        id: 'as-gitlab-2',
        provider: 'gitlab',
        name: 'Remaining configuration',
        scan_params: { baseUrl: 'https://gitlab.remaining.example' },
      };
      let configs = [
        removed,
        ...(hasRemaining ? [remaining] : []),
        {
          id: 'as-github-1',
          provider: 'github',
          name: 'Other provider',
          scan_params: {},
        },
      ];
      apiGetMock.mockImplementation(url =>
        Promise.resolve({
          data: { items: String(url).endsWith('/auto-sync') ? configs : [] },
        })
      );
      apiDeleteMock.mockImplementation(() => {
        configs = configs.filter(config => config.id !== removed.id);
        return Promise.resolve({ data: {} });
      });
      render(
        renderModal({
          provider: 'gitlab',
          integrationSubTab: 'manage',
          autoSyncConfigId: removed.id,
        })
      );
      await waitFor(() =>
        expect(
          screen.getByRole('combobox', { name: 'Configuration' })
        ).toHaveValue(removed.id)
      );
      fireEvent.click(
        screen.getByRole('button', { name: 'Disable auto-sync', exact: true })
      );
      fireEvent.click(
        await screen.findByRole('button', {
          name: 'Disable Auto-Sync',
          exact: true,
        })
      );
      await waitFor(() =>
        expect(apiDeleteMock).toHaveBeenCalledWith(
          '/api/v1/workspaces/ws-1/auto-sync/as-gitlab-1'
        )
      );
      if (hasRemaining) {
        await waitFor(() =>
          expect(gitlabFormProps.at(-1)?.baseUrl).toBe(
            remaining.scan_params.baseUrl
          )
        );
        expect(
          screen.getByRole('button', { name: 'Scan & Import', exact: true })
        ).toBeVisible();
        fireEvent.click(
          screen.getByRole('button', { name: 'Manage auto-sync', exact: true })
        );
        expect(
          screen.getByRole('combobox', { name: 'Configuration' })
        ).toHaveValue(remaining.id);
        expect(
          screen.queryByRole('option', { name: removed.name })
        ).not.toBeInTheDocument();
        // The removed deep-link selection must not return when reopening this provider.
        fireEvent.click(
          screen.getByRole('button', { name: 'GitHub', exact: true })
        );
        await screen.findByText('github-form');
        fireEvent.click(
          screen.getByRole('button', { name: 'GitLab', exact: true })
        );
        await waitFor(() =>
          expect(gitlabFormProps.at(-1)?.baseUrl).toBe(
            remaining.scan_params.baseUrl
          )
        );
        expect(
          screen.getByRole('button', { name: 'Manage auto-sync', exact: true })
        ).toBeVisible();
      } else {
        await waitFor(() => expect(gitlabFormProps.at(-1)).toBeNull());
        expect(
          screen.queryByRole('button', {
            name: 'Manage auto-sync',
            exact: true,
          })
        ).not.toBeInTheDocument();
        expect(
          screen.getByRole('button', { name: 'Enable auto-sync', exact: true })
        ).toBeVisible();
      }
    }
  );

  it('clears a previous provider error when switching integrations', async () => {
    render(renderModal({ provider: 'gitlab' }));
    fireEvent.click(
      await screen.findByRole('button', { name: 'Fail GitLab scan' })
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'GitLab scan failed'
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'GitHub', exact: true })
    );
    await screen.findByText('github-form');
    await waitFor(() =>
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    );
  });

  it('never hands GitLab scan params to the GitHub form when switching providers', async () => {
    const { rerender } = render(renderModal({ provider: 'gitlab' }));

    // Wait for the GitLab restore to land in the GitLab form.
    await waitFor(() => {
      expect(
        gitlabFormProps.some(sp => sp && sp.baseUrl === GITLAB_SELF_HOSTED)
      ).toBe(true);
    });

    // Switch to GitHub (same flow as clicking the GitHub provider card).
    rerender(renderModal({ provider: 'github' }));

    await waitFor(() => {
      expect(githubFormProps.length).toBeGreaterThan(0);
    });
    // Let the auto-sync refetch for GitHub settle too.
    await waitFor(() => {
      expect(
        apiGetMock.mock.calls.filter(c => String(c[0]).includes('/auto-sync'))
          .length
      ).toBeGreaterThanOrEqual(2);
    });

    // Regression: the GitHub form must never see GitLab's saved params
    // (previously it mounted with the stale shared restoredScanParams and
    // prefilled the GitHub URL with the GitLab base URL).
    for (const sp of githubFormProps) {
      expect(
        sp === null || sp === undefined || sp.baseUrl !== GITLAB_SELF_HOSTED
      ).toBe(true);
    }
  });

  it('restores the exact requested config when a provider has multiple configs', async () => {
    const firstUrl = 'https://gitlab.first.example';
    const secondUrl = 'https://gitlab.second.example';
    apiGetMock.mockImplementation(url =>
      Promise.resolve(
        String(url).includes('/auto-sync')
          ? {
              data: {
                items: [
                  {
                    id: 'as-gitlab-1',
                    provider: 'gitlab',
                    scan_params: { baseUrl: firstUrl },
                  },
                  {
                    id: 'as-gitlab-2',
                    provider: 'gitlab',
                    scan_params: { baseUrl: secondUrl },
                  },
                ],
              },
            }
          : { data: {} }
      )
    );
    render(
      renderModal({
        provider: 'gitlab',
        integrationSubTab: 'manage',
        autoSyncConfigId: 'as-gitlab-2',
      })
    );
    await waitFor(() => {
      expect(gitlabFormProps.some(sp => sp?.baseUrl === secondUrl)).toBe(true);
    });
    expect(gitlabFormProps.some(sp => sp?.baseUrl === firstUrl)).toBe(false);
  });

  it('hides the previous configuration history while another configuration loads', async () => {
    let finishSecond;
    const secondHistory = new Promise(resolve => {
      finishSecond = resolve;
    });
    apiGetMock.mockImplementation(url => {
      if (String(url).includes('/as-gitlab-1/runs'))
        return Promise.resolve({
          data: {
            items: [
              {
                run_id: 'run-1',
                status: 'first-history',
                started_at: '2026-10-01',
                discovered_count: 1,
              },
            ],
            next_cursor: 'old-cursor',
          },
        });
      if (String(url).includes('/as-gitlab-2/runs')) return secondHistory;
      if (String(url).endsWith('/auto-sync'))
        return Promise.resolve({
          data: {
            items: [
              {
                id: 'as-gitlab-1',
                provider: 'gitlab',
                name: 'First',
                scan_params: {},
              },
              {
                id: 'as-gitlab-2',
                provider: 'gitlab',
                name: 'Second',
                scan_params: {},
              },
            ],
          },
        });
      return Promise.resolve({ data: {} });
    });
    render(
      renderModal({
        provider: 'gitlab',
        integrationSubTab: 'manage',
        autoSyncConfigId: 'as-gitlab-1',
      })
    );
    expect(await screen.findByText(/first-history/)).toBeTruthy();
    fireEvent.change(screen.getByRole('combobox', { name: 'Configuration' }), {
      target: { value: 'as-gitlab-2' },
    });
    expect(await screen.findByText('Loading run history…')).toBeTruthy();
    expect(screen.queryByText(/first-history/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Earlier runs' })).toBeNull();
    finishSecond({
      data: {
        items: [
          {
            run_id: 'run-2',
            status: 'second-history',
            started_at: '2026-10-02',
          },
        ],
      },
    });
    expect(await screen.findByText(/second-history/)).toBeTruthy();
  });
});
