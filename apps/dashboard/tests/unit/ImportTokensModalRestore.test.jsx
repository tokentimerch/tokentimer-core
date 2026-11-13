import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  render,
  waitFor,
  screen,
  fireEvent,
  cleanup,
  act,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import ImportTokensModal from '../../src/components/ImportTokensModal.jsx';
import apiClient, {
  tokenAPI,
  integrationAPI,
  azureADAPI,
} from '../../src/utils/apiClient';
import { IMPORT_DOCS } from '../../src/utils/docsUrls.js';

const { apiGetMock, apiDeleteMock, gitlabFormProps, githubFormProps, wsCtx } =
  vi.hoisted(() => ({
    apiGetMock: vi.fn(),
    apiDeleteMock: vi.fn(),
    gitlabFormProps: [],
    githubFormProps: [],
    wsCtx: { id: 'ws-1' },
  }));

vi.mock('../../src/utils/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), log: vi.fn() },
}));

vi.mock('../../src/utils/toast.js', () => ({
  showWarning: vi.fn(),
  showError: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: wsCtx.id, selectWorkspace: vi.fn() }),
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
  authAPI: {
    getPlan: vi.fn().mockResolvedValue({
      integrationScansUsed: 0,
      integrationScansLimit: null,
      integrationScansRemaining: null,
    }),
  },
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
  default: ({ items, onToggleRow }) => (
    <div>
      import-table
      <button
        onClick={() => onToggleRow?.(0)}
      >{`select-first-${items?.length || 0}`}</button>
    </div>
  ),
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
vi.mock('../../src/hooks/useDashboardTheme.js', async importOriginal => ({
  ...(await importOriginal()),
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
vi.mock('../../src/styles/theme.js', async importOriginal => ({
  ...(await importOriginal()),
  dashboardModalInlineActionButtonProps: {},
}));

const GITLAB_SELF_HOSTED = 'https://gitlab.selfhosted.example';

function renderModal(openRequest, extraProps = {}) {
  return (
    <ChakraProvider>
      <ImportTokensModal
        isOpen
        {...extraProps}
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
    },
    15000
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

  it('requests five runs per cursor page and keeps only the current page visible', async () => {
    const makeRuns = (start, length) =>
      Array.from({ length }, (_, i) => ({
        run_id: `run-${start + i}`,
        status: `result-${start + i}`,
        started_at: '2026-10-30',
      }));
    apiGetMock.mockImplementation(url => {
      if (String(url).includes('/as-gitlab-1/runs?limit=5&cursor='))
        return Promise.resolve({
          data: { items: makeRuns(5, 2), next_cursor: null },
        });
      if (String(url).endsWith('/as-gitlab-1/runs?limit=5'))
        return Promise.resolve({
          data: { items: makeRuns(0, 5), next_cursor: 'cursor/5' },
        });
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
    await screen.findByText('result-0');
    expect(screen.getAllByRole('button', { name: /Details for/ })).toHaveLength(
      5
    );
    fireEvent.click(screen.getByRole('button', { name: 'Earlier runs' }));
    await screen.findByText('result-5');
    expect(screen.queryByText('result-0')).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Details for/ })).toHaveLength(
      2
    );
    expect(apiGetMock).toHaveBeenCalledWith(
      '/api/v1/workspaces/ws-1/auto-sync/as-gitlab-1/runs?limit=5&cursor=cursor%2F5'
    );
    fireEvent.click(screen.getByRole('button', { name: 'Newer runs' }));
    expect(screen.getByText('result-0')).toBeVisible();
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

describe('Entra identity selection and saved filters', () => {
  const filterRules = [
    {
      action: 'include',
      field: 'location',
      matchType: 'regex',
      value: '^azure-ad:managedIdentities/',
    },
  ];
  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    apiClient.put.mockResolvedValue({ data: {} });
    apiGetMock.mockImplementation(url =>
      Promise.resolve({
        data: String(url).endsWith('/auto-sync')
          ? {
              items: [
                {
                  id: 'entra-config',
                  provider: 'azure-ad',
                  name: 'Managed identities',
                  frequency: 'daily',
                  schedule_time: '08:00',
                  schedule_tz: 'UTC',
                  enabled: true,
                  scan_params: {
                    managedIdentityMode: 'only',
                    filterRules,
                    include: { applications: true, servicePrincipals: false },
                  },
                },
              ],
            }
          : {},
      })
    );
  });

  it('restores the native mode and rules and preserves them on a credential-retaining save', async () => {
    render(
      renderModal({
        provider: 'azure-ad',
        integrationSubTab: 'manage',
        autoSyncConfigId: 'entra-config',
      })
    );
    await waitFor(() =>
      expect(
        screen.getByRole('combobox', { name: 'Identity selection' })
      ).toHaveValue('only')
    );
    expect(screen.getByDisplayValue(filterRules[0].value)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(apiClient.put).toHaveBeenCalled());
    const body = apiClient.put.mock.calls[0][1];
    expect(body.scan_params).toMatchObject({
      managedIdentityMode: 'only',
      filterRules,
      include: { applications: false, servicePrincipals: true },
    });
    expect(body.credentials).toBeUndefined();
  });

  it.each(['scan', 'manage'])(
    'places identity and filter settings after scope selectors in the %s view',
    async integrationSubTab => {
      render(
        renderModal({
          provider: 'azure-ad',
          integrationSubTab,
          autoSyncConfigId: 'entra-config',
        })
      );
      const identity = await screen.findByRole('combobox', {
        name: 'Identity selection',
      });
      const filters = screen.getByText('Filter rules');
      for (const label of [
        'Scan App Registrations',
        'Scan Service Principals',
      ]) {
        expect(
          screen.getByText(label).compareDocumentPosition(identity) &
            Node.DOCUMENT_POSITION_FOLLOWING
        ).toBeTruthy();
      }
      expect(
        identity.compareDocumentPosition(filters) &
          Node.DOCUMENT_POSITION_FOLLOWING
      ).toBeTruthy();
      expect(identity).toBeVisible();
      expect(filters).toBeVisible();
    }
  );

  it.each(['all', 'exclude', 'only'])(
    'saves edited %s selection and filter rules without replacing credentials',
    async mode => {
      render(
        renderModal({
          provider: 'azure-ad',
          integrationSubTab: 'manage',
          autoSyncConfigId: 'entra-config',
        })
      );
      const rule = await screen.findByDisplayValue(filterRules[0].value);
      fireEvent.change(
        screen.getByRole('combobox', { name: 'Identity selection' }),
        { target: { value: mode } }
      );
      fireEvent.change(rule, { target: { value: '^azure-ad:.*production' } });
      fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
      await waitFor(() => expect(apiClient.put).toHaveBeenCalled());
      const body = apiClient.put.mock.calls[0][1];
      expect(body.scan_params).toMatchObject({
        managedIdentityMode: mode,
        filterRules: [{ ...filterRules[0], value: '^azure-ad:.*production' }],
      });
      expect(body.credentials).toBeUndefined();
    }
  );

  it('can clear rules and change identity mode while replacing credentials', async () => {
    render(
      renderModal({
        provider: 'azure-ad',
        integrationSubTab: 'manage',
        autoSyncConfigId: 'entra-config',
      })
    );
    await screen.findByDisplayValue(filterRules[0].value);
    fireEvent.click(screen.getByRole('button', { name: 'Remove rule' }));
    fireEvent.change(
      screen.getByRole('combobox', { name: 'Identity selection' }),
      { target: { value: 'exclude' } }
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Replace credentials' })
    );
    fireEvent.click(
      screen.getByRole('radio', { name: 'Entra app (client credentials)' })
    );
    for (const [placeholder, value] of [
      ['Tenant ID or domain', 'tenant'],
      ['Client ID', 'client'],
      ['Client secret', 'secret'],
    ]) {
      fireEvent.change(screen.getByPlaceholderText(placeholder), {
        target: { value },
      });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(apiClient.put).toHaveBeenCalled());
    expect(apiClient.put.mock.calls[0][1]).toMatchObject({
      scan_params: { managedIdentityMode: 'exclude', filterRules: [] },
      credentials: {
        authMethod: 'client_credentials',
        tenantId: 'tenant',
        clientId: 'client',
        clientSecret: 'secret',
      },
    });
  });

  it.each(['all', 'exclude', 'only'])(
    'sends %s mode and generic rules on a manual scan',
    async mode => {
      apiGetMock.mockResolvedValue({ data: {} });
      azureADAPI.scan.mockResolvedValue({
        items: [],
        summary: [],
        scan_id: 'scan',
      });
      render(renderModal({ provider: 'azure-ad' }));
      await screen.findByRole('combobox', { name: 'Identity selection' });
      fireEvent.change(
        screen.getByRole('combobox', { name: 'Identity selection' }),
        { target: { value: mode } }
      );
      fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
      fireEvent.change(screen.getByPlaceholderText('exact value'), {
        target: { value: 'ignore-me' },
      });
      fireEvent.change(document.querySelector('input[type="password"]'), {
        target: { value: 'graph-token' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
      await waitFor(() => expect(azureADAPI.scan).toHaveBeenCalled());
      expect(azureADAPI.scan.mock.calls[0][0]).toMatchObject({
        managedIdentityMode: mode,
        filterRules: [
          {
            action: 'exclude',
            field: 'name',
            matchType: 'exact',
            value: 'ignore-me',
          },
        ],
        ...(mode === 'only'
          ? { include: { applications: false, servicePrincipals: true } }
          : {}),
      });
    }
  );
  const preview = {
    items: [
      {
        name: 'Ordinary principal',
        location: 'azure-ad:servicePrincipals/app/secrets/key',
        sourceKind: 'azure-ad-sp-secret',
        sourceObjectId: 'app:key',
        servicePrincipalType: 'Application',
      },
    ],
    summary: [{ type: 'service_principals', found: 1, complete: true }],
    scan_id: 'entra-preview',
    filterSummary: { matchedCount: 1, excludedCount: 2 },
  };
  const scanEntra = async () => {
    apiGetMock.mockResolvedValue({ data: {} });
    azureADAPI.scan.mockResolvedValue(preview);
    render(renderModal({ provider: 'azure-ad' }));
    fireEvent.change(
      await screen.findByPlaceholderText(/Paste (?:access )?token/),
      {
        target: { value: 'graph-token' },
      }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
    await screen.findByText('1 matched');
    fireEvent.click(screen.getByRole('button', { name: 'select-first-1' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Import selected' })
      ).toBeEnabled()
    );
  };

  it('imports a verified Entra preview with its original scan id', async () => {
    await scanEntra();
    fireEvent.click(screen.getByRole('button', { name: 'Import selected' }));
    await waitFor(() => expect(integrationAPI.import).toHaveBeenCalled());
    expect(integrationAPI.import.mock.calls[0][0]).toMatchObject({
      scanId: 'entra-preview',
      items: preview.items,
    });
  });

  it.each(['identity', 'rules', 'scope', 'credentials'])(
    'invalidates an Entra preview after changing %s',
    async change => {
      await scanEntra();
      expect(screen.getByText('2 excluded by rules')).toBeInTheDocument();
      if (change === 'identity')
        fireEvent.change(
          screen.getByRole('combobox', { name: 'Identity selection' }),
          { target: { value: 'only' } }
        );
      if (change === 'rules')
        fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
      if (change === 'scope')
        fireEvent.click(
          screen
            .getByText('Scan Service Principals')
            .parentElement.querySelector('input')
        );
      if (change === 'credentials')
        fireEvent.change(
          screen.getByPlaceholderText(/Paste (?:access )?token/),
          {
            target: { value: 'new-graph-token' },
          }
        );
      expect(
        screen.getByRole('button', { name: 'Import selected' })
      ).toBeDisabled();
      expect(
        screen.queryByRole('status', { name: 'Filter results' })
      ).toBeNull();
      expect(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      ).toBeDisabled();
      fireEvent.click(screen.getByRole('button', { name: 'Import selected' }));
      expect(integrationAPI.import).not.toHaveBeenCalled();
    }
  );

  it.each(['resolve', 'reject'])(
    'keeps the newer Entra scan loading when a discarded request settles by %s',
    async outcome => {
      let finishOld, failOld, finishCurrent;
      azureADAPI.scan
        .mockImplementationOnce(
          () =>
            new Promise((resolve, reject) => {
              finishOld = resolve;
              failOld = reject;
            })
        )
        .mockImplementationOnce(
          () =>
            new Promise(resolve => {
              finishCurrent = resolve;
            })
        );
      apiGetMock.mockResolvedValue({ data: {} });
      render(renderModal({ provider: 'azure-ad' }));
      fireEvent.change(
        await screen.findByPlaceholderText(/Paste (?:access )?token/),
        {
          target: { value: 'graph-token' },
        }
      );
      const scanElement = screen.getByRole('button', {
        name: 'Scan',
        exact: true,
      });
      const scan = () => scanElement;
      fireEvent.click(scan());
      fireEvent.change(
        screen.getByRole('combobox', { name: 'Identity selection' }),
        {
          target: { value: 'only' },
        }
      );
      fireEvent.click(scan());
      expect(azureADAPI.scan).toHaveBeenCalledTimes(2);
      await act(async () => {
        if (outcome === 'reject') failOld(new Error('Old scan failed'));
        else finishOld(preview);
      });
      expect(scan()).toBeDisabled();
      expect(
        screen.getByRole('button', { name: 'Import selected' })
      ).toBeDisabled();
      expect(screen.queryByText('1 matched')).toBeNull();
      fireEvent.click(scan());
      expect(azureADAPI.scan).toHaveBeenCalledTimes(2);
      await act(async () => {
        finishCurrent(preview);
      });
      await waitFor(() => expect(scan()).toBeEnabled());
      expect(screen.getByText('1 matched')).toBeInTheDocument();
    }
  );

  it('ignores an Entra scan that completes after identity selection changes', async () => {
    let finish;
    apiGetMock.mockResolvedValue({ data: {} });
    azureADAPI.scan.mockReturnValue(
      new Promise(resolve => {
        finish = resolve;
      })
    );
    render(renderModal({ provider: 'azure-ad' }));
    fireEvent.change(
      await screen.findByPlaceholderText(/Paste (?:access )?token/),
      {
        target: { value: 'graph-token' },
      }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
    fireEvent.change(
      screen.getByRole('combobox', { name: 'Identity selection' }),
      { target: { value: 'only' } }
    );
    await act(async () => {
      finish(preview);
    });
    expect(
      screen.getByRole('button', { name: 'Import selected' })
    ).toBeDisabled();
    expect(screen.queryByText('1 matched')).toBeNull();
    expect(
      screen.getByRole('checkbox', { name: /Remove previously imported/ })
    ).toBeDisabled();
  });

  it('shows filter feedback when all Entra credentials were excluded', async () => {
    apiGetMock.mockResolvedValue({ data: {} });
    azureADAPI.scan.mockResolvedValue({
      items: [],
      summary: [],
      scan_id: 'empty',
      filterSummary: { matchedCount: 0, excludedCount: 3 },
    });
    render(renderModal({ provider: 'azure-ad' }));
    fireEvent.change(
      await screen.findByPlaceholderText(/Paste (?:access )?token/),
      {
        target: { value: 'graph-token' },
      }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
    expect(await screen.findByText('0 matched')).toBeInTheDocument();
    expect(screen.getByText('3 excluded by rules')).toBeInTheDocument();
  });
});

describe('ImportTokensModal docs panel', () => {
  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    apiGetMock.mockResolvedValue({ data: {} });
  });

  it('shows one Learn more panel for the file source', async () => {
    render(renderModal(null));
    const panel = await screen.findByRole('note', { name: 'Learn more' });
    expect(
      within(panel).getByRole('link', { name: 'Importing from files' })
    ).toHaveAttribute('href', IMPORT_DOCS.file);
    expect(screen.getAllByRole('note', { name: 'Learn more' })).toHaveLength(1);
  });

  it('shows the Entra ID guide for the Microsoft Entra ID source', async () => {
    render(renderModal({ provider: 'azure-ad' }));
    const panel = await screen.findByRole('note', { name: 'Learn more' });
    expect(
      within(panel).getByRole('link', {
        name: 'Importing from Microsoft Entra ID',
      })
    ).toHaveAttribute('href', IMPORT_DOCS.entraId);
  });

  it('shows Entra scan scope and separates incomplete-scan and cleanup warnings', async () => {
    azureADAPI.scan.mockResolvedValue({
      items: [],
      scan_id: 'scan-1',
      summary: [{ type: 'App Registrations', found: 0, complete: false }],
    });
    render(renderModal({ provider: 'azure-ad' }));
    expect(
      await screen.findByText(/Application.Read.All is the/)
    ).toBeInTheDocument();
    fireEvent.change(
      screen.getByPlaceholderText(
        'Paste access token with Application.Read.All permission'
      ),
      { target: { value: 'synthetic-token' } }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
    expect(await screen.findByText(/Incomplete scan:/)).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: /Remove previously imported items no longer found/,
      })
    );
    expect(screen.getByText(/Permanent deletion:/)).toBeInTheDocument();
  });

  it('renders no panel when the host already shows its own', async () => {
    render(renderModal(null, { hideDocs: true }));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    expect(screen.queryByRole('note', { name: 'Learn more' })).toBeNull();
  });
});

describe('ImportTokensModal file preview', () => {
  const NO_ROWS =
    'No rows could be read from this file. Check the columns against the template.';

  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    apiGetMock.mockResolvedValue({ data: {} });
  });

  const upload = (body, name) => {
    const input = document.querySelector('input[type="file"]');
    const file = new File([body], name, { type: 'text/plain' });
    // jsdom's File has no text(); browsers do.
    file.text = () => Promise.resolve(body);
    fireEvent.change(input, { target: { files: [file] } });
  };

  it.each([
    ['wrong columns', 'foo,bar\n1,2\n', 'wrong.csv'],
    ['an empty csv', '', 'empty.csv'],
    ['an empty json array', '[]', 'empty.json'],
  ])('explains an unreadable file: %s', async (_label, body, name) => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(body, name);
    expect(await screen.findByText(NO_ROWS)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Import 0 selected/ })
    ).toBeDisabled();
  });

  it('shows the preview without the message for a readable file', async () => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(
      'name,category,type,expiresAt\nweb,cert,ssl_cert,2030-01-01\n',
      'ok.csv'
    );
    expect(
      await screen.findByText('Detected 1 valid rows')
    ).toBeInTheDocument();
    expect(screen.queryByText(NO_ROWS)).toBeNull();
  });

  it('joins the sections of a row with a comma and a space', async () => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(
      JSON.stringify([
        {
          name: 'web',
          category: 'cert',
          type: 'ssl_cert',
          expiresAt: '2030-01-01',
          section: ['prod', 'public'],
        },
      ]),
      'sections.json'
    );
    expect(await screen.findByText('prod, public')).toBeInTheDocument();
    expect(screen.queryByText('prodpublic')).toBeNull();
  });

  it('lists the rows left out and what each one is missing', async () => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(
      [
        'name,category,type,expiresAt',
        ',cert,ssl_cert,2030-01-01',
        'ok,cert,ssl_cert,2030-01-01',
        'nodate,cert,ssl_cert,',
      ].join('\n'),
      'partial.csv'
    );
    expect(
      await screen.findByText('Detected 1 valid rows')
    ).toBeInTheDocument();
    const note = screen.getByTestId('skipped-rows-note');
    expect(note).toHaveTextContent('2 rows left out');
    expect(note).toHaveTextContent('row 2 (name)');
    expect(note).toHaveTextContent('row 4 (expiresAt)');
  });

  it('numbers rows of a JSON file from 1 because it has no header row', async () => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(
      JSON.stringify([
        {
          name: '',
          category: 'cert',
          type: 'ssl_cert',
          expiresAt: '2030-01-01',
        },
        {
          name: 'ok',
          category: 'cert',
          type: 'ssl_cert',
          expiresAt: '2030-01-01',
        },
      ]),
      'items.json'
    );
    expect(
      await screen.findByText('Detected 1 valid rows')
    ).toBeInTheDocument();
    expect(screen.getByTestId('skipped-rows-note')).toHaveTextContent(
      'row 1 (name)'
    );
  });

  it('refuses a file with more than 5000 rows and says why', async () => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    const lines = ['name,category,type,expiresAt'];
    for (let i = 0; i < 5001; i += 1) {
      lines.push(`a${i},cert,ssl_cert,2030-01-01`);
    }
    upload(lines.join('\n'), 'big.csv');
    expect(
      await screen.findByText(/This file has 5001 rows\. The limit is 5000/)
    ).toBeInTheDocument();
    expect(screen.queryByText(/Detected/)).toBeNull();
  });

  it('refuses a file over 5 MB before reading it', async () => {
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    const input = document.querySelector('input[type="file"]');
    const file = new File(['x'], 'huge.csv', { type: 'text/csv' });
    Object.defineProperty(file, 'size', { value: 6 * 1024 * 1024 });
    fireEvent.change(input, { target: { files: [file] } });
    expect(
      await screen.findByText(/This file is 6\.0 MB\. The limit is 5 MB/)
    ).toBeInTheDocument();
  });

  it('sends rows the preview flagged as existing straight to update', async () => {
    tokenAPI.createToken.mockReset().mockResolvedValue({ id: 1 });
    integrationAPI.checkDuplicates.mockResolvedValueOnce({
      duplicate_count: 1,
      duplicates: [{ name: 'dup', location: null }],
    });
    window.history.pushState({}, '', '/?workspace=ws-1');
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(
      [
        'name,category,type,expiresAt',
        'dup,cert,ssl_cert,2030-01-01',
        'fresh,cert,ssl_cert,2030-01-01',
      ].join('\n'),
      'dups.csv'
    );
    expect(
      await screen.findByText(/1 token already exists/)
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Import 2 selected/ }));
    await waitFor(() => expect(tokenAPI.createToken).toHaveBeenCalledTimes(2));
    const calls = tokenAPI.createToken.mock.calls.map(c => c[0]);
    expect(calls.find(c => c.name === 'dup').confirm_duplicate).toBe(true);
    expect(
      calls.find(c => c.name === 'fresh').confirm_duplicate
    ).toBeUndefined();
    window.history.pushState({}, '', '/');
  });

  it('reports a failed row by its line in the file, not its position among kept rows', async () => {
    tokenAPI.createToken.mockRejectedValueOnce(new Error('Invalid date'));
    window.history.pushState({}, '', '/?workspace=ws-1');
    render(renderModal(null));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    upload(
      [
        'name,category,type,expiresAt',
        ',cert,ssl_cert,2030-01-01',
        'bad,cert,ssl_cert,2030-01-01',
      ].join('\n'),
      'lines.csv'
    );
    fireEvent.click(
      await screen.findByRole('button', { name: /Import 1 selected/ })
    );
    expect(await screen.findByText('Invalid date')).toBeInTheDocument();
    const row = screen.getByText('Invalid date').closest('tr');
    expect(row).toHaveTextContent('3');
    window.history.pushState({}, '', '/');
  });
});

describe('ImportTokensModal workspace resolution', () => {
  const CSV = 'name,category,type,expiresAt\nweb,cert,ssl_cert,2030-01-01\n';

  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    apiGetMock.mockResolvedValue({ data: {} });
    tokenAPI.createToken.mockReset().mockResolvedValue({ id: 1 });
    window.history.pushState({}, '', '/');
  });

  afterEach(() => {
    wsCtx.id = 'ws-1';
    window.history.pushState({}, '', '/');
  });

  const importCsv = async extraProps => {
    render(renderModal(null, extraProps));
    await screen.findByText(/CSV, XLSX, JSON or YAML/);
    const input = document.querySelector('input[type="file"]');
    const file = new File([CSV], 'ok.csv', { type: 'text/plain' });
    file.text = () => Promise.resolve(CSV);
    fireEvent.change(input, { target: { files: [file] } });
    fireEvent.click(
      await screen.findByRole('button', { name: /Import 1 selected/ })
    );
  };

  it('imports into the active workspace when the URL has no workspace', async () => {
    wsCtx.id = 'ws-ctx';
    await importCsv();
    await waitFor(() => expect(tokenAPI.createToken).toHaveBeenCalledTimes(1));
    expect(tokenAPI.createToken.mock.calls[0][0].workspace_id).toBe('ws-ctx');
    expect(
      screen.queryByText('Please select a workspace first.')
    ).not.toBeInTheDocument();
  });

  it('prefers the URL workspace over the active workspace', async () => {
    wsCtx.id = 'ws-ctx';
    window.history.pushState({}, '', '/?workspace=ws-url');
    await importCsv();
    await waitFor(() => expect(tokenAPI.createToken).toHaveBeenCalledTimes(1));
    expect(tokenAPI.createToken.mock.calls[0][0].workspace_id).toBe('ws-url');
  });

  it('uses the setup guide workspace when embedded', async () => {
    wsCtx.id = 'ws-ctx';
    await importCsv({ hideDocs: true, embeddedWorkspaceId: 'ws-guide' });
    await waitFor(() => expect(tokenAPI.createToken).toHaveBeenCalledTimes(1));
    expect(tokenAPI.createToken.mock.calls[0][0].workspace_id).toBe('ws-guide');
  });

  it('asks for a workspace only when none can be determined', async () => {
    wsCtx.id = null;
    await importCsv();
    expect(
      await screen.findByText('Please select a workspace first.')
    ).toBeInTheDocument();
    expect(tokenAPI.createToken).not.toHaveBeenCalled();
  });
});
