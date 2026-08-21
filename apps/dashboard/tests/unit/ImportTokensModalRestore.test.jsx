import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import ImportTokensModal from '../../src/components/ImportTokensModal.jsx';

const {
  apiGetMock,
  gitlabFormProps,
  githubFormProps,
} = vi.hoisted(() => ({
  apiGetMock: vi.fn(),
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
    delete: vi.fn().mockResolvedValue({ data: {} }),
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
    return <div>gitlab-form</div>;
  }),
}));
vi.mock('../../src/components/imports/ImportGitHubForm', () => ({
  default: React.forwardRef(function GitHubMock(props, _ref) {
    githubFormProps.push(props.initialScanParams);
    return <div>github-form</div>;
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
    vi.clearAllMocks();
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
      expect(sp === null || sp === undefined || sp.baseUrl !== GITLAB_SELF_HOSTED).toBe(
        true
      );
    }
  });
});
