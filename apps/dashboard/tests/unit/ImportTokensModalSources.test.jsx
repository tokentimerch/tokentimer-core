import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  screen,
  cleanup,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import ImportTokensModal from '../../src/components/ImportTokensModal.jsx';

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

function renderPlain(extraProps = {}) {
  return render(
    <ChakraProvider>
      <ImportTokensModal
        isOpen
        {...extraProps}
        onClose={vi.fn()}
        onImported={vi.fn()}
        openRequest={null}
        onOpenRequestHandled={vi.fn()}
      />
    </ChakraProvider>
  );
}

const pressed = name =>
  screen.getByRole('button', { name }).getAttribute('aria-pressed');

describe('ImportTokensModal source options', () => {
  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    apiGetMock.mockResolvedValue({ data: { items: [] } });
  });

  it('opens on File and lists every source by default', () => {
    renderPlain();
    expect(pressed('File import')).toBe('true');
    expect(
      screen.getByRole('button', { name: 'Public certificate PEM import' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Microsoft Entra ID' })
    ).toBeInTheDocument();
  });

  it('hides File and Certificate (PEM) and starts on the first service', () => {
    renderPlain({ hiddenSources: ['file', 'cert-pem'] });
    expect(screen.queryByRole('button', { name: 'File import' })).toBeNull();
    expect(
      screen.queryByRole('button', { name: 'Public certificate PEM import' })
    ).toBeNull();
    [
      'HashiCorp Vault',
      'GitLab',
      'GitHub',
      'AWS',
      'Azure Key Vault',
      'Microsoft Entra ID',
      'Google Cloud',
    ].forEach(name =>
      expect(screen.getByRole('button', { name })).toBeInTheDocument()
    );
    expect(pressed('HashiCorp Vault')).toBe('true');
  });

  it('starts on the source it is asked to', () => {
    renderPlain({ initialSource: 'github' });
    expect(pressed('GitHub')).toBe('true');
    expect(pressed('File import')).toBe('false');
  });

  it('falls back when the asked source is hidden', () => {
    renderPlain({ initialSource: 'file', hiddenSources: ['file'] });
    expect(screen.queryByRole('button', { name: 'File import' })).toBeNull();
    expect(pressed('HashiCorp Vault')).toBe('true');
  });
});
