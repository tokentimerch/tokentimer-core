import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  render,
  waitFor,
  screen,
  fireEvent,
  cleanup,
  act,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import ImportTokensModal from '../../src/components/ImportTokensModal.jsx';
import apiClient, { gitlabAPI, githubAPI } from '../../src/utils/apiClient';

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
  gitlabAPI: { scan: vi.fn() },
  githubAPI: { scan: vi.fn() },
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
// Real provider forms inside the composed modal exceed five seconds under
// full-suite V8 coverage. Keep the complete journeys and their assertions.
const AUTO_SYNC_FLOW_TIMEOUT = 20000;

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

describe.each(['gitlab', 'github'])(
  '%s auto-sync verification with real provider forms',
  provider => {
    let configs;
    const scan = () =>
      provider === 'gitlab' ? gitlabAPI.scan : githubAPI.scan;
    const result = { items: [], summary: [], scan_id: 'fixture-scan' };
    const enable = () =>
      screen.getByRole('button', { name: 'Enable auto-sync', exact: true });
    const scanButton = () =>
      screen.getByRole('button', { name: 'Scan', exact: true });
    async function addAnother() {
      render(
        renderModal({
          provider,
          integrationSubTab: 'manage',
          autoSyncConfigId: 'existing-1',
        })
      );
      fireEvent.click(
        await screen.findByRole('button', { name: 'Add another', exact: true })
      );
      const secret = await screen.findByPlaceholderText(/Paste token/);
      fireEvent.change(secret, { target: { value: 'synthetic-one' } });
      return secret;
    }
    beforeEach(() => {
      cleanup();
      vi.clearAllMocks();
      localStorage.clear();
      wsCtx.id = 'ws-1';
      configs = [2, 3].map((n, i) => ({
        id: `existing-${i + 1}`,
        provider,
        name: ` ${provider.toUpperCase()}   ${n} `,
        frequency: 'daily',
        scan_params: {
          baseUrl:
            provider === 'gitlab'
              ? 'https://gitlab.com'
              : 'https://api.github.com',
        },
      }));
      scan().mockReset().mockResolvedValue(result);
      apiGetMock.mockImplementation(url =>
        Promise.resolve({
          data: {
            metric_label_policy: {
              extra_labels: ['asset_name', 'project', 'group'],
            },
            items: String(url).endsWith('/auto-sync') ? configs : [],
          },
        })
      );
      apiClient.post.mockReset().mockImplementation((_url, body) => {
        const created = { ...body, id: 'created-config' };
        configs.push(created);
        return Promise.resolve({ data: created });
      });
    });
    afterEach(cleanup);
    it('allows an empty scan to enable a second same-URL configuration and selects the created ID', async () => {
      await addAnother();
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      fireEvent.click(enable());
      await screen.findByRole('button', {
        name: 'Enable Auto-Sync',
        exact: true,
      });
      fireEvent.click(
        screen.getByRole('button', { name: 'Enable Auto-Sync', exact: true })
      );
      await waitFor(() =>
        expect(apiClient.post).toHaveBeenCalledWith(
          '/api/v1/workspaces/ws-1/auto-sync',
          expect.objectContaining({
            provider,
            credentials: expect.objectContaining({ token: 'synthetic-one' }),
          })
        )
      );
      await waitFor(() =>
        expect(
          screen.getByRole('combobox', { name: 'Configuration' })
        ).toHaveValue('created-config')
      );
      fireEvent.click(
        screen.getByRole('button', { name: 'Add another', exact: true })
      );
      expect(enable()).toBeDisabled();
    }, AUTO_SYNC_FLOW_TIMEOUT);
    it('requires a fresh scan after credentials or scope change and after failed or stale scans', async () => {
      const secret = await addAnother();
      scan().mockResolvedValue({
        ...result,
        items: [{ name: 'fixture', type: 'api_key' }],
      });
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      fireEvent.change(secret, { target: { value: 'synthetic-two' } });
      expect(enable()).toBeDisabled();
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      const url = screen.getByPlaceholderText(
        provider === 'gitlab' ? 'https://gitlab.com' : 'https://api.github.com'
      );
      const originalUrl = url.value;
      fireEvent.change(url, { target: { value: '' } });
      expect(enable()).toBeDisabled();
      fireEvent.change(url, { target: { value: originalUrl } });
      expect(enable()).toBeDisabled();
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      fireEvent.click(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      );
      expect(enable()).toBeDisabled();
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      scan().mockRejectedValueOnce(new Error('Synthetic scan failure'));
      fireEvent.click(scanButton());
      await screen.findAllByText(/Synthetic scan failure/);
      expect(enable()).toBeDisabled();
      let finish;
      scan().mockImplementationOnce(
        () =>
          new Promise(resolve => {
            finish = resolve;
          })
      );
      fireEvent.click(scanButton());
      await waitFor(() => expect(finish).toBeTypeOf('function'));
      fireEvent.change(secret, { target: { value: 'synthetic-three' } });
      await act(async () => {
        finish(result);
        await Promise.resolve();
      });
      await waitFor(() => expect(scanButton()).toBeEnabled());
      expect(enable()).toBeDisabled();
      scan().mockResolvedValue(result);
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      fireEvent.click(enable());
      const confirm = await screen.findByRole('button', {
        name: 'Enable Auto-Sync',
        exact: true,
      });
      fireEvent.change(secret, {
        target: { value: 'changed-after-confirmation-opened' },
      });
      fireEvent.click(confirm);
      expect(apiClient.post).not.toHaveBeenCalled();
    }, AUTO_SYNC_FLOW_TIMEOUT);
    it('persists selected metric labels without another scan and clears them for the next configuration', async () => {
      await addAnother();
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      fireEvent.click(
        screen.getByRole('button', { name: 'Auto-sync metrics', exact: true })
      );
      fireEvent.click(
        await screen.findByRole('checkbox', {
          name: 'Expose additional auto-sync metrics',
        })
      );
      fireEvent.change(
        screen.getByRole('textbox', { name: 'Monitoring group label' }),
        { target: { value: 'critical' } }
      );
      fireEvent.click(
        screen.getByRole('checkbox', { name: 'Token / asset name' })
      );
      fireEvent.click(enable());
      fireEvent.click(
        await screen.findByRole('button', {
          name: 'Enable Auto-Sync',
          exact: true,
        })
      );
      await waitFor(() =>
        expect(apiClient.post).toHaveBeenCalledWith(
          '/api/v1/workspaces/ws-1/auto-sync',
          expect.objectContaining({
            metrics_settings: {
              enabled: true,
              labels: [
                'configuration_name',
                'monitoring_group',
                'kind',
                'asset_name',
              ],
              monitoring_group: 'critical',
            },
          })
        )
      );
      await waitFor(() =>
        expect(
          screen.getByRole('combobox', { name: 'Configuration' })
        ).toHaveValue('created-config')
      );
      fireEvent.click(
        screen.getByRole('button', { name: 'Auto-sync metrics', exact: true })
      );
      await waitFor(() =>
        expect(
          screen.getAllByRole('textbox', { name: 'Monitoring group label' })
        ).toHaveLength(1)
      );
      expect(
        screen.getByRole('textbox', { name: 'Monitoring group label' })
      ).toHaveValue('critical');
      expect(scan()).toHaveBeenCalledTimes(1);
      fireEvent.click(
        screen.getByRole('button', { name: 'Add another', exact: true })
      );
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      expect(
        screen.getByRole('button', { name: 'Auto-sync metrics', exact: true })
      ).toHaveAttribute('aria-expanded', 'false');
      fireEvent.click(
        screen.getByRole('button', { name: 'Auto-sync metrics', exact: true })
      );
      expect(
        await screen.findByRole('checkbox', {
          name: 'Expose additional auto-sync metrics',
        })
      ).not.toBeChecked();
      expect(
        screen.getByRole('textbox', { name: 'Monitoring group label' })
      ).toHaveValue('');
    });
    it('allocates an unused configuration name despite deletions, whitespace and case', async () => {
      await addAnother();
      scan().mockResolvedValue({ ...result, items: [{ name: 'fixture' }] });
      fireEvent.click(scanButton());
      await waitFor(() => expect(enable()).toBeEnabled());
      fireEvent.click(enable());
      await screen.findByRole('button', {
        name: 'Enable Auto-Sync',
        exact: true,
      });
      const input = screen.getByRole('textbox', { name: 'Configuration name' });
      expect(input).toHaveValue(`${provider} 4`);
    }, AUTO_SYNC_FLOW_TIMEOUT);
  }
);
