import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import ImportVaultForm from '../../src/components/imports/ImportVaultForm.jsx';
import ImportAWSForm from '../../src/components/imports/ImportAWSForm.jsx';
import ImportGCPForm from '../../src/components/imports/ImportGCPForm.jsx';
import ImportAzureForm from '../../src/components/imports/ImportAzureForm.jsx';
import ImportGitHubForm from '../../src/components/imports/ImportGitHubForm.jsx';
import ImportGitLabForm from '../../src/components/imports/ImportGitLabForm.jsx';
import { IMPORT_DOCS } from '../../src/utils/docsUrls.js';

const {
  vaultScanMock,
  vaultImportMock,
  awsDetectRegionsMock,
  awsScanMock,
  gcpScanMock,
  azureScanMock,
  githubScanMock,
  gitlabScanMock,
  integrationImportMock,
  checkDuplicatesMock,
} = vi.hoisted(() => ({
  vaultScanMock: vi.fn(),
  vaultImportMock: vi.fn(),
  awsDetectRegionsMock: vi.fn(),
  awsScanMock: vi.fn(),
  gcpScanMock: vi.fn(),
  azureScanMock: vi.fn(),
  githubScanMock: vi.fn(),
  gitlabScanMock: vi.fn(),
  integrationImportMock: vi.fn(),
  checkDuplicatesMock: vi.fn(),
}));

vi.mock('../../src/components/IntegrationImportTable', () => ({
  default: ({ items, onToggleRow }) => (
    <button
      onClick={() => onToggleRow?.(0)}
    >{`select-first-${items?.length || 0}`}</button>
  ),
}));

vi.mock('../../src/components/BulkIntegrationAssignment', () => ({
  default: () => <div>bulk-assignment</div>,
}));

vi.mock('../../src/utils/logger', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

vi.mock('../../src/utils/apiClient', async () => {
  const actual = await vi.importActual('../../src/utils/apiClient');
  return {
    ...actual,
    vaultAPI: {
      scan: vaultScanMock,
      import: vaultImportMock,
    },
    awsAPI: {
      detectRegions: awsDetectRegionsMock,
      scan: awsScanMock,
    },
    gcpAPI: {
      scan: gcpScanMock,
    },
    azureAPI: {
      scan: azureScanMock,
    },
    githubAPI: { scan: githubScanMock },
    gitlabAPI: { scan: gitlabScanMock },
    integrationAPI: {
      checkDuplicates: checkDuplicatesMock,
      import: integrationImportMock,
    },
  };
});

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

describe('Dashboard import forms', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkDuplicatesMock.mockResolvedValue({
      duplicate_count: 0,
      duplicates: [],
    });
  });

  it.each([
    ['AWS', ImportAWSForm, 'Secret Access Key'],
    ['Azure Key Vault', ImportAzureForm, 'Key Vault URL'],
    ['GCP', ImportGCPForm, 'Certificates'],
    ['Vault', ImportVaultForm, 'Scan PKI'],
  ])(
    '%s restores saved rules below scope selectors and serializes an intentional clear',
    async (_name, Form, scopeLabel) => {
      const ref = React.createRef();
      const filterRules = [
        {
          action: 'exclude',
          field: 'description',
          matchType: 'exact',
          value: 'ignore-me',
        },
      ];
      const scanParams = { filterRules };
      renderWithProviders(
        <Form
          ref={ref}
          workspaceId='ws-1'
          onImportComplete={vi.fn()}
          onError={vi.fn()}
          onScanSuccess={vi.fn()}
          onSelectionChange={vi.fn()}
          contactGroups={[]}
          initialScanParams={scanParams}
          initialAutoSyncScanParams={scanParams}
          updateQuotaFromResponse={() => true}
          refreshIntegrationQuota={vi.fn()}
          isQuotaExceededError={() => false}
          extractQuotaFromError={() => false}
          formatQuotaError={error => error.message}
        />
      );
      await screen.findByDisplayValue('ignore-me');
      expect(
        screen
          .getByText(scopeLabel)
          .compareDocumentPosition(screen.getByText('Filter rules')) &
          Node.DOCUMENT_POSITION_FOLLOWING
      ).toBeTruthy();
      expect(ref.current.getCredentials().scanParams.filterRules).toEqual(
        filterRules
      );
      fireEvent.click(screen.getByRole('button', { name: 'Remove rule' }));
      expect(ref.current.getCredentials().scanParams.filterRules).toEqual([]);
    }
  );

  it.each([
    ['AWS', ImportAWSForm, awsScanMock],
    ['Azure', ImportAzureForm, azureScanMock],
    ['GCP', ImportGCPForm, gcpScanMock],
  ])(
    '%s shows zero-match filter feedback and clears it on rule edits',
    async (provider, Form, scan) => {
      scan.mockResolvedValue({
        items: [],
        summary: [],
        scan_id: 'empty',
        filterSummary: { matchedCount: 0, excludedCount: 4 },
      });
      awsDetectRegionsMock.mockResolvedValue({
        regionsWithSecrets: ['us-east-1'],
        regionsWithCertificates: [],
        iam: { keysCount: 0 },
      });
      renderWithProviders(
        <Form
          workspaceId='ws-1'
          onError={vi.fn()}
          onScanSuccess={vi.fn()}
          onImportComplete={vi.fn()}
          onSelectionChange={vi.fn()}
          contactGroups={[]}
          autoSyncTokenPlaceholder='scan-token'
          updateQuotaFromResponse={() => true}
        />
      );
      if (provider === 'AWS') {
        fireEvent.change(screen.getByPlaceholderText('AKIAIOSFODNN7EXAMPLE'), {
          target: { value: 'key' },
        });
        fireEvent.change(screen.getByPlaceholderText('scan-token'), {
          target: { value: 'secret' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Detect Regions' }));
        fireEvent.click(
          await screen.findByRole('button', { name: /Scan us-east-1/ })
        );
      } else {
        const placeholder =
          provider === 'Azure'
            ? 'https://my-vault.vault.azure.net'
            : 'my-project-123';
        fireEvent.change(screen.getByPlaceholderText(placeholder), {
          target: {
            value:
              provider === 'Azure'
                ? 'https://my-vault.vault.azure.net'
                : 'my-project',
          },
        });
        fireEvent.change(screen.getByPlaceholderText('scan-token'), {
          target: { value: 'access-token' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
      }
      expect(await screen.findByText('0 matched')).toBeInTheDocument();
      expect(screen.getByText('4 excluded by rules')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
      expect(
        screen.queryByRole('status', { name: 'Filter results' })
      ).toBeNull();
    }
  );

  it.each([
    [
      'GitHub',
      ImportGitHubForm,
      githubScanMock,
      'https://api.github.com',
      'Paste token',
    ],
    [
      'GitLab',
      ImportGitLabForm,
      gitlabScanMock,
      'https://gitlab.com',
      'Paste token (read_api)',
    ],
  ])(
    '%s excludes an incomplete type from cleanup',
    async (_name, Form, scan, url, token) => {
      scan.mockResolvedValue({
        items: [],
        scan_id: 'synthetic-scan',
        summary: [{ type: 'tokens', found: 0, complete: false }],
      });
      renderWithProviders(
        <Form
          workspaceId='ws-1'
          onError={vi.fn()}
          borderColor='gray.200'
          helpTextColor='gray.500'
        />
      );
      fireEvent.change(screen.getByPlaceholderText(url), {
        target: { value: url },
      });
      fireEvent.change(screen.getByPlaceholderText(token), {
        target: { value: 'synthetic-token' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
      expect(
        await screen.findByText(
          /item type if any required scope failed or was incomplete/
        )
      ).toBeInTheDocument();
      fireEvent.click(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      );
      expect(
        screen.getByText(/Only fully scanned item types are eligible/)
      ).toBeInTheDocument();
    }
  );

  it('ImportVaultForm handles scan success and import callback contract', async () => {
    const onError = vi.fn();
    const onScanSuccess = vi.fn();
    const onImportComplete = vi.fn();
    const ref = React.createRef();

    vaultScanMock.mockResolvedValue({
      items: [
        {
          name: 'vault-token-1',
          expiration: '2030-01-01',
          category: 'general',
          type: 'other',
          location: 'kv/app',
        },
      ],
      summary: [{ mount: 'kv', type: 'kv_v2', found: 1 }],
    });
    vaultImportMock.mockResolvedValue({ created_count: 1, updated_count: 0 });

    renderWithProviders(
      <ImportVaultForm
        ref={ref}
        workspaceId='ws-1'
        onImportComplete={onImportComplete}
        onError={onError}
        onScanSuccess={onScanSuccess}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(
      screen.getByPlaceholderText('https://vault.your-org.com'),
      {
        target: { value: 'https://vault.example.com' },
      }
    );
    fireEvent.change(screen.getByPlaceholderText('token'), {
      target: { value: 'vault-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() => expect(vaultScanMock).toHaveBeenCalledTimes(1));
    expect(onScanSuccess).toHaveBeenCalledWith('vault');

    fireEvent.click(screen.getByRole('button', { name: /select-first-1/i }));
    await ref.current.importSelected();

    await waitFor(() => expect(vaultImportMock).toHaveBeenCalledTimes(1));
    expect(onImportComplete).toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(null);
  });

  it('ImportVaultForm scans with exclusive AppRole credentials', async () => {
    vaultScanMock.mockResolvedValue({ items: [], summary: [], mounts: [] });

    renderWithProviders(
      <ImportVaultForm
        workspaceId='ws-approle'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(
      screen.getByPlaceholderText('https://vault.your-org.com'),
      { target: { value: 'https://vault.example.com' } }
    );
    fireEvent.click(screen.getByRole('radio', { name: 'AppRole' }));
    fireEvent.change(screen.getByPlaceholderText('AppRole role ID'), {
      target: { value: 'role-uuid' },
    });
    fireEvent.change(screen.getByPlaceholderText('AppRole secret ID'), {
      target: { value: 'secret-uuid' },
    });
    fireEvent.change(
      screen.getByPlaceholderText('Vault Enterprise namespace'),
      { target: { value: 'ops' } }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() => expect(vaultScanMock).toHaveBeenCalledTimes(1));
    expect(vaultScanMock.mock.calls[0][0]).toMatchObject({
      workspaceId: 'ws-approle',
      address: 'https://vault.example.com',
      roleId: 'role-uuid',
      secretId: 'secret-uuid',
      namespace: 'ops',
    });
    expect(vaultScanMock.mock.calls[0][0].token).toBeUndefined();
  });

  it('ImportVaultForm warns when a scan has per-path permission errors', async () => {
    vaultScanMock.mockResolvedValue({
      items: [
        {
          name: 'readable',
          expiration: '2030-01-01',
          category: 'general',
          type: 'other',
          location: 'kv/app',
        },
      ],
      summary: [
        {
          mount: 'secret/',
          type: 'kv',
          found: 1,
          hasErrors: true,
          permissionDenied: true,
        },
      ],
    });

    renderWithProviders(
      <ImportVaultForm
        workspaceId='ws-perm'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(
      screen.getByPlaceholderText('https://vault.your-org.com'),
      { target: { value: 'https://vault.example.com' } }
    );
    fireEvent.change(screen.getByPlaceholderText('token'), {
      target: { value: 'vault-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() =>
      expect(
        screen.getByText(/permission denied on some paths/)
      ).toBeInTheDocument()
    );
    expect(screen.queryByText(/^found 1$/)).toBeNull();
  });

  it('ImportVaultForm surfaces quota exceeded UI state', async () => {
    const onError = vi.fn();
    vaultScanMock.mockRejectedValue(new Error('quota exceeded from backend'));

    renderWithProviders(
      <ImportVaultForm
        workspaceId='ws-2'
        onImportComplete={vi.fn()}
        onError={onError}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => true}
        formatQuotaError={() => 'Integration quota exceeded'}
        extractQuotaFromError={() => true}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(
      screen.getByPlaceholderText('https://vault.your-org.com'),
      {
        target: { value: 'https://vault.example.com' },
      }
    );
    fireEvent.change(screen.getByPlaceholderText('token'), {
      target: { value: 'vault-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() =>
      expect(onError).toHaveBeenCalledWith('Integration quota exceeded')
    );
  });

  it('ImportAWSForm supports scan and import payload composition', async () => {
    const onError = vi.fn();
    const onScanSuccess = vi.fn();
    const onImportComplete = vi.fn();
    const ref = React.createRef();

    awsDetectRegionsMock.mockResolvedValue({
      regionsWithSecrets: ['us-east-1'],
      regionsWithCertificates: [],
      iam: { keysCount: 0 },
    });
    awsScanMock.mockResolvedValue({
      items: [
        {
          name: 'aws-secret-1',
          expiration: '2031-01-01',
          category: 'key_secret',
          type: 'secret',
          location: 'aws/secretsmanager/us-east-1',
        },
      ],
      summary: [{ type: 'secrets_manager', found: 1 }],
    });
    integrationImportMock.mockResolvedValue({
      created_count: 1,
      updated_count: 0,
    });

    renderWithProviders(
      <ImportAWSForm
        ref={ref}
        workspaceId='ws-aws'
        onImportComplete={onImportComplete}
        onError={onError}
        onScanSuccess={onScanSuccess}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='secret'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(screen.getByPlaceholderText('AKIAIOSFODNN7EXAMPLE'), {
      target: { value: 'AKIATEST' },
    });
    fireEvent.change(screen.getByPlaceholderText('secret'), {
      target: { value: 'secret-value' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Detect Regions' }));
    await waitFor(() => expect(awsDetectRegionsMock).toHaveBeenCalledTimes(1));
    expect(awsDetectRegionsMock).toHaveBeenCalledWith(
      expect.objectContaining({ workspaceId: 'ws-aws' })
    );

    fireEvent.click(screen.getByRole('button', { name: /Scan us-east-1/i }));
    await waitFor(() => expect(awsScanMock).toHaveBeenCalledTimes(1));
    expect(onScanSuccess).toHaveBeenCalledWith('aws');

    fireEvent.click(screen.getByRole('button', { name: /select-first-1/i }));
    await ref.current.importSelected();

    await waitFor(() => expect(integrationImportMock).toHaveBeenCalledTimes(1));
    expect(onImportComplete).toHaveBeenCalled();
  });

  it('ImportGCPForm scans secrets by default and can scan certificates only', async () => {
    const onError = vi.fn();
    const onScanSuccess = vi.fn();
    gcpScanMock.mockResolvedValue({
      items: [{ name: 'secret-1', location: 'gcp:proj/secrets/secret-1' }],
      summary: [{ type: 'secrets', found: 1 }],
      scan_id: 'scan-1',
    });

    renderWithProviders(
      <ImportGCPForm
        workspaceId='ws-gcp'
        onImportComplete={vi.fn()}
        onError={onError}
        onScanSuccess={onScanSuccess}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='gcp-token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    expect(
      screen.getByText(/Scans GCP Secret Manager and SSL certificates/)
    ).toBeInTheDocument();
    expect(
      screen.getByText('gcloud auth print-access-token')
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Scan certificates too/i)
    ).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Secrets' })).toBeChecked();
    expect(
      screen.getByRole('checkbox', { name: 'Certificates' })
    ).not.toBeChecked();

    fireEvent.change(screen.getByPlaceholderText('my-project-123'), {
      target: { value: 'my-project' },
    });
    fireEvent.change(screen.getByPlaceholderText('gcp-token'), {
      target: { value: 'ya29.token' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() => expect(gcpScanMock).toHaveBeenCalledTimes(1));
    expect(gcpScanMock).toHaveBeenCalledWith(
      expect.objectContaining({
        include: { secrets: true, certificates: false },
      })
    );
    expect(onScanSuccess).toHaveBeenCalledWith('gcp');

    fireEvent.click(screen.getByRole('checkbox', { name: 'Secrets' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Certificates' }));
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() => expect(gcpScanMock).toHaveBeenCalledTimes(2));
    expect(gcpScanMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        include: { secrets: false, certificates: true },
      })
    );
  });

  it('ImportGCPForm refuses to scan when neither secrets nor certificates is selected', async () => {
    const onError = vi.fn();
    renderWithProviders(
      <ImportGCPForm
        workspaceId='ws-gcp'
        onImportComplete={vi.fn()}
        onError={onError}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='gcp-token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('checkbox', { name: 'Secrets' }));
    expect(screen.getByRole('button', { name: 'Scan' })).toBeDisabled();
    expect(gcpScanMock).not.toHaveBeenCalled();
  });

  it('ImportGCPForm shows a failed certificate sub-scan as readable text', async () => {
    gcpScanMock.mockResolvedValue({
      items: [],
      summary: [
        {
          type: 'compute_ssl_certs',
          found: 0,
          complete: false,
          error:
            "Compute Engine SSL certificates: this project's Compute Engine API (compute.googleapis.com) is not enabled. Enable it in APIs & Services, then retry.",
        },
      ],
    });

    renderWithProviders(
      <ImportGCPForm
        workspaceId='ws-gcp'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='gcp-token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(screen.getByPlaceholderText('my-project-123'), {
      target: { value: 'my-project' },
    });
    fireEvent.change(screen.getByPlaceholderText('gcp-token'), {
      target: { value: 'ya29.token' },
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Certificates' }));
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() =>
      expect(
        screen.getByText('Compute Engine SSL certificates')
      ).toBeInTheDocument()
    );
    const failedBadge = screen.getByText('Failed');
    expect(failedBadge).toBeInTheDocument();
    expect(failedBadge.textContent).toBe('Failed');
    const errorText = screen.getByText(/not enabled/);
    expect(errorText.tagName).toBe('P');
    expect(errorText.textContent).not.toMatch(
      /^Compute Engine SSL certificates:/
    );
    expect(
      screen.queryByText(/Request failed with status code/)
    ).not.toBeInTheDocument();
  });

  it('ImportAzureForm scans with Entra client credentials', async () => {
    const onError = vi.fn();
    azureScanMock.mockResolvedValue({
      items: [
        {
          name: 'db-password',
          expiration: '2030-01-01',
          location: 'https://my-vault.vault.azure.net/secrets/db-password',
        },
      ],
      summary: [{ type: 'secrets', found: 1, complete: true }],
      scan_id: 'scan-1',
    });

    renderWithProviders(
      <ImportAzureForm
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={onError}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='Paste token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    fireEvent.change(
      screen.getByPlaceholderText('https://my-vault.vault.azure.net'),
      { target: { value: 'https://my-vault.vault.azure.net' } }
    );
    fireEvent.click(
      screen.getByRole('radio', { name: 'Entra app (client credentials)' })
    );
    fireEvent.change(screen.getByPlaceholderText('Tenant ID or domain'), {
      target: { value: 'tenant-id' },
    });
    fireEvent.change(screen.getByPlaceholderText('Client ID'), {
      target: { value: 'client-id' },
    });
    fireEvent.change(screen.getByPlaceholderText('Client secret'), {
      target: { value: 'client-secret' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }));

    await waitFor(() => expect(azureScanMock).toHaveBeenCalledTimes(1));
    expect(azureScanMock.mock.calls[0][0]).toMatchObject({
      workspaceId: 'ws-1',
      vaultUrl: 'https://my-vault.vault.azure.net',
      authMethod: 'client_credentials',
      tenantId: 'tenant-id',
      clientId: 'client-id',
      clientSecret: 'client-secret',
    });
    expect(azureScanMock.mock.calls[0][0].token).toBeUndefined();
  });

  it('ImportAzureForm Replace credentials keeps stored secrets off the PUT payload', () => {
    const ref = React.createRef();
    renderWithProviders(
      <ImportAzureForm
        ref={ref}
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='Paste token'
        autoSyncManageMode
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    expect(
      screen.queryByRole('button', { name: 'Scan' })
    ).not.toBeInTheDocument();
    expect(ref.current.getCredentials().credentials).toEqual({});
    fireEvent.click(
      screen.getByRole('button', { name: 'Replace credentials' })
    );
    fireEvent.click(
      screen.getByRole('radio', { name: 'Entra app (client credentials)' })
    );
    fireEvent.change(
      screen.getByPlaceholderText('https://my-vault.vault.azure.net'),
      { target: { value: 'https://my-vault.vault.azure.net' } }
    );
    fireEvent.change(screen.getByPlaceholderText('Tenant ID or domain'), {
      target: { value: 'tenant-id' },
    });
    fireEvent.change(screen.getByPlaceholderText('Client ID'), {
      target: { value: 'client-id' },
    });
    fireEvent.change(screen.getByPlaceholderText('Client secret'), {
      target: { value: 'rotated-secret' },
    });
    expect(ref.current.getCredentials().credentials).toMatchObject({
      authMethod: 'client_credentials',
      tenantId: 'tenant-id',
      clientId: 'client-id',
      clientSecret: 'rotated-secret',
      vaultUrl: 'https://my-vault.vault.azure.net',
    });
  });

  it('ImportAzureForm keeps Key Vault URL read-only until Replace credentials', () => {
    const ref = React.createRef();
    renderWithProviders(
      <ImportAzureForm
        ref={ref}
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='Paste token'
        autoSyncManageMode
        initialVaultUrl='https://old-vault.vault.azure.net'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );

    const vaultUrl = screen.getByPlaceholderText(
      'https://my-vault.vault.azure.net'
    );
    expect(vaultUrl).toBeDisabled();
    expect(vaultUrl).toHaveValue('https://old-vault.vault.azure.net');
    expect(ref.current.validateReplacement()).toBeNull();
    fireEvent.click(
      screen.getByRole('button', { name: 'Replace credentials' })
    );
    expect(vaultUrl).not.toBeDisabled();
    expect(ref.current.validateReplacement()).toBe('Access token is required');
    fireEvent.change(vaultUrl, {
      target: { value: 'https://new-vault.vault.azure.net' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel replace' }));
    expect(vaultUrl).toBeDisabled();
    expect(vaultUrl).toHaveValue('https://old-vault.vault.azure.net');
    expect(ref.current.getCredentials().credentials).toEqual({});
  });
});

describe('Import form docs panel', () => {
  it('ImportAWSForm shows a compact Learn more panel under the description', () => {
    renderWithProviders(
      <ImportAWSForm
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );
    const panel = screen.getByRole('note', { name: 'Learn more' });
    expect(
      within(panel).getByRole('link', { name: 'Importing from AWS' })
    ).toHaveAttribute('href', IMPORT_DOCS.aws);
  });

  it('ImportAWSForm renders no panel when the host shows its own', () => {
    renderWithProviders(
      <ImportAWSForm
        hideDocs
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );
    expect(screen.queryByRole('note', { name: 'Learn more' })).toBeNull();
  });

  it('ImportGitHubForm shows the panel, and hides it in manage mode', () => {
    const { unmount } = renderWithProviders(
      <ImportGitHubForm
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );
    expect(
      within(screen.getByRole('note', { name: 'Learn more' })).getByRole(
        'link',
        { name: 'Importing from GitHub' }
      )
    ).toHaveAttribute('href', IMPORT_DOCS.github);
    unmount();

    renderWithProviders(
      <ImportGitHubForm
        autoSyncManageMode
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );
    expect(screen.queryByRole('note', { name: 'Learn more' })).toBeNull();
  });

  it.each([
    ['ImportGitHubForm', ImportGitHubForm],
    ['ImportGitLabForm', ImportGitLabForm],
  ])('%s exposes the groups picked for the import', (_name, Form) => {
    const ref = React.createRef();
    renderWithProviders(
      <Form
        ref={ref}
        workspaceId='ws-1'
        onImportComplete={vi.fn()}
        onError={vi.fn()}
        onScanSuccess={vi.fn()}
        borderColor='gray.200'
        helpTextColor='gray.500'
        autoSyncTokenPlaceholder='token'
        updateQuotaFromResponse={() => true}
        refreshIntegrationQuota={vi.fn()}
        isQuotaExceededError={() => false}
        formatQuotaError={e => e?.message}
        extractQuotaFromError={() => false}
        contactGroups={[]}
        onSelectionChange={vi.fn()}
      />
    );
    expect(ref.current.getContactGroupIds()).toEqual([]);
  });
});
