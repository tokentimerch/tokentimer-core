import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import ImportVaultForm from '../../src/components/imports/ImportVaultForm.jsx';
import ImportAWSForm from '../../src/components/imports/ImportAWSForm.jsx';
import ImportGCPForm from '../../src/components/imports/ImportGCPForm.jsx';
import ImportAzureForm from '../../src/components/imports/ImportAzureForm.jsx';

const {
  vaultScanMock,
  vaultImportMock,
  awsDetectRegionsMock,
  awsScanMock,
  gcpScanMock,
  azureScanMock,
  integrationImportMock,
  checkDuplicatesMock,
} = vi.hoisted(() => ({
  vaultScanMock: vi.fn(),
  vaultImportMock: vi.fn(),
  awsDetectRegionsMock: vi.fn(),
  awsScanMock: vi.fn(),
  gcpScanMock: vi.fn(),
  azureScanMock: vi.fn(),
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
    expect(errorText.textContent).not.toMatch(/^Compute Engine SSL certificates:/);
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
    fireEvent.change(
      screen.getByPlaceholderText('Directory (tenant) ID or domain'),
      { target: { value: 'tenant-id' } }
    );
    fireEvent.change(
      screen.getByPlaceholderText('App registration client ID'),
      { target: { value: 'client-id' } }
    );
    fireEvent.change(
      screen.getByPlaceholderText('App registration client secret'),
      { target: { value: 'client-secret' } }
    );
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

    expect(screen.queryByRole('button', { name: 'Scan' })).not.toBeInTheDocument();
    expect(ref.current.getCredentials().credentials).toEqual({});
    fireEvent.click(screen.getByRole('button', { name: 'Replace credentials' }));
    fireEvent.click(
      screen.getByRole('radio', { name: 'Entra app (client credentials)' })
    );
    fireEvent.change(
      screen.getByPlaceholderText('https://my-vault.vault.azure.net'),
      { target: { value: 'https://my-vault.vault.azure.net' } }
    );
    fireEvent.change(
      screen.getByPlaceholderText('Directory (tenant) ID or domain'),
      { target: { value: 'tenant-id' } }
    );
    fireEvent.change(
      screen.getByPlaceholderText('App registration client ID'),
      { target: { value: 'client-id' } }
    );
    fireEvent.change(
      screen.getByPlaceholderText('App registration client secret'),
      { target: { value: 'rotated-secret' } }
    );
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
    fireEvent.click(screen.getByRole('button', { name: 'Replace credentials' }));
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
