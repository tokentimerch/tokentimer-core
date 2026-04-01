import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import ImportVaultForm from '../../src/components/imports/ImportVaultForm.jsx';
import ImportAWSForm from '../../src/components/imports/ImportAWSForm.jsx';

const {
  vaultScanMock,
  vaultImportMock,
  awsDetectRegionsMock,
  awsScanMock,
  integrationImportMock,
  checkDuplicatesMock,
} = vi.hoisted(() => ({
  vaultScanMock: vi.fn(),
  vaultImportMock: vi.fn(),
  awsDetectRegionsMock: vi.fn(),
  awsScanMock: vi.fn(),
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

    fireEvent.click(screen.getByRole('button', { name: /Scan us-east-1/i }));
    await waitFor(() => expect(awsScanMock).toHaveBeenCalledTimes(1));
    expect(onScanSuccess).toHaveBeenCalledWith('aws');

    fireEvent.click(screen.getByRole('button', { name: /select-first-1/i }));
    await ref.current.importSelected();

    await waitFor(() => expect(integrationImportMock).toHaveBeenCalledTimes(1));
    expect(onImportComplete).toHaveBeenCalled();
  });
});
