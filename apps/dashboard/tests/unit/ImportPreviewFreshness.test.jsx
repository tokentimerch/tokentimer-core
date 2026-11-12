import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import ImportVaultForm from '../../src/components/imports/ImportVaultForm.jsx';
import ImportAWSForm from '../../src/components/imports/ImportAWSForm.jsx';
import ImportAzureForm from '../../src/components/imports/ImportAzureForm.jsx';
import ImportGCPForm from '../../src/components/imports/ImportGCPForm.jsx';

const mocks = vi.hoisted(() => ({
  vaultScan: vi.fn(),
  awsScan: vi.fn(),
  azureScan: vi.fn(),
  gcpScan: vi.fn(),
  listMounts: vi.fn(),
  detectRegions: vi.fn(),
  checkDuplicates: vi.fn(),
  import: vi.fn(),
}));
vi.mock('../../src/utils/apiClient', async () => ({
  ...(await vi.importActual('../../src/utils/apiClient')),
  vaultAPI: {
    scan: mocks.vaultScan,
    import: mocks.import,
    listMounts: mocks.listMounts,
  },
  awsAPI: { scan: mocks.awsScan, detectRegions: mocks.detectRegions },
  azureAPI: { scan: mocks.azureScan },
  gcpAPI: { scan: mocks.gcpScan },
  integrationAPI: {
    checkDuplicates: mocks.checkDuplicates,
    import: mocks.import,
  },
}));
vi.mock('../../src/components/IntegrationImportTable', () => ({
  default: ({ items, onToggleRow }) => (
    <button onClick={() => onToggleRow(0)}>select-first-{items.length}</button>
  ),
}));
vi.mock('../../src/components/BulkIntegrationAssignment', () => ({
  default: () => null,
}));
vi.mock('../../src/utils/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
}));
const preview = {
  items: [
    {
      name: 'Scoped credential',
      location: 'kv/app',
      type: 'other',
      category: 'general',
    },
  ],
  summary: [],
  scan_id: 'fresh-scan',
  filterSummary: { matchedCount: 1, excludedCount: 2 },
};
const providers = [
  ['Vault', ImportVaultForm, mocks.vaultScan, 'https://vault.your-org.com'],
  ['AWS', ImportAWSForm, mocks.awsScan, 'AKIAIOSFODNN7EXAMPLE'],
  [
    'Azure',
    ImportAzureForm,
    mocks.azureScan,
    'https://my-vault.vault.azure.net',
  ],
  ['GCP', ImportGCPForm, mocks.gcpScan, 'my-project-123'],
];
function renderForm(Form, props = {}) {
  const ref = React.createRef();
  const onError = vi.fn();
  const onSelectionChange = vi.fn();
  render(
    <ChakraProvider>
      <MemoryRouter>
        <Form
          ref={ref}
          workspaceId='ws-1'
          onError={onError}
          onSelectionChange={onSelectionChange}
          autoSyncTokenPlaceholder='scan-token'
          contactGroups={[]}
          updateQuotaFromResponse={() => true}
          {...props}
        />
      </MemoryRouter>
    </ChakraProvider>
  );
  return { ref, onError, onSelectionChange };
}
async function connect(provider, placeholder) {
  fireEvent.change(screen.getByPlaceholderText(placeholder), {
    target: { value: provider === 'AWS' ? 'key' : 'https://example.test' },
  });
  fireEvent.change(screen.getByPlaceholderText('scan-token'), {
    target: { value: 'secret' },
  });
  if (provider === 'AWS') {
    fireEvent.click(screen.getByRole('button', { name: 'Detect Regions' }));
    await screen.findByRole('button', { name: /Scan us-east-1/ });
  }
}
const scanButton = provider =>
  screen.getByRole('button', {
    name: provider === 'AWS' ? /Scan us-east-1/ : 'Scan',
  });
beforeEach(() => {
  vi.resetAllMocks();
  localStorage.clear();
  mocks.checkDuplicates.mockResolvedValue({
    duplicate_count: 0,
    duplicates: [],
  });
  mocks.detectRegions.mockResolvedValue({
    regionsWithSecrets: ['us-east-1'],
    regionsWithCertificates: [],
    iam: { keysCount: 0 },
  });
  for (const [, , scan] of providers) scan.mockResolvedValue(preview);
});

describe('Import preview freshness', () => {
  it.each(providers)(
    '%s clears selections and provenance on a raw rule edit and permits a rescan',
    async (provider, Form, scan, placeholder) => {
      const { ref, onSelectionChange } = renderForm(Form);
      await connect(provider, placeholder);
      fireEvent.click(scanButton(provider));
      await screen.findByText('1 matched');
      fireEvent.click(screen.getByRole('button', { name: 'select-first-1' }));
      await waitFor(() => expect(ref.current.getSelectedCount()).toBe(1));
      fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
      expect(ref.current.getSelectedCount()).toBe(0);
      expect(onSelectionChange).toHaveBeenLastCalledWith(0);
      expect(
        screen.queryByRole('status', { name: 'Filter results' })
      ).toBeNull();
      expect(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      ).toBeDisabled();
      await act(() => ref.current.importSelected());
      expect(mocks.import).not.toHaveBeenCalled();
      fireEvent.click(scanButton(provider));
      await screen.findByText('1 matched');
      fireEvent.click(screen.getByRole('button', { name: 'select-first-1' }));
      await waitFor(() => expect(ref.current.getSelectedCount()).toBe(1));
      fireEvent.click(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      );
      await act(() => ref.current.importSelected());
      expect(mocks.import).toHaveBeenCalledWith(
        expect.objectContaining({
          scanId: 'fresh-scan',
          cleanup: {
            enabled: true,
            provider: provider.toLowerCase(),
            scanId: 'fresh-scan',
          },
        })
      );
      expect(scan).toHaveBeenCalledTimes(2);
    }
  );

  it.each(providers)(
    '%s ignores a response after its rules change',
    async (provider, Form, scan, placeholder) => {
      let finish;
      scan.mockReturnValue(
        new Promise(resolve => {
          finish = resolve;
        })
      );
      const { ref } = renderForm(Form);
      await connect(provider, placeholder);
      fireEvent.click(scanButton(provider));
      fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
      await act(async () => {
        finish(preview);
      });
      expect(screen.queryByText('1 matched')).toBeNull();
      expect(ref.current.getSelectedCount()).toBe(0);
      await act(() => ref.current.importSelected());
      expect(mocks.import).not.toHaveBeenCalled();
    }
  );

  it.each(providers)(
    '%s ignores duplicate checks that finish after a credential edit',
    async (provider, Form, _scan, placeholder) => {
      let finish;
      mocks.checkDuplicates.mockReturnValue(
        new Promise(resolve => {
          finish = resolve;
        })
      );
      const { ref } = renderForm(Form);
      await connect(provider, placeholder);
      fireEvent.click(scanButton(provider));
      await screen.findByText('1 matched');
      fireEvent.change(screen.getByPlaceholderText('scan-token'), {
        target: { value: 'changed' },
      });
      await act(async () => {
        finish({ duplicate_count: 0, duplicates: [] });
      });
      expect(screen.queryByText('1 matched')).toBeNull();
      expect(ref.current.getSelectedCount()).toBe(0);
      expect(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      ).toBeDisabled();
    }
  );
});

describe('Restored Vault mount restrictions', () => {
  it.each([
    ['prod-only', ['prod/']],
    ['all', null],
    ['empty', []],
  ])(
    'preserves a %s selection made while mount refresh is pending',
    async (selection, expected) => {
      const prod = { path: 'prod/', type: 'kv', options: { version: '2' } };
      const dev = { path: 'dev/', type: 'kv', options: { version: '2' } };
      let finishRefresh;
      mocks.listMounts
        .mockResolvedValueOnce([prod, dev])
        .mockImplementationOnce(
          () =>
            new Promise(resolve => {
              finishRefresh = resolve;
            })
        );
      const { ref, onError } = renderForm(ImportVaultForm);
      await connect('Vault', 'https://vault.your-org.com');
      fireEvent.click(
        screen.getByRole('button', { name: /Advanced: Secrets engines/ })
      );
      fireEvent.click(
        await screen.findByRole('button', { name: 'Load engines' })
      );
      const devCheckbox = await screen.findByRole('checkbox', {
        name: 'dev/ (kv v2)',
      });
      const allCheckbox = screen.getByRole('checkbox', {
        name: 'Scan all secrets engines',
      });
      expect(allCheckbox).toBeChecked();
      if (selection === 'all') fireEvent.click(devCheckbox);
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
      expect(mocks.listMounts).toHaveBeenCalledTimes(2);
      expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();
      fireEvent.click(selection === 'all' ? allCheckbox : devCheckbox);
      if (selection === 'empty')
        fireEvent.click(
          screen.getByRole('checkbox', { name: 'prod/ (kv v2)' })
        );
      await act(async () => {
        finishRefresh([prod, dev]);
      });
      expect(allCheckbox.checked).toBe(selection === 'all');
      expect(devCheckbox.checked).toBe(selection === 'all');
      expect(
        screen.getByRole('checkbox', { name: 'prod/ (kv v2)' }).checked
      ).toBe(selection !== 'empty');
      expect(ref.current.getCredentials().scanParams.mounts).toEqual(expected);
      fireEvent.click(scanButton('Vault'));
      if (selection === 'empty') {
        expect(mocks.vaultScan).not.toHaveBeenCalled();
        expect(onError).toHaveBeenLastCalledWith(
          'Select at least one secrets engine to scan.'
        );
      } else {
        await screen.findByText('1 matched');
        expect(mocks.vaultScan).toHaveBeenLastCalledWith(
          expect.objectContaining({ mounts: expected })
        );
      }
    }
  );

  it('retains explicit scope after a nonempty refresh shrink until all engines are deliberately chosen', async () => {
    const prod = { path: 'prod/', type: 'kv', options: { version: '2' } };
    const dev = { path: 'dev/', type: 'kv', options: { version: '2' } };
    mocks.listMounts
      .mockResolvedValueOnce([prod, dev])
      .mockResolvedValueOnce([prod])
      .mockResolvedValueOnce([prod, dev]);
    const { ref } = renderForm(ImportVaultForm);
    await connect('Vault', 'https://vault.your-org.com');
    fireEvent.click(
      screen.getByRole('button', { name: /Advanced: Secrets engines/ })
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Load engines' })
    );
    fireEvent.click(
      await screen.findByRole('checkbox', { name: 'dev/ (kv v2)' })
    );
    expect(ref.current.getCredentials().scanParams.mounts).toEqual(['prod/']);
    for (const count of [2, 3]) {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
      await waitFor(() =>
        expect(mocks.listMounts).toHaveBeenCalledTimes(count)
      );
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled()
      );
      expect(ref.current.getCredentials().scanParams.mounts).toEqual(['prod/']);
    }
    expect(
      screen.getByRole('checkbox', { name: 'dev/ (kv v2)' })
    ).not.toBeChecked();
    fireEvent.click(scanButton('Vault'));
    await screen.findByText('1 matched');
    expect(mocks.vaultScan).toHaveBeenLastCalledWith(
      expect.objectContaining({ mounts: ['prod/'] })
    );
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Scan all secrets engines' })
    );
    expect(ref.current.getCredentials().scanParams.mounts).toBeNull();
    expect(ref.current.getSelectedCount()).toBe(0);
  });

  it.each(['empty', 'error'])(
    'revokes a default preview after %s discovery',
    async outcome => {
      const { ref } = renderForm(ImportVaultForm);
      await connect('Vault', 'https://vault.your-org.com');
      fireEvent.click(scanButton('Vault'));
      await screen.findByText('1 matched');
      fireEvent.click(screen.getByRole('button', { name: 'select-first-1' }));
      await waitFor(() => expect(ref.current.getSelectedCount()).toBe(1));
      fireEvent.click(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      );
      if (outcome === 'error')
        mocks.listMounts.mockRejectedValue(new Error('Discovery failed'));
      else mocks.listMounts.mockResolvedValue([]);
      fireEvent.click(
        screen.getByRole('button', { name: /Advanced: Secrets engines/ })
      );
      fireEvent.click(
        await screen.findByRole('button', { name: 'Load engines' })
      );
      await waitFor(() =>
        expect(ref.current.getCredentials().scanParams.mounts).toEqual([])
      );
      expect(ref.current.getSelectedCount()).toBe(0);
      expect(
        screen.getByRole('checkbox', { name: /Remove previously imported/ })
      ).toBeDisabled();
      await act(() => ref.current.importSelected());
      expect(mocks.import).not.toHaveBeenCalled();
      fireEvent.click(scanButton('Vault'));
      expect(mocks.vaultScan).toHaveBeenCalledTimes(1);
    }
  );

  it.each([
    [
      ['saved/', 'removed/'],
      [
        { path: 'saved/', type: 'kv' },
        { path: 'other/', type: 'pki' },
      ],
      ['saved/'],
    ],
    [['saved/'], [{ path: 'other/', type: 'kv' }], []],
    [['saved/'], [], []],
    [[], [{ path: 'other/', type: 'kv' }], []],
    [null, [{ path: 'other/', type: 'kv' }], null],
  ])(
    'keeps saved %j restricted after loading %j',
    async (saved, live, expected) => {
      mocks.listMounts.mockResolvedValue(live);
      const { ref, onError } = renderForm(ImportVaultForm, {
        initialScanParams: {
          address: 'https://vault.example.test',
          mounts: saved,
        },
      });
      fireEvent.change(screen.getByPlaceholderText('scan-token'), {
        target: { value: 'secret' },
      });
      fireEvent.click(
        screen.getByRole('button', { name: /Advanced: Secrets engines/ })
      );
      fireEvent.click(
        await screen.findByRole('button', { name: 'Load engines' })
      );
      await waitFor(() => expect(mocks.listMounts).toHaveBeenCalledTimes(1));
      await waitFor(() =>
        expect(ref.current.getCredentials().scanParams.mounts).toEqual(expected)
      );
      if (expected?.length === 0) {
        fireEvent.click(scanButton('Vault'));
        expect(mocks.vaultScan).not.toHaveBeenCalled();
        expect(onError).toHaveBeenLastCalledWith(
          'Select at least one secrets engine to scan.'
        );
        const reload = await screen.findByRole('button', {
          name: live.length ? 'Refresh' : 'Load engines',
        });
        await waitFor(() => expect(reload).toBeEnabled());
        fireEvent.click(reload);
        await waitFor(() => expect(mocks.listMounts).toHaveBeenCalledTimes(2));
        await waitFor(() => expect(reload).toBeEnabled());
        expect(ref.current.getCredentials().scanParams.mounts).toEqual([]);
      }
    }
  );
});
