import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import { FileImportStep } from '../../src/components/onboarding/importSteps.jsx';
import { IntegrationStep } from '../../src/components/onboarding/integrationStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

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
    get: vi.fn().mockResolvedValue({ data: {} }),
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

function makeCtx(extra = {}) {
  const session = { progress: {}, operationRefs: {}, intent: {} };
  return {
    workspaceId: 'ws-1',
    session,
    summary: { assets: { total: 0 }, autoSync: { items: [] } },
    capabilities: { items: [] },
    docs: (_key, label) => [
      { label, url: `https://tokentimer.ch/docs/self-hosted/${label}` },
    ],
    refresh: vi
      .fn()
      .mockResolvedValue({ assets: { total: 0 }, autoSync: { items: [] } }),
    skip: vi.fn(),
    controller: { session, update: vi.fn().mockResolvedValue(undefined) },
    ...extra,
  };
}

function mount(ui) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );
}

// The open modal marks the rest of the page hidden, so count every panel.
const allPanels = () =>
  screen.getAllByRole('note', { name: 'Learn more', hidden: true });

describe('Import forms embedded in an onboarding step', () => {
  beforeEach(() => vi.clearAllMocks());

  it('keeps a single Learn more panel while the file import is open', async () => {
    mount(<FileImportStep ctx={makeCtx()} />);
    expect(allPanels()).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Choose a file' }));
    await screen.findByText(/Upload a file in/);

    expect(allPanels()).toHaveLength(1);
    expect(screen.getAllByText('Learn more', { selector: 'p' }).length).toBe(1);
  });

  it('keeps a single Learn more panel while a service import is open', async () => {
    const ctx = makeCtx();
    ctx.session.intent = { provider: 'github' };
    mount(<IntegrationStep ctx={ctx} />);
    expect(allPanels()).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Scan and import' }));
    await waitFor(() =>
      expect(screen.getAllByText(/Scans GitHub for tokens/).length).toBe(1)
    );

    expect(allPanels()).toHaveLength(1);
  });
});
