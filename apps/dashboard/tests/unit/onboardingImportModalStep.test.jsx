import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import {
  FileImportModalStep,
  IMPORT_MODAL_PROPS,
  IntegrationModalStep,
} from '../../src/components/onboarding/importModalStep.jsx';
import { importStepComponents } from '../../src/components/onboarding/OnboardingPage.jsx';
import {
  FileImportStep,
  IntegrationStep,
} from '../../src/components/onboarding/importSteps.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const modal = vi.hoisted(() => ({ props: null }));
vi.mock('../../src/components/ImportTokensModal.jsx', () => ({
  default: props => {
    modal.props = props;
    return props.isOpen ? <div data-testid='modal-open'>modal</div> : null;
  },
}));

const makeCtx = () => ({
  workspaceId: 'ws-1',
  session: { progress: {}, operationRefs: {}, intent: {} },
  summary: { assets: { total: 0 }, autoSync: { items: [] } },
  capabilities: { items: [] },
  docs: () => [],
  refresh: vi.fn().mockResolvedValue({}),
  skip: vi.fn(),
  hold: vi.fn(),
  release: vi.fn(),
  controller: { update: vi.fn().mockResolvedValue(undefined) },
});

const wrap = ui => (
  <ChakraProvider>
    <DashboardThemeProvider>{ui}</DashboardThemeProvider>
  </ChakraProvider>
);

describe.each([
  ['file_import', FileImportModalStep, 'Import assets from a file'],
  ['integration', IntegrationModalStep, 'Connect a service'],
])('%s modal step', (stepId, Step, title) => {
  it('opens the regular import dialog straight away', () => {
    render(wrap(<Step ctx={makeCtx()} />));
    expect(screen.getByRole('region', { name: title })).toBeInTheDocument();
    expect(screen.getByTestId('modal-open')).toBeInTheDocument();
    expect(modal.props.embeddedWorkspaceId).toBe('ws-1');
    expect(modal.props.hideDocs).toBe(true);
  });

  it('waits for a successful import before Continue', async () => {
    const ctx = makeCtx();
    render(wrap(<Step ctx={ctx} />));
    expect(screen.getByTestId('import-continue')).toBeDisabled();
    await act(async () => {
      await modal.props.onImported([{ id: 1 }, { id: 2 }]);
    });
    expect(screen.getByTestId('import-done')).toHaveTextContent(
      '2 assets imported'
    );
    expect(screen.getByTestId('import-continue')).toBeEnabled();
    expect(ctx.hold).toHaveBeenCalledWith(stepId);
    const next = ctx.controller.update.mock.calls[0][0]({ progress: {} });
    expect(next.progress.imported).toEqual([
      expect.objectContaining({ step: stepId, count: 2 }),
    ]);
    fireEvent.click(screen.getByTestId('import-continue'));
    expect(ctx.release).toHaveBeenCalled();
  });

  it('does not count an import that created nothing', async () => {
    render(wrap(<Step ctx={makeCtx()} />));
    await act(async () => {
      await modal.props.onImported([]);
    });
    expect(screen.getByTestId('import-continue')).toBeDisabled();
  });

  it('offers a button to reopen the dialog after it is closed', () => {
    render(wrap(<Step ctx={makeCtx()} />));
    act(() => modal.props.onClose());
    expect(screen.queryByTestId('modal-open')).toBeNull();
    fireEvent.click(
      screen.getByRole('button', { name: 'Open the import dialog' })
    );
    expect(screen.getByTestId('modal-open')).toBeInTheDocument();
  });

  it('can be skipped', () => {
    const ctx = makeCtx();
    render(wrap(<Step ctx={ctx} />));
    fireEvent.click(screen.getByRole('button', { name: 'Skip for now' }));
    expect(ctx.skip).toHaveBeenCalledWith(stepId);
  });
});

describe('what the dialog is told for each goal', () => {
  it('opens on File for the file goal', () => {
    render(wrap(<FileImportModalStep ctx={makeCtx()} />));
    expect(modal.props.initialSource).toBe('file');
    expect(modal.props.hiddenSources).toBeUndefined();
  });

  it('hides File and Certificate (PEM) for the integration goal', () => {
    render(wrap(<IntegrationModalStep ctx={makeCtx()} />));
    expect(modal.props.hiddenSources).toEqual(['file', 'cert-pem']);
    expect(IMPORT_MODAL_PROPS.integration.initialSource).toBeUndefined();
  });
});

describe('the parked guided steps', () => {
  it('stay selectable behind the switch', () => {
    expect(importStepComponents(true)).toEqual({
      file_import: FileImportStep,
      integration: IntegrationStep,
    });
    expect(importStepComponents(false).file_import).toBe(FileImportModalStep);
    expect(importStepComponents(false).integration).toBe(IntegrationModalStep);
  });

  it('are off by default', async () => {
    const { GUIDED_IMPORT_STEPS } =
      await import('../../src/components/onboarding/importFlow.js');
    expect(GUIDED_IMPORT_STEPS).toBe(false);
  });
});
