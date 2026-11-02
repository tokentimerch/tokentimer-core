import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { FileImportStep } from '../../src/components/onboarding/importSteps.jsx';
import { IntegrationStep } from '../../src/components/onboarding/integrationStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

vi.mock('../../src/components/ImportTokensModal.jsx', () => ({
  default: () => null,
}));

const ctx = {
  workspaceId: 'ws-1',
  session: { progress: {}, operationRefs: {}, intent: {} },
  summary: { assets: { total: 0 }, autoSync: { items: [] } },
  capabilities: {
    items: [
      { id: 'integrations.github', state: 'ready', blockers: [] },
      { id: 'autosync.github', state: 'ready', blockers: [] },
    ],
  },
  docs: () => [],
  refresh: vi.fn(),
  skip: vi.fn(),
  controller: { update: vi.fn() },
};

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('file import step', () => {
  it('uses the same required fields as the import dialog and shows a header row', () => {
    wrap(<FileImportStep ctx={ctx} />);
    expect(
      screen.getByText(
        /Required fields per row: name, category, type, expiresAt\./
      )
    ).toBeVisible();
    const example = screen.getByTestId('csv-example').textContent;
    expect(example.split('\n')[0]).toBe(
      'name,category,type,expiresAt,location'
    );
  });

  it('keeps Skip for now on the live step and hides it in review', () => {
    const live = wrap(<FileImportStep ctx={ctx} />);
    expect(screen.getByRole('button', { name: 'Skip for now' })).toBeVisible();
    live.unmount();
    wrap(<FileImportStep ctx={ctx} reviewing />);
    expect(screen.queryByRole('button', { name: 'Skip for now' })).toBeNull();
  });
});

describe('integration step', () => {
  it('starts on Import once and says Keep in sync stores the token', () => {
    const intent = { provider: 'github' };
    wrap(
      <IntegrationStep ctx={{ ...ctx, session: { ...ctx.session, intent } }} />
    );
    expect(screen.getByRole('radio', { name: 'Import once' })).toBeChecked();
    expect(
      screen.getByRole('radio', { name: 'Keep in sync' })
    ).not.toBeChecked();
    expect(
      screen.getByRole('button', { name: 'Scan and import' })
    ).toBeEnabled();
    expect(
      screen.getByText(
        /Keep in sync saves your token on this server \(encrypted\)/
      )
    ).toBeVisible();
  });

  it('hides Skip for now while a finished step is reviewed', () => {
    wrap(<IntegrationStep ctx={ctx} reviewing />);
    expect(screen.queryByRole('button', { name: 'Skip for now' })).toBeNull();
  });
});
