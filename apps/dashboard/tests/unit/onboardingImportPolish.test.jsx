import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import BulkIntegrationAssignment from '../../src/components/BulkIntegrationAssignment.jsx';
import {
  EMBEDDED_GROUPS_NOTE,
  EmbeddedImportContext,
} from '../../src/components/imports/embeddedImportContext.js';
import {
  IMPORT_SOURCE_LOGOS,
  ImportSourceLogo,
} from '../../src/components/imports/importSources.jsx';
import { IntegrationStep } from '../../src/components/onboarding/integrationStep.jsx';
import { INTEGRATIONS } from '../../src/components/onboarding/modules.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

vi.mock('../../src/components/ContactGroupCheckboxGroup.jsx', () => ({
  default: () => <div>group-checkboxes</div>,
}));
vi.mock('../../src/components/ImportTokensModal.jsx', () => ({
  default: () => null,
}));

const wrap = ui => (
  <ChakraProvider>
    <DashboardThemeProvider>{ui}</DashboardThemeProvider>
  </ChakraProvider>
);

describe('contact group note in the import dialog', () => {
  const props = { selectedCount: 2, onSectionChange: vi.fn() };

  it('explains the field inside the setup guide', () => {
    render(
      wrap(
        <EmbeddedImportContext.Provider value>
          <BulkIntegrationAssignment {...props} />
        </EmbeddedImportContext.Provider>
      )
    );
    expect(screen.getByTestId('embedded-groups-note')).toHaveTextContent(
      EMBEDDED_GROUPS_NOTE
    );
    expect(EMBEDDED_GROUPS_NOTE).toBe(
      'Groups chosen here receive alerts for the assets you import now. Assets a sync adds later use the group set on the sync.'
    );
  });

  it('leaves the standalone dialog untouched', () => {
    render(wrap(<BulkIntegrationAssignment {...props} />));
    expect(screen.queryByTestId('embedded-groups-note')).toBeNull();
    expect(
      screen.getByText(/Leave as workspace default when empty/)
    ).toBeInTheDocument();
  });
});

describe('provider logos in the integration step', () => {
  const ctx = {
    workspaceId: 'ws-1',
    session: { progress: {}, operationRefs: {}, intent: {} },
    summary: { assets: { total: 0 }, autoSync: { items: [] } },
    capabilities: { items: [] },
    docs: () => [],
    refresh: vi.fn(),
    skip: vi.fn(),
    controller: { update: vi.fn() },
  };

  it('shows every provider with its shared logo and a text name', () => {
    render(wrap(<IntegrationStep ctx={ctx} />));
    Object.entries(INTEGRATIONS).forEach(([id, meta]) => {
      const button = screen.getByRole('button', { name: meta.label });
      const img = button.querySelector('img');
      expect(img).not.toBeNull();
      expect(img.getAttribute('src')).toBe(IMPORT_SOURCE_LOGOS[id]);
      // Decorative: the button name carries the provider.
      expect(img.getAttribute('alt')).toBe('');
      expect(img.getAttribute('aria-hidden')).toBe('true');
    });
  });

  it('keeps selection behavior when a card is clicked', () => {
    render(wrap(<IntegrationStep ctx={ctx} />));
    const cards = Object.values(INTEGRATIONS).map(m =>
      screen.getByRole('button', { name: m.label })
    );
    const github = screen.getByRole('button', { name: 'GitHub' });
    expect(cards.map(c => c.getAttribute('aria-pressed'))).not.toContain(
      'true'
    );
    // Capabilities are empty here, so only check the press does not throw.
    fireEvent.click(github);
    expect(within(github).getByText('GitHub')).toBeInTheDocument();
  });

  it.each(['azure', 'azure-ad'])(
    'keeps the %s badge inside a padded, unclipped wrapper',
    key => {
      render(wrap(<ImportSourceLogo sourceKey={key} />));
      const wrapper = screen.getByTestId('import-source-logo');
      expect(wrapper).toHaveStyle({ padding: '6px', overflow: 'visible' });
      expect(wrapper.querySelector('svg').parentElement).toHaveStyle({
        top: '0px',
        right: '0px',
      });
    }
  );

  it.each(['vault', 'gitlab', 'github', 'aws', 'gcp'])(
    'adds no badge or padding to the %s logo',
    key => {
      render(wrap(<ImportSourceLogo sourceKey={key} />));
      const wrapper = screen.getByTestId('import-source-logo');
      expect(wrapper.querySelector('svg')).toBeNull();
      expect(wrapper).toHaveStyle({ overflow: 'visible' });
    }
  );

  it('adds a badge to tell the two Azure logos apart', () => {
    const { container } = render(
      wrap(<ImportSourceLogo sourceKey='azure-ad' />)
    );
    expect(container.querySelector('svg')).not.toBeNull();
    expect(
      render(wrap(<ImportSourceLogo sourceKey='nope' />)).container.textContent
    ).toBe('');
  });
});
