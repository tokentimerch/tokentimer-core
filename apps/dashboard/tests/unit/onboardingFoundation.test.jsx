import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it } from 'vitest';
import StepFrame, {
  STEP_KINDS,
  assertStepKind,
} from '../../src/components/onboarding/StepFrame.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { docUrl } from '../../src/components/onboarding/docLinks.js';
import {
  isTourCompleted,
  markTourCompleted,
  resetTourCompleted,
  tourCompletedKey,
} from '../../src/utils/tourStorage.js';

function renderFrame(props) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <StepFrame title='A step' {...props}>
          <span>body</span>
        </StepFrame>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('StepFrame', () => {
  it('labels each step kind so users know where the work happens', () => {
    const cases = {
      ui: 'Guided in the dashboard',
      runbook: 'Needs a command on your server',
      handoff: 'Needs an administrator',
      verify: 'Live check',
      info: 'Reference',
    };
    for (const [kind, label] of Object.entries(cases)) {
      const { unmount } = renderFrame({ kind });
      expect(screen.getByTestId('step-kind')).toHaveTextContent(label);
      unmount();
    }
  });

  it('rejects unknown kinds instead of rendering a mislabeled step', () => {
    expect(() => assertStepKind('wizardry')).toThrow(/Unknown/);
    for (const kind of STEP_KINDS) {
      expect(assertStepKind(kind)).toBe(kind);
    }
  });

  it('shows blocker remediation and hides docs links that do not exist', () => {
    renderFrame({
      kind: 'handoff',
      blockers: [{ code: 'ROLE_REQUIRED', remediation: 'Ask an admin.' }],
      docs: [
        { label: 'Real page', url: 'https://tokentimer.ch/docs/x#y' },
        { label: 'Missing page', url: null },
      ],
    });
    expect(screen.getByText('Ask an admin.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Real page' })).toHaveAttribute(
      'href',
      'https://tokentimer.ch/docs/x#y'
    );
    expect(screen.queryByText('Missing page')).not.toBeInTheDocument();
  });
});

describe('docUrl', () => {
  it('builds self-hosted, cloud and enterprise links', () => {
    expect(
      docUrl('alerts.thresholds', 'https://tokentimer.ch/docs/self-hosted')
    ).toBe('https://tokentimer.ch/docs/self-hosted/alerts#thresholds');
    expect(
      docUrl('quickstart.firstAsset', 'https://tokentimer.ch/docs/cloud')
    ).toBe('https://tokentimer.ch/docs/cloud/quickstart#first-token');
    // Enterprise inherits the self-hosted guides for these topics.
    expect(
      docUrl('alerts.thresholds', 'https://tokentimer.ch/docs/enterprise')
    ).toBe('https://tokentimer.ch/docs/self-hosted/alerts#thresholds');
  });

  it('hides links the edition has no page for', () => {
    expect(docUrl('smtp.setup', 'https://tokentimer.ch/docs/cloud')).toBeNull();
    expect(docUrl('nope', 'https://tokentimer.ch/docs/cloud')).toBeNull();
    expect(docUrl('alerts.thresholds', undefined)).toBeNull();
  });
});

describe('tourStorage', () => {
  beforeEach(() => localStorage.clear());

  it('uses the same key ProductTour reads and writes', () => {
    expect(tourCompletedKey('dashboard')).toBe('tt_tour_dashboard');
    markTourCompleted('dashboard');
    expect(localStorage.getItem('tt_tour_dashboard')).toBe('true');
    expect(isTourCompleted('dashboard')).toBe(true);
  });

  it('restart clears both the real and the legacy key', () => {
    localStorage.setItem('tt_tour_dashboard', 'true');
    localStorage.setItem('tt_tour_dashboard_v1', 'true');
    resetTourCompleted('dashboard');
    expect(localStorage.getItem('tt_tour_dashboard')).toBeNull();
    expect(localStorage.getItem('tt_tour_dashboard_v1')).toBeNull();
    expect(isTourCompleted('dashboard')).toBe(false);
  });
});
