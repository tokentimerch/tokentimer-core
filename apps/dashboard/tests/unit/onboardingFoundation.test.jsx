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

  it('separates the header from the body only when there is a body', () => {
    const { unmount } = renderFrame({ kind: 'ui', description: 'Subtitle' });
    const separator = screen.getByRole('separator');
    const heading = screen.getByRole('heading', { name: 'A step' });
    const body = screen.getByText('body');
    expect(
      heading.compareDocumentPosition(separator) &
        Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(
      separator.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    unmount();

    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <StepFrame kind='info' title='Empty step' />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(screen.queryByRole('separator')).not.toBeInTheDocument();
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

  it('opens docs in a new tab safely and says it leaves the app', () => {
    renderFrame({
      kind: 'info',
      docs: [{ label: 'Real page', url: 'https://tokentimer.ch/docs/x#y' }],
    });
    const link = screen.getByRole('link', { name: 'Real page' });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toMatch(/noopener/);
    // The external-link icon is decoration, not part of the accessible name.
    expect(link.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
  });

  it('shows no docs row at all when no link resolves', () => {
    renderFrame({ kind: 'info', docs: [{ label: 'Missing', url: null }] });
    expect(screen.queryByText('Learn more')).not.toBeInTheDocument();
  });

  it('labels the docs row once, however many links there are', () => {
    renderFrame({
      kind: 'info',
      docs: [
        { label: 'One', url: 'https://tokentimer.ch/docs/1' },
        { label: 'Two', url: 'https://tokentimer.ch/docs/2' },
      ],
    });
    expect(screen.getAllByText('Learn more')).toHaveLength(1);
    expect(screen.getAllByRole('link')).toHaveLength(2);
  });

  it('puts the docs links inside a quiet info panel', () => {
    renderFrame({
      kind: 'info',
      docs: [
        { label: 'One', url: 'https://tokentimer.ch/docs/1' },
        { label: 'Two', url: 'https://tokentimer.ch/docs/2' },
      ],
    });
    const panel = screen.getByRole('note', { name: 'Learn more' });
    expect(panel).toHaveAttribute('data-status', 'info');
    expect(panel).toHaveTextContent('Learn more');
    // A note is not announced like an alert on every step render.
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    for (const link of screen.getAllByRole('link')) {
      expect(panel).toContainElement(link);
    }
  });

  it('renders no info panel when there are no docs', () => {
    renderFrame({ kind: 'info', docs: [] });
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
    renderFrame({ kind: 'info', docs: [{ label: 'Missing', url: null }] });
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
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
