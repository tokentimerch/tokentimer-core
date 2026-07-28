import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import CertificateInstances from '../../src/components/certops/CertificateInstances.jsx';
import { formatDateTime } from '../../src/components/certops/certopsFormat';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

function renderInstances(props) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <CertificateInstances available error='' instances={[]} {...props} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function instance(overrides = {}) {
  return {
    id: 'instance-1',
    targetId: 'target-1',
    deploymentReference: 'k8s://cluster/ns/secret/tls',
    status: 'active',
    source: 'cert_manager',
    observedAt: '2026-07-28T13:15:14.000Z',
    observedFingerprintSha256: 'aaaa',
    ...overrides,
  };
}

describe('CertificateInstances', () => {
  it('shows the empty state when there are no instances', () => {
    renderInstances({ instances: [] });

    expect(screen.getByText('No locations recorded yet')).toBeInTheDocument();
  });

  it('shows the unavailable state independently of an empty instance list', () => {
    renderInstances({ instances: [], available: false });

    expect(screen.getByText('History not available yet')).toBeInTheDocument();
  });

  it('shows the error state', () => {
    renderInstances({ instances: [], error: 'boom' });

    expect(screen.getByText('Could not load locations')).toBeInTheDocument();
    expect(screen.getByText('boom')).toBeInTheDocument();
  });

  it('renders one row per distinct target rather than one row per instance', () => {
    renderInstances({
      instances: [
        instance({ id: 'a', targetId: 't1' }),
        instance({ id: 'b', targetId: 't2', deploymentReference: 'other-target' }),
      ],
    });

    expect(screen.getAllByText('active')).toHaveLength(2);
    expect(screen.queryByText(/earlier observation/)).not.toBeInTheDocument();
  });

  it('collapses multiple observations at the same target behind a toggle instead of showing duplicate-looking rows', () => {
    renderInstances({
      instances: [
        instance({
          id: 'older',
          targetId: 't1',
          observedAt: '2026-07-28T13:15:14.000Z',
          observedFingerprintSha256: 'fingerprint-old',
        }),
        instance({
          id: 'newer',
          targetId: 't1',
          observedAt: '2026-07-28T13:34:26.000Z',
          observedFingerprintSha256: 'fingerprint-new',
        }),
      ],
    });

    // Only the current (newest) observation renders as a top-level row by default.
    expect(screen.getByText('Show 1 earlier observation at this location')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Show 1 earlier observation at this location'));

    expect(screen.getByText('Hide earlier observations')).toBeInTheDocument();
  });

  it('shows a Renewed badge only when two observations at the same target have different fingerprints', () => {
    renderInstances({
      instances: [
        instance({ id: 'older', targetId: 't1', observedFingerprintSha256: 'old' }),
        instance({ id: 'newer', targetId: 't1', observedFingerprintSha256: 'new' }),
      ],
    });

    expect(screen.getByText('Renewed')).toBeInTheDocument();
  });

  it('does not show a Renewed badge when fingerprints are missing (cannot be proven true)', () => {
    renderInstances({
      instances: [
        instance({ id: 'older', targetId: 't1', observedFingerprintSha256: null }),
        instance({ id: 'newer', targetId: 't1', observedFingerprintSha256: null }),
      ],
    });

    expect(screen.queryByText('Renewed')).not.toBeInTheDocument();
  });

  it('renders full date-time precision so same-day observations are distinguishable', () => {
    const observedAt = '2026-07-28T13:34:26.000Z';
    renderInstances({
      instances: [instance({ observedAt })],
    });

    expect(screen.getByText(formatDateTime(observedAt))).toBeInTheDocument();
  });

  it('distinguishes two same-day observations at different targets once expanded, unlike day-only formatting', () => {
    const older = '2026-07-28T13:15:14.000Z';
    const newer = '2026-07-28T13:34:26.000Z';
    renderInstances({
      instances: [
        instance({ id: 'older', targetId: 't1', observedAt: older, observedFingerprintSha256: 'old' }),
        instance({ id: 'newer', targetId: 't1', observedAt: newer, observedFingerprintSha256: 'new' }),
      ],
    });

    fireEvent.click(screen.getByText('Show 1 earlier observation at this location'));

    expect(screen.getByText(formatDateTime(newer))).toBeInTheDocument();
    expect(screen.getByText(formatDateTime(older))).toBeInTheDocument();
  });
});
