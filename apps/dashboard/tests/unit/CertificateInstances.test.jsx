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

  it('renders full date-time precision as a title so same-day observations are distinguishable on hover', () => {
    const observedAt = '2026-07-28T13:34:26.000Z';
    renderInstances({
      instances: [instance({ observedAt })],
    });

    expect(screen.getByTitle(formatDateTime(observedAt))).toBeInTheDocument();
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

    expect(screen.getByTitle(formatDateTime(newer))).toBeInTheDocument();
    expect(screen.getByTitle(formatDateTime(older))).toBeInTheDocument();
  });

  it('shows the location kind and a placeholder agent for a location with no responsible agent', () => {
    renderInstances({
      instances: [instance({ locationKind: 'windows_store' })],
    });

    expect(screen.getByText('Windows Certificate Store')).toBeInTheDocument();
    expect(screen.getAllByText('--').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });

  it('renders a null legacy location kind as Unknown without filesystem evidence', () => {
    renderInstances({
      instances: [
        instance({
          locationKind: null,
          source: 'import',
          deploymentReference: 'legacy-import-record',
        }),
      ],
    });

    expect(screen.getAllByText('Unknown')).toHaveLength(2);
    expect(screen.queryByText('Filesystem')).not.toBeInTheDocument();
  });

  it('infers Filesystem only from safe source or reference evidence', () => {
    renderInstances({
      instances: [
        instance({
          locationKind: null,
          source: 'agent_filesystem',
          deploymentReference: 'file://C:/certs/site.pem',
        }),
      ],
    });

    expect(screen.getByText('Filesystem')).toBeInTheDocument();
  });

  it('keeps IIS bindings with the same site and port visually distinct by SNI host', () => {
    renderInstances({
      instances: [
        instance({
          id: 'iis-a',
          targetId: 'iis-target-a',
          locationKind: 'iis_binding',
          deploymentReference: 'iis://Default Web Site:443#example.com',
        }),
        instance({
          id: 'iis-b',
          targetId: 'iis-target-b',
          locationKind: 'iis_binding',
          deploymentReference: 'iis://Default Web Site:443#other.example.com',
        }),
      ],
    });

    expect(
      screen.getByText('iis://Default Web Site:443#example.com')
    ).toBeInTheDocument();
    expect(
      screen.getByText('iis://Default Web Site:443#other.example.com')
    ).toBeInTheDocument();
  });

  it('shows the HTTP.sys binding address instead of the agent hostname', () => {
    renderInstances({
      instances: [
        instance({
          locationKind: 'http_sys',
          deploymentReference: 'http-sys://0.0.0.0:443',
          target: { hostname: 'edge-host.example.com' },
        }),
      ],
    });

    expect(screen.getByText('http-sys://0.0.0.0:443')).toBeInTheDocument();
    expect(
      screen.queryByText('http-sys://edge-host.example.com:443')
    ).not.toBeInTheDocument();
  });

  it('shows a reachable connectivity badge for a location whose responsible agent is live', () => {
    renderInstances({
      instances: [
        instance({
          agent: {
            agentId: 'agent-1',
            name: 'edge-agent-01',
            hostname: 'edge01',
            livenessState: 'live',
          },
        }),
      ],
    });

    expect(screen.getByText('edge-agent-01')).toBeInTheDocument();
    expect(screen.getByText('Reachable')).toBeInTheDocument();
  });

  it('shows an agent-offline connectivity badge for a location whose responsible agent has gone stale', () => {
    renderInstances({
      instances: [
        instance({
          agent: {
            agentId: 'agent-1',
            name: 'edge-agent-01',
            hostname: 'edge01',
            livenessState: 'stale',
            lastSeenAt: '2026-07-28T13:00:00.000Z',
          },
        }),
      ],
    });

    expect(screen.getByText('Agent offline')).toBeInTheDocument();
  });

  it('keeps the observed location visible with an agent-offline badge rather than hiding the row', () => {
    renderInstances({
      instances: [
        instance({
          targetId: 't1',
          status: 'active',
          agent: {
            agentId: 'agent-1',
            name: 'prod-iis-01',
            livenessState: 'stale',
            lastSeenAt: '2026-07-28T13:00:00.000Z',
          },
        }),
      ],
    });

    // The location itself (target, status) is still rendered; only
    // connectivity changed. Agent offline must never be confused with
    // "certificate removed".
    expect(screen.getByText('k8s://cluster/ns/secret/tls')).toBeInTheDocument();
    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('Agent offline')).toBeInTheDocument();
  });
});
