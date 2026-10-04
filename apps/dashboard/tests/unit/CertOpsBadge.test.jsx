import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { CertificateLifecycleBadge } from '../../src/components/certops/CertOpsBadge.jsx';
import KeyLocalityBadge from '../../src/components/certops/KeyLocalityBadge.jsx';
import {
  certificateLifecycleDescriptor,
  expiryDescriptor,
  MANAGED_CERTIFICATE_STATUSES,
} from '../../src/components/certops/certopsFormat.js';

afterEach(() => vi.useRealTimers());

describe('Certificate badge semantics', () => {
  it('keeps immutable lifecycle independent of source expiry and renewal states', () => {
    for (const status of ['active', 'expiring', 'expired', 'renewing']) {
      expect(
        certificateLifecycleDescriptor({
          identityId: 'identity-a',
          lifecycleStatus: 'active',
          status,
        })
      ).toEqual({ status: 'active', label: 'Active', scheme: 'green' });
    }
    expect(
      certificateLifecycleDescriptor({
        identityId: 'identity-a',
        lifecycleStatus: 'revoked',
        status: 'active',
        lifecycleDisplay: 'Revoked · Still observed',
      })
    ).toEqual({
      status: 'revoked',
      label: 'Revoked · Still observed',
      scheme: 'red',
    });
  });

  it('does not relabel an unidentified provisioning source as active', () => {
    expect(
      certificateLifecycleDescriptor({
        lifecycleStatus: 'active',
        lifecycleDisplay: 'Active',
        status: 'provisioning',
        identityId: null,
        fingerprintSha256: null,
      })
    ).toEqual({
      status: 'provisioning',
      label: 'Provisioning',
      scheme: 'purple',
    });
  });

  it('retains legacy provisioning states and human-readable unknown labels', () => {
    render(
      <ChakraProvider>
        <CertificateLifecycleBadge certificate={{ status: 'UNKNOWN' }} />
        <CertificateLifecycleBadge certificate={{ status: 'provisioning' }} />
      </ChakraProvider>
    );
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('Provisioning')).toBeInTheDocument();
    expect(MANAGED_CERTIFICATE_STATUSES).not.toContain('unknown');
  });

  it('keeps expiry severity boundaries independent of lifecycle', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-04T12:00:00Z'));
    for (const [days, label, scheme] of [
      [-1, 'Expired 1d ago', 'red'],
      [0, 'Expires today', 'red'],
      [14, '14d left', 'red'],
      [15, '15d left', 'orange'],
      [30, '30d left', 'orange'],
      [31, '31d left', 'green'],
    ]) {
      const date = new Date(Date.now() + days * 86400000).toISOString();
      expect(expiryDescriptor(date)).toEqual({ label, scheme, days });
    }
    expect(expiryDescriptor(null)).toEqual({
      label: 'Unknown',
      scheme: 'gray',
      days: null,
    });
  });

  it('describes key custody without suggesting a renewal fault or key ownership', () => {
    render(
      <ChakraProvider>
        <KeyLocalityBadge keyMode='agent-local' />
      </ChakraProvider>
    );
    expect(screen.getByText('Agent-local')).toBeInTheDocument();
    expect(
      screen.queryByText(/unavailable|degraded|error/i)
    ).not.toBeInTheDocument();
  });
});
