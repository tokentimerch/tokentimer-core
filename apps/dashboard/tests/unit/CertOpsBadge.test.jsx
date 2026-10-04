import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge, ChakraProvider, extendTheme } from '@chakra-ui/react';
import CertOpsBadge, {
  CertificateLifecycleBadge,
} from '../../src/components/certops/CertOpsBadge.jsx';
import { theme } from '../../src/styles/theme.js';
import { dashboardBadgeTheme } from '../../src/styles/badges.js';
import KeyLocalityBadge from '../../src/components/certops/KeyLocalityBadge.jsx';
import {
  certificateLifecycleDescriptor,
  expiryDescriptor,
  MANAGED_CERTIFICATE_STATUSES,
} from '../../src/components/certops/certopsFormat.js';

afterEach(() => vi.useRealTimers());

describe('Certificate badge semantics', () => {
  it('keeps small badge text at accessible contrast in both themes', () => {
    const resolveColor = token => {
      if (token === 'white') return '#ffffff';
      const [scheme, shade] = token.split('.');
      return theme.colors[scheme][shade];
    };
    const luminance = hex => {
      const channels = hex
        .replace('#', '')
        .match(/../g)
        .map(value => {
          const channel = parseInt(value, 16) / 255;
          return channel <= 0.04045
            ? channel / 12.92
            : ((channel + 0.055) / 1.055) ** 2.4;
        });
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };
    for (const scheme of [
      'gray',
      'red',
      'orange',
      'yellow',
      'green',
      'blue',
      'purple',
      'teal',
      'cyan',
      'pink',
    ]) {
      for (const [variant, describeVariant] of Object.entries(
        dashboardBadgeTheme.variants
      )) {
        const style = describeVariant({ colorScheme: scheme });
        for (const mode of ['light', 'dark']) {
          const colors = mode === 'dark' ? { ...style, ...style._dark } : style;
          const background =
            colors.bg === 'transparent'
              ? mode === 'dark'
                ? 'gray.900'
                : 'white'
              : colors.bg;
          const textLuminance = luminance(resolveColor(colors.color));
          const backgroundLuminance = luminance(resolveColor(background));
          const contrast =
            (Math.max(textLuminance, backgroundLuminance) + 0.05) /
            (Math.min(textLuminance, backgroundLuminance) + 0.05);
          expect(
            contrast,
            `${scheme} ${variant} ${mode}`
          ).toBeGreaterThanOrEqual(4.5);
        }
      }
    }
  });

  it('gives ordinary website badges and CertOps badges the same readable sizing', () => {
    render(
      <ChakraProvider
        theme={extendTheme(theme, {
          config: { initialColorMode: 'light', useSystemColorMode: false },
        })}
      >
        <Badge>Workspace member</Badge>
        <CertOpsBadge colorScheme='green'>Agent online</CertOpsBadge>
      </ChakraProvider>
    );
    for (const label of ['Workspace member', 'Agent online']) {
      expect(screen.getByText(label)).toHaveStyle({
        display: 'inline-flex',
        minHeight: '24px',
        textTransform: 'none',
      });
    }
  });

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
