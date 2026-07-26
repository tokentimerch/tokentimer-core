import { describe, it, expect } from 'vitest';

import {
  RENEWAL_STATES,
  formatDate,
  renewalDescriptor,
} from '../../src/components/certops/certopsFormat';

describe('renewalDescriptor', () => {
  it('announces the renewal window date for an auto certificate', () => {
    const renewsFrom = '2026-08-12T00:00:00.000Z';
    const descriptor = renewalDescriptor({
      state: RENEWAL_STATES.auto,
      renewsFrom,
      renewBeforeDays: 30,
    });

    expect(descriptor.state).toBe('auto');
    expect(descriptor.label).toBe(`Auto-renews from ${formatDate(renewsFrom)}`);
    expect(descriptor.label).toMatch(/^Auto-renews from \S/);
    expect(descriptor.scheme).toBe('green');
    expect(descriptor.isWarning).toBe(false);
  });

  it('falls back to a dateless auto label when no window was computed', () => {
    const descriptor = renewalDescriptor({
      state: RENEWAL_STATES.auto,
      renewBeforeDays: 30,
    });

    expect(descriptor.label).toBe('Auto-renews');
    expect(descriptor.help).toMatch(/30 days before expiry/);
  });

  it('flags not-configured as the only warning-level renewal state', () => {
    const descriptor = renewalDescriptor({
      state: RENEWAL_STATES.notConfigured,
    });

    expect(descriptor.label).toBe('No auto-renewal');
    expect(descriptor.scheme).toBe('orange');
    expect(descriptor.isWarning).toBe(true);
    expect(descriptor.help).toMatch(/will not renew automatically/i);
  });

  it('prefers the server explanation over the generic copy', () => {
    const descriptor = renewalDescriptor({
      state: RENEWAL_STATES.notConfigured,
      detail: 'This certificate will not renew automatically: no ACME command.',
    });

    expect(descriptor.help).toBe(
      'This certificate will not renew automatically: no ACME command.'
    );
  });

  it('presents not-eligible as a neutral monitored-only state', () => {
    const descriptor = renewalDescriptor({
      state: RENEWAL_STATES.notEligible,
    });

    expect(descriptor.label).toBe('Monitored only');
    expect(descriptor.scheme).toBe('gray');
    expect(descriptor.isWarning).toBe(false);
    expect(descriptor.help).toMatch(/does not hold this certificate key/i);
  });

  it('presents not-applicable as neutral', () => {
    const descriptor = renewalDescriptor({
      state: RENEWAL_STATES.notApplicable,
    });

    expect(descriptor.label).toBe('Renewal not applicable');
    expect(descriptor.scheme).toBe('gray');
    expect(descriptor.isWarning).toBe(false);
  });

  it('treats a missing or unrecognized renewal object as a caution, never as healthy', () => {
    for (const renewal of [undefined, null, {}, { state: 'something-new' }]) {
      const descriptor = renewalDescriptor(renewal);
      expect(descriptor.label).toBe('Renewal unknown');
      expect(descriptor.isWarning).toBe(true);
      expect(descriptor.scheme).not.toBe('green');
    }
  });
});
