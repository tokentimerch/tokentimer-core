import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import RenewalBadge from '../../src/components/certops/RenewalBadge.jsx';
import { RENEWAL_STATES } from '../../src/components/certops/certopsFormat.js';

function renderBadge(renewal) {
  return render(
    <ChakraProvider>
      <RenewalBadge renewal={renewal} />
    </ChakraProvider>
  );
}

describe('RenewalBadge', () => {
  it('renders the auto-renewal window date', () => {
    renderBadge({
      state: RENEWAL_STATES.auto,
      renewsFrom: '2026-08-12T00:00:00.000Z',
      renewBeforeDays: 30,
    });

    expect(screen.getByText(/^Auto-renews from /)).toBeInTheDocument();
  });

  it('exposes the not-configured warning to assistive tech without a hover', () => {
    renderBadge({ state: RENEWAL_STATES.notConfigured });

    expect(screen.getByText('No auto-renewal')).toBeInTheDocument();
    expect(
      screen.getByLabelText(/will not renew automatically and will expire/i)
    ).toBeInTheDocument();
  });

  it('renders observed-only certificates as a neutral monitored-only badge', () => {
    renderBadge({ state: RENEWAL_STATES.notEligible });

    expect(screen.getByText('Monitored only')).toBeInTheDocument();
    expect(
      screen.getByLabelText(/does not hold this certificate key/i)
    ).toBeInTheDocument();
  });

  it('distinguishes a deliberately switched-off certificate from a misconfigured one', () => {
    renderBadge({ state: RENEWAL_STATES.disabled });

    expect(screen.getByText('Auto-renewal off')).toBeInTheDocument();
    // Must not reuse the not-configured copy: that tells the operator to go fix
    // a profile, which is wrong when they switched it off on purpose.
    expect(screen.queryByText('No auto-renewal')).not.toBeInTheDocument();
    expect(
      screen.getByLabelText(/switched off/i)
    ).toBeInTheDocument();
  });

  it('never renders a reassuring badge when the API omits the renewal field', () => {
    renderBadge(undefined);

    expect(screen.getByText('Renewal unknown')).toBeInTheDocument();
  });
});
