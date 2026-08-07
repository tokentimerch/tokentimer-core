import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import RenewalPathBadge from '../../src/components/certops/RenewalPathBadge.jsx';

function renderBadge(certificate) {
  return render(
    <ChakraProvider>
      <RenewalPathBadge certificate={certificate} />
    </ChakraProvider>
  );
}

describe('RenewalPathBadge', () => {
  it('renders nothing when the certificate has no renewalPathState (question does not apply)', () => {
    renderBadge({ renewalPathState: null });
    expect(document.querySelectorAll('.chakra-badge').length).toBe(0);
  });

  it('renders a green Healthy badge', () => {
    renderBadge({ renewalPathState: 'healthy' });

    expect(screen.getByText('Healthy')).toBeInTheDocument();
  });

  it('renders a Degraded badge with the server-provided summary as its accessible label', () => {
    renderBadge({
      renewalPathState: 'degraded',
      renewalPathSummary: '1 of 2 renewal execution agents are online; a redundant path is still available.',
    });

    expect(screen.getByText('Degraded')).toBeInTheDocument();
    expect(
      screen.getByLabelText(/1 of 2 renewal execution agents are online/)
    ).toBeInTheDocument();
  });

  it('renders "Renewal path unavailable" for the unavailable state', () => {
    renderBadge({
      renewalPathState: 'unavailable',
      renewalPathSummary: 'The only agent able to renew this certificate is offline.',
    });

    expect(screen.getByText('Renewal path unavailable')).toBeInTheDocument();
    expect(
      screen.getByLabelText(/only agent able to renew this certificate is offline/)
    ).toBeInTheDocument();
  });

  it('renders a neutral Unknown badge distinct from the failure states', () => {
    renderBadge({ renewalPathState: 'unknown' });

    expect(screen.getByText('Renewal path unknown')).toBeInTheDocument();
  });

  it('falls back to built-in help text when the server omits renewalPathSummary', () => {
    renderBadge({ renewalPathState: 'unavailable' });

    expect(screen.getByText('Renewal path unavailable')).toBeInTheDocument();
    expect(
      screen.getByLabelText(/no complete execution path currently exists/i)
    ).toBeInTheDocument();
  });
});
