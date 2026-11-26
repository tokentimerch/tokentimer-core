import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { expect, it, vi } from 'vitest';
import DeploymentBadge from '../../src/components/certops/DeploymentBadge.jsx';
const view = props => (
  <ChakraProvider>
    <DeploymentBadge {...props} />
  </ChakraProvider>
);
it.each([
  ['verified', 3, '3 live', 'Verified and current'],
  ['partial', 2, '2 of 3 live', 'Partially complete'],
  ['failed', 0, 'Failed', 'Deployment failed'],
  ['uncertain', 0, 'Uncertain', 'Deployment outcome uncertain'],
  ['stale', 0, 'Outdated', 'Verification outdated'],
  ['pending', 0, '3 pending', 'Pending verification'],
])(
  'keeps %s compact and its full state accessible',
  (status, verified, label, description) => {
    const onClick = vi.fn();
    render(view({ summary: { total: 3, verified, status }, onClick }));
    const button = screen.getByRole('button', {
      name: `Open certificate deployments: ${label}. ${verified}/3 verified. ${description}`,
    });
    expect(button).toHaveTextContent(label);
    expect(button).not.toHaveTextContent(description);
    expect(button).toHaveStyle({ height: '20px' });
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(1);
  }
);
it('leaves a certificate with no rollout off the scan row', () => {
  const { rerender } = render(
    view({
      summary: { total: 3, verified: 0, status: 'not_deployed' },
      onClick: vi.fn(),
    })
  );
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
  rerender(
    view({
      summary: { total: 0, status: 'not_distributed' },
      onClick: vi.fn(),
    })
  );
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
});
it('preserves the same indicator and dimensions throughout background refresh and failure', () => {
  const summary = { total: 5, verified: 3, status: 'partial' };
  const onClick = vi.fn();
  const { rerender } = render(view({ summary, onClick }));
  const node = screen.getByRole('button');
  const size = window.getComputedStyle(node).height;
  rerender(view({ summary, loading: true, onClick }));
  expect(screen.getByRole('button')).toBe(node);
  expect(node).toHaveTextContent('3 of 5 live');
  expect(node).not.toHaveTextContent('Loading');
  rerender(view({ summary, error: 'offline', onClick }));
  expect(screen.getByRole('button')).toBe(node);
  expect(node).toHaveTextContent('Needs refresh');
  expect(node).toHaveAccessibleName(/Last known.*Refresh unavailable/);
  expect(window.getComputedStyle(node).height).toBe(size);
});
it('stays blank while deployment status is loading and names a failed refresh', () => {
  const { rerender } = render(view({ loading: true, onClick: vi.fn() }));
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
  rerender(view({ error: 'offline', onClick: vi.fn() }));
  const node = screen.getByRole('button');
  expect(node).toHaveTextContent('Unavailable');
  expect(node).toHaveStyle({ height: '20px' });
  expect(node).toHaveAccessibleName(/Deployment status unavailable/);
});
it('shows an explicit choice for multiple linked certificates', () => {
  render(view({ certificateCount: 2, onClick: vi.fn() }));
  expect(
    screen.getByRole('button', {
      name: /2 distributed certificates. Select a certificate/,
    })
  ).toHaveTextContent('2 certs');
});
it('does not advertise current verification when an older server snapshot expires', () => {
  render(
    view({
      summary: { total: 3, verified: 3, status: 'unavailable' },
      onClick: vi.fn(),
    })
  );
  expect(screen.getByRole('button')).toHaveTextContent('Needs refresh');
  expect(screen.getByRole('button')).toHaveAccessibleName(
    /Verification needs refresh/
  );
});
