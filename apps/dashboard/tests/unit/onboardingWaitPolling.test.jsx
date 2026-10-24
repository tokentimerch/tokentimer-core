import { act, cleanup, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import { FirstCertificateStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import {
  SUMMARY_POLL_MS,
  WAIT_POLL_MS,
  useSummaryPolling,
  verifyNeedsPolling,
} from '../../src/components/onboarding/useSummaryPolling.js';

vi.mock('../../src/hooks/useDashboardTheme', async importOriginal => ({
  ...(await importOriginal()),
  useDashboardTheme: () => ({ muted: 'gray.500' }),
}));

const setHidden = hidden => {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  });
};

beforeEach(() => {
  vi.useFakeTimers();
  setHidden(false);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  setHidden(false);
});

const tick = ms =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });

function Probe({ refresh, active, ms }) {
  useSummaryPolling(refresh, active, ms);
  return null;
}

describe('useSummaryPolling', () => {
  it('reads on the interval while active and stops when it turns off', async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    const { rerender } = render(<Probe refresh={refresh} active ms={5000} />);
    await tick(15000);
    expect(refresh).toHaveBeenCalledTimes(3);
    rerender(<Probe refresh={refresh} active={false} ms={5000} />);
    await tick(15000);
    expect(refresh).toHaveBeenCalledTimes(3);
  });

  it('skips its turn in a hidden tab and reads once when it is shown', async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    render(<Probe refresh={refresh} active ms={5000} />);
    setHidden(true);
    await tick(20000);
    expect(refresh).not.toHaveBeenCalled();
    setHidden(false);
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('survives a refresh that rejects', async () => {
    const refresh = vi.fn().mockRejectedValue(new Error('offline'));
    render(<Probe refresh={refresh} active ms={5000} />);
    await tick(10000);
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('waits no longer than 15 seconds', () => {
    expect(WAIT_POLL_MS).toBeGreaterThanOrEqual(5000);
    expect(WAIT_POLL_MS).toBeLessThanOrEqual(15000);
    expect(SUMMARY_POLL_MS).toBeLessThanOrEqual(15000);
  });
});

describe('verifyNeedsPolling', () => {
  const check = (id, status) => ({ id, status });
  it('keeps reading while a website has no readable certificate yet', () => {
    expect(
      verifyNeedsPolling({
        checks: [check('certificate:https://a.example', 'warn')],
      })
    ).toBe(true);
  });
  it('stops once the certificate is read, or when the check failed outright', () => {
    expect(
      verifyNeedsPolling({
        checks: [check('certificate:https://a.example', 'pass')],
      })
    ).toBe(false);
    expect(verifyNeedsPolling({ checks: [check('certificate', 'fail')] })).toBe(
      false
    );
  });
});

describe('the first certificate step (Discover)', () => {
  const lin = {
    id: 'a1',
    platform: 'linux',
    livenessState: 'live',
    existedBeforeSession: false,
  };
  const ctxFor = (certificates, refresh = vi.fn().mockResolvedValue()) => ({
    docs: () => [],
    refresh,
    session: {
      intent: { goal: 'certops_observe' },
      progress: { certops: { objective: 'observe', infrastructure: 'linux' } },
    },
    summary: {
      certops: {
        agents: { items: [lin], live: 1 },
        certificates,
      },
    },
  });
  const show = ctx =>
    render(
      <ChakraProvider>
        <FirstCertificateStep ctx={ctx} />
      </ChakraProvider>
    );

  it('checks again by itself while nothing is reported, and says so truthfully', async () => {
    const ctx = ctxFor({ observed: 0, total: 0 });
    show(ctx);
    expect(
      screen.getByText(/This page checks again every 10 seconds/)
    ).toBeVisible();
    await tick(WAIT_POLL_MS - 1);
    expect(ctx.refresh).not.toHaveBeenCalled();
    await tick(1);
    expect(ctx.refresh).toHaveBeenCalledTimes(1);
    await tick(WAIT_POLL_MS * 2);
    expect(ctx.refresh).toHaveBeenCalledTimes(3);
  });

  it('stops once the agent has reported a certificate', async () => {
    const refresh = vi.fn().mockResolvedValue();
    const { rerender } = show(ctxFor({ observed: 0, total: 0 }, refresh));
    await tick(WAIT_POLL_MS);
    expect(refresh).toHaveBeenCalledTimes(1);
    rerender(
      <ChakraProvider>
        <FirstCertificateStep
          ctx={ctxFor({ observed: 2, total: 2 }, refresh)}
        />
      </ChakraProvider>
    );
    expect(screen.getByText('2 certificates in the inventory')).toBeVisible();
    await tick(WAIT_POLL_MS * 3);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('does not read while the tab is hidden', async () => {
    const ctx = ctxFor({ observed: 0, total: 0 });
    show(ctx);
    setHidden(true);
    await tick(WAIT_POLL_MS * 3);
    expect(ctx.refresh).not.toHaveBeenCalled();
  });
});

describe('the Microsoft CA step', () => {
  const agent = {
    livenessState: 'live',
    platform: 'win32',
    declaredCapabilities: ['adcs-enroll-v1'],
  };
  const issuer = {
    id: 'i1',
    name: 'Corp CA',
    confirmed: true,
    safe: true,
    profileCount: 1,
    attachedCertificates: 1,
  };
  const ctxFor = (adcs, refresh = vi.fn().mockResolvedValue()) => ({
    docs: () => [],
    refresh,
    session: {
      progress: {
        certops: {
          objective: 'adcs',
          infrastructure: 'windows',
          caHost: 'ca01.corp.example.com',
          caName: 'Corp Issuing CA',
        },
      },
    },
    summary: { certops: { adcs, agents: { items: [agent] } } },
  });
  const show = ctx =>
    render(
      <ChakraProvider>
        <AdcsStep ctx={ctx} />
      </ChakraProvider>
    );

  it('reads again while the issuer, profile or attachment is missing', async () => {
    const waiting = [
      { issuers: [], profiles: 0 },
      { issuers: [{ ...issuer, profileCount: 0, attachedCertificates: 0 }] },
      { issuers: [{ ...issuer, attachedCertificates: 0 }], profiles: 1 },
    ];
    for (const adcs of waiting) {
      const ctx = ctxFor({ profiles: 0, ...adcs });
      const view = show(ctx);
      await tick(WAIT_POLL_MS);
      expect(ctx.refresh).toHaveBeenCalledTimes(1);
      view.unmount();
    }
  });

  it('stops once everything it watches is in place', async () => {
    const ctx = ctxFor({ issuers: [issuer], profiles: 1 });
    show(ctx);
    await tick(WAIT_POLL_MS * 3);
    expect(ctx.refresh).not.toHaveBeenCalled();
  });

  it('picks up an attachment made elsewhere without a click', async () => {
    const refresh = vi.fn().mockResolvedValue();
    const open = { issuers: [{ ...issuer, attachedCertificates: 0 }] };
    const { rerender } = show(ctxFor({ ...open, profiles: 1 }, refresh));
    expect(screen.queryByTestId('adcs-attached')).toBeNull();
    await tick(WAIT_POLL_MS);
    expect(refresh).toHaveBeenCalledTimes(1);
    rerender(
      <ChakraProvider>
        <AdcsStep ctx={ctxFor({ issuers: [issuer], profiles: 1 }, refresh)} />
      </ChakraProvider>
    );
    expect(screen.getByTestId('adcs-attached')).toBeVisible();
    await tick(WAIT_POLL_MS * 3);
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
