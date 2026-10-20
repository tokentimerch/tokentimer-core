import { render, screen, waitFor, within } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions } = vi.hoisted(() => ({
  actions: { getToken: vi.fn(), soonestToken: vi.fn() },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

import { VerifyStep } from '../../src/components/onboarding/recipientAndVerifySteps.jsx';
import { evaluateVerification } from '../../src/components/onboarding/verification.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const NO_CERT =
  'No certificate could be read yet. TokenTimer keeps checking it.';

const site = (n, extra = {}) => ({
  id: `m-${n}`,
  url: `https://${n}.example.com`,
  tokenId: 10,
  certificateExpiresAt: '2027-03-04T00:00:00Z',
  ...extra,
});
const noCert = n =>
  site(n, { tokenId: null, certificateExpiresAt: null, validated: false });

const summaryOf = (items, extra = {}) => ({
  monitors: { total: items.length, items },
  references: {
    tokenIds: { existing: [10], missing: [] },
    monitorIds: { existing: items.map(i => i.id), missing: [] },
  },
  alerts: { smtpConfigured: true },
  assets: { total: items.length },
  ...extra,
});

function mount({ items, refs, summaryExtra }) {
  const summary = summaryOf(items, summaryExtra);
  const ctx = {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    fetchSummary: vi.fn().mockResolvedValue(summary),
    session: { intent: { goal: 'monitor_https' }, operationRefs: refs },
    controller: { update: vi.fn() },
  };
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <VerifyStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  return ctx;
}

const row = text => screen.getByText(text).closest('div').parentElement;

beforeEach(() => {
  actions.getToken.mockReset().mockResolvedValue({
    alert_state: { eligibility: { eligible_channels: ['email'] } },
  });
  actions.soonestToken.mockReset().mockResolvedValue(null);
});

describe('VerifyStep with several websites', () => {
  it('lists every website of the session with its own certificate line', async () => {
    mount({
      items: [
        site('a'),
        noCert('b'),
        site('c', { certificateExpiresAt: '2028-01-02T00:00:00Z' }),
      ],
      refs: {
        monitorIds: ['m-a', 'm-b', 'm-c'],
        monitorUrl: 'https://a.example.com',
      },
    });
    await screen.findByText('https://a.example.com');
    expect(
      within(row('https://a.example.com')).getByText(/Expires 2027-03-04/)
    ).toBeTruthy();
    expect(
      within(row('https://c.example.com')).getByText(/Expires 2028-01-02/)
    ).toBeTruthy();
    const bad = row('https://b.example.com');
    expect(within(bad).getByText(NO_CERT)).toBeTruthy();
    expect(within(bad).getByText('Follow up')).toBeTruthy();
    expect(screen.getAllByText('OK').length).toBeGreaterThanOrEqual(2);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Finish setup' })).toBeEnabled()
    );
  });

  it('does not let the first address of the batch decide the result', async () => {
    mount({
      items: [noCert('first'), site('second')],
      refs: {
        monitorIds: ['m-first', 'm-second'],
        monitorUrl: 'https://first.example.com',
      },
    });
    await screen.findByText('https://second.example.com');
    expect(
      within(row('https://second.example.com')).getByText(/Expires 2027-03-04/)
    ).toBeTruthy();
    expect(
      within(row('https://first.example.com')).getByText(NO_CERT)
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Finish setup' })).toBeEnabled();
  });

  it('is not OK when no website has a readable certificate', async () => {
    mount({
      items: [noCert('a'), noCert('b')],
      refs: { monitorIds: ['m-a', 'm-b'], monitorUrl: 'https://a.example.com' },
    });
    await screen.findByText('https://a.example.com');
    expect(screen.getAllByText(NO_CERT)).toHaveLength(2);
    expect(screen.getByText('Needs attention')).toBeTruthy();
    expect(
      screen.queryByText('Certificate was read from the website')
    ).toBeNull();
    expect(screen.getByRole('button', { name: 'Finish setup' })).toBeDisabled();
  });

  it('ignores monitors that belong to other sessions', async () => {
    mount({
      items: [site('mine'), noCert('other')],
      refs: { monitorIds: ['m-mine'], monitorUrl: 'https://mine.example.com' },
    });
    await screen.findByText(/Expires 2027-03-04/);
    expect(screen.queryByText('https://other.example.com')).toBeNull();
    expect(screen.queryByText(NO_CERT)).toBeNull();
  });

  it('keeps the alert recipient and email delivery checks', async () => {
    mount({
      items: [site('a'), noCert('b')],
      refs: { monitorIds: ['m-a', 'm-b'] },
      summaryExtra: { alerts: { smtpConfigured: false } },
    });
    expect(await screen.findByText('Alerts have a recipient')).toBeTruthy();
    expect(screen.getByText('Email delivery is not set up yet')).toBeTruthy();
    expect(actions.getToken).toHaveBeenCalledWith(10);
  });
});

describe('evaluateVerification for websites', () => {
  const base = { goal: 'monitor_https', token: null, summary: {} };
  const status = (r, id) => r.checks.find(c => c.id === id)?.status;

  it('keeps the single website wording and result', () => {
    const ok = evaluateVerification({ ...base, monitors: [site('a')] });
    expect(ok.checks.find(c => c.id === 'certificate').label).toBe(
      'Certificate was read from the website'
    );
    expect(ok.ok).toBe(true);
    const none = evaluateVerification({ ...base, monitors: [noCert('a')] });
    expect(status(none, 'certificate')).toBe('fail');
    expect(none.ok).toBe(false);
  });

  it('passes with one readable certificate among unreadable ones', () => {
    const r = evaluateVerification({
      ...base,
      monitors: [noCert('a'), site('b'), noCert('c')],
    });
    expect(status(r, 'certificate:https://a.example.com')).toBe('warn');
    expect(status(r, 'certificate:https://b.example.com')).toBe('pass');
    expect(status(r, 'certificate')).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('fails when none of several websites has a certificate', () => {
    const r = evaluateVerification({
      ...base,
      monitors: [noCert('a'), noCert('b')],
    });
    expect(status(r, 'certificate')).toBe('fail');
    expect(r.ok).toBe(false);
  });

  it('flags a readable certificate that was never tracked as an asset', () => {
    const r = evaluateVerification({
      ...base,
      monitors: [site('a', { tokenId: null }), site('b')],
    });
    expect(status(r, 'asset:https://a.example.com')).toBe('fail');
    expect(r.ok).toBe(false);
  });

  it('says when some of the session websites could not be listed', () => {
    const r = evaluateVerification({
      ...base,
      monitors: [site('a')],
      unlistedMonitors: 3,
    });
    expect(r.checks.find(c => c.id === 'unlisted').label).toBe(
      '3 more websites are not listed here'
    );
    expect(r.ok).toBe(true);
  });

  it('still accepts the legacy single monitor input', () => {
    const r = evaluateVerification({ ...base, monitor: site('a') });
    expect(r.ok).toBe(true);
  });
});
