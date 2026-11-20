import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import AdcsPreflightReadiness, {
  preflightReadinessLabel,
} from '../../src/components/certops/AdcsPreflightReadiness.jsx';
import { issuerNeedsRecheck } from '../../src/components/onboarding/adcsModel.js';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
describe('AD CS approval and current readiness', () => {
  it('distinguishes every refresh state', () => {
    for (const [state, label] of Object.entries({
      required: 'Preflight required',
      queued: 'Preflight queued',
      running: 'Preflight running',
      awaiting_approval: 'Preflight waiting for approval',
      agent_unavailable: 'Agent unavailable',
      agent_ineligible: 'Agent incompatible or missing required capability',
      retrying: 'Retrying after temporary failure',
      blocked: 'Blocked / operator action required',
    }))
      expect(preflightReadinessLabel({ state })).toBe(label);
  });
  it('expires evidence while the page stays open and retains CA approval', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-16T12:00:00Z'));
    const expiresAt = new Date(Date.now() + 1000).toISOString();
    render(
      <AdcsPreflightReadiness
        issuer={{
          confirmedKeySha256: 'approved',
          renewalReadiness: {
            checks: [
              {
                agentId: 'agent-a',
                state: 'fresh',
                expiresAt,
                renewalReady: true,
              },
            ],
          },
        }}
      />
    );
    expect(screen.getByText(/Fresh preflight available/)).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(15000));
    expect(screen.getByText(/Preflight required/)).toBeInTheDocument();
    expect(screen.getByText(/CA approved/)).toBeInTheDocument();
  });
  it('shows actionable retry and failure details on the relevant agent', () => {
    render(
      <AdcsPreflightReadiness
        issuer={{
          preflightRefresh: [
            {
              agentId: 'a',
              state: 'retrying',
              nextRefreshAt: '2026-11-16T13:00:00Z',
              code: 'ADCS_CA_UNREACHABLE',
            },
            { agentId: 'b', state: 'blocked', code: 'ADCS_CA_KEY_CHANGED' },
          ],
        }}
      />
    );
    expect(
      screen.getByText(/Next attempt.*when renewal is due/)
    ).toHaveTextContent('ADCS_CA_UNREACHABLE');
    expect(
      screen.getByText(/Changed CA key — explicit approval required/)
    ).toHaveTextContent('ADCS_CA_KEY_CHANGED');
  });
  it('shows a current jobless blocker ahead of unrelated historical evidence', () => {
    render(
      <AdcsPreflightReadiness
        issuer={{
          confirmedKeySha256: 'approved',
          preflightRefresh: [
            {
              agentId: 'unrelated',
              state: 'fresh',
              expiresAt: '2099-01-01T00:00:00Z',
            },
          ],
          renewalReadiness: {
            checks: [
              {
                state: 'agent_unavailable',
                code: 'CERTOPS_ADCS_AGENT_UNAVAILABLE',
                action: 'Restore the owning Windows agent.',
              },
            ],
          },
        }}
      />
    );
    expect(screen.getByText(/Agent unavailable/)).toHaveTextContent(
      'Restore the owning Windows agent.'
    );
    expect(screen.queryByText(/Fresh preflight/)).not.toBeInTheDocument();
    expect(screen.getByText(/CA approved/)).toBeInTheDocument();
  });
  it('does not promote historical evidence into renewal readiness and names policy blockers', () => {
    expect(
      preflightReadinessLabel({
        state: 'fresh',
        expiresAt: '2099-01-01T00:00:00Z',
      })
    ).toContain('eligibility not established');
    for (const [code, label] of Object.entries({
      issuer_not_allowlisted: 'Local enrollment policy blocker',
      ADCS_TEMPLATE_UNSAFE: 'Unsafe certificate template',
      ADCS_CA_CONFIG_UNSAFE: 'Unsafe CA configuration',
      CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED:
        'Retries exhausted — operator action required',
    }))
      expect(preflightReadinessLabel({ state: 'blocked', code })).toBe(label);
  });
  it('requires recheck on onboarding resume after expiry or unsafe supersession', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-16T12:00:00Z'));
    const issuer = {
      confirmed: true,
      checkedAfterPin: true,
      preflightExpiresAt: new Date(Date.now() + 1000).toISOString(),
    };
    expect(issuerNeedsRecheck(issuer)).toBe(false);
    act(() => vi.advanceTimersByTime(1001));
    expect(issuerNeedsRecheck(issuer)).toBe(true);
    expect(issuerNeedsRecheck({ ...issuer, checkedAfterPin: false })).toBe(
      true
    );
  });
});
