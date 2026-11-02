import { describe, expect, it } from 'vitest';
import {
  CERTOPS_FLOW,
  shouldShowCertopsBanner,
} from '../../src/components/onboarding/certopsBannerRules.js';

const empty = {
  certops: {
    agents: { total: 0 },
    certificates: { total: 0 },
    adcs: { issuers: [], profiles: 0 },
  },
};
const fresh = { revision: 0, status: 'in_progress', intent: {} };
const base = {
  enabled: true,
  paused: false,
  canManage: true,
  summary: empty,
  session: fresh,
};

describe('shouldShowCertopsBanner', () => {
  it('shows for a manager in a truly empty CertOps workspace', () => {
    expect(shouldShowCertopsBanner(base)).toBe(true);
  });

  it('uses its own flow, apart from the dashboard prompt', () => {
    expect(CERTOPS_FLOW).toBe('certops');
  });

  it('waits for every answer instead of reading unknown as empty', () => {
    expect(shouldShowCertopsBanner({ ...base, enabled: null })).toBe(false);
    expect(shouldShowCertopsBanner({ ...base, enabled: false })).toBe(false);
    expect(shouldShowCertopsBanner({ ...base, summary: null })).toBe(false);
    expect(shouldShowCertopsBanner({ ...base, session: null })).toBe(false);
    expect(
      shouldShowCertopsBanner({ ...base, summary: { certops: 'unknown' } })
    ).toBe(false);
    expect(
      shouldShowCertopsBanner({
        ...base,
        summary: { certops: { agents: {}, certificates: { total: 0 } } },
      })
    ).toBe(false);
    expect(
      shouldShowCertopsBanner({
        ...base,
        summary: {
          certops: { agents: { total: 0 }, certificates: { total: 0 } },
        },
      })
    ).toBe(false);
  });

  it('stays quiet for people who cannot act on it', () => {
    expect(shouldShowCertopsBanner({ ...base, canManage: false })).toBe(false);
  });

  it('leaves the space to the paused warning', () => {
    expect(shouldShowCertopsBanner({ ...base, paused: true })).toBe(false);
  });

  it('stays quiet once anything is set up', () => {
    const withAgent = {
      certops: { ...empty.certops, agents: { total: 1 } },
    };
    const withCert = {
      certops: { ...empty.certops, certificates: { total: 2 } },
    };
    const withIssuer = {
      certops: {
        ...empty.certops,
        adcs: { issuers: [{ id: 'i' }], profiles: 0 },
      },
    };
    for (const summary of [withAgent, withCert, withIssuer]) {
      expect(shouldShowCertopsBanner({ ...base, summary })).toBe(false);
    }
  });

  it('respects a hidden or finished banner', () => {
    for (const status of ['dismissed', 'completed']) {
      expect(
        shouldShowCertopsBanner({ ...base, session: { ...fresh, status } })
      ).toBe(false);
    }
  });
});
