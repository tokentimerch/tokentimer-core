import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import AdcsStep, {
  adcsStatus,
} from '../../src/components/onboarding/certopsAdcsStep.jsx';

vi.mock('../../src/hooks/useDashboardTheme', async importOriginal => ({
  ...(await importOriginal()),
  useDashboardTheme: () => ({ muted: 'gray.500' }),
}));

const agent = {
  livenessState: 'live',
  platform: 'win32',
  declaredCapabilities: ['adcs-enroll-v1'],
};
const safe = { id: 'i1', name: 'Corp CA', confirmed: true, safe: true };

function ctxWith({ adcs, agents = [agent], progress } = {}) {
  return {
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    session: {
      progress: {
        certops: {
          objective: 'adcs',
          infrastructure: 'windows',
          caHost: 'ca01.corp.example.com',
          caName: 'Corp Issuing CA',
          template: 'WebServer',
          ...progress,
        },
      },
    },
    summary: { certops: { adcs, agents: { items: agents } } },
  };
}

const show = ctx =>
  render(
    <ChakraProvider>
      <AdcsStep ctx={ctx} />
    </ChakraProvider>
  );

describe('adcsStatus', () => {
  it('needs a live-agent flag, a confirmed safe issuer and a profile separately', () => {
    expect(adcsStatus({ adcs: undefined, agentDeclares: false })).toMatchObject(
      {
        agent: false,
        issuer: false,
        profile: false,
      }
    );
    expect(
      adcsStatus({
        adcs: { issuers: [safe], profiles: 2 },
        agentDeclares: true,
      })
    ).toMatchObject({ agent: true, issuer: true, profile: true });
  });

  it('does not count an unpinned or unsafe issuer', () => {
    const bad = { id: 'i2', name: 'Bad', confirmed: false, safe: false };
    const s = adcsStatus({
      adcs: { issuers: [bad], profiles: 0 },
      agentDeclares: true,
    });
    expect(s.issuer).toBe(false);
    expect(s.unsafe.map(i => i.name)).toEqual(['Bad']);
  });
});

describe('AdcsStep', () => {
  it('always says enrollment is not verified and has no trailing to-do list', () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 }, agents: [] }));
    expect(screen.getByText(/cannot verify enrollment/i)).toBeTruthy();
    expect(screen.queryByText(/Still to do on your side/i)).toBeNull();
    expect(screen.getAllByText('To do')).toHaveLength(3);
  });

  it('says what the guide cannot do without a testing disclaimer', () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 }, agents: [] }));
    expect(document.body.textContent).toMatch(/start the first enrollment/i);
    expect(document.body.textContent).not.toMatch(/not been verified/i);
  });
  it('shows the exact CA and template the issuer must match', () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 } }));
    expect(
      screen.getByText(/ca01\.corp\.example\.com\\Corp Issuing CA/)
    ).toBeTruthy();
  });

  it('marks each part done only from what the server reports', () => {
    show(ctxWith({ adcs: { issuers: [safe], profiles: 1 } }));
    expect(screen.queryAllByText('To do')).toHaveLength(0);
    expect(screen.getAllByText('Done')).toHaveLength(3);
    // Even with everything present it must not claim enrollment works.
    expect(screen.getByText(/cannot verify enrollment/i)).toBeTruthy();
  });

  it('keeps the agent row open when the agent lacks the capability', () => {
    show(
      ctxWith({
        adcs: { issuers: [safe], profiles: 1 },
        agents: [
          {
            livenessState: 'live',
            platform: 'win32',
            declaredCapabilities: [],
          },
        ],
      })
    );
    expect(screen.getAllByText('To do')).toHaveLength(1);
  });

  it('names an issuer that failed its check', () => {
    show(
      ctxWith({
        adcs: {
          issuers: [{ id: 'x', name: 'Old CA', confirmed: false, safe: false }],
          profiles: 0,
        },
      })
    );
    expect(screen.getByText(/Old CA did not pass the check/)).toBeTruthy();
  });
});
