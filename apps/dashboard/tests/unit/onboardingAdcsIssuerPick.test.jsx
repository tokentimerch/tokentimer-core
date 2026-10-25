import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import {
  candidateIssuers,
  issuerNeedsRecheck,
  scopeAdcs,
} from '../../src/components/onboarding/adcsModel.js';
import {
  chooseInfrastructure,
  chooseIssuer,
  scopeCertops,
} from '../../src/components/onboarding/certopsScope.js';
import {
  isStepSatisfied,
  planJourney,
} from '../../src/components/onboarding/journeyPlanner.js';
import { finishesByItself } from '../../src/components/onboarding/heldSteps.js';
import { evaluateVerification } from '../../src/components/onboarding/verification.js';
import { adcsRecheckLink } from '../../src/components/certops/adcsIssuerLink.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const ISSUER_A = '11111111-1111-4111-8111-111111111111';
const ISSUER_B = '22222222-2222-4222-8222-222222222222';

const issuer = (id, over = {}) => ({
  id,
  name: id === ISSUER_A ? 'Old CA' : 'New CA',
  confirmed: true,
  safe: true,
  existedBeforeSession: false,
  profileCount: 1,
  attachedCertificates: 1,
  checkedAfterPin: true,
  revalidationRequired: false,
  caConfig: 'ca01.corp.example.com\\Corp CA',
  template: 'WebServer',
  ...over,
});
const old = over => issuer(ISSUER_A, { existedBeforeSession: true, ...over });
const fresh = over => issuer(ISSUER_B, over);
const agent = {
  id: 'ag1',
  livenessState: 'live',
  platform: 'win32',
  declaredCapabilities: ['adcs-enroll-v1'],
  existedBeforeSession: false,
};
const reality = issuers => ({
  certops: {
    agents: { items: [agent], live: 1 },
    adcs: {
      issuers,
      profiles: issuers.reduce((n, i) => n + i.profileCount, 0),
    },
  },
});
const saved = (over = {}) => ({
  objective: 'adcs',
  infrastructure: 'windows',
  ...over,
});
const done = (issuers, over) =>
  isStepSatisfied('certops_adcs', {
    reality: reality(issuers),
    progress: { certops: saved(over) },
    objective: 'adcs',
    goal: 'certops_adcs',
  });

describe('issuers a session may use', () => {
  it('without an opt-in only issuers made in this session count', () => {
    expect(candidateIssuers([old(), fresh()]).map(i => i.id)).toEqual([
      ISSUER_B,
    ]);
  });

  it('with an opt-in only the chosen issuer counts', () => {
    expect(candidateIssuers([old(), fresh()], ISSUER_A).map(i => i.id)).toEqual(
      [ISSUER_A]
    );
    expect(candidateIssuers([old(), fresh()], 'nope')).toEqual([]);
  });

  it('reads an API that does not say as all new', () => {
    const plain = { id: 'x', confirmed: true, safe: true };
    expect(candidateIssuers([plain])).toHaveLength(1);
  });

  it('counts the profiles of the usable issuers only', () => {
    const scoped = scopeAdcs(
      {
        issuers: [old({ profileCount: 2 }), fresh({ profileCount: 0 })],
        profiles: 2,
      },
      ''
    );
    expect(scoped.profiles).toBe(0);
    expect(
      scopeAdcs({ issuers: [old({ profileCount: 2 })], profiles: 2 }, ISSUER_A)
        .profiles
    ).toBe(2);
  });

  it('keeps the workspace profile count from a server that does not split it', () => {
    const scoped = scopeAdcs(
      { issuers: [{ id: 'x', confirmed: true, safe: true }], profiles: 3 },
      ''
    );
    expect(scoped.profiles).toBe(3);
    expect(scoped.attached).toBeNull();
  });

  it('asks for a new check only when the server says so', () => {
    expect(issuerNeedsRecheck(issuer('a', { checkedAfterPin: false }))).toBe(
      true
    );
    expect(
      issuerNeedsRecheck(issuer('a', { revalidationRequired: true }))
    ).toBe(true);
    expect(issuerNeedsRecheck(issuer('a'))).toBe(false);
    expect(issuerNeedsRecheck({ id: 'a', confirmed: true, safe: true })).toBe(
      false
    );
    expect(
      issuerNeedsRecheck(
        issuer('a', { confirmed: false, checkedAfterPin: false })
      )
    ).toBe(false);
  });
});

describe('Connect your Microsoft CA in the planner', () => {
  it('stays open when the only issuer was there before the session', () => {
    expect(done([old()])).toBe(false);
  });

  it('is satisfied by an issuer made in this session with a profile', () => {
    expect(done([old(), fresh()])).toBe(true);
    expect(done([fresh({ profileCount: 0 })])).toBe(false);
  });

  it('does not count a profile that belongs to an older issuer', () => {
    expect(done([old({ profileCount: 3 }), fresh({ profileCount: 0 })])).toBe(
      false
    );
  });

  it('is satisfied by a chosen issuer only after Continue confirms it', () => {
    expect(done([old()], { chosenIssuerId: ISSUER_A })).toBe(false);
    expect(
      done([old()], {
        chosenIssuerId: ISSUER_A,
        chosenIssuerConfirmed: ISSUER_A,
      })
    ).toBe(true);
  });

  it('ignores a confirmation that was about another issuer', () => {
    expect(
      done([old(), fresh()], {
        chosenIssuerId: ISSUER_A,
        chosenIssuerConfirmed: ISSUER_B,
      })
    ).toBe(false);
  });

  it('needs the chosen issuer to be pinned and safe', () => {
    expect(
      done([old({ confirmed: false })], {
        chosenIssuerId: ISSUER_A,
        chosenIssuerConfirmed: ISSUER_A,
      })
    ).toBe(false);
    expect(
      done([old({ safe: false })], {
        chosenIssuerId: ISSUER_A,
        chosenIssuerConfirmed: ISSUER_A,
      })
    ).toBe(false);
  });

  it('keeps the step on the Microsoft CA when the second issuer is still to do', () => {
    const plan = planJourney({
      intent: { goal: 'certops_adcs' },
      progress: {
        certops: saved({ configReviewed: true }),
      },
      reality: reality([old()]),
    });
    expect(plan.steps.find(s => s.id === 'certops_adcs').status).not.toBe(
      'done'
    );
  });
});

describe('the issuer choice', () => {
  it('is saved for the Microsoft CA goal and cleared on untick', () => {
    const a = chooseIssuer(saved(), 'adcs', ISSUER_A);
    expect(a.chosenIssuerId).toBe(ISSUER_A);
    const none = chooseIssuer(a, 'adcs', null);
    expect(none.chosenIssuerId).toBeUndefined();
  });

  it('drops the confirmation when another issuer is picked', () => {
    const a = chooseIssuer(saved(), 'adcs', ISSUER_A);
    const confirmed = { ...a, chosenIssuerConfirmed: ISSUER_A };
    expect(
      chooseIssuer(confirmed, 'adcs', ISSUER_A).chosenIssuerConfirmed
    ).toBe(ISSUER_A);
    expect(
      chooseIssuer(confirmed, 'adcs', ISSUER_B).chosenIssuerConfirmed
    ).toBeUndefined();
  });

  it('is reset when the pick changes', () => {
    const picked = {
      ...saved(),
      chosenIssuerId: ISSUER_A,
      chosenIssuerConfirmed: ISSUER_A,
    };
    const next = chooseInfrastructure(picked, 'adcs', 'linux');
    expect(next.chosenIssuerId).toBeUndefined();
    expect(next.chosenIssuerConfirmed).toBeUndefined();
    expect(chooseInfrastructure(picked, 'adcs', 'windows').chosenIssuerId).toBe(
      ISSUER_A
    );
  });

  it('does not leak into another goal', () => {
    const picked = { ...saved(), chosenIssuerId: ISSUER_A };
    expect(scopeCertops(picked, 'observe').chosenIssuerId).toBeUndefined();
  });

  it('waits for Continue only when an issuer was chosen', () => {
    const goal = 'certops_adcs';
    expect(finishesByItself('certops_adcs', { goal, progress: {} })).toBe(true);
    expect(
      finishesByItself('certops_adcs', {
        goal,
        progress: { certops: saved({ chosenIssuerId: ISSUER_A }) },
      })
    ).toBe(false);
  });
});

describe('verification of the Microsoft CA goal', () => {
  const run = (issuers, issuerId) =>
    evaluateVerification({
      goal: 'certops_adcs',
      summary: reality(issuers),
      infrastructure: 'windows',
      issuerId,
    }).checks.find(c => c.id === 'adcs');

  it('does not call an older issuer the one the guide set up', () => {
    expect(run([old()]).label).toMatch(/issuer or profile is missing/);
    expect(run([old()], ISSUER_A).label).toMatch(/enrollment is not verified/);
    expect(run([fresh()]).label).toMatch(/enrollment is not verified/);
  });
});

describe('re-check link', () => {
  it('opens one issuer on the Renewals page', () => {
    expect(adcsRecheckLink({ workspaceId: 'ws', issuerId: ISSUER_A })).toBe(
      `/certops/renewals?workspace=ws&action=check-adcs-issuer&issuerId=${ISSUER_A}`
    );
  });
});

// The step itself.
function ctxFor(issuers, savedOver = {}, extra = {}) {
  const session = {
    intent: { goal: 'certops_adcs' },
    progress: {
      certops: saved({
        caHost: 'ca01.corp.example.com',
        caName: 'Corp Issuing CA',
        template: 'WebServer',
        ...savedOver,
      }),
    },
  };
  return {
    session,
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    summary: reality(issuers),
    controller: {
      update: vi.fn(async mutate => {
        Object.assign(session, mutate(session));
      }),
    },
    ...extra,
  };
}

const show = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <AdcsStep ctx={ctx} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('Connect your Microsoft CA with an issuer from before', () => {
  it('offers to add a new issuer and does not call the old one done', () => {
    show(ctxFor([old()]));
    expect(screen.getByTestId('adcs-add-issuer')).toBeEnabled();
    expect(screen.queryByTestId('adcs-issuer-ready')).toBeNull();
    expect(screen.getByTestId('existing-issuers-note')).toHaveTextContent(
      '1 issuer is already in this workspace'
    );
    expect(screen.queryByRole('combobox')).toBeNull();
  });

  it('lists the old issuer only after the box is ticked, then asks Continue to confirm it', async () => {
    const ctx = ctxFor([old()]);
    const { rerender } = show(ctx);
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'My Microsoft CA issuer is already set up',
      })
    );
    const select = await screen.findByLabelText('Choose your issuer');
    fireEvent.change(select, { target: { value: ISSUER_A } });
    await waitFor(() =>
      expect(
        scopeCertops(ctx.session.progress.certops, 'adcs').chosenIssuerId
      ).toBe(ISSUER_A)
    );
    rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <AdcsStep ctx={{ ...ctx }} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(await screen.findByTestId('adcs-issuer-ready')).toHaveTextContent(
      'Old CA passed the CA check'
    );
    const next = screen.getByTestId('adcs-use-issuer');
    expect(next).toBeEnabled();
    fireEvent.click(next);
    await waitFor(() =>
      expect(
        scopeCertops(ctx.session.progress.certops, 'adcs').chosenIssuerConfirmed
      ).toBe(ISSUER_A)
    );
  });

  it('holds Continue while the chosen issuer has no profile yet', () => {
    show(
      ctxFor([old({ profileCount: 0, attachedCertificates: 0 })], {
        chosenIssuerId: ISSUER_A,
      })
    );
    expect(screen.getByTestId('adcs-use-issuer')).toBeDisabled();
  });

  it('only lists issuers that passed and are pinned', () => {
    show(
      ctxFor([old(), old({ id: ISSUER_B, name: 'Bad', safe: false })], {
        chosenIssuerId: ISSUER_A,
      })
    );
    const options = screen.getAllByRole('option').map(o => o.textContent);
    expect(options.join(' ')).toMatch(/Old CA/);
    expect(options.join(' ')).not.toMatch(/Bad/);
  });

  it('shows no pick at all when the workspace has no usable older issuer', () => {
    show(ctxFor([fresh()]));
    expect(screen.queryByTestId('existing-issuer-pick')).toBeNull();
  });

  it('gives the profile dialog only the issuer of this session', () => {
    show(ctxFor([old(), fresh({ profileCount: 0 })]));
    expect(screen.getByTestId('adcs-issuer-ready')).toHaveTextContent('New CA');
    expect(screen.getByTestId('adcs-add-profile')).toBeEnabled();
  });
});

describe('Connect your Microsoft CA merged instructions', () => {
  it('puts the domain join and the Enroll permission before the issuer dialog', () => {
    show(ctxFor([]));
    const ready = screen.getByRole('region', { name: 'Have these ready' });
    expect(ready).toHaveTextContent(
      'joined to the domain (not a domain controller)'
    );
    expect(ready).toHaveTextContent(
      'Enroll on the template for its computer account'
    );
    expect(
      ready.compareDocumentPosition(screen.getByTestId('adcs-add-issuer'))
    ).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
  });

  it('runs the post-pin check in the guide and blocks profile setup until it passes', () => {
    show(ctxFor([fresh({ checkedAfterPin: false })]));
    const panel = screen.getByTestId('adcs-issuer-recheck');
    expect(panel).toHaveTextContent('Renewal needs a CA check taken after');
    expect(
      screen.getByRole('button', { name: 'Run post-pin check' })
    ).toBeEnabled();
    expect(
      screen.queryByRole('link', { name: 'Open New CA in Renewals' })
    ).toBeNull();
    expect(done([fresh({ checkedAfterPin: false })])).toBe(false);
    expect(done([fresh({ revalidationRequired: true })])).toBe(false);
    expect(screen.queryByTestId('adcs-real-enrollment')).toBeNull();
  });

  it('does not ask once the check came after the pin, or on an older server', () => {
    const first = show(ctxFor([fresh()]));
    expect(screen.queryByTestId('adcs-issuer-recheck')).toBeNull();
    first.unmount();
    show(ctxFor([fresh({ checkedAfterPin: undefined })]));
    expect(screen.queryByTestId('adcs-issuer-recheck')).toBeNull();
  });

  it('shows the profile as a state that follows reality', () => {
    const first = show(ctxFor([fresh({ attachedCertificates: 0 })]));
    const row = screen.getByRole('region', {
      name: '4. Profile attached to the site certificate',
    });
    expect(row).toHaveTextContent('To do');
    expect(
      screen.getByRole('link', { name: 'Open Certificate Management' })
    ).toBeVisible();
    first.unmount();
    show(ctxFor([fresh()]));
    expect(screen.getByTestId('adcs-attached')).toHaveTextContent(
      'Watch the first enrollment in Certificate Management'
    );
  });

  it('claims nothing about the attachment from a server that does not report it', () => {
    show(
      ctxFor([
        {
          id: ISSUER_B,
          name: 'New CA',
          confirmed: true,
          safe: true,
        },
      ])
    );
    expect(
      screen.queryByRole('region', {
        name: '4. Profile attached to the site certificate',
      })
    ).toBeNull();
  });

  it('has no trailing list of leftovers', () => {
    show(ctxFor([fresh()]));
    expect(screen.queryByText('Still to do on your side')).toBeNull();
    expect(document.body.textContent).not.toMatch(
      /Join the Windows server to the domain/
    );
  });
});
