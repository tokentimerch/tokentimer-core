import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import {
  ConfigStep,
  ObjectiveStep,
} from '../../src/components/onboarding/certopsSetupSteps.jsx';
import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import { infrastructuresFor } from '../../src/components/onboarding/certopsMatrix.js';
import { ADCS_DRY_RUN_NOTE } from '../../src/components/onboarding/adcsModel.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const WS = '045d89e4-3c97-4029-ab18-fa6f200ebe96';

const docs = (key, label) => [{ label, url: `https://docs.example/${key}` }];

function makeCtx(goal, certops = {}, summary, extra = {}) {
  const session = { intent: { goal }, progress: { certops } };
  return {
    session,
    workspaceId: WS,
    apiUrl: 'https://tt.example.com',
    docs,
    refresh: vi.fn().mockResolvedValue(undefined),
    summary,
    controller: {
      update: vi.fn(mutate => {
        Object.assign(session, mutate(session));
        return Promise.resolve();
      }),
    },
    ...extra,
  };
}

const mount = (Step, ctx) =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <Step ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const adcs = extra => ({
  objective: 'adcs',
  infrastructure: 'windows',
  ...extra,
});
const noAgents = { certops: { agents: { live: 0, total: 0, items: [] } } };

describe('AD CS config step validation display', () => {
  it('shows no errors before the operator has typed anything', () => {
    const { container } = mount(
      ConfigStep,
      makeCtx('certops_adcs', adcs({ template: '' }))
    );
    expect(container.querySelector('[aria-invalid="true"]')).toBeNull();
    expect(screen.queryByText(/Enter at least one name/)).toBeNull();
    expect(screen.queryByText(/Enter the CA server name/)).toBeNull();
    expect(
      screen.getByRole('button', { name: 'I saved this file' })
    ).toBeDisabled();
  });

  it('shows an error after typing or leaving a field', () => {
    mount(ConfigStep, makeCtx('certops_adcs', adcs()));
    const host = screen.getByLabelText(/CA server/);
    fireEvent.change(host, { target: { value: 'ca01..corp' } });
    expect(screen.getByText(/no empty parts/)).toBeInTheDocument();

    const names = screen.getByLabelText(/Names/);
    expect(screen.queryByText(/Enter at least one name/)).toBeNull();
    fireEvent.blur(names);
    expect(screen.getByText(/Enter at least one name/)).toBeInTheDocument();
  });

  it('says why a template with a space is refused', () => {
    mount(ConfigStep, makeCtx('certops_adcs', adcs()));
    fireEvent.change(screen.getByLabelText(/Template/), {
      target: { value: 'Web Server' },
    });
    expect(screen.getByText(/not its display name/)).toBeInTheDocument();
  });

  it('enables the button once every field is valid', () => {
    mount(
      ConfigStep,
      makeCtx(
        'certops_adcs',
        adcs({
          names: 'web.corp.example.com',
          caHost: 'ca01.corp.example.com',
          caName: 'Corp Issuing CA',
          template: 'WebServer',
          dnsScopes: 'corp.example.com',
        })
      )
    );
    expect(
      screen.getByRole('button', { name: 'I saved this file' })
    ).toBeEnabled();
  });
});

describe('AD CS config step copy', () => {
  const filled = adcs({
    names: 'web.corp.example.com',
    caHost: 'ca01.corp.example.com',
    caName: 'Corp Issuing CA',
    template: 'WebServer',
    dnsScopes: 'corp.example.com',
  });

  it('explains dry run and leaves out the Windows ACME text', () => {
    const { container } = mount(ConfigStep, makeCtx('certops_adcs', filled));
    expect(screen.getByTestId('adcs-dry-run-note').textContent).toBe(
      ADCS_DRY_RUN_NOTE
    );
    expect(container.textContent).not.toMatch(/DNS credential/);
    expect(container.textContent).not.toMatch(/Let's Encrypt|Let’s Encrypt/);
    expect(container.textContent).toMatch(/"dryRun": true/);
  });

  it('does not offer the DNS providers link for AD CS but keeps it for ACME', () => {
    const first = mount(ConfigStep, makeCtx('certops_adcs', filled));
    expect(screen.queryByRole('link', { name: 'DNS providers' })).toBeNull();
    expect(
      screen.getByRole('link', { name: 'Agent configuration' })
    ).toBeTruthy();
    first.unmount();

    mount(
      ConfigStep,
      makeCtx('certops_automate', {
        objective: 'automate',
        infrastructure: 'linux',
      })
    );
    expect(screen.getByRole('link', { name: 'DNS providers' })).toBeTruthy();
  });
});

describe('Windows card for AD CS', () => {
  it('states the qualified minimum, not the 2016 floor', () => {
    const win = infrastructuresFor('adcs').find(i => i.id === 'windows');
    expect(win.detail).toMatch(/Server 2019 or later \(build 17763\+\)/);
    expect(win.detail).not.toMatch(/2016|14393/);
    expect(win.detail).toMatch(/domain-joined/);
    expect(win.detail).toMatch(/not a domain controller/);
  });

  it('leaves the observe and ACME wording as it was', () => {
    for (const objective of ['observe', 'automate']) {
      const win = infrastructuresFor(objective).find(i => i.id === 'windows');
      expect(win.detail).toMatch(/Server 2016 or later \(build 14393\+\)/);
    }
  });

  it('renders on the AD CS picker', () => {
    mount(ObjectiveStep, makeCtx('certops_adcs'));
    expect(screen.getByText(/Server 2019 or later/)).toBeInTheDocument();
  });
});

describe('agent step for AD CS', () => {
  const ctxFor = (certops, summary = noAgents) =>
    makeCtx('certops_adcs', adcs(certops), summary);

  it('says up front where the agent must run', () => {
    mount(AgentStep, ctxFor({}));
    const note = screen.getByTestId('adcs-host-note').textContent;
    expect(note).toMatch(/domain-joined Windows Server/);
    expect(note).toMatch(/reach your CA/);
    expect(note).toMatch(/domain controller/);
  });

  it('does not show the domain note for other goals', () => {
    mount(
      AgentStep,
      makeCtx(
        'certops_automate',
        { objective: 'automate', infrastructure: 'linux' },
        noAgents
      )
    );
    expect(screen.queryByTestId('adcs-host-note')).toBeNull();
  });

  it('offers an exit that saves progress, explains the way back, and never completes the step', async () => {
    const ctx = ctxFor({ configReviewed: true });
    mount(AgentStep, ctx);
    fireEvent.click(
      screen.getByRole('button', { name: 'I will install it later' })
    );
    await waitFor(() =>
      expect(screen.getByTestId('install-later')).toBeTruthy()
    );

    const text = screen.getByTestId('install-later').textContent;
    expect(text).toMatch(/setup banner/);
    expect(text).toMatch(/Preferences, Setup guide, Open setup guide/);
    expect(text).not.toMatch(/\/onboarding/);
    expect(ctx.session.progress.certops.agentLaterAt).toBeTruthy();
    // Config and objective survive.
    expect(ctx.session.progress.certops.objective).toBe('adcs');

    const plan = planJourney({
      intent: ctx.session.intent,
      progress: ctx.session.progress,
      capabilities: null,
      reality: noAgents,
    });
    const agent = plan.steps.find(s => s.id === 'certops_agent');
    expect(agent.status).toBe('current');
    expect(plan.skippedSteps).toBeUndefined();
    expect(ctx.session.progress.skipped).toBeUndefined();
  });

  it('can leave the guide from the confirmation', async () => {
    const leaveGuide = vi.fn();
    const ctx = makeCtx('certops_adcs', adcs(), noAgents, { leaveGuide });
    mount(AgentStep, ctx);
    fireEvent.click(
      screen.getByRole('button', { name: 'I will install it later' })
    );
    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Go to Certificate Management',
      })
    );
    expect(leaveGuide).toHaveBeenCalled();
  });

  it('remembers on return that the operator paused here', () => {
    mount(AgentStep, ctxFor({ agentLaterAt: '2026-10-20T10:00:00.000Z' }));
    expect(screen.getByText(/You paused here earlier/)).toBeInTheDocument();
  });

  it('hides the exit once a usable agent is connected', () => {
    const connected = {
      certops: {
        agents: {
          live: 1,
          total: 1,
          items: [
            {
              id: 'a1',
              platform: 'win32',
              livenessState: 'live',
              agentVersion: '0.18.0',
              declaredCapabilities: [
                'windows-cert-store-v1',
                'iis-binding-v1',
                'adcs-enroll-v1',
              ],
            },
          ],
        },
      },
    };
    mount(AgentStep, ctxFor({}, connected));
    expect(
      screen.queryByRole('button', { name: 'I will install it later' })
    ).toBeNull();
  });

  it('shows the install script at its packaged location', () => {
    mount(AgentStep, ctxFor({}));
    expect(
      screen.getByText(/\.\\scripts\\install-agent\.ps1/)
    ).toBeInTheDocument();
  });
});

describe('AD CS step shows the dry-run switch when it applies', () => {
  const safe = { id: 'i1', name: 'Corp CA', confirmed: true, safe: true };

  it('keeps it out of the way until the issuer has passed its check', () => {
    mount(
      AdcsStep,
      makeCtx('certops_adcs', adcs(), { certops: { agents: { items: [] } } })
    );
    expect(screen.queryByTestId('adcs-real-enrollment')).toBeNull();
    expect(screen.queryByText('Still to do on your side')).toBeNull();
  });

  it('names dryRun false, the file and the restart once the issuer passed', () => {
    mount(
      AdcsStep,
      makeCtx('certops_adcs', adcs(), {
        certops: {
          agents: { items: [] },
          adcs: { issuers: [safe], profiles: 0 },
        },
      })
    );
    const box = screen.getByTestId('adcs-real-enrollment');
    expect(box).toHaveTextContent('Turn on real enrollment');
    expect(box).toHaveTextContent('real enrollment is refused');
    expect(box).toHaveTextContent(
      'C:\\ProgramData\\TokenTimerAgent\\state\\config.json'
    );
    expect(box).toHaveTextContent('"dryRun": false');
    expect(box).toHaveTextContent('Restart-Service TokenTimerAgent');
  });
});
