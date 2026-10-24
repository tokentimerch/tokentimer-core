import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ObjectiveStep } from '../../src/components/onboarding/certopsSetupSteps.jsx';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { realAgent } from './helpers/realAgentPayload.js';

afterEach(cleanup);

const caps = {
  items: [
    { id: 'certops.core', state: 'ready' },
    { id: 'alerts.contact_groups', state: 'ready' },
  ],
};

const lin = realAgent('linux', {
  id: 'lin-row',
  name: 'web-01',
  hostname: 'web-01',
  commandProfiles: ['certbot'],
  existedBeforeSession: true,
});
const win = realAgent('win32', {
  id: 'win-row',
  name: 'WIN-CA01',
  hostname: 'WIN-CA01',
  existedBeforeSession: true,
});

const LABEL = {
  linux: /Linux server/,
  windows: /Windows Server/,
  kubernetes: /Kubernetes with cert-manager/,
};

function harness({ goal, certops = {}, items }) {
  let session = {
    intent: { goal },
    progress: { certops },
    operationRefs: {},
  };
  const ctx = {
    get session() {
      return session;
    },
    summary: {
      alerts: { smtpConfigured: true },
      certops: items
        ? {
            agents: {
              live: items.filter(a => a.livenessState === 'live').length,
              items,
            },
            controllers: { clusters: [] },
          }
        : 'unknown',
    },
    docs: () => [],
    release: vi.fn(),
    onDone: vi.fn(),
    refresh: vi.fn().mockResolvedValue(undefined),
    controller: {
      update: vi.fn(mutate => {
        session = { ...session, ...mutate(session) };
        return Promise.resolve();
      }),
    },
  };
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <ObjectiveStep ctx={ctx} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  return { ctx, saved: () => session.progress.certops };
}

const pickRadio = infra =>
  fireEvent.click(screen.getByRole('radio', { name: LABEL[infra] }));
const checkbox = () =>
  screen.queryByRole('checkbox', { name: 'My agent is already set up' });
const dropdown = () =>
  screen.queryByRole('combobox', { name: 'Choose your agent' });
const optionFor = name =>
  Array.from(dropdown().querySelectorAll('option')).find(o =>
    o.textContent.startsWith(name)
  );
const cont = () => screen.getByRole('button', { name: 'Continue' });

// Every pick that runs on an agent, with the agent that fits it.
const AGENT_PICKS = [
  ['certops_observe', 'observe', 'linux', lin],
  ['certops_observe', 'observe', 'windows', win],
  ['certops_automate', 'automate', 'linux', lin],
  ['certops_vault', 'vault', 'linux', lin],
  [
    'certops_automate',
    'automate',
    'windows',
    { ...win, commandProfiles: ['acme-windows'] },
  ],
  ['certops_adcs', 'adcs', 'windows', win],
];

describe('the existing agent choice on Where will the certificates live?', () => {
  it.each(AGENT_PICKS)(
    '%s on %s offers the checkbox and only the fitting agent',
    (goal, objective, infra, fits) => {
      const other = infra === 'linux' ? win : lin;
      harness({ goal, items: [other, fits] });
      expect(checkbox()).toBeNull();
      pickRadio(infra);
      expect(checkbox()).toBeEnabled();
      expect(dropdown()).toBeNull();
      fireEvent.click(checkbox());
      expect(optionFor(fits.name).disabled).toBe(false);
      const wrong = optionFor(other.name);
      expect(wrong.disabled).toBe(true);
      expect(wrong.textContent).toMatch(
        infra === 'linux'
          ? /Windows agent, this setup needs Linux/
          : /Linux agent, this setup needs Windows/
      );
    }
  );

  it('the checkbox starts unticked: reuse is opt-in', () => {
    harness({
      goal: 'certops_observe',
      certops: { objective: 'observe', infrastructure: 'linux' },
      items: [lin],
    });
    expect(checkbox()).not.toBeChecked();
    expect(dropdown()).toBeNull();
  });

  it('Kubernetes never offers it', () => {
    harness({ goal: 'certops_observe', items: [lin, win] });
    pickRadio('kubernetes');
    expect(checkbox()).toBeNull();
  });

  it('an API that does not list agents shows no checkbox', () => {
    harness({ goal: 'certops_observe' });
    pickRadio('linux');
    expect(checkbox()).toBeNull();
    expect(cont()).toBeEnabled();
  });

  it('with no fitting agent the checkbox is disabled and says why', () => {
    harness({ goal: 'certops_observe', items: [win] });
    pickRadio('linux');
    expect(checkbox()).toBeDisabled();
    expect(screen.getByTestId('no-fitting-agent').textContent).toBe(
      'No fitting agent found in this workspace yet.'
    );
    expect(cont()).toBeEnabled();
  });

  it('a missing capability is listed disabled with the reason', () => {
    const weak = {
      ...win,
      declaredCapabilities: ['windows-cert-store-v1', 'iis-binding-v1'],
    };
    harness({
      goal: 'certops_adcs',
      items: [weak, { ...win, id: 'w2', name: 'CA-02', hostname: 'CA-02' }],
    });
    pickRadio('windows');
    fireEvent.click(checkbox());
    const bad = optionFor('WIN-CA01');
    expect(bad.disabled).toBe(true);
    expect(bad.textContent).toMatch(/Missing capability: adcs-enroll-v1/);
    expect(optionFor('CA-02').disabled).toBe(false);
  });

  it('shows name, platform, liveness and version', () => {
    harness({ goal: 'certops_observe', items: [lin] });
    pickRadio('linux');
    fireEvent.click(checkbox());
    expect(optionFor('web-01').textContent).toBe(
      'web-01 (Linux, live, v0.18.0)'
    );
  });

  it('Continue waits for a choice once the box is ticked', () => {
    harness({ goal: 'certops_observe', items: [lin] });
    pickRadio('linux');
    fireEvent.click(checkbox());
    expect(cont()).toBeDisabled();
    fireEvent.change(dropdown(), { target: { value: 'lin-row' } });
    expect(cont()).toBeEnabled();
  });

  it('an offline agent is selectable with a warning that the guide waits', () => {
    harness({
      goal: 'certops_observe',
      items: [{ ...lin, livenessState: 'offline' }],
    });
    pickRadio('linux');
    fireEvent.click(checkbox());
    expect(optionFor('web-01').disabled).toBe(false);
    expect(optionFor('web-01').textContent).toMatch(/offline, last seen/);
    fireEvent.change(dropdown(), { target: { value: 'lin-row' } });
    expect(screen.getByTestId('agent-offline-warning').textContent).toMatch(
      /waits for it to come online/
    );
    expect(cont()).toBeEnabled();
  });

  it('saves the choice in the session progress on Continue', async () => {
    const h = harness({ goal: 'certops_observe', items: [lin] });
    pickRadio('linux');
    fireEvent.click(checkbox());
    fireEvent.change(dropdown(), { target: { value: 'lin-row' } });
    fireEvent.click(cont());
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    expect(h.saved()).toMatchObject({
      objective: 'observe',
      infrastructure: 'linux',
      chosenAgentId: 'lin-row',
    });
    expect(h.saved().chosenAgentConfirmed).toBeUndefined();
  });

  it('without the checkbox nothing is saved', async () => {
    const h = harness({ goal: 'certops_observe', items: [lin] });
    pickRadio('linux');
    fireEvent.click(cont());
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    expect(h.saved().chosenAgentId).toBeUndefined();
  });

  it('unticking clears a saved choice', async () => {
    const h = harness({
      goal: 'certops_observe',
      certops: {
        objective: 'observe',
        infrastructure: 'linux',
        chosenAgentId: 'lin-row',
        chosenAgentConfirmed: 'lin-row',
      },
      items: [lin],
    });
    expect(checkbox()).toBeChecked();
    expect(dropdown().value).toBe('lin-row');
    fireEvent.click(checkbox());
    expect(dropdown()).toBeNull();
    fireEvent.click(cont());
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    expect(h.saved().chosenAgentId).toBeUndefined();
    expect(h.saved().chosenAgentConfirmed).toBeUndefined();
  });

  it('switching the pick resets the choice, in the form and in the session', async () => {
    const h = harness({
      goal: 'certops_observe',
      certops: {
        objective: 'observe',
        infrastructure: 'linux',
        chosenAgentId: 'lin-row',
      },
      items: [lin, win],
    });
    expect(checkbox()).toBeChecked();
    pickRadio('windows');
    expect(checkbox()).not.toBeChecked();
    expect(dropdown()).toBeNull();
    fireEvent.click(cont());
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    expect(h.saved().infrastructure).toBe('windows');
    expect(h.saved().chosenAgentId).toBeUndefined();
  });

  it('the planner then ignores the old agent for the new pick', async () => {
    const h = harness({
      goal: 'certops_observe',
      certops: {
        objective: 'observe',
        infrastructure: 'linux',
        chosenAgentId: 'lin-row',
        chosenAgentConfirmed: 'lin-row',
        configReviewed: true,
      },
      items: [lin, win],
    });
    pickRadio('windows');
    fireEvent.click(cont());
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    const p = planJourney({
      intent: { goal: 'certops_observe' },
      progress: { certops: { ...h.saved(), configReviewed: true } },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 2, items: [lin, win] } },
      },
    });
    expect(p.steps.find(s => s.id === 'certops_agent').status).not.toBe('done');
  });
});
