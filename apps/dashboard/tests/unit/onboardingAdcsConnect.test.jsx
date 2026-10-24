import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ issuerProps: null, paused: false }));

vi.mock('../../src/hooks/useDashboardTheme', async importOriginal => ({
  ...(await importOriginal()),
  useDashboardTheme: () => ({ muted: 'gray.500' }),
}));
vi.mock('../../src/components/certops/AdcsIssuerWizard.jsx', () => ({
  default: props => {
    h.issuerProps = props;
    return (
      <div role='dialog' aria-label='New AD CS issuer'>
        <button type='button' onClick={props.onClose}>
          close issuer
        </button>
      </div>
    );
  },
}));
vi.mock('../../src/components/certops/AdcsProfileWizard.jsx', () => ({
  default: props => (
    <div role='dialog' aria-label='New AD CS profile'>
      <button type='button' onClick={props.onClose}>
        close profile
      </button>
    </div>
  ),
}));
vi.mock('../../src/components/certops/certopsEnrollmentsApi.js', () => ({
  listIssuers: async () => ({ items: [] }),
}));
vi.mock('../../src/components/certops/certopsApi.js', () => ({
  getWorkspaceCertOpsPauseState: async () => ({ certOpsPaused: h.paused }),
}));

import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import {
  adcsIssuerState,
  adcsFailureAdvice,
} from '../../src/components/onboarding/adcsModel.js';

const agent = {
  id: 'row-1',
  name: 'win-01',
  hostname: 'win-01',
  livenessState: 'live',
  platform: 'win32',
  declaredCapabilities: [
    'windows-cert-store-v1',
    'iis-binding-v1',
    'adcs-enroll-v1',
  ],
};
const ready = {
  id: 'i1',
  name: 'Corp CA',
  confirmed: true,
  safe: true,
  checked: true,
  caConfig: 'ca01.corp.example.com\\Corp Issuing CA',
  template: 'WebServer',
  reasons: [],
};
const failed = {
  id: 'i2',
  name: 'Corp CA',
  confirmed: false,
  safe: false,
  checked: true,
  caConfig: 'ca01.corp.example.com\\Corp Issuing CA',
  template: 'WebServer',
  reasons: ['template_not_found'],
};

function ctxWith({ adcs, agents = [agent], capabilities } = {}) {
  return {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    capabilities,
    session: {
      progress: {
        certops: {
          objective: 'adcs',
          infrastructure: 'windows',
          caHost: 'ca01.corp.example.com',
          caName: 'Corp Issuing CA',
          template: 'WebServer',
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

beforeEach(() => {
  h.issuerProps = null;
  h.paused = false;
});

describe('adcsIssuerState', () => {
  it('reads none, pending, failed, unpinned and ready from the summary', () => {
    expect(adcsIssuerState({ issuers: [] }).kind).toBe('none');
    expect(
      adcsIssuerState({ issuers: [{ ...failed, checked: false }] }).kind
    ).toBe('pending');
    expect(adcsIssuerState({ issuers: [failed] }).kind).toBe('failed');
    expect(
      adcsIssuerState({ issuers: [{ ...ready, confirmed: false }] }).kind
    ).toBe('unpinned');
    expect(adcsIssuerState({ issuers: [failed, ready] }).kind).toBe('ready');
  });

  it('keeps the exact reason and the CA pair for a failed check', () => {
    expect(adcsFailureAdvice(failed)).toMatchObject({
      reasons: ['template_not_found'],
      pair: 'ca01.corp.example.com\\Corp Issuing CA with template WebServer',
    });
  });
});

describe('Connect your Microsoft CA step', () => {
  it('offers to add the issuer and lists what to have ready', async () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 } }));
    expect(screen.getByText('Have these ready')).toBeVisible();
    expect(
      screen.getByText(/CA: ca01\.corp\.example\.com\\Corp Issuing CA/)
    ).toBeVisible();
    expect(screen.getByText(/Agent: win-01/)).toBeVisible();
    const button = await screen.findByTestId('adcs-add-issuer');
    expect(button).toBeEnabled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('opens the issuer dialog in place with the agent and CA preselected', async () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 } }));
    fireEvent.click(await screen.findByTestId('adcs-add-issuer'));
    expect(
      screen.getByRole('dialog', { name: 'New AD CS issuer' })
    ).toBeVisible();
    expect(h.issuerProps).toMatchObject({
      workspaceId: 'ws-1',
      initialAgentId: 'row-1',
      initialCaConfig: 'ca01.corp.example.com\\Corp Issuing CA',
      initialTemplate: 'WebServer',
    });
  });

  it('refreshes the summary when the dialog closes', async () => {
    const ctx = ctxWith({ adcs: { issuers: [], profiles: 0 } });
    show(ctx);
    fireEvent.click(await screen.findByTestId('adcs-add-issuer'));
    fireEvent.click(screen.getByText('close issuer'));
    expect(ctx.refresh).toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('says why the check failed and what to do, and stays actionable', async () => {
    show(ctxWith({ adcs: { issuers: [failed], profiles: 0 } }));
    const panel = screen.getByTestId('adcs-issuer-failed');
    expect(panel.textContent).toMatch(/did not pass the check/);
    expect(panel.textContent).toMatch(/Reason: template_not_found/);
    expect(panel.textContent).toMatch(/enrollment rule names the same pair/);
    const button = await screen.findByTestId('adcs-add-issuer');
    expect(button).toHaveTextContent('Add the issuer again');
    expect(button).toBeEnabled();
  });

  it('explains an issuer whose check has not reported', () => {
    show(
      ctxWith({
        adcs: {
          issuers: [{ ...failed, checked: false, reasons: [] }],
          profiles: 0,
        },
      })
    );
    expect(screen.getByTestId('adcs-issuer-pending').textContent).toMatch(
      /has not reported a verdict/
    );
  });

  it('shows the passed check and hides the add button', () => {
    show(ctxWith({ adcs: { issuers: [ready], profiles: 0 } }));
    expect(screen.getByTestId('adcs-issuer-ready').textContent).toMatch(
      /passed the CA check and its CA certificate is pinned/
    );
    expect(screen.queryByTestId('adcs-add-issuer')).toBeNull();
  });

  it('waits for the agent before the issuer can be added', async () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 }, agents: [] }));
    expect(await screen.findByTestId('adcs-add-issuer')).toBeDisabled();
    expect(screen.getByTestId('adcs-issuer-disabled').textContent).toMatch(
      /Waiting for the agent/
    );
  });

  it('shows the explanation instead of a working button without permission', async () => {
    show(
      ctxWith({
        adcs: { issuers: [], profiles: 0 },
        capabilities: {
          items: [
            {
              id: 'certops.adcs',
              state: 'role_handoff',
              blockers: [{ remediation: 'Ask a workspace administrator.' }],
            },
          ],
        },
      })
    );
    expect(await screen.findByTestId('adcs-add-issuer')).toBeDisabled();
    expect(screen.getByTestId('adcs-issuer-disabled').textContent).toBe(
      'Ask a workspace administrator.'
    );
  });

  it('disables the actions while certificate operations are paused', async () => {
    h.paused = true;
    show(ctxWith({ adcs: { issuers: [ready], profiles: 0 } }));
    expect(await screen.findByTestId('adcs-add-profile')).toBeDisabled();
    expect(screen.getByTestId('adcs-profile-disabled').textContent).toMatch(
      /paused/
    );
  });

  it('opens the profile dialog once the issuer is ready', async () => {
    show(ctxWith({ adcs: { issuers: [ready], profiles: 0 } }));
    const button = await screen.findByTestId('adcs-add-profile');
    expect(button).toBeEnabled();
    fireEvent.click(button);
    expect(
      screen.getByRole('dialog', { name: 'New AD CS profile' })
    ).toBeVisible();
  });

  it('keeps the profile action off until the issuer is ready', async () => {
    show(ctxWith({ adcs: { issuers: [], profiles: 0 } }));
    expect(await screen.findByTestId('adcs-add-profile')).toBeDisabled();
  });
});
