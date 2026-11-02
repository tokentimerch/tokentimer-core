import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import {
  ConfigStep,
  ObjectiveStep,
} from '../../src/components/onboarding/certopsSetupSteps.jsx';
import IssueStep from '../../src/components/onboarding/certopsIssueStep.jsx';
import AdcsStep from '../../src/components/onboarding/certopsAdcsStep.jsx';
import {
  INFRASTRUCTURES,
  infrastructuresFor,
} from '../../src/components/onboarding/certopsMatrix.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const makeCtx = (goal, certops = {}, summary) => ({
  workspaceId: 'ws-1',
  apiUrl: 'http://localhost:4010',
  docs: () => [],
  refresh: vi.fn().mockResolvedValue(undefined),
  summary,
  controller: { update: vi.fn() },
  session: {
    intent: { goal },
    progress: { certops },
    operationRefs: {},
  },
});

const mount = (Step, ctx) =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <Step ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const windows = extra => ({
  objective: 'automate',
  infrastructure: 'windows',
  ...extra,
});

describe('Windows infrastructure option', () => {
  it('is labelled Windows Server without mentioning IIS in the name', () => {
    expect(INFRASTRUCTURES.windows.label).toBe('Windows Server');
    expect(INFRASTRUCTURES.windows.label).not.toMatch(/iis/i);
  });

  it('says IIS is not needed when the goal is to observe', () => {
    const win = infrastructuresFor('observe').find(i => i.id === 'windows');
    expect(win.detail).toMatch(/machine certificate store/);
    expect(win.detail).toMatch(/No IIS needed/);
  });

  it('describes the HTTPS listener for automate and AD CS', () => {
    for (const objective of ['automate', 'adcs']) {
      const win = infrastructuresFor(objective).find(i => i.id === 'windows');
      expect(win.detail).toMatch(/HTTPS listener, typically an IIS site/);
      expect(win.detail).not.toMatch(/No IIS needed/);
    }
  });

  it('renders the goal-aware detail in the picker', () => {
    mount(ObjectiveStep, makeCtx('certops_observe'));
    expect(screen.getByText('Windows Server')).toBeInTheDocument();
    expect(screen.getByText(/No IIS needed/)).toBeInTheDocument();
    expect(screen.queryByText('Windows Server with IIS')).toBeNull();
  });
});

describe('Windows configuration copy', () => {
  it('shows no IIS wording for the observe goal', () => {
    const { container } = mount(
      ConfigStep,
      makeCtx(
        'certops_observe',
        windows({ objective: 'observe', directories: 'C:\\certs' })
      )
    );
    expect(container.textContent).toMatch(/no folder to choose/);
    expect(container.textContent).not.toMatch(/Folders to scan/);
    expect(container.textContent).not.toMatch(/iis/i);
    expect(screen.queryByText(/HTTPS binding/)).toBeNull();
  });

  it('asks for the shell and the credential lock-down on Windows automate', () => {
    const { container } = mount(
      ConfigStep,
      makeCtx(
        'certops_automate',
        windows({
          names: 'wiz.example.com',
          zone: 'example.com',
          acmeClientPath: 'C:\\acme\\acme.sh',
        })
      )
    );
    expect(container.textContent).toMatch(/Shell that runs the ACME client/);
    expect(container.textContent).toMatch(
      /Program Files\\\\Git\\\\bin\\\\bash\.exe/
    );
    expect(container.textContent).toMatch(/icacls/);
    expect(container.textContent).toMatch(
      /state\\\\dns-cloudflare-credentials\.json/
    );
    expect(container.textContent).not.toMatch(/mode 0600/);
  });

  it('labels the automate binding and warns that it is replaced', () => {
    mount(ConfigStep, makeCtx('certops_automate', windows()));
    expect(screen.getByText('HTTPS binding (IIS site)')).toBeInTheDocument();
    expect(screen.queryByText('IIS site')).toBeNull();
    const note = screen.getByTestId('binding-note').textContent;
    expect(note).toMatch(/replaces the certificate currently bound/);
    expect(note).toMatch(/must already exist/);
    expect(note).toMatch(/does not create sites/);
  });

  it('labels the AD CS binding and warns that it is replaced', () => {
    mount(ConfigStep, makeCtx('certops_adcs', windows({ objective: 'adcs' })));
    expect(screen.getByText('HTTPS binding (IIS site)')).toBeInTheDocument();
    expect(screen.queryByText('IIS site')).toBeNull();
    expect(screen.getByTestId('binding-note').textContent).toMatch(
      /replaces the certificate currently bound/
    );
  });

  it('does not show the binding fields on Linux', () => {
    mount(
      ConfigStep,
      makeCtx('certops_automate', {
        objective: 'automate',
        infrastructure: 'linux',
      })
    );
    expect(screen.queryByText('HTTPS binding (IIS site)')).toBeNull();
    expect(screen.queryByTestId('binding-note')).toBeNull();
  });
});

describe('Windows issuance and AD CS step copy', () => {
  const summary = job => ({
    certops: { agents: { items: [] }, issueJob: job },
  });

  it('explains the binding replacement before issuing', () => {
    mount(
      IssueStep,
      makeCtx(
        'certops_automate',
        windows({ iisSite: 'Shop', iisPort: 8443 }),
        summary(null)
      )
    );
    const note = screen.getByTestId('reload-note').textContent;
    expect(note).toMatch(/HTTPS binding Shop \(usually an IIS site\)/);
    expect(note).toMatch(/port 8443/);
    expect(note).toMatch(/replacing the certificate currently bound there/);
  });

  it('softens the failure hint and the success text', () => {
    const failed = mount(
      IssueStep,
      makeCtx('certops_automate', windows(), summary({ status: 'failed' }))
    );
    expect(failed.container.textContent).toMatch(
      /HTTPS listener \(usually an IIS site\) must exist/
    );
    failed.unmount();
    const done = mount(
      IssueStep,
      makeCtx(
        'certops_automate',
        windows(),
        summary({ status: 'succeeded', mode: 'real' })
      )
    );
    expect(done.container.textContent).toMatch(
      /issued and bound to the HTTPS binding Default Web Site\./
    );
  });

  it('asks for the HTTPS binding when creating the AD CS profile', () => {
    const { container } = mount(
      AdcsStep,
      makeCtx('certops_adcs', windows({ objective: 'adcs' }), {
        certops: { agents: { items: [] } },
      })
    );
    expect(container.textContent).toMatch(
      /the HTTPS binding \(IIS site\) and the certificate name/
    );
  });
});
