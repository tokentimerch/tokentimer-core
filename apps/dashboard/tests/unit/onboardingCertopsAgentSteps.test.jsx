import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';
import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import { ConfigStep } from '../../src/components/onboarding/certopsSetupSteps.jsx';
import {
  agentConfigPathFor,
  agentRestartCommandFor,
  buildPackageCommand,
  registrationNotesFor,
} from '../../src/components/onboarding/certopsConfig.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const WS = '045d89e4-3c97-4029-ab18-fa6f200ebe96';

const docs = (key, label) => [{ label, url: `https://docs.example/${key}` }];

function makeCtx(goal, certops = {}, summary) {
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

const noAgents = { certops: { agents: { live: 0, total: 0, items: [] } } };
const linux = { objective: 'observe', infrastructure: 'linux' };
const windows = { objective: 'observe', infrastructure: 'windows' };

describe('package download and verification', () => {
  it('downloads the release tarball with its checksum file and refuses a mismatch (Linux)', () => {
    const cmd = buildPackageCommand('linux');
    expect(cmd).toContain('tokentimer-agent-${VERSION}.tgz');
    expect(cmd).toContain('releases/download/v${VERSION}');
    expect(cmd).toMatch(/sha256sum -c "\$\{TARBALL\}\.sha256"/);
    // Nothing is extracted unless the checksum command succeeded.
    expect(cmd.indexOf('sha256sum')).toBeLessThan(cmd.indexOf('tar -xzf'));
    expect(cmd).toMatch(/&&\s*\n\s*tar -xzf/);
    expect(cmd).toMatch(/cd package$/);
  });

  it('verifies the SHA-256 before extracting (Windows)', () => {
    const cmd = buildPackageCommand('windows');
    expect(cmd).toContain('Get-FileHash $Archive -Algorithm SHA256');
    expect(cmd).toContain("throw 'Agent archive checksum mismatch'");
    expect(cmd.indexOf('Get-FileHash')).toBeLessThan(cmd.indexOf('tar -xzf'));
    expect(cmd).toMatch(/Set-Location package$/);
  });

  it('carries no secret and no em dash', () => {
    for (const os of ['linux', 'windows']) {
      expect(buildPackageCommand(os)).not.toMatch(/ttboot_|\u2014/);
    }
  });

  it('gives the config path and the restart command per system', () => {
    expect(agentConfigPathFor('linux')).toBe(
      '/opt/tokentimer-agent/state/config.json'
    );
    expect(agentConfigPathFor('windows')).toBe(
      'C:\\ProgramData\\TokenTimerAgent\\state\\config.json'
    );
    expect(agentRestartCommandFor('linux')).toBe(
      'sudo systemctl restart tokentimer-agent'
    );
    expect(agentRestartCommandFor('windows')).toBe(
      'Restart-Service TokenTimerAgent'
    );
  });

  it('numbers the same four actions on Linux and Windows', () => {
    const lin = registrationNotesFor('linux');
    const win = registrationNotesFor('windows');
    const start = [/download/i, /extract/i, /install command/i, /token/i];
    start.forEach((re, i) => {
      expect(lin[i]).toMatch(re);
      expect(win[i]).toMatch(re);
    });
    expect(lin[1]).toMatch(/scripts\/install-agent\.sh/);
    expect(win[1]).toMatch(/scripts\\install-agent\.ps1/);
  });
});

describe('agent step', () => {
  it('shows where the package comes from, how to verify it, and the order of the work (Linux)', () => {
    mount(AgentStep, makeCtx('certops_observe', linux, noAgents));
    const steps = screen.getByTestId('install-steps').textContent;
    expect(steps).toMatch(/1\. On the server, download the agent package/);
    expect(steps).toMatch(/checksum/);
    expect(steps).toMatch(/2\. Extract it/);
    expect(steps).toMatch(/3\. Create a one-time bootstrap token/);
    expect(steps).toMatch(/4\. Run the install command/);
    expect(steps).toMatch(/5\. The installer asks for the bootstrap token/);
    expect(
      screen.getByLabelText(/Copy Download, verify and extract/)
    ).toBeInTheDocument();
    expect(screen.getByTestId('package-doc-link').getAttribute('href')).toBe(
      'https://docs.example/certops.agentPackage'
    );
  });

  it('gives Windows the same steps with its own folder and shell', () => {
    mount(AgentStep, makeCtx('certops_observe', windows, noAgents));
    const steps = screen.getByTestId('install-steps').textContent;
    expect(steps).toMatch(/1\. On the server, download the agent package/);
    expect(steps).toMatch(/2\. Extract it and open an elevated PowerShell/);
    expect(steps).toMatch(/scripts\\install-agent\.ps1/);
    expect(steps).toMatch(/4\. Run the install command/);
    expect(steps).not.toMatch(/--write-path/);
  });

  it('says the token lasts 24 hours and what to do when it is lost', () => {
    mount(AgentStep, makeCtx('certops_observe', linux, noAgents));
    const steps = screen.getByTestId('install-steps').textContent;
    expect(steps).toMatch(/expires in 24 hours/);
    expect(steps).toMatch(/lose it or it expires, create another/);
  });

  it('says the installer keeps an existing config.json', () => {
    mount(AgentStep, makeCtx('certops_observe', linux, noAgents));
    const note = screen.getByTestId('keep-config-note').textContent;
    expect(note).toMatch(/keeps a config\.json that already exists/);
    expect(note).toContain('/opt/tokentimer-agent/state/config.json');
  });

  it('keeps the Windows config path in that note', () => {
    mount(AgentStep, makeCtx('certops_observe', windows, noAgents));
    expect(screen.getByTestId('keep-config-note').textContent).toContain(
      'C:\\ProgramData\\TokenTimerAgent\\state\\config.json'
    );
  });

  it('names the exact machine token scope for the Kubernetes controller', () => {
    mount(
      AgentStep,
      makeCtx(
        'certops_observe',
        { objective: 'observe', infrastructure: 'kubernetes' },
        noAgents
      )
    );
    expect(
      screen.getByText(/certops:observations:write/, { selector: 'code' })
    ).toBeInTheDocument();
    expect(screen.getByText(/open Settings/)).toBeInTheDocument();
  });
});

describe('Kubernetes configuration step', () => {
  it('has a Continue button that saves the step', async () => {
    const ctx = makeCtx(
      'certops_observe',
      { objective: 'observe', infrastructure: 'kubernetes' },
      noAgents
    );
    mount(ConfigStep, ctx);
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() =>
      expect(ctx.session.progress.certops.configReviewed).toBe(true)
    );
  });
});
