import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
  cleanup,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';

const { createToken } = vi.hoisted(() => ({ createToken: vi.fn() }));
vi.mock('../../src/components/certops/certopsAgentsApi.js', async orig => ({
  ...(await orig()),
  createBootstrapToken: createToken,
}));

import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import {
  agentConfigPathFor,
  agentRestartCommandFor,
  buildPackageCommand,
  installerOptionsFor,
  installerOptionsKey,
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
    expect(
      within(screen.getByTestId('package-doc-links'))
        .getByRole('link')
        .getAttribute('href')
    ).toBe('https://docs.example/certops.agentPackage');
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

describe('Kubernetes install step', () => {
  it('saves only the cluster id and does not mark a configuration done', async () => {
    const ctx = makeCtx(
      'certops_observe',
      { objective: 'observe', infrastructure: 'kubernetes' },
      noAgents
    );
    mount(AgentStep, ctx);
    fireEvent.change(screen.getByLabelText('Cluster id'), {
      target: { value: 'prod-eu' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'I installed it' }));
    await waitFor(() =>
      expect(ctx.session.progress.certops.clusterId).toBe('prod-eu')
    );
    expect(ctx.session.progress.certops.configReviewed).toBeUndefined();
  });
});

describe('installer options after the agent registered', () => {
  const automate = {
    objective: 'automate',
    infrastructure: 'linux',
    certPath: '/etc/ssl/tokentimer/a.pem',
    reloadService: 'haproxy',
  };
  const agent = {
    id: 'a1',
    platform: 'linux',
    livenessState: 'live',
    commandProfiles: ['certbot'],
  };
  const registered = {
    certops: { agents: { live: 1, total: 1, items: [agent] } },
  };
  const key = installerOptionsKey(installerOptionsFor(automate));

  it('tells the operator to run the installer again when the goal needs other options', () => {
    mount(AgentStep, makeCtx('certops_automate', automate, registered));
    const prompt = screen.getByTestId('reinstall-needed').textContent;
    expect(prompt).toMatch(
      /This goal needs different installer options\. Run the command below again on the server\./
    );
    expect(prompt).toMatch(/bootstrap token again/);
    const steps = screen.getByTestId('install-steps').textContent;
    expect(steps).toContain("--write-path '/etc/ssl/tokentimer'");
    expect(steps).toContain('--reload-service haproxy');
  });

  it('does not ask on a first install, and not once the options match', () => {
    mount(AgentStep, makeCtx('certops_automate', automate, noAgents));
    expect(screen.queryByTestId('reinstall-needed')).toBeNull();
    cleanup();
    mount(
      AgentStep,
      makeCtx(
        'certops_automate',
        { ...automate, installerKey: key },
        registered
      )
    );
    expect(screen.queryByTestId('reinstall-needed')).toBeNull();
  });

  it('does not ask for a goal that needs no installer options', () => {
    mount(AgentStep, makeCtx('certops_observe', linux, registered));
    expect(screen.queryByTestId('reinstall-needed')).toBeNull();
  });

  it('records the second run only when the operator confirms it', async () => {
    const ctx = makeCtx('certops_automate', automate, registered);
    mount(AgentStep, ctx);
    expect(ctx.session.progress.certops.installerKey).toBeUndefined();
    fireEvent.click(
      screen.getByRole('button', { name: 'I ran the command again' })
    );
    await waitFor(() =>
      expect(ctx.session.progress.certops.installerKey).toBe(key)
    );
  });

  it('records the options with the token of a first install, not of a second run', async () => {
    createToken.mockReset().mockResolvedValue({ plaintextToken: 'ttboot_x' });
    const first = makeCtx('certops_automate', automate, noAgents);
    mount(AgentStep, first);
    fireEvent.click(
      screen.getByRole('button', { name: 'Create a one-time token' })
    );
    await waitFor(() =>
      expect(first.session.progress.certops.installerKey).toBe(key)
    );
    cleanup();
    const again = makeCtx('certops_automate', automate, registered);
    mount(AgentStep, again);
    fireEvent.click(
      screen.getByRole('button', { name: 'Create a one-time token' })
    );
    await waitFor(() =>
      expect(again.session.progress.certops.tokenCreatedAt).toBeTruthy()
    );
    expect(again.session.progress.certops.installerKey).toBeUndefined();
  });
});

describe('bootstrap token name', () => {
  it('calls the token a setup guide token, not a wizard token', async () => {
    createToken.mockReset().mockResolvedValue({ plaintextToken: 'ttboot_x' });
    mount(AgentStep, makeCtx('certops_observe', linux, noAgents));
    fireEvent.click(
      screen.getByRole('button', { name: 'Create a one-time token' })
    );
    await waitFor(() => expect(createToken).toHaveBeenCalled());
    expect(createToken.mock.calls[0][1].name).toMatch(/^Setup guide \d{4}-/);
    expect(createToken.mock.calls[0][1].name).not.toMatch(/wizard/i);
  });
});
