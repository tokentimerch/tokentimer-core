import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider, Text } from '@chakra-ui/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ConfigStep,
  ObjectiveStep,
} from '../../src/components/onboarding/certopsSetupSteps.jsx';
import {
  CopyBlock,
  ErrorText,
  WarnText,
} from '../../src/components/onboarding/blocks.jsx';
import {
  buildAutomateConfig,
  buildLinuxCredentialPrep,
  buildPreseedSteps,
} from '../../src/components/onboarding/certopsConfig.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { theme } from '../../src/styles/theme.js';

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

const mount = (ui, withTheme = false) =>
  render(
    <ChakraProvider theme={withTheme ? theme : undefined}>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );

const linuxAcme = { objective: 'automate', infrastructure: 'linux' };
const winAcme = { objective: 'automate', infrastructure: 'windows' };

afterEach(() => {
  document.body.classList.remove('chakra-ui-light');
  vi.unstubAllGlobals();
});

describe('before you start', () => {
  it('lists what ACME needs before the first step', () => {
    mount(<ObjectiveStep ctx={makeCtx('certops_automate')} />);
    const text = screen.getByTestId('before-you-start').textContent;
    expect(text).toMatch(/domain you control/);
    expect(text).toMatch(/API credential for that DNS provider/);
    expect(text).toMatch(/web server/);
    expect(text).toMatch(/staging CA/);
    expect(text).toMatch(/not trusted by browsers/);
  });

  it('lists what AD CS needs', () => {
    mount(<ObjectiveStep ctx={makeCtx('certops_adcs')} />);
    const text = screen.getByTestId('before-you-start').textContent;
    expect(text).toMatch(
      /joined to your domain and is not a domain controller/
    );
    expect(text).toMatch(/Enroll permission on the certificate template/);
    expect(text).toMatch(
      /route from that server to your Certification Authority/
    );
  });

  it('adds nothing for a discovery-only goal', () => {
    mount(<ObjectiveStep ctx={makeCtx('certops_observe')} />);
    expect(screen.queryByTestId('before-you-start')).toBeNull();
  });
});

describe('ACME configuration form', () => {
  it('has no pre-filled certificate path and explains the field', () => {
    mount(<ConfigStep ctx={makeCtx('certops_automate', linuxAcme)} />);
    const input = screen.getByLabelText(/Certificate file path/);
    expect(input.value).toBe('');
    expect(input.getAttribute('placeholder')).toBe(
      '/etc/ssl/tokentimer/www.example.com.pem'
    );
    expect(screen.getByTestId('cert-path-helper').textContent).toMatch(
      /Choose a new file name/
    );
  });

  it('keeps the button off, says why, and shows no error before the first touch', () => {
    mount(<ConfigStep ctx={makeCtx('certops_automate', linuxAcme)} />);
    expect(
      screen.getByRole('button', { name: 'I saved this file' })
    ).toBeDisabled();
    const why = screen.getByTestId('config-missing').textContent;
    expect(why).toMatch(/stays disabled until/);
    expect(why).toMatch(/the names/);
    expect(why).toMatch(/the DNS zone/);
    expect(why).toMatch(/the certificate file path/);
    expect(screen.queryByText('Enter at least one name.')).toBeNull();
  });

  it('shows the error next to the field after the person leaves it', () => {
    mount(<ConfigStep ctx={makeCtx('certops_automate', linuxAcme)} />);
    fireEvent.blur(screen.getByLabelText(/^Names/));
    expect(screen.getByText('Enter at least one name.')).toBeInTheDocument();
    // Other fields stay quiet until touched.
    expect(screen.queryByText('Enter a valid DNS zone.')).toBeNull();
  });

  it('enables the button once the form is valid', () => {
    mount(
      <ConfigStep
        ctx={makeCtx('certops_automate', {
          ...linuxAcme,
          names: 'www.example.com',
          zone: 'example.com',
          certPath: '/etc/ssl/tokentimer/www.example.com.pem',
        })}
      />
    );
    expect(
      screen.getByRole('button', { name: 'I saved this file' })
    ).not.toBeDisabled();
    expect(screen.queryByTestId('config-missing')).toBeNull();
  });

  it('keeps the Vault issuer valid without a certificate path field', () => {
    mount(
      <ConfigStep
        ctx={makeCtx('certops_vault', {
          objective: 'vault',
          infrastructure: 'linux',
          names: 'www.example.com',
          zone: 'example.com',
        })}
      />
    );
    expect(screen.queryByLabelText(/Certificate file path/)).toBeNull();
    expect(
      screen.getByRole('button', { name: 'I saved this file' })
    ).not.toBeDisabled();
  });

  it('groups builder problems by field', () => {
    const res = buildAutomateConfig({
      os: 'linux',
      names: [],
      zone: 'bad',
      dnsProvider: 'cloudflare',
      certPath: 'relative.pem',
    });
    expect(res.ok).toBe(false);
    expect(Object.keys(res.fieldErrors).sort()).toEqual([
      'certPath',
      'names',
      'zone',
    ]);
    expect(res.problems).toEqual(Object.values(res.fieldErrors).flat());
  });

  it('puts the one-line helpers on the Windows binding fields', () => {
    mount(<ConfigStep ctx={makeCtx('certops_automate', winAcme)} />);
    expect(screen.getByTestId('sni-helper').textContent).toMatch(
      /several sites share this IP address and port/
    );
    expect(screen.getByTestId('iis-site-helper').textContent).toMatch(
      /existing IIS site, as shown in IIS Manager/
    );
  });

  it('tells a Windows reader to install Git for Windows first', () => {
    mount(<ConfigStep ctx={makeCtx('certops_automate', winAcme)} />);
    expect(screen.getByTestId('git-for-windows-note').textContent).toMatch(
      /Install Git for Windows on this server first/
    );
  });

  it('explains the nginx reload setup inside a collapsed panel', () => {
    mount(
      <ConfigStep
        ctx={makeCtx('certops_automate', {
          ...linuxAcme,
          reloadService: 'nginx',
        })}
      />
    );
    const panel = screen.getByTestId('reload-nginx-panel');
    expect(panel.tagName).toBe('DETAILS');
    expect(panel.hasAttribute('open')).toBe(false);
  });

  it('shows the folder command next to the credential path and keeps the wizard path', () => {
    mount(
      <ConfigStep
        ctx={makeCtx('certops_automate', {
          ...linuxAcme,
          names: 'www.example.com',
          zone: 'example.com',
          certPath: '/etc/ssl/tokentimer/www.example.com.pem',
        })}
      />
    );
    const block = document.body.textContent;
    expect(block).toContain('/etc/tokentimer-agent/cloudflare.json');
    expect(block).toContain('sudo install -d -m 0755 /etc/tokentimer-agent');
    expect(block).toContain(
      'sudo chown tokentimer-agent:tokentimer-agent /etc/tokentimer-agent/cloudflare.json'
    );
    expect(buildLinuxCredentialPrep('')).toBe('');
  });

  it('describes DNS propagation in words, not setting names', () => {
    mount(
      <ConfigStep
        ctx={makeCtx('certops_automate', {
          ...linuxAcme,
          names: 'www.example.com',
          zone: 'example.com',
          certPath: '/etc/ssl/tokentimer/www.example.com.pem',
        })}
      />
    );
    const note = screen.getByTestId('dns-propagation-note').textContent;
    expect(note).toMatch(/split-horizon or private zones/);
    expect(note).not.toMatch(/checkAuthoritative|timeoutMs|dnsPropagation/);
  });

  it('says the installer comes on the next page and keeps the file', () => {
    const { steps } = buildPreseedSteps({ os: 'windows', config: {} });
    expect(steps[steps.length - 1]).toMatch(/Next page: you install the agent/);
    expect(steps.join(' ')).not.toMatch(/adds the server address/);
  });

  it('rewrites the description without registration jargon', () => {
    mount(<ConfigStep ctx={makeCtx('certops_automate', linuxAcme)} />);
    const text = document.body.textContent;
    expect(text).toMatch(/You save a settings file on the server/);
    expect(text).not.toMatch(/command profiles are reported only/);
  });
});

describe('AD CS field helpers', () => {
  it('explains scopes and the template in one line each', () => {
    mount(
      <ConfigStep
        ctx={makeCtx('certops_adcs', {
          objective: 'adcs',
          infrastructure: 'windows',
        })}
      />
    );
    expect(screen.getByTestId('dns-scopes-helper').textContent).toMatch(
      /corp\.example\.com also covers web\.corp\.example\.com/
    );
    expect(screen.getByTestId('template-helper').textContent).toMatch(
      /common name from the CA console/
    );
    expect(screen.getByTestId('iis-site-helper')).toBeInTheDocument();
  });
});

describe('error colours', () => {
  it('renders errors red in the light theme where a plain Text prop turns dark grey', () => {
    document.body.classList.add('chakra-ui-light');
    vi.stubGlobal(
      'matchMedia',
      vi.fn(() => ({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
      }))
    );
    mount(
      <>
        <Text data-testid='plain' color='red.400'>
          plain
        </Text>
        <ErrorText data-testid='error'>error</ErrorText>
        <WarnText data-testid='warn'>warn</WarnText>
      </>,
      true
    );
    const color = id => getComputedStyle(screen.getByTestId(id)).color;
    // The pitfall: the theme pins Text to gray.800 in the light theme.
    expect(color('plain')).not.toBe('rgb(220, 38, 38)');
    expect(color('error')).toBe('rgb(220, 38, 38)');
    expect(color('warn')).toBe('rgb(217, 119, 6)');
  });
});

describe('copy block refusal', () => {
  it('says what to do next when it refuses content', () => {
    mount(<CopyBlock label='Install command' text='token ttboot_abc123' />);
    const text = screen.getByTestId('copy-refused').textContent;
    expect(text).toMatch(/looks like a credential, so it is not shown/);
    expect(text).toMatch(/Remove any token or key you pasted into a field/);
    expect(text).not.toContain('ttboot_abc123');
  });
});
