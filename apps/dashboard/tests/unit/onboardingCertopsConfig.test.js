import { describe, expect, it } from 'vitest';
import {
  buildAutomateConfig,
  buildControllerSecretCommand,
  buildControllerValues,
  buildDryRunJob,
  buildInstallCommand,
  buildIssueJob,
  buildObserveConfig,
  buildVaultConfigs,
  buildVaultPolicies,
  isValidHostname,
  nameInZone,
  SENSITIVE_PATTERN,
  STAGING_CA,
} from '../../src/components/onboarding/certopsConfig.js';
import {
  capabilityGap,
  infrastructuresFor,
  isSupported,
  requiredCapabilities,
} from '../../src/components/onboarding/certopsMatrix.js';

const WS = '11111111-1111-4111-8111-111111111111';
const GROUP = '22222222-2222-4222-8222-222222222222';

describe('support matrix', () => {
  it('only offers qualified or candidate combinations', () => {
    expect(infrastructuresFor('observe').map(i => i.id)).toEqual([
      'linux',
      'windows',
      'kubernetes',
    ]);
    expect(infrastructuresFor('automate').map(i => i.id)).toEqual([
      'linux',
      'windows',
    ]);
    // Vault distribution exists only on Linux and is a candidate.
    const vault = infrastructuresFor('vault');
    expect(vault.map(i => i.id)).toEqual(['linux']);
    expect(vault[0].status).toBe('candidate');
  });

  it('never offers unsupported combinations', () => {
    expect(isSupported('automate', 'kubernetes')).toBe(false);
    expect(isSupported('vault', 'windows')).toBe(false);
    expect(isSupported('observe', 'mainframe')).toBe(false);
  });

  it('reports exactly which capabilities an agent is missing', () => {
    expect(capabilityGap('observe', 'linux', [])).toEqual([]);
    expect(capabilityGap('automate', 'windows', ['iis-binding-v1'])).toEqual([
      'windows-cert-store-v1',
    ]);
    expect(requiredCapabilities('vault', 'linux')).toHaveLength(3);
    expect(
      capabilityGap('vault', 'linux', requiredCapabilities('vault', 'linux'))
    ).toEqual([]);
  });
});

describe('install command', () => {
  it('never contains a bootstrap token and quotes values', () => {
    const cmd = buildInstallCommand({
      os: 'linux',
      apiUrl: 'https://tt.example.com',
      workspaceId: WS,
      writePaths: ['/etc/nginx/tls'],
      reloadServices: ['nginx'],
    });
    expect(cmd).toContain("--api-url 'https://tt.example.com'");
    expect(cmd).toContain('--write-path');
    expect(cmd).toContain('--reload-service nginx');
    expect(cmd).not.toMatch(/bootstrap-token/);
    expect(cmd).not.toMatch(SENSITIVE_PATTERN);
  });

  it('is explicit about the trust store instead of assuming it', () => {
    const base = { os: 'linux', apiUrl: 'https://a.b', workspaceId: WS };
    expect(buildInstallCommand(base)).toContain('--no-trust-store');
    expect(buildInstallCommand({ ...base, trustStore: true })).toContain(
      '--trust-store'
    );
  });

  it('builds a PowerShell command for Windows', () => {
    const cmd = buildInstallCommand({
      os: 'windows',
      apiUrl: 'https://tt.example.com',
      workspaceId: WS,
    });
    expect(cmd).toMatch(/^\.\\install-agent\.ps1/);
    expect(cmd).not.toContain('sudo');
  });

  it('rejects an insecure address and a bad workspace id', () => {
    expect(() =>
      buildInstallCommand({
        os: 'linux',
        apiUrl: 'http://x.y',
        workspaceId: WS,
      })
    ).toThrow(/https/);
    expect(() =>
      buildInstallCommand({
        os: 'linux',
        apiUrl: 'https://x.y',
        workspaceId: 'nope',
      })
    ).toThrow(/workspace/);
  });

  it('cannot be used to inject shell commands', () => {
    const cmd = buildInstallCommand({
      os: 'linux',
      apiUrl: "https://x.y/'; rm -rf /; '",
      workspaceId: WS,
    });
    // The quote is escaped, so the payload stays inside one quoted argument.
    expect(cmd).toContain(`'\\''`);
  });
});

describe('observe config', () => {
  it('keeps execution disabled so the agent can never claim a job', () => {
    expect(buildObserveConfig({ os: 'linux' }).execution).toEqual({
      enabled: false,
      dryRun: true,
    });
    expect(buildObserveConfig({ os: 'windows' }).execution.enabled).toBe(false);
  });

  it('uses OS-appropriate discovery', () => {
    expect(
      buildObserveConfig({ os: 'linux', directories: ['/srv/tls'] }).discovery
        .directories
    ).toEqual(['/srv/tls']);
    expect(
      buildObserveConfig({ os: 'windows' }).windowsDiscovery.stores
    ).toEqual(['My']);
  });
});

describe('automate config', () => {
  const base = {
    os: 'linux',
    names: ['www.example.com'],
    zone: 'example.com',
    dnsProvider: 'cloudflare',
    certPath: '/etc/ssl/example/example.com.pem',
  };

  it('defaults to the staging CA and dry run', () => {
    const { ok, config } = buildAutomateConfig(base);
    expect(ok).toBe(true);
    expect(config.policy.allowedCaEndpoints).toEqual([STAGING_CA]);
    expect(config.execution.dryRun).toBe(true);
  });

  it('is default-deny: allowlists are exactly the request', () => {
    const { config } = buildAutomateConfig(base);
    expect(config.policy.allowedDnsZones).toEqual(['example.com']);
    expect(config.policy.allowedDnsProviders).toEqual(['cloudflare']);
    expect(config.policy.allowedTargetSelectors).toEqual(['www.example.com']);
    expect(config.dnsProviders.zoneProviderMap).toEqual({
      'example.com': 'cloudflare',
    });
  });

  it('puts the credential in a file path, never inline', () => {
    const { config } = buildAutomateConfig(base);
    expect(config.dnsProviders.cloudflare.credentialsFile).toBe(
      '/etc/tokentimer-agent/cloudflare.json'
    );
    expect(JSON.stringify(config)).not.toMatch(/apiToken|secret|password/i);
  });

  it('includes the certbot terms flags that otherwise fail as a DNS error', () => {
    const { config } = buildAutomateConfig(base);
    const argv = config.policy.allowedCommands.certbot.argv;
    expect(argv).toContain('--agree-tos');
    expect(argv.join(' ')).toMatch(/--register-unsafely-without-email|--email/);
    // Adapter-appended flags must not be repeated.
    expect(argv).not.toContain('certonly');
    expect(argv).not.toContain('--csr');
    expect(argv).not.toContain('--server');
  });

  it('rejects names outside the zone and bad input with reasons', () => {
    const outside = buildAutomateConfig({ ...base, names: ['www.other.org'] });
    expect(outside.ok).toBe(false);
    expect(outside.problems.join(' ')).toMatch(/not inside example\.com/);
    expect(buildAutomateConfig({ ...base, certPath: 'relative.pem' }).ok).toBe(
      false
    );
    expect(buildAutomateConfig({ ...base, dnsProvider: 'nope' }).ok).toBe(
      false
    );
    expect(buildAutomateConfig({ ...base, names: [] }).ok).toBe(false);
    expect(buildAutomateConfig({ ...base, caEndpoint: 'http://ca' }).ok).toBe(
      false
    );
  });

  it('accepts wildcards inside the zone', () => {
    expect(
      buildAutomateConfig({ ...base, names: ['*.example.com', 'example.com'] })
        .ok
    ).toBe(true);
    expect(nameInZone('*.example.com', 'example.com')).toBe(true);
    expect(nameInZone('evilexample.com', 'example.com')).toBe(false);
    expect(isValidHostname('a b.com')).toBe(false);
  });

  it('omits Linux-only settings for Windows', () => {
    const { config } = buildAutomateConfig({
      ...base,
      os: 'windows',
      certPath: undefined,
    });
    expect(config.execution.keysDir).toBeUndefined();
    expect(config.policy.allowedCommands).toBeUndefined();
  });
});

describe('jobs', () => {
  it('builds an issue job that carries no key material', () => {
    const job = buildIssueJob({
      os: 'linux',
      names: ['www.example.com'],
      zone: 'example.com',
      dnsProvider: 'cloudflare',
      certPath: '/etc/ssl/example/example.com.pem',
      idempotencyKey: 'wizard-1',
      assignedAgentId: 'row-1',
      verifyHost: 'www.example.com',
    });
    expect(job.operation).toBe('issue');
    expect(job.idempotencyKey).toBe('wizard-1');
    expect(job.assignedAgentId).toBe('row-1');
    expect(job.payload.verifyPort).toBe(443);
    expect(JSON.stringify(job)).not.toMatch(SENSITIVE_PATTERN);
    expect(JSON.stringify(job)).not.toMatch(/keyPath|privateKey/);
  });

  it('builds a harmless dry-run noop pinned to the agent', () => {
    expect(
      buildDryRunJob({ assignedAgentId: 'a', idempotencyKey: 'k' })
    ).toEqual({
      operation: 'noop',
      payload: { mode: 'dry_run' },
      idempotencyKey: 'k',
      assignedAgentId: 'a',
    });
  });
});

describe('kubernetes', () => {
  it('generates observe-mode values and validates the cluster id', () => {
    const values = buildControllerValues({
      apiUrl: 'https://tt.example.com',
      workspaceId: WS,
      clusterId: 'prod-eu',
    });
    expect(values).toContain('mode: observe');
    expect(values).toContain('clusterId: prod-eu');
    expect(values).not.toMatch(/ttx_/);
    expect(() =>
      buildControllerValues({
        apiUrl: 'https://a.b',
        workspaceId: WS,
        clusterId: 'Prod EU',
      })
    ).toThrow(/cluster id/);
  });

  it('reads the machine token from stdin, not the command line', () => {
    const cmd = buildControllerSecretCommand({});
    expect(cmd).toMatch(/read -rs TOKEN/);
    expect(cmd).not.toMatch(/ttx_[0-9a-f]/);
  });
});

describe('vault distribution', () => {
  const base = {
    vaultAddress: 'https://vault.example.com:8200',
    workspaceId: WS,
    groupId: GROUP,
    names: ['*.example.com', 'example.com'],
    zone: 'example.com',
    dnsProvider: 'cloudflare',
  };

  it('generates issuer and consumer configs with no Vault token', () => {
    const out = buildVaultConfigs(base);
    expect(out.ok).toBe(true);
    const text = JSON.stringify(out);
    expect(text).not.toMatch(SENSITIVE_PATTERN);
    expect(out.issuer.materialStores.customer.tokenFile).toBe(
      '/run/tokentimer-vault/issuer-token'
    );
    expect(out.consumer.materialStores.customer.tokenFile).toBe(
      '/run/tokentimer-vault/consumer-token'
    );
  });

  it('starts both agents in dry run and keeps placeholders for wire ids', () => {
    const out = buildVaultConfigs(base);
    expect(out.issuer.execution.dryRun).toBe(true);
    expect(out.consumer.execution.dryRun).toBe(true);
    expect(out.issuer.agentId).toMatch(/REPLACE_WITH/);
  });

  it('scopes the object prefix to the workspace and group', () => {
    const out = buildVaultConfigs(base);
    expect(out.issuer.materialStores.customer.groups[GROUP].prefix).toBe(
      `tokentimer/${WS}/${GROUP}`
    );
  });

  it('requires the real group id and an https Vault address', () => {
    expect(buildVaultConfigs({ ...base, groupId: 'x' }).ok).toBe(false);
    expect(buildVaultConfigs({ ...base, vaultAddress: 'http://v' }).ok).toBe(
      false
    );
  });

  it('scopes policies tightly and denies the scanner', () => {
    const p = buildVaultPolicies({ workspaceId: WS, groupId: GROUP });
    expect(p.issuer).toContain(
      `secret/data/tokentimer/${WS}/${GROUP}/bundles/*`
    );
    expect(p.issuer).toContain('"create", "read"');
    expect(p.issuer).not.toMatch(/update|delete|list|sudo/);
    expect(p.consumer).toContain('["read"]');
    expect(p.consumer).not.toContain('create');
    expect(p.scanner).toContain('["deny"]');
    expect(p.scanner).toContain('/metadata/');
    // Never a wildcard that reaches other groups.
    expect(p.issuer).not.toMatch(/tokentimer\/\*/);
  });

  it('rejects bad policy inputs', () => {
    expect(() =>
      buildVaultPolicies({ workspaceId: 'x', groupId: GROUP })
    ).toThrow();
    expect(() =>
      buildVaultPolicies({ mount: 'a/b', workspaceId: WS, groupId: GROUP })
    ).toThrow(/mount/);
  });
});
