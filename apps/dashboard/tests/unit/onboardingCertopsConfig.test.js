import { describe, expect, it } from 'vitest';
import {
  buildAutomateConfig,
  buildControllerSecretCommand,
  buildControllerValues,
  buildDryRunJob,
  buildInstallCommand,
  buildIssueJob,
  buildObserveConfig,
  buildPreseedSteps,
  buildVaultConfigs,
  buildVaultPolicies,
  buildVaultPublishJob,
  buildVaultConsumerAssignment,
  buildVaultRollout,
  buildControllerOnlyValues,
  isLoopbackHttp,
  WINDOWS_ACME_PROFILE,
  RELOAD_SERVICES,
  NGINX_RELOAD_DROPIN,
  reloadCommands,
  issueIdempotencyKey,
  isValidHostname,
  nameInZone,
  SENSITIVE_PATTERN,
  STAGING_CA,
  AGENT_KEYS_DIR,
  certDirectoryFor,
  dnsCredentialsExample,
  vaultPublishIdempotencyKey,
  DNS_PROVIDERS,
  mergeInstallerFields,
  registrationNotesFor,
  windowsCredentialAclCommand,
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
    // Vault distribution exists only on Linux and is qualified since 0.18.0.
    const vault = infrastructuresFor('vault');
    expect(vault.map(i => i.id)).toEqual(['linux']);
    expect(vault[0].status).toBe('qualified');
    // The AD CS guide is unverified on a real host, so it stays a candidate.
    expect(infrastructuresFor('adcs').map(i => [i.id, i.status])).toEqual([
      ['windows', 'candidate'],
    ]);
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
  it('runs the installer from the scripts folder of the agent package', () => {
    const cmd = buildInstallCommand({
      os: 'linux',
      apiUrl: 'https://tt.example.com',
      workspaceId: WS,
    });
    expect(cmd).toMatch(/^sudo \.\/scripts\/install-agent\.sh/);
  });

  it('derives the write folder from the certificate file', () => {
    expect(certDirectoryFor('/etc/ssl/tokentimer/a.pem')).toBe(
      '/etc/ssl/tokentimer'
    );
    expect(certDirectoryFor('relative.pem')).toBe('');
    expect(certDirectoryFor('/a.pem')).toBe('');
    expect(certDirectoryFor('')).toBe('');
  });

  it('adds the loopback opt-in to a prepared config only for http loopback', () => {
    const local = mergeInstallerFields(
      { execution: { enabled: false } },
      { apiUrl: 'http://localhost:4010', workspaceId: WS }
    );
    expect(local.allowInsecureLocalHttp).toBe(true);
    expect(local.serverUrl).toBe('http://localhost:4010');
    const remote = mergeInstallerFields(
      { execution: { enabled: false } },
      { apiUrl: 'https://tt.example.com', workspaceId: WS }
    );
    expect(remote.allowInsecureLocalHttp).toBeUndefined();
  });
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
    expect(cmd).toMatch(/^\.\\scripts\\install-agent\.ps1/);
    expect(cmd).not.toContain('sudo');
  });

  it('allows plain http only for a loopback host, with the installer flag', () => {
    const local = buildInstallCommand({
      os: 'linux',
      apiUrl: 'http://localhost:4010',
      workspaceId: WS,
    });
    expect(local).toContain('--allow-insecure-local-http');
    const win = buildInstallCommand({
      os: 'windows',
      apiUrl: 'http://127.0.0.1:4010',
      workspaceId: WS,
    });
    expect(win).toContain('--allow-insecure-local-http');
    // The flag is never added for https.
    expect(
      buildInstallCommand({
        os: 'linux',
        apiUrl: 'https://tt.example.com',
        workspaceId: WS,
      })
    ).not.toContain('--allow-insecure-local-http');
    // A remote host over http would send the token in clear text.
    for (const url of [
      'http://tt.example.com',
      'http://10.0.0.5:4000',
      'http://localhost.evil.com',
    ]) {
      expect(() =>
        buildInstallCommand({ os: 'linux', apiUrl: url, workspaceId: WS })
      ).toThrow(/https/);
    }
    expect(isLoopbackHttp('http://[::1]:4000')).toBe(true);
    expect(isLoopbackHttp('https://localhost')).toBe(false);
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

  it('turns execution on, because the dry-run stage needs it', () => {
    const { config } = buildAutomateConfig(base);
    expect(config.execution.enabled).toBe(true);
  });

  it('keeps keys in the state directory and allows exactly that and the certificate folder', () => {
    const { config } = buildAutomateConfig(base);
    expect(config.execution.keysDir).toBe(AGENT_KEYS_DIR);
    expect(AGENT_KEYS_DIR).toBe('/opt/tokentimer-agent/state/keys');
    // A deploy also names the key path, so both folders must be allowed.
    expect(config.policy.allowedPaths).toEqual([
      '/etc/ssl/example',
      AGENT_KEYS_DIR,
    ]);
  });

  it('declares the names and command profile the control plane routes on', () => {
    // Policy alone is not enough: the agent registers and passes a dry run but
    // never claims an issue job unless it also declares these.
    const { config } = buildAutomateConfig(base);
    expect(config.declaredTargetSelectors).toEqual(['www.example.com']);
    expect(config.declaredCommandProfileNames).toEqual(['certbot']);
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

  it('omits Linux-only settings for Windows and allows only the ACME client', () => {
    const { config } = buildAutomateConfig({
      ...base,
      os: 'windows',
      certPath: undefined,
      acmeClientPath: 'C:\\acme\\acme.sh.exe',
    });
    expect(config.execution.keysDir).toBeUndefined();
    expect(Object.keys(config.policy.allowedCommands)).toEqual([
      WINDOWS_ACME_PROFILE,
    ]);
    expect(config.policy.allowedPaths).toEqual([]);
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

  it('builds a Windows IIS issue job with a store and binding, never a path', () => {
    const job = buildIssueJob({
      os: 'windows',
      names: ['iis.example.com'],
      zone: 'example.com',
      dnsProvider: 'cloudflare',
      iisSite: 'Default Web Site',
      iisPort: 443,
      sniHost: 'iis.example.com',
      assignedAgentId: 'row-9',
      idempotencyKey: 'wizard-win-1',
    });
    expect(job.operation).toBe('issue');
    expect(job.payload.target).toEqual({
      type: 'windows-iis',
      reference: 'iis.example.com',
      store: 'My',
      binding: {
        site: 'Default Web Site',
        port: 443,
        sniHost: 'iis.example.com',
      },
    });
    expect(job.payload.certPath).toBeUndefined();
    expect(job.payload.commandRef).toBe(WINDOWS_ACME_PROFILE);
    expect(job.assignedAgentId).toBe('row-9');
    expect(JSON.stringify(job)).not.toMatch(/keyPath|privateKey/);
  });

  it('omits the SNI host when none is given', () => {
    const job = buildIssueJob({
      os: 'windows',
      names: ['iis.example.com'],
      zone: 'example.com',
      dnsProvider: 'cloudflare',
      idempotencyKey: 'wizard-win-2',
    });
    expect(job.payload.target.binding).toEqual({
      site: 'Default Web Site',
      port: 443,
    });
  });

  it('builds a harmless dry-run noop pinned to the agent', () => {
    expect(
      buildDryRunJob({ assignedAgentId: 'a', idempotencyKey: 'k' })
    ).toEqual({
      operation: 'noop',
      mode: 'dry_run',
      idempotencyKey: 'k',
      assignedAgentId: 'a',
    });
  });

  it('keeps mode out of the payload, where the server would ignore it', () => {
    const job = buildDryRunJob({ assignedAgentId: 'a', idempotencyKey: 'k' });
    expect(job.payload).toBeUndefined();
    expect(job.mode).toBe('dry_run');
  });
});

describe('kubernetes', () => {
  it('can render the controller without the rest of the application', () => {
    const only = buildControllerOnlyValues();
    expect(only).toContain('enabled: false');
    expect(only).toContain('disableAdminBootstrap: true');
    expect(only).toContain('host: unused.invalid');
    expect(only).not.toMatch(SENSITIVE_PATTERN);
  });

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

  it('declares what the control plane routes distribution jobs on', () => {
    // Policy alone does not route jobs; both agents also need declarations.
    const out = buildVaultConfigs({
      ...base,
      consumerBindingId: '33333333-3333-4333-8333-333333333333',
    });
    expect(out.issuer.declaredTargetSelectors).toEqual(base.names);
    expect(out.issuer.declaredCommandProfileNames).toEqual(['certbot']);
    expect(out.consumer.declaredTargetSelectors).toEqual([
      '33333333-3333-4333-8333-333333333333',
    ]);
  });

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

  it('adds a trust CA file to the consumer probe only when given', () => {
    const plain = buildVaultConfigs({
      ...base,
      consumerBindingId: '33333333-3333-4333-8333-333333333333',
    });
    const probe = () =>
      Object.values(plain.consumer.materialBindings)[0].probes[0];
    expect(probe().trustCaFile).toBeUndefined();
    const withCa = buildVaultConfigs({
      ...base,
      consumerBindingId: '33333333-3333-4333-8333-333333333333',
      probeTrustCaFile: '/etc/tokentimer-agent/issuing-ca.pem',
    });
    expect(
      Object.values(withCa.consumer.materialBindings)[0].probes[0].trustCaFile
    ).toBe('/etc/tokentimer-agent/issuing-ca.pem');
    expect(
      buildVaultConfigs({ ...base, probeTrustCaFile: 'relative.pem' }).ok
    ).toBe(false);
  });

  it('gives the consumer the same unprivileged reload commands as the automate guide', () => {
    const out = buildVaultConfigs(base);
    const commands = out.consumer.policy.allowedCommands;
    expect(commands['nginx-validate'].argv).toEqual(
      RELOAD_SERVICES.nginx.validate
    );
    expect(commands['nginx-reload'].argv).toEqual(RELOAD_SERVICES.nginx.reload);
  });

  it('builds the publish job with the key algorithm the agent requires, held for approval', () => {
    const job = buildVaultPublishJob({
      names: ['www.example.com'],
      zone: 'example.com',
      dnsProvider: 'cloudflare',
      assignedAgentId: 'issuer-row',
      idempotencyKey: 'k',
    });
    expect(job.operation).toBe('issue');
    expect(job.requiresApproval).toBe(true);
    expect(job.payload.keyAlgorithm).toBe('ecdsa');
    expect(job.payload.keySize).toBe(256);
    expect(job.payload.publicationDestination).toEqual({
      materialStoreRef: 'customer',
      issuanceProfileRef: 'wildcard',
      profileRevision: 1,
    });
    expect(job.payload.certPath).toBeUndefined();
    expect(JSON.stringify(job)).not.toMatch(SENSITIVE_PATTERN);
  });

  it('builds the consumer assignment and rollout bodies', () => {
    expect(buildVaultConsumerAssignment({ agentRowId: 'row' })).toMatchObject({
      agentId: 'row',
      deploymentProfileRef: 'nginx-public',
      verificationPolicy: 'trust',
      state: 'active',
    });
    expect(buildVaultRollout({ materialVersionId: 'v' })).toEqual({
      materialVersionId: 'v',
      maxParallel: 1,
    });
  });

  it('keeps keys in the installed state folder and allows only what it needs', () => {
    const out = buildVaultConfigs(base);
    expect(out.issuer.execution.keysDir).toBe(AGENT_KEYS_DIR);
    expect(out.issuer.policy.allowedPaths).toEqual([AGENT_KEYS_DIR]);
    expect(out.consumer.execution.keysDir).toBe(AGENT_KEYS_DIR);
    expect(out.consumer.policy.allowedPaths).toEqual([
      '/etc/nginx/tokentimer',
      AGENT_KEYS_DIR,
    ]);
  });

  it('adds a Vault CA file to both stores only when given, and only as an absolute path', () => {
    const plain = buildVaultConfigs(base);
    expect(plain.issuer.materialStores.customer.caFile).toBeUndefined();
    const withCa = buildVaultConfigs({
      ...base,
      caFile: '/etc/tokentimer-agent/vault-ca.pem',
    });
    expect(withCa.issuer.materialStores.customer.caFile).toBe(
      '/etc/tokentimer-agent/vault-ca.pem'
    );
    expect(withCa.consumer.materialStores.customer.caFile).toBe(
      '/etc/tokentimer-agent/vault-ca.pem'
    );
    expect(buildVaultConfigs({ ...base, caFile: 'vault-ca.pem' }).ok).toBe(
      false
    );
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

describe('issuance request key', () => {
  const args = {
    names: ['a.example.com'],
    zone: 'example.com',
    certPath: '/etc/ssl/a.pem',
  };
  it('is stable for the same request, so a reload cannot place a second order', () => {
    expect(issueIdempotencyKey(args)).toBe(issueIdempotencyKey({ ...args }));
  });
  it('changes with the request or the attempt', () => {
    const k = issueIdempotencyKey(args);
    expect(issueIdempotencyKey({ ...args, zone: 'other.com' })).not.toBe(k);
    expect(issueIdempotencyKey({ ...args, attempt: 2 })).not.toBe(k);
  });
  it('matches the server key pattern', () => {
    expect(issueIdempotencyKey(args)).toMatch(/^[A-Za-z0-9._:-]{1,128}$/);
  });
});

describe('optional web server reload', () => {
  const base = {
    os: 'linux',
    names: ['www.example.com'],
    zone: 'example.com',
    dnsProvider: 'cloudflare',
    certPath: '/etc/nginx/tls/www.pem',
  };

  it('does nothing unless the user chooses a server', () => {
    const { config } = buildAutomateConfig(base);
    expect(Object.keys(config.policy.allowedCommands)).toEqual(['certbot']);
    const job = buildIssueJob({ ...base, idempotencyKey: 'k1' });
    expect(job.payload.reloadService).toBeUndefined();
    expect(job.payload.reloadCommandRefs).toBeUndefined();
  });

  it('allows exactly the validate and reload commands for the chosen server', () => {
    for (const id of Object.keys(RELOAD_SERVICES)) {
      const { config } = buildAutomateConfig({ ...base, reloadService: id });
      const commands = config.policy.allowedCommands;
      expect(commands[`${id}-validate`].argv).toEqual(
        RELOAD_SERVICES[id].validate
      );
      expect(commands[`${id}-reload`].argv).toEqual(RELOAD_SERVICES[id].reload);
      expect(Object.keys(commands).sort()).toEqual(
        ['certbot', `${id}-reload`, `${id}-validate`].sort()
      );
    }
  });

  it('runs a check before the reload, and tests the config as root for nginx', () => {
    for (const def of Object.values(RELOAD_SERVICES)) {
      expect(def.validate.join(' ')).toMatch(
        /-t$|configtest$|-c |is-active --quiet nginx$/
      );
      expect(def.reload[1]).toBe('reload');
    }
    // nginx -t needs write access the unprivileged service user lacks, so the
    // config test moves into the unit's reload, which runs as root.
    expect(RELOAD_SERVICES.nginx.validate).not.toContain('-t');
    expect(NGINX_RELOAD_DROPIN).toContain('ExecReload=/usr/sbin/nginx -t');
    expect(NGINX_RELOAD_DROPIN).toContain(
      '/etc/systemd/system/nginx.service.d/'
    );
    expect(NGINX_RELOAD_DROPIN).not.toMatch(SENSITIVE_PATTERN);
  });

  it('refers to the same command names in the job as in the policy', () => {
    for (const id of Object.keys(RELOAD_SERVICES)) {
      const { config } = buildAutomateConfig({ ...base, reloadService: id });
      const job = buildIssueJob({
        ...base,
        reloadService: id,
        idempotencyKey: 'k2',
      });
      expect(job.payload.reloadService).toBe(id);
      expect(
        config.policy.allowedCommands[job.payload.reloadCommandRefs.validate]
      ).toBeTruthy();
      expect(
        config.policy.allowedCommands[job.payload.reloadCommandRefs.reload]
      ).toBeTruthy();
    }
  });

  it('uses shell-free argv only', () => {
    for (const id of Object.keys(RELOAD_SERVICES)) {
      for (const { argv } of Object.values(reloadCommands(id))) {
        expect(argv.every(a => !/[;&|`$<>]/.test(a))).toBe(true);
      }
    }
  });

  it('rejects an unknown server and a Windows host', () => {
    expect(buildAutomateConfig({ ...base, reloadService: 'iis' }).ok).toBe(
      false
    );
    expect(
      buildAutomateConfig({ ...base, os: 'windows', reloadService: 'nginx' }).ok
    ).toBe(false);
    expect(() =>
      buildIssueJob({ ...base, reloadService: 'iis', idempotencyKey: 'k3' })
    ).toThrow(/Unknown web server/);
    expect(reloadCommands('iis')).toEqual({});
  });

  it('creates a new job, not a replay, when the reload choice changes', () => {
    const args = {
      names: ['www.example.com'],
      zone: 'example.com',
      certPath: '/etc/nginx/tls/www.pem',
    };
    const plain = issueIdempotencyKey(args);
    const withNginx = issueIdempotencyKey({ ...args, reloadService: 'nginx' });
    const withApache = issueIdempotencyKey({
      ...args,
      reloadService: 'apache',
    });
    expect(new Set([plain, withNginx, withApache]).size).toBe(3);
    expect(issueIdempotencyKey({ ...args, reloadService: 'nginx' })).toBe(
      withNginx
    );
    expect(withNginx).toMatch(/^[A-Za-z0-9._:-]{1,128}$/);
  });
});

describe('windows ACME configuration', () => {
  const base = {
    os: 'windows',
    names: ['iis.example.com'],
    zone: 'example.com',
    dnsProvider: 'cloudflare',
    acmeClientPath: 'C:\\acme\\acme.sh.exe',
  };

  it('needs the full path of the ACME client', () => {
    expect(buildAutomateConfig({ ...base, acmeClientPath: '' }).ok).toBe(false);
    expect(buildAutomateConfig({ ...base, acmeClientPath: 'acme.sh' }).ok).toBe(
      false
    );
    expect(buildAutomateConfig(base).ok).toBe(true);
  });

  it('allows exactly that client under the name the job uses', () => {
    const { config } = buildAutomateConfig(base);
    expect(config.policy.allowedCommands[WINDOWS_ACME_PROFILE]).toEqual({
      argv: ['C:\\acme\\acme.sh.exe'],
    });
    expect(config.declaredCommandProfileNames).toEqual([WINDOWS_ACME_PROFILE]);
    expect(config.policy.allowedCommands.certbot).toBeUndefined();
  });

  it('declares the names and keeps the same routing fields as Linux', () => {
    const { config } = buildAutomateConfig(base);
    expect(config.declaredTargetSelectors).toEqual(['iis.example.com']);
    expect(config.execution.enabled).toBe(true);
  });

  it('accepts a UNC path too', () => {
    expect(
      buildAutomateConfig({
        ...base,
        acmeClientPath: '\\\\fileserver\\tools\\acme.exe',
      }).ok
    ).toBe(true);
  });

  it('runs a script client through the shell the operator names', () => {
    const shell = 'C:\\Program Files\\Git\\bin\\bash.exe';
    const { config } = buildAutomateConfig({
      ...base,
      acmeClientPath: 'C:\\tools\\acme.sh\\acme.sh',
      acmeShellPath: shell,
    });
    expect(config.policy.allowedCommands[WINDOWS_ACME_PROFILE].argv).toEqual([
      shell,
      'C:\\tools\\acme.sh\\acme.sh',
    ]);
    expect(buildAutomateConfig({ ...base, acmeShellPath: 'bash' }).ok).toBe(
      false
    );
  });

  it('keeps the credential file in the state folder and locks it with icacls', () => {
    const { config } = buildAutomateConfig(base);
    const { credentialsFile: file } = config.dnsProviders.cloudflare;
    expect(file).toBe(
      'C:\\ProgramData\\TokenTimerAgent\\state\\dns-cloudflare-credentials.json'
    );
    const cmd = windowsCredentialAclCommand(file);
    expect(cmd).toContain('/inheritance:r');
    expect(cmd).toContain("'*S-1-5-32-544:(F)'");
    expect(cmd).toContain("'SYSTEM:(F)'");
  });

  it('gives Windows its own registration notes without --write-path', () => {
    expect(registrationNotesFor('windows').join(' ')).not.toMatch(/write-path/);
    expect(registrationNotesFor('linux').join(' ')).toMatch(/write-path/);
  });

  it('warns a Windows reader with an installed agent to keep its agentId line', () => {
    const windows = buildPreseedSteps({ os: 'windows', config: {} });
    expect(windows.steps.join(' ')).toMatch(/agentId/);
    expect(windows.steps.join(' ')).toMatch(/refuses to start/);
  });
});

describe('DNS credential file examples', () => {
  it('shows a JSON example with placeholders for every supported provider', () => {
    for (const id of Object.keys(DNS_PROVIDERS)) {
      const parsed = JSON.parse(dnsCredentialsExample(id));
      expect(Object.keys(parsed).length).toBeGreaterThan(0);
      expect(dnsCredentialsExample(id)).not.toMatch(SENSITIVE_PATTERN);
    }
    expect(dnsCredentialsExample('nope')).toBe('');
  });

  it('uses the field names the agent solvers read', () => {
    expect(Object.keys(JSON.parse(dnsCredentialsExample('azure-dns')))).toEqual(
      expect.arrayContaining([
        'tenantId',
        'clientId',
        'clientSecret',
        'subscriptionId',
        'resourceGroup',
      ])
    );
    expect(
      Object.keys(JSON.parse(dnsCredentialsExample('google-cloud-dns')))
    ).toEqual(
      expect.arrayContaining(['project_id', 'client_email', 'private_key'])
    );
    expect(Object.keys(JSON.parse(dnsCredentialsExample('rfc2136')))).toEqual(
      expect.arrayContaining(['server', 'keyName', 'keySecretBase64'])
    );
  });

  it('keeps the generated agent config on the safe propagation default', () => {
    const r = buildAutomateConfig({
      os: 'linux',
      names: ['www.example.com'],
      zone: 'example.com',
      dnsProvider: 'azure-dns',
      certPath: '/etc/ssl/tokentimer/a.pem',
    });
    expect(r.ok).toBe(true);
    expect(r.config.dnsPropagation).toBeUndefined();
  });
});

describe('Vault publish job creation', () => {
  const base = {
    names: ['*.example.com', 'example.com'],
    zone: 'example.com',
    dnsProvider: 'azure-dns',
    agentId: 'agent-1',
  };

  it('uses a stable key per issuer and request', () => {
    const key = vaultPublishIdempotencyKey(base);
    expect(vaultPublishIdempotencyKey(base)).toBe(key);
    expect(
      vaultPublishIdempotencyKey({ ...base, agentId: 'agent-2' })
    ).not.toBe(key);
    expect(key).toMatch(/^[A-Za-z0-9._:-]{1,128}$/);
  });

  it('holds the job for approval and carries the key algorithm', () => {
    const job = buildVaultPublishJob({
      ...base,
      assignedAgentId: 'agent-1',
      idempotencyKey: vaultPublishIdempotencyKey(base),
    });
    expect(job.requiresApproval).toBe(true);
    expect(job.payload.keyAlgorithm).toBe('ecdsa');
    expect(job.payload.publicationDestination.materialStoreRef).toBe(
      'customer'
    );
    expect(job.assignedAgentId).toBe('agent-1');
  });
});
