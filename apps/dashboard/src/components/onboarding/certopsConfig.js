// Generates the host-side artifacts the wizard hands to the operator. The
// control plane cannot edit agent configuration, so these are copy-paste
// runbooks. Nothing here ever contains a credential: only file paths and
// references the operator fills in on the host.

const HOSTNAME =
  /^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const ZONE =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LETS_ENCRYPT_STAGING =
  'https://acme-staging-v02.api.letsencrypt.org/directory';
const LETS_ENCRYPT_PRODUCTION =
  'https://acme-v02.api.letsencrypt.org/directory';

export const DNS_PROVIDERS = {
  cloudflare: {
    label: 'Cloudflare',
    fields: ['apiToken'],
    note: 'Token needs Zone:DNS:Edit on the zone.',
  },
  route53: {
    label: 'AWS Route 53',
    fields: ['accessKeyId', 'secretAccessKey', 'hostedZoneId'],
    note: 'Use a key limited to the hosted zone.',
  },
  'azure-dns': {
    label: 'Azure DNS',
    fields: [
      'tenantId',
      'clientId',
      'clientSecret',
      'subscriptionId',
      'resourceGroup',
    ],
    note: 'Grant DNS Zone Contributor on the zone.',
  },
  'google-cloud-dns': {
    label: 'Google Cloud DNS',
    fields: ['service account JSON'],
    note: 'Service account with DNS administrator on the zone.',
  },
  rfc2136: {
    label: 'RFC 2136 (TSIG)',
    fields: ['server', 'keyName', 'keySecretBase64'],
    note: 'Dynamic updates must be allowed for _acme-challenge.',
  },
};

export function isValidHostname(value) {
  return HOSTNAME.test(String(value || '').trim());
}

export function isValidZone(value) {
  return ZONE.test(String(value || '').trim());
}

/** Whether a name falls inside the DNS zone (wildcards allowed). */
export function nameInZone(name, zone) {
  const n = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '');
  const z = String(zone || '')
    .trim()
    .toLowerCase();
  return Boolean(z) && (n === z || n.endsWith(`.${z}`));
}

/**
 * Plain http is accepted only for a loopback host, which is what the
 * installers allow behind --allow-insecure-local-http. Anything else must be
 * https so a bootstrap token is never sent in clear text over a network.
 */
export function isLoopbackHttp(value) {
  try {
    const url = new URL(String(value || ''));
    return (
      url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)
    );
  } catch (_) {
    return false;
  }
}
function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

/**
 * Install command without the bootstrap token. The installer prompts for the
 * token, so it never lands in shell history or in this app's state.
 */
export function buildInstallCommand({
  os,
  apiUrl,
  workspaceId,
  trustStore = false,
  writePaths = [],
  reloadServices = [],
  caBundle = '',
}) {
  if (!/^https:\/\//i.test(apiUrl || '') && !isLoopbackHttp(apiUrl)) {
    throw new Error(
      'The API address must use https. Plain http is only allowed for localhost.'
    );
  }
  if (!UUID.test(workspaceId || '')) {
    throw new Error('Invalid workspace id.');
  }
  const insecureLoopback = isLoopbackHttp(apiUrl);
  if (os === 'windows') {
    const parts = [
      `--api-url ${psQuote(apiUrl)}`,
      `--workspace-id ${psQuote(workspaceId)}`,
    ];
    if (caBundle) parts.push(`--ca-bundle ${psQuote(caBundle)}`);
    if (insecureLoopback) parts.push('--allow-insecure-local-http');
    return `.\\install-agent.ps1 \`\n  ${parts.join(' `\n  ')}`;
  }
  const flags = [
    `--api-url ${shQuote(apiUrl)}`,
    `--workspace-id ${shQuote(workspaceId)}`,
  ];
  if (insecureLoopback) flags.push('--allow-insecure-local-http');
  for (const p of writePaths) flags.push(`--write-path ${shQuote(p)}`);
  for (const s of reloadServices) flags.push(`--reload-service ${s}`);
  if (caBundle) flags.push(`--ca-bundle ${shQuote(caBundle)}`);
  // The docs advise opting out of the trust store on hosts that will not
  // receive a trust anchor, so it is explicit rather than assumed.
  flags.push(trustStore ? '--trust-store' : '--no-trust-store');
  return `sudo ./install-agent.sh \\\n  ${flags.join(' \\\n  ')}`;
}

export const REGISTRATION_NOTES = [
  'The installer asks for the bootstrap token with a hidden prompt. Do not put it on the command line.',
  'Run it once with --dry-run first to see what it will change.',
  'Every --write-path directory must already exist, or the service fails to start.',
];

/**
 * Observe-only agent configuration: it registers and reports discovery, and
 * never claims jobs, because execution stays disabled.
 */
export function buildObserveConfig({ os, directories = [] }) {
  const config = {
    execution: { enabled: false, dryRun: true },
  };
  if (os === 'windows') {
    config.windowsDiscovery = {
      enabled: true,
      intervalMs: 1800000,
      stores: ['My'],
    };
  } else {
    config.discovery = {
      directories: directories.length ? directories : ['/etc/ssl/certs'],
      intervalMs: 3600000,
    };
  }
  return config;
}

/**
 * ACME DNS-01 issuance configuration. Policy is default-deny, so every
 * allowlist is explicit and as narrow as the request.
 */
export function buildAutomateConfig({
  os,
  names,
  zone,
  dnsProvider,
  caEndpoint = LETS_ENCRYPT_STAGING,
  certPath,
  credentialsFile,
  dryRun = true,
}) {
  const problems = [];
  const list = (names || []).map(n => String(n).trim()).filter(Boolean);
  if (list.length === 0) problems.push('Enter at least one name.');
  for (const n of list) {
    if (!isValidHostname(n)) problems.push(`"${n}" is not a valid hostname.`);
    else if (!nameInZone(n, zone))
      problems.push(`"${n}" is not inside ${zone}.`);
  }
  if (!isValidZone(zone)) problems.push('Enter a valid DNS zone.');
  if (!DNS_PROVIDERS[dnsProvider]) problems.push('Choose a DNS provider.');
  if (!/^https:\/\//.test(caEndpoint || ''))
    problems.push('The CA address must use https.');
  if (os !== 'windows' && !String(certPath || '').startsWith('/')) {
    problems.push('The certificate path must be an absolute file path.');
  }
  if (problems.length) return { ok: false, problems };

  const certbot =
    os === 'windows'
      ? undefined
      : {
          // certbot needs terms acceptance and a contact choice in argv.
          argv: [
            '/usr/bin/certbot',
            '--agree-tos',
            '--register-unsafely-without-email',
          ],
        };
  const config = {
    execution: {
      enabled: true,
      dryRun,
      keysDir: os === 'windows' ? undefined : '/var/lib/tokentimer-agent/keys',
    },
    policy: {
      allowedTargetSelectors: list,
      allowedPaths:
        os === 'windows'
          ? []
          : [certPath.replace(/\/[^/]+$/, ''), '/var/lib/tokentimer-agent'],
      allowedCaEndpoints: [caEndpoint],
      allowedDnsZones: [zone],
      allowedDnsProviders: [dnsProvider],
      ...(certbot ? { allowedCommands: { certbot } } : {}),
    },
    dnsProviders: {
      [dnsProvider]: {
        credentialsFile:
          credentialsFile ||
          (os === 'windows'
            ? `C:\\ProgramData\\TokenTimerAgent\\${dnsProvider}.json`
            : `/etc/tokentimer-agent/${dnsProvider}.json`),
      },
      zoneProviderMap: { [zone]: dnsProvider },
    },
  };
  return { ok: true, config: stripUndefined(config) };
}

function stripUndefined(value) {
  return JSON.parse(JSON.stringify(value));
}

/** The issue job body for the Jobs API (never contains a private key). */
export function buildIssueJob({
  os,
  names,
  zone,
  dnsProvider,
  caEndpoint = LETS_ENCRYPT_STAGING,
  certPath,
  commandRef = 'certbot',
  verifyHost,
  assignedAgentId,
  idempotencyKey,
}) {
  const list = (names || []).map(n => String(n).trim()).filter(Boolean);
  const payload = {
    target: { type: 'domain', reference: list[0] },
    sans: list,
    commandRef,
    caEndpoint,
    dnsZone: zone,
    dnsProvider,
    certPath,
  };
  if (verifyHost) {
    payload.verifyHost = verifyHost;
    payload.verifyPort = 443;
  }
  if (os === 'windows') {
    delete payload.certPath;
    delete payload.commandRef;
  }
  return {
    operation: 'issue',
    payload,
    idempotencyKey,
    ...(assignedAgentId ? { assignedAgentId } : {}),
  };
}

export const STAGING_CA = LETS_ENCRYPT_STAGING;
export const PRODUCTION_CA = LETS_ENCRYPT_PRODUCTION;

/** The harmless job used to prove signed dispatch works before real work. */
export function buildDryRunJob({ assignedAgentId, idempotencyKey }) {
  return {
    operation: 'noop',
    payload: { mode: 'dry_run' },
    idempotencyKey,
    assignedAgentId,
  };
}

/** Kubernetes controller values, observe mode by default. */
export function buildControllerValues({
  apiUrl,
  workspaceId,
  clusterId,
  mode = 'observe',
}) {
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(clusterId || '')) {
    throw new Error(
      'The cluster id must be lowercase letters, digits and dashes.'
    );
  }
  return [
    'certops:',
    '  controller:',
    '    enabled: true',
    `    mode: ${mode === 'provision' ? 'provision' : 'observe'}`,
    '    api:',
    `      url: ${apiUrl}`,
    `      workspaceId: ${workspaceId}`,
    `      clusterId: ${clusterId}`,
    '    apiToken:',
    '      existingSecret: tokentimer-controller-token',
    '      key: token',
  ].join('\n');
}

export function buildControllerSecretCommand({ namespace = 'tokentimer' }) {
  // The token is read from stdin so it never appears in shell history.
  return [
    `kubectl create namespace ${namespace} --dry-run=client -o yaml | kubectl apply -f -`,
    `read -rs TOKEN && kubectl -n ${namespace} create secret generic tokentimer-controller-token --from-literal=token="$TOKEN"`,
  ].join('\n');
}

/**
 * Vault distribution configuration. It is generated from the shipped
 * examples and contains no Vault token: agents read a token file refreshed by
 * Vault Agent.
 */
export function buildVaultConfigs({
  vaultAddress,
  mount = 'secret',
  namespace,
  workspaceId,
  groupId,
  names,
  zone,
  dnsProvider,
  caEndpoint = LETS_ENCRYPT_STAGING,
  issuerAgentId,
  consumerAgentId,
  consumerBindingId,
  deployPath = '/etc/nginx/tokentimer',
}) {
  const problems = [];
  if (!/^https:\/\//.test(vaultAddress || ''))
    problems.push('The Vault address must use https.');
  if (!UUID.test(workspaceId || '')) problems.push('Invalid workspace id.');
  if (!UUID.test(groupId || '')) {
    problems.push(
      'Use the group id shown on the distribution group after the first publish job.'
    );
  }
  if (!(names || []).length) problems.push('Enter at least one name.');
  if (!isValidZone(zone)) problems.push('Enter a valid DNS zone.');
  if (problems.length) return { ok: false, problems };

  const prefix = `tokentimer/${workspaceId}/${groupId}`;
  const store = {
    address: vaultAddress,
    mount,
    ...(namespace ? { namespace } : {}),
    timeoutMs: 10000,
  };
  const group = { workspaceId, prefix, sans: names, keyAlgorithm: 'ec' };
  const issuer = {
    agentId: issuerAgentId || 'REPLACE_WITH_ISSUER_WIRE_ID',
    execution: {
      enabled: true,
      dryRun: true,
      keysDir: '/var/lib/tokentimer-agent/keys',
    },
    policy: {
      allowedTargetSelectors: names,
      allowedPaths: ['/var/lib/tokentimer-agent'],
      allowedCaEndpoints: [caEndpoint],
      allowedDnsZones: [zone],
      allowedDnsProviders: [dnsProvider],
      allowedCommands: {
        certbot: {
          argv: [
            '/usr/bin/certbot',
            '--agree-tos',
            '--register-unsafely-without-email',
          ],
        },
      },
    },
    dnsProviders: {
      [dnsProvider]: {
        credentialsFile: `/etc/tokentimer-agent/${dnsProvider}.json`,
      },
      zoneProviderMap: { [zone]: dnsProvider },
    },
    materialStores: {
      customer: {
        ...store,
        tokenFile: '/run/tokentimer-vault/issuer-token',
        groups: {
          [groupId]: {
            ...group,
            issuerAgentId: issuerAgentId || 'REPLACE_WITH_ISSUER_WIRE_ID',
            issuanceProfileRef: 'wildcard',
            profileRevision: 1,
            caEndpoint,
            dnsProvider,
            dnsZone: zone,
          },
        },
      },
    },
  };
  const bindingId = consumerBindingId || 'REPLACE_WITH_BINDING_ID';
  const consumer = {
    agentId: consumerAgentId || 'REPLACE_WITH_CONSUMER_WIRE_ID',
    execution: {
      enabled: true,
      dryRun: true,
      keysDir: '/var/lib/tokentimer-agent/keys',
    },
    policy: {
      allowedTargetSelectors: [bindingId],
      allowedPaths: [deployPath, '/var/lib/tokentimer-agent'],
      allowedCommands: {
        'nginx-validate': { argv: ['/usr/sbin/nginx', '-t'] },
        'nginx-reload': { argv: ['/usr/sbin/nginx', '-s', 'reload'] },
      },
    },
    materialStores: {
      customer: {
        ...store,
        tokenFile: '/run/tokentimer-vault/consumer-token',
        groups: { [groupId]: group },
      },
    },
    materialBindings: {
      [bindingId]: {
        workspaceId,
        groupId,
        agentId: consumerAgentId || 'REPLACE_WITH_CONSUMER_WIRE_ID',
        materialStoreRef: 'customer',
        deploymentProfileRef: 'nginx-public',
        profileRevision: 1,
        authorizationRevision: 1,
        verificationPolicy: 'trust',
        reloadService: 'nginx',
        reloadCommandRefs: {
          validate: 'nginx-validate',
          reload: 'nginx-reload',
        },
        target: {
          type: 'endpoint',
          reference: 'nginx-public',
          certPath: `${deployPath}/fullchain.pem`,
          keyPath: `${deployPath}/privkey.pem`,
        },
        probes: [
          {
            dialAddress: '127.0.0.1',
            port: 443,
            sni: names[0].replace(/^\*\./, 'www.'),
          },
        ],
      },
    },
  };
  return { ok: true, issuer, consumer };
}

/**
 * Vault policies scoped to one workspace and group, matching the shipped
 * example: the issuer can only create and read immutable bundle objects, the
 * consumer can only read them, and the scanner identity is explicitly denied.
 * Nothing broader than the bundles path is ever granted.
 */
export function buildVaultPolicies({ mount = 'secret', workspaceId, groupId }) {
  if (!UUID.test(workspaceId || '') || !UUID.test(groupId || '')) {
    throw new Error('Workspace and group ids are required for Vault policies.');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(mount)) {
    throw new Error('Invalid Vault mount name.');
  }
  const bundles = `${mount}/data/tokentimer/${workspaceId}/${groupId}/bundles/*`;
  const metadata = `${mount}/metadata/tokentimer/${workspaceId}/${groupId}/bundles/*`;
  return {
    issuer: `path "${bundles}" {\n  capabilities = ["create", "read"]\n}`,
    consumer: `path "${bundles}" {\n  capabilities = ["read"]\n}`,
    scanner:
      `path "${bundles}" {\n  capabilities = ["deny"]\n}\n` +
      `path "${metadata}" {\n  capabilities = ["deny"]\n}`,
  };
}
export const SENSITIVE_PATTERN =
  /(ttboot_|ttagent_|ttx_|hvs\.|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

/**
 * The installer keeps an existing config.json untouched, which is the only
 * supported way to have command profiles and other settings in place before
 * the first registration (command profile names are reported only then). The
 * prepared file must not contain agentId or a credential: the agent writes
 * those itself.
 */
export function buildPreseedSteps({ os, config }) {
  const json = JSON.stringify(config, null, 2);
  if (os === 'windows') {
    return {
      location: 'C:\\ProgramData\\TokenTimerAgent\\state\\config.json',
      steps: [
        'Create the state folder if it does not exist: C:\\ProgramData\\TokenTimerAgent\\state',
        'Save the JSON below as config.json in that folder.',
        'Run the installer. It keeps your config.json and adds the server address.',
      ],
      json,
    };
  }
  return {
    location: '/opt/tokentimer-agent/state/config.json',
    steps: [
      'Create the state directory: sudo mkdir -p /opt/tokentimer-agent/state && sudo chmod 0700 /opt/tokentimer-agent/state',
      'Save the JSON below as /opt/tokentimer-agent/state/config.json with mode 0600.',
      'Run the installer. It logs "Existing config.json found; leaving it untouched" and keeps your file.',
      'The installer adds the service user and fixes ownership. Check the file is readable by it with: sudo -u tokentimer-agent test -r /opt/tokentimer-agent/state/config.json',
    ],
    json,
  };
}

/** serverUrl and workspaceId are normally written by the installer. */
export function mergeInstallerFields(config, { apiUrl, workspaceId }) {
  return { serverUrl: apiUrl, workspaceId, ...config };
}
