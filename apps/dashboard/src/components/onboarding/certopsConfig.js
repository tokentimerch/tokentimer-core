import { WINDOWS_ACME_PROFILE } from './certopsMatrix.js';
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

// Where the Linux installer puts the agent state. Keys live under it because
// it is the one writable location of the hardened service.
export const AGENT_STATE_DIR = '/opt/tokentimer-agent/state';
export const AGENT_KEYS_DIR = `${AGENT_STATE_DIR}/keys`;

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
 * The agent refuses a DNS credential file whose access list is wider than
 * SYSTEM and Administrators, so the file must be locked down after it is
 * created. *S-1-5-32-544 is the built-in Administrators group.
 */
export function windowsCredentialAclCommand(credentialsFile) {
  return `icacls ${psQuote(credentialsFile)} /inheritance:r /grant:r 'SYSTEM:(F)' '*S-1-5-32-544:(F)'`;
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
    return `.\\scripts\\install-agent.ps1 \`\n  ${parts.join(' `\n  ')}`;
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
  // The script lives under scripts/ in the agent package, like the Windows one.
  return `sudo ./scripts/install-agent.sh \\\n  ${flags.join(' \\\n  ')}`;
}

/**
 * The directory a Linux install grants write access to, derived from the
 * chosen certificate file. Nothing is granted when the path is not absolute.
 */
export function certDirectoryFor(certPath) {
  const text = String(certPath || '');
  if (!text.startsWith('/')) return '';
  const dir = text.replace(/\/[^/]*$/, '');
  return dir && dir !== '/' ? dir : '';
}

export const REGISTRATION_NOTES = [
  'The installer asks for the bootstrap token with a hidden prompt. Do not put it on the command line.',
  'Run it once with --dry-run first to see what it will change.',
  'Every --write-path directory must already exist, or the service fails to start.',
];

// --write-path only applies to the Linux service sandbox. The Windows
// installer takes the flag for parity but does not use it.
export const WINDOWS_REGISTRATION_NOTES = [
  'Run it from an elevated PowerShell, in the folder where you extracted the agent package (the one that contains scripts\\install-agent.ps1). Node.js 22 or 24 must be installed on the server.',
  'The installer asks for the bootstrap token with a hidden prompt. Do not put it on the command line.',
  'Run it once with --dry-run first to see what it will change.',
];

export function registrationNotesFor(os) {
  return os === 'windows' ? WINDOWS_REGISTRATION_NOTES : REGISTRATION_NOTES;
}

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
 * Web servers the agent can reload after it writes a certificate. The agent
 * always runs a "validate" command before the reload and both run as its
 * unprivileged service user. Apache and HAProxy can test their configuration
 * that way; nginx cannot (nginx -t must open /run/nginx.pid and its error log
 * for writing, which stock packages only allow for root). For nginx the
 * validate step therefore only checks that the unit is running, and the
 * configuration test is done as root by the unit's own reload (see
 * NGINX_RELOAD_DROPIN). argv is exact: policy refuses anything else.
 */
/** Name the Windows job and policy use for the operator's ACME client. */
export { WINDOWS_ACME_PROFILE };
const WINDOWS_PATH = /^([A-Za-z]:[\\/]|\\\\)[^\n\r]+$/;

export const RELOAD_SERVICES = {
  nginx: {
    label: 'nginx',
    validate: ['/usr/bin/systemctl', 'is-active', '--quiet', 'nginx'],
    reload: ['/usr/bin/systemctl', 'reload', 'nginx'],
  },
  apache: {
    label: 'Apache (apache2)',
    validate: ['/usr/sbin/apachectl', 'configtest'],
    reload: ['/usr/bin/systemctl', 'reload', 'apache2'],
  },
  haproxy: {
    label: 'HAProxy',
    validate: ['/usr/sbin/haproxy', '-c', '-f', '/etc/haproxy/haproxy.cfg'],
    reload: ['/usr/bin/systemctl', 'reload', 'haproxy'],
  },
};

/**
 * One-time host setup that makes `systemctl reload nginx` test the
 * configuration (as root) before it signals nginx. The stock nginx unit
 * reloads without testing, so without this a rejected configuration would
 * look like a successful reload. The final one-second pause gives the new
 * workers time to take over: `nginx -s reload` returns before they serve, and
 * a consumer's check of the served certificate right after the reload would
 * otherwise still see the old one.
 */
export const NGINX_RELOAD_DROPIN = [
  'sudo mkdir -p /etc/systemd/system/nginx.service.d',
  "sudo tee /etc/systemd/system/nginx.service.d/tokentimer-reload.conf <<'EOF'",
  '[Service]',
  'ExecReload=',
  'ExecReload=/usr/sbin/nginx -t -q -g "daemon on; master_process on;"',
  'ExecReload=/usr/sbin/nginx -g "daemon on; master_process on;" -s reload',
  'ExecReload=/usr/bin/sleep 1',
  'EOF',
  'sudo systemctl daemon-reload',
].join('\n');

/** The two named commands a reload needs; names are what jobs refer to. */
export function reloadCommands(service) {
  const def = RELOAD_SERVICES[service];
  if (!def) return {};
  return {
    [`${service}-validate`]: { argv: def.validate },
    [`${service}-reload`]: { argv: def.reload },
  };
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
  reloadService = '',
  acmeClientPath = '',
  acmeShellPath = '',
  acmeProfile = WINDOWS_ACME_PROFILE,
  dryRun = true,
}) {
  const problems = [];
  if (os === 'windows' && !WINDOWS_PATH.test(String(acmeClientPath || '')))
    problems.push(
      'Enter the full path of the ACME client on the Windows host, for example C:\\acme\\acme.sh.'
    );
  if (
    os === 'windows' &&
    String(acmeShellPath || '').trim() &&
    !WINDOWS_PATH.test(String(acmeShellPath).trim())
  )
    problems.push(
      'Enter the full path of the shell that runs the ACME client, for example C:\\Program Files\\Git\\bin\\bash.exe, or leave it empty for a native program.'
    );
  if (reloadService && os === 'windows')
    problems.push('Reloading a web server is for Linux hosts.');
  if (reloadService && !RELOAD_SERVICES[reloadService])
    problems.push('Choose nginx, Apache or HAProxy, or no reload.');
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

  // Windows uses an operator-supplied ACME client under a name the job refers
  // to; Linux uses certbot. acme.sh is a shell script, so on Windows the
  // allowed command is the shell followed by the script.
  const windowsAcme =
    os === 'windows'
      ? {
          argv: [
            ...(String(acmeShellPath || '').trim()
              ? [String(acmeShellPath).trim()]
              : []),
            String(acmeClientPath).trim(),
          ],
        }
      : undefined;
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
    // The control plane routes jobs by what the agent declares, not by what
    // the policy allows. Without these two the agent registers and passes a
    // dry run but never claims an issuance job.
    declaredTargetSelectors: list,
    ...(certbot ? { declaredCommandProfileNames: ['certbot'] } : {}),
    ...(windowsAcme ? { declaredCommandProfileNames: [acmeProfile] } : {}),
    execution: {
      enabled: true,
      dryRun,
      keysDir: os === 'windows' ? undefined : AGENT_KEYS_DIR,
    },
    policy: {
      allowedTargetSelectors: list,
      // Deploying also names the private key in its keys directory, so that
      // directory has to be allowed next to the certificate directory.
      allowedPaths:
        os === 'windows'
          ? []
          : [certPath.replace(/\/[^/]+$/, ''), AGENT_KEYS_DIR],
      allowedCaEndpoints: [caEndpoint],
      allowedDnsZones: [zone],
      allowedDnsProviders: [dnsProvider],
      ...(certbot || windowsAcme || reloadService
        ? {
            allowedCommands: {
              ...(certbot ? { certbot } : {}),
              ...(windowsAcme ? { [acmeProfile]: windowsAcme } : {}),
              ...(reloadService ? reloadCommands(reloadService) : {}),
            },
          }
        : {}),
    },
    dnsProviders: {
      [dnsProvider]: {
        credentialsFile:
          credentialsFile ||
          (os === 'windows'
            ? `C:\\ProgramData\\TokenTimerAgent\\state\\dns-${dnsProvider}-credentials.json`
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

/**
 * Windows IIS issuance: the certificate goes to a machine store and an IIS
 * binding, never a file path. Shape follows the server's windows-iis target
 * contract. Not yet verified on a real Windows host.
 */
function buildWindowsIssueJob({
  names,
  zone,
  dnsProvider,
  caEndpoint,
  iisSite,
  iisPort,
  iisStore,
  sniHost,
  acmeProfile,
  assignedAgentId,
  idempotencyKey,
}) {
  const list = (names || []).map(n => String(n).trim()).filter(Boolean);
  const binding = { site: iisSite, port: Number(iisPort) };
  if (String(sniHost || '').trim()) binding.sniHost = String(sniHost).trim();
  return {
    operation: 'issue',
    payload: {
      target: {
        type: 'windows-iis',
        reference: list[0],
        store: iisStore,
        binding,
      },
      sans: list,
      commandRef: acmeProfile,
      acmeKind: 'acme.sh',
      caEndpoint,
      dnsZone: zone,
      dnsProvider,
    },
    idempotencyKey,
    ...(assignedAgentId ? { assignedAgentId } : {}),
  };
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
  reloadService = '',
  iisSite = 'Default Web Site',
  iisPort = 443,
  iisStore = 'My',
  sniHost = '',
  acmeProfile = WINDOWS_ACME_PROFILE,
  assignedAgentId,
  idempotencyKey,
}) {
  if (os === 'windows') {
    return buildWindowsIssueJob({
      names,
      zone,
      dnsProvider,
      caEndpoint,
      iisSite,
      iisPort,
      iisStore,
      sniHost,
      acmeProfile,
      assignedAgentId,
      idempotencyKey,
    });
  }
  if (reloadService && !RELOAD_SERVICES[reloadService]) {
    throw new Error(`Unknown web server: ${reloadService}.`);
  }
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
  if (reloadService) {
    payload.reloadService = reloadService;
    // Same names the configuration step put in the agent's policy.
    payload.reloadCommandRefs = {
      validate: `${reloadService}-validate`,
      reload: `${reloadService}-reload`,
    };
  }
  return {
    operation: 'issue',
    payload,
    idempotencyKey,
    ...(assignedAgentId ? { assignedAgentId } : {}),
  };
}

/**
 * Stable per request: the same names, zone, path and CA always map to the same
 * key, so a reload or double click returns the existing job instead of
 * placing a second (rate-limited) ACME order. A new attempt number is the
 * only way to ask again after a failure.
 */
export function issueIdempotencyKey({
  names,
  zone,
  certPath,
  caEndpoint = LETS_ENCRYPT_STAGING,
  reloadService = '',
  attempt = 1,
}) {
  // The reload choice is part of the request: changing it must create a new
  // job, not replay the earlier one without the reload.
  const text = [
    (names || []).join(','),
    zone,
    certPath,
    caEndpoint,
    reloadService,
  ].join('|');
  let hash = 5381;
  for (let i = 0; i < text.length; i += 1) {
    hash = ((hash << 5) + hash + text.charCodeAt(i)) >>> 0;
  }
  return `wizard-issue-${hash.toString(16)}-${attempt}`;
}

export const STAGING_CA = LETS_ENCRYPT_STAGING;
export const PRODUCTION_CA = LETS_ENCRYPT_PRODUCTION;

/**
 * The harmless job used to prove signed dispatch works before real work.
 * `mode` is a top-level field: inside the payload it would be ignored and the
 * server would create a real job instead of a dry run.
 */
export function buildDryRunJob({ assignedAgentId, idempotencyKey }) {
  return {
    operation: 'noop',
    mode: 'dry_run',
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

/**
 * Upgrade of the TokenTimer chart release that carries the controller. The
 * release keeps its other values; only the controller block is added.
 */
export function buildControllerUpgradeCommand({
  namespace = 'tokentimer',
  release = 'tokentimer',
}) {
  return [
    `helm upgrade --install ${release} oci://ghcr.io/tokentimerch/charts/tokentimer \\`,
    `  --namespace ${namespace} --reuse-values -f controller-values.yaml`,
  ].join('\n');
}

/**
 * Extra values for a cluster that does not run TokenTimer itself. The chart
 * renders the whole application unless these are set, and it insists on an
 * admin email and a database host even when only the controller is wanted.
 * The database values are placeholders the controller never reads.
 */
export function buildControllerOnlyValues() {
  return [
    'api:',
    '  enabled: false',
    'dashboard:',
    '  enabled: false',
    'worker:',
    '  cronjobs:',
    '    discovery: { enabled: false }',
    '    delivery: { enabled: false }',
    '    weeklyDigest: { enabled: false }',
    '    endpointCheck: { enabled: false }',
    '    autoSync: { enabled: false }',
    '    certops: { enabled: false }',
    'postgresql:',
    '  cloudnative: { enabled: false }',
    '  external: { enabled: true, host: unused.invalid, password: unused }',
    'config:',
    '  disableAdminBootstrap: true',
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
  caFile = '',
  probeTrustCaFile = '',
}) {
  const problems = [];
  if (!/^https:\/\//.test(vaultAddress || ''))
    problems.push('The Vault address must use https.');
  if (caFile && !String(caFile).startsWith('/'))
    problems.push('The Vault CA file must be an absolute path.');
  if (probeTrustCaFile && !String(probeTrustCaFile).startsWith('/'))
    problems.push(
      'The CA file for the served-certificate check must be an absolute path.'
    );
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
    ...(caFile ? { caFile } : {}),
    timeoutMs: 10000,
  };
  const group = { workspaceId, prefix, sans: names, keyAlgorithm: 'ec' };
  const issuer = {
    agentId: issuerAgentId || 'REPLACE_WITH_ISSUER_WIRE_ID',
    // Job routing reads these, not the policy (same as first issuance).
    declaredTargetSelectors: names,
    declaredCommandProfileNames: ['certbot'],
    execution: {
      enabled: true,
      dryRun: true,
      keysDir: AGENT_KEYS_DIR,
    },
    policy: {
      allowedTargetSelectors: names,
      allowedPaths: [AGENT_KEYS_DIR],
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
    declaredTargetSelectors: [bindingId],
    execution: {
      enabled: true,
      dryRun: true,
      keysDir: AGENT_KEYS_DIR,
    },
    policy: {
      allowedTargetSelectors: [bindingId],
      allowedPaths: [deployPath, AGENT_KEYS_DIR],
      allowedCommands: {
        ...reloadCommands('nginx'),
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
            // Needed when the certificate comes from a private CA: the
            // "trust" check validates the chain against this file.
            ...(probeTrustCaFile ? { trustCaFile: probeTrustCaFile } : {}),
          },
        ],
      },
    },
  };
  return { ok: true, issuer, consumer };
}

/**
 * The job that publishes a certificate to Vault. The group id appears on the
 * created job as payload.publication.groupId. The agent refuses a publish job
 * without a key algorithm, so it is part of the body. There is no screen for
 * this job: it is created through the Jobs API.
 */
export function buildVaultPublishJob({
  names,
  zone,
  dnsProvider,
  caEndpoint = LETS_ENCRYPT_STAGING,
  assignedAgentId,
  idempotencyKey,
  materialStoreRef = 'customer',
  issuanceProfileRef = 'wildcard',
  profileRevision = 1,
}) {
  const list = (names || []).map(n => String(n).trim()).filter(Boolean);
  return {
    operation: 'issue',
    // Hold the job until the Vault policies and agent configuration exist.
    requiresApproval: true,
    idempotencyKey,
    ...(assignedAgentId ? { assignedAgentId } : {}),
    payload: {
      target: { type: 'domain', reference: list[0] },
      sans: list,
      commandRef: 'certbot',
      caEndpoint,
      dnsZone: zone,
      dnsProvider,
      keyAlgorithm: 'ecdsa',
      keySize: 256,
      publicationDestination: {
        materialStoreRef,
        issuanceProfileRef,
        profileRevision,
      },
    },
  };
}

/** Assigns one consumer agent to the distribution group. */
export function buildVaultConsumerAssignment({ agentRowId }) {
  return {
    agentId: agentRowId,
    deploymentProfileRef: 'nginx-public',
    profileRevision: 1,
    required: true,
    wave: 0,
    verificationPolicy: 'trust',
    freshnessSeconds: 3600,
    state: 'active',
  };
}

/** Rollout of one published version to the assigned consumers. */
export function buildVaultRollout({ materialVersionId }) {
  return { materialVersionId, maxParallel: 1 };
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
        'Save the JSON below as config.json in that folder, as UTF-8 without a byte order mark. Notepad does this by default. In Windows PowerShell 5.1, Set-Content -Encoding utf8 adds a mark and the agent then refuses the file; use [IO.File]::WriteAllText with a UTF8Encoding($false) instead.',
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

/**
 * serverUrl and workspaceId are normally written by the installer. The
 * installer keeps a prepared file untouched, so a loopback http address also
 * needs the matching opt-in here or the agent refuses to start.
 */
export function mergeInstallerFields(config, { apiUrl, workspaceId }) {
  return {
    serverUrl: apiUrl,
    workspaceId,
    ...(isLoopbackHttp(apiUrl) ? { allowInsecureLocalHttp: true } : {}),
    ...config,
  };
}
