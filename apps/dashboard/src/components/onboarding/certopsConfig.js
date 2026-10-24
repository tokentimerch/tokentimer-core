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
export const AGENT_USER = 'tokentimer-agent';

// Where a Vault consumer installs the shared certificate and key. The install
// command creates it with --write-path, owned by the agent user.
export const CONSUMER_DEPLOY_PATH = '/etc/nginx/tokentimer';

/**
 * Where a Linux order leaves the private key: a file next to the certificate
 * with .key appended. HAProxy loads exactly that name on its own when the
 * certificate file holds no key, and nginx and Apache name it explicitly.
 */
export function keyPathFor(certPath) {
  const text = String(certPath || '');
  return text.startsWith('/') ? `${text}.key` : '';
}

/** Host name the consumer's own served-certificate check asks for. */
export function probeHostFor(names) {
  const first = String((names || [])[0] || '');
  return first.replace(/^\*\./, 'www.');
}

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

// Shape of the agent-local credential file per provider, with placeholders
// only. Field names are the ones the agent's DNS solvers read.
const DNS_CREDENTIAL_SHAPES = {
  cloudflare: { apiToken: '<api token>' },
  route53: {
    accessKeyId: '<access key id>',
    secretAccessKey: '<secret access key>',
    hostedZoneId: '<hosted zone id>',
  },
  'azure-dns': {
    tenantId: '<tenant id>',
    clientId: '<application (client) id>',
    clientSecret: '<client secret>',
    subscriptionId: '<subscription id>',
    resourceGroup: '<resource group of the DNS zone>',
  },
  'google-cloud-dns': {
    project_id: '<project id>',
    client_email: '<service account email>',
    private_key: '<private_key from the service account JSON key>',
  },
  rfc2136: {
    server: '<name server host or IP>',
    port: 53,
    keyName: '<TSIG key name>',
    keyAlgorithm: 'hmac-sha256',
    keySecretBase64: '<base64 TSIG secret>',
  },
};

/** Credential file example with placeholders, or '' for an unknown provider. */
export function dnsCredentialsExample(dnsProvider) {
  const shape = DNS_CREDENTIAL_SHAPES[dnsProvider];
  return shape ? JSON.stringify(shape, null, 2) : '';
}

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
 * Linux DNS credential file preparation. The installer does not create
 * /etc/tokentimer-agent, and the agent user only exists after it has run, so
 * the owner is set afterwards.
 */
export function buildLinuxCredentialPrep(credentialsFile) {
  const file = String(credentialsFile || '');
  const dir = file.startsWith('/') ? file.replace(/\/[^/]*$/, '') : '';
  if (!dir) return '';
  const quote = p => (/^[\w./-]+$/.test(p) ? p : shQuote(p));
  return [
    `sudo install -d -m 0755 ${quote(dir)}`,
    `# create ${file} with the credential fields, then after the installer has run:`,
    `sudo chown ${AGENT_USER}:${AGENT_USER} ${quote(file)}`,
    `sudo chmod 0600 ${quote(file)}`,
  ].join('\n');
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
  // Run through bash: the release tarball does not mark it executable.
  return `sudo bash ./scripts/install-agent.sh \\\n  ${flags.join(' \\\n  ')}`;
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

/**
 * What the Linux installer has to be given for this setup: the folder the
 * agent writes to and the web server it may reload. A registered agent keeps
 * the options it was installed with, so a change needs the installer again.
 */
export function installerOptionsFor({
  objective,
  infrastructure = 'linux',
  certPath = '',
  reloadService = '',
} = {}) {
  if (infrastructure !== 'linux' || objective !== 'automate') {
    return { writePaths: [], reloadServices: [] };
  }
  const dir = certDirectoryFor(certPath);
  return {
    writePaths: dir ? [dir] : [],
    reloadServices: RELOAD_SERVICES[reloadService] ? [reloadService] : [],
  };
}

/** Stable text for the options above, empty when the installer needs none. */
export function installerOptionsKey(options) {
  const { writePaths = [], reloadServices = [] } = options || {};
  if (!writePaths.length && !reloadServices.length) return '';
  return JSON.stringify([writePaths, reloadServices]);
}

// Same four points on both systems, in the order an operator does them.
// "Download and verify" is shown as its own block (buildPackageCommand).
export const REGISTRATION_NOTES = [
  'On the server, download the agent package for your TokenTimer version and check its checksum, with the commands below.',
  'Extract it and open a terminal in the extracted folder, the one that contains scripts/install-agent.sh.',
  'Run the install command below from that folder, with sudo. Add --dry-run first to see what it will change.',
  'The installer asks for the bootstrap token with a hidden prompt: paste the token there. Do not put it on the command line.',
  'The installer creates every --write-path directory and hands it to the agent user (mode 0750). Files you place there yourself must belong to that user too, or the agent cannot replace them.',
];

// --write-path only applies to the Linux service sandbox. The Windows
// installer takes the flag for parity but does not use it.
export const WINDOWS_REGISTRATION_NOTES = [
  'On the server, download the agent package for your TokenTimer version and check its checksum, with the commands below. Node.js 22 or 24 must be installed on the server.',
  'Extract it and open an elevated PowerShell in the extracted folder, the one that contains scripts\\install-agent.ps1.',
  'Run the install command below from that folder. Add --dry-run first to see what it will change.',
  'The installer asks for the bootstrap token with a hidden prompt: paste the token there. Do not put it on the command line.',
];

export function registrationNotesFor(os) {
  return os === 'windows' ? WINDOWS_REGISTRATION_NOTES : REGISTRATION_NOTES;
}

/**
 * Download, checksum and extract the agent release. Same commands as the
 * install runbook ("Getting the agent package"). The release publishes the
 * tarball and a .sha256 file next to it, and the tarball unpacks into
 * package/.
 */
export function buildPackageCommand(os) {
  if (os === 'windows') {
    return [
      "$Version = '<version>'   # your TokenTimer version, for example 0.18.0",
      '$Base = "https://github.com/tokentimerch/tokentimer-core/releases/download/v$Version"',
      '$Archive = "tokentimer-agent-$Version.tgz"',
      'Invoke-WebRequest "$Base/$Archive" -OutFile $Archive',
      'Invoke-WebRequest "$Base/$Archive.sha256" -OutFile "$Archive.sha256"',
      '$Expected = ((Get-Content "$Archive.sha256" -Raw).Trim() -split \'\\s+\')[0]',
      "if ($Expected -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash $Archive -Algorithm SHA256).Hash -ine $Expected) { throw 'Agent archive checksum mismatch' }",
      "if (Test-Path package) { throw 'Use an empty folder; package already exists' }",
      'tar -xzf $Archive',
      'Set-Location package',
    ].join('\n');
  }
  return [
    'VERSION="<version>"   # your TokenTimer version, for example 0.18.0',
    'BASE_URL="https://github.com/tokentimerch/tokentimer-core/releases/download/v${VERSION}"',
    'TARBALL="tokentimer-agent-${VERSION}.tgz"',
    'curl -fsSL -O "${BASE_URL}/${TARBALL}" &&',
    'curl -fsSL -O "${BASE_URL}/${TARBALL}.sha256" &&',
    'sha256sum -c "${TARBALL}.sha256" &&',
    'test ! -e package &&',
    'tar -xzf "${TARBALL}" &&',
    'cd package',
  ].join('\n');
}

/** Where the agent keeps config.json, and how to restart it, per system. */
export function agentConfigPathFor(os) {
  return os === 'windows'
    ? 'C:\\ProgramData\\TokenTimerAgent\\state\\config.json'
    : `${AGENT_STATE_DIR}/config.json`;
}

export function agentRestartCommandFor(os) {
  return os === 'windows'
    ? 'Restart-Service TokenTimerAgent'
    : 'sudo systemctl restart tokentimer-agent';
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
 * unprivileged service user. A configuration test cannot run reliably as that
 * user: nginx -t needs /run/nginx.pid and its error log, and apachectl
 * configtest or haproxy -c fail as soon as any site loads a key or PEM that
 * only root can read (Debian's default-ssl site, most HAProxy PEM folders).
 * The validate step therefore only checks that the unit is running, and the
 * configuration test is done as root by the unit's own reload: apachectl
 * graceful and haproxy -c -q already refuse a broken configuration, and
 * NGINX_RELOAD_DROPIN adds the same to nginx. argv is exact: policy refuses
 * anything else.
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
    validate: ['/usr/bin/systemctl', 'is-active', '--quiet', 'apache2'],
    reload: ['/usr/bin/systemctl', 'reload', 'apache2'],
  },
  haproxy: {
    label: 'HAProxy',
    validate: ['/usr/bin/systemctl', 'is-active', '--quiet', 'haproxy'],
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
  // The same messages, grouped by the field they belong to so the form can
  // show each one next to its input.
  const fieldErrors = {};
  const problem = (field, message) => {
    problems.push(message);
    (fieldErrors[field] ||= []).push(message);
  };
  if (os === 'windows' && !WINDOWS_PATH.test(String(acmeClientPath || '')))
    problem(
      'acmeClientPath',
      'Enter the full path of the ACME client on the Windows host, for example C:\\acme\\acme.sh.'
    );
  if (
    os === 'windows' &&
    String(acmeShellPath || '').trim() &&
    !WINDOWS_PATH.test(String(acmeShellPath).trim())
  )
    problem(
      'acmeShellPath',
      'Enter the full path of the shell that runs the ACME client, for example C:\\Program Files\\Git\\bin\\bash.exe, or leave it empty for a native program.'
    );
  if (reloadService && os === 'windows')
    problem('reloadService', 'Reloading a web server is for Linux hosts.');
  if (reloadService && !RELOAD_SERVICES[reloadService])
    problem('reloadService', 'Choose nginx, Apache or HAProxy, or no reload.');
  const list = (names || []).map(n => String(n).trim()).filter(Boolean);
  if (list.length === 0) problem('names', 'Enter at least one name.');
  for (const n of list) {
    if (!isValidHostname(n))
      problem('names', `"${n}" is not a valid hostname.`);
    else if (!nameInZone(n, zone))
      problem('names', `"${n}" is not inside ${zone}.`);
  }
  if (!isValidZone(zone)) problem('zone', 'Enter a valid DNS zone.');
  if (!DNS_PROVIDERS[dnsProvider])
    problem('dnsProvider', 'Choose a DNS provider.');
  if (!/^https:\/\//.test(caEndpoint || ''))
    problem('caEndpoint', 'The CA address must use https.');
  if (os !== 'windows' && !String(certPath || '').startsWith('/')) {
    problem('certPath', 'The certificate path must be an absolute file path.');
  }
  if (problems.length) return { ok: false, problems, fieldErrors };

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
    // The key is installed next to the certificate so the web server can be
    // pointed at it. Without this it stays in the agent's private key store.
    ...(keyPathFor(certPath) ? { keyPath: keyPathFor(certPath) } : {}),
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
 * The lines that point a web server at the files a Linux order writes. The
 * key is a separate 0600 file owned by the agent user: nginx, Apache and
 * HAProxy read their key as root when they start or reload, so nothing else
 * needs access, and the owner and mode should be left alone so the next
 * renewal can replace the file.
 */
export function buildServerSnippet({ reloadService = '', certPath }) {
  const key = keyPathFor(certPath);
  if (!key) return '';
  if (reloadService === 'apache') {
    return [
      `SSLCertificateFile ${certPath}`,
      `SSLCertificateKeyFile ${key}`,
    ].join('\n');
  }
  if (reloadService === 'haproxy') {
    // HAProxy loads <crt>.key by itself when the certificate file holds no key.
    return `bind :443 ssl crt ${certPath}\n# HAProxy reads the key from ${key} next to it.`;
  }
  return [
    `ssl_certificate     ${certPath};`,
    `ssl_certificate_key ${key};`,
  ].join('\n');
}

/**
 * Placeholder pair that lets nginx start its TLS listener before the first
 * rollout. It must be created as the agent user: the agent reads the existing
 * files before it replaces them, and files owned by root with mode 0600 make
 * the first rollout fail with material_install_failed.
 */
export function buildConsumerPlaceholderCommand({
  deployPath = CONSUMER_DEPLOY_PATH,
  host = 'placeholder.invalid',
} = {}) {
  return [
    `sudo -u ${AGENT_USER} openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \\`,
    `  -subj ${shQuote(`/CN=${host}`)} \\`,
    `  -keyout ${deployPath}/privkey.pem -out ${deployPath}/fullchain.pem`,
  ].join('\n');
}

/** nginx server block for the consumer, using the files the agent replaces. */
export function buildConsumerNginxServer({
  names,
  deployPath = CONSUMER_DEPLOY_PATH,
}) {
  const hosts = (names || []).filter(Boolean).join(' ') || 'example.com';
  return [
    "sudo tee /etc/nginx/conf.d/tokentimer.conf <<'EOF'",
    'server {',
    '    listen 443 ssl;',
    `    server_name ${hosts};`,
    `    ssl_certificate     ${deployPath}/fullchain.pem;`,
    `    ssl_certificate_key ${deployPath}/privkey.pem;`,
    '    location / { return 200 "ok\\n"; }',
    '}',
    'EOF',
    'sudo nginx -t && sudo systemctl reload nginx',
  ].join('\n');
}

/**
 * Local recovery after a consumer rollout left an uncertain marker. The
 * command is the agent's own certops-reconcile-binding, run as the agent user
 * with its normal configuration directory.
 */
export function buildReconcileCommand(bindingId) {
  return [
    `sudo -u ${AGENT_USER} env TOKENTIMER_AGENT_CONFIG_DIR=${AGENT_STATE_DIR} \\`,
    `  node /opt/tokentimer-agent/app/bin/reconcile-material-binding.js ${bindingId || 'BINDING_ID'}`,
  ].join('\n');
}

/**
 * Vault administrator commands for the two AppRoles. The policies are the
 * ones printed above, saved as issuer.hcl and consumer.hcl.
 */
export function buildVaultRoleCommands() {
  return [
    '# Needs the Vault CLI and an administrative login (VAULT_ADDR, VAULT_CACERT).',
    'vault auth enable approle   # skip when AppRole is already enabled',
    'vault policy write tt-issuer issuer.hcl',
    'vault policy write tt-consumer consumer.hcl',
    'for role in tt-issuer tt-consumer; do',
    '  vault write auth/approle/role/$role token_policies=$role \\',
    '    token_period=20m secret_id_ttl=24h',
    'done',
    '# Per host: print the two values to place in role-id and secret-id.',
    'vault read -field=role_id auth/approle/role/tt-issuer/role-id',
    'vault write -f -field=secret_id auth/approle/role/tt-issuer/secret-id',
    '# Repeat with tt-consumer for the consumer host.',
  ].join('\n');
}

/** Host side of Vault Agent: protected directories and how to start it. */
export function buildVaultAgentHostSetup({
  configPath = '/etc/tokentimer-vault-agent/agent.hcl',
} = {}) {
  return [
    `sudo install -d -o ${AGENT_USER} -g ${AGENT_USER} -m 0700 /etc/tokentimer-vault-agent /run/tokentimer-vault`,
    '# As the agent user, save role-id and secret-id in /etc/tokentimer-vault-agent (mode 0600)',
    `# and the Vault Agent config above as ${configPath}. Then:`,
    `sudo -u ${AGENT_USER} HOME=${AGENT_STATE_DIR} vault agent -config=${configPath}`,
    '# Run it under your service manager. /run is emptied at reboot, so recreate',
    '# /run/tokentimer-vault with the same owner and mode before it starts.',
  ].join('\n');
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

/**
 * Vault Agent config that logs in with AppRole and keeps a token file fresh.
 * The TokenTimer agent reads only that file (materialStores.*.tokenFile): it
 * has no AppRole login of its own.
 */
export function buildVaultAgentConfig({
  vaultAddress,
  caFile = '',
  tokenFile = '/run/tokentimer-vault/issuer-token',
  credentialDir = '/etc/tokentimer-vault-agent',
}) {
  return [
    'vault {',
    `  address = "${vaultAddress || 'https://vault.example.com:8200'}"`,
    ...(caFile ? [`  ca_cert = "${caFile}"`] : []),
    '}',
    'auto_auth {',
    '  method "approle" {',
    '    config = {',
    `      role_id_file_path = "${credentialDir}/role-id"`,
    `      secret_id_file_path = "${credentialDir}/secret-id"`,
    '      remove_secret_id_file_after_reading = false',
    '    }',
    '  }',
    '  sink "file" {',
    `    config = { path = "${tokenFile}", mode = 0600 }`,
    '  }',
    '}',
    '',
  ].join('\n');
}

/**
 * Stable per issuer and request, so a reload or double click returns the
 * existing publish job instead of creating a second one.
 */
export function vaultPublishIdempotencyKey({
  names,
  zone,
  dnsProvider,
  caEndpoint = LETS_ENCRYPT_STAGING,
  agentId,
}) {
  const text = [
    (names || []).join(','),
    zone,
    dnsProvider,
    caEndpoint,
    agentId,
  ].join('|');
  let hash = 5381;
  for (let i = 0; i < text.length; i += 1) {
    hash = ((hash << 5) + hash + text.charCodeAt(i)) >>> 0;
  }
  return `wizard-vault-publish-${hash.toString(16)}`;
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
  deployPath = CONSUMER_DEPLOY_PATH,
  caFile = '',
  probeTrustCaFile = '',
}) {
  const problems = [];
  // Grouped by field so the Vault form can show each message next to its input.
  const fieldErrors = {};
  const problem = (field, message) => {
    problems.push(message);
    (fieldErrors[field] ||= []).push(message);
  };
  if (!/^https:\/\//.test(vaultAddress || ''))
    problem('vaultAddress', 'The Vault address must use https.');
  if (caFile && !String(caFile).startsWith('/'))
    problem('caFile', 'The Vault CA file must be an absolute path.');
  if (probeTrustCaFile && !String(probeTrustCaFile).startsWith('/'))
    problem(
      'probeCa',
      'The CA file for the served-certificate check must be an absolute path.'
    );
  if (!UUID.test(workspaceId || ''))
    problem('workspace', 'Invalid workspace id.');
  if (!UUID.test(groupId || '')) {
    problem(
      'groupId',
      'Use the group id shown on the distribution group after the first publish job.'
    );
  }
  if (!(names || []).length) problem('names', 'Enter at least one name.');
  if (!isValidZone(zone)) problem('zone', 'Enter a valid DNS zone.');
  if (problems.length) return { ok: false, problems, fieldErrors };

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
            sni: probeHostFor(names),
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
 * this job: it is created through the Jobs API. It waits for approval only
 * when the workspace requires approval for every job.
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
    // No per-job approval flag: the workspace Job approval policy decides.
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
/**
 * Sign-in for the API calls in the Vault guide. These routes accept a
 * signed-in workspace manager session with a CSRF token, not a machine
 * token, so the example signs in once. Email and password are prompted for:
 * they never appear in the command or in shell history.
 */
export function buildApiSignIn({ apiUrl, workspaceId }) {
  const api = String(apiUrl || '').replace(/\/+$/, '');
  return [
    `API=${shQuote(api)}`,
    `WS=${shQuote(workspaceId || '')}`,
    'JAR="$(mktemp)"',
    'csrf() { curl -fsS -b "$JAR" -c "$JAR" "$API/api/csrf-token" | sed -n \'s/.*"csrfToken" *: *"\\([^"]*\\)".*/\\1/p\'; }',
    "read -r -p 'TokenTimer email: ' EMAIL",
    "read -r -s -p 'TokenTimer password: ' PASSWORD; echo",
    'curl -fsS -b "$JAR" -c "$JAR" -X POST "$API/auth/login" \\',
    '  -H \'Content-Type: application/json\' -H "X-CSRF-Token: $(csrf)" \\',
    '  -d "$(printf \'{"email":"%s","password":"%s"}\' "$EMAIL" "$PASSWORD")" >/dev/null',
    'unset PASSWORD',
  ].join('\n');
}

/** One workspace API write, sent with the session from buildApiSignIn. */
export function buildApiCall({ method, path, body, idempotencyKey = '' }) {
  return [
    `curl -fsS -b "$JAR" -c "$JAR" -X ${method} "$API/api/v1/workspaces/$WS/${path}" \\`,
    '  -H \'Content-Type: application/json\' -H "X-CSRF-Token: $(csrf)" \\',
    ...(idempotencyKey ? [`  -H 'Idempotency-Key: ${idempotencyKey}' \\`] : []),
    "  -d @- <<'JSON'",
    JSON.stringify(body, null, 2),
    'JSON',
  ].join('\n');
}

/** A read with the same session, used to find the published version id. */
export function buildApiRead(path) {
  return `curl -fsS -b "$JAR" -c "$JAR" "$API/api/v1/workspaces/$WS/${path}"`;
}

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
        'If an agent is already installed on this server, a config.json exists and holds an agentId line. Keep that line when you replace the file, or the service refuses to start.',
        'Next page: you install the agent. The installer keeps this config.json as it is.',
      ],
      json,
    };
  }
  return {
    location: '/opt/tokentimer-agent/state/config.json',
    steps: [
      'Create the state directory: sudo mkdir -p /opt/tokentimer-agent/state && sudo chmod 0700 /opt/tokentimer-agent/state',
      'Save the JSON below as /opt/tokentimer-agent/state/config.json with mode 0600.',
      'If an agent is already installed on this server, the existing config.json holds an agentId line. Keep that line when you replace the file, or the service refuses to start.',
      'Next page: you install the agent. The installer then logs "Existing config.json found; leaving it untouched" and keeps your file.',
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
