"use strict";

/**
 * DNS-01 manual-auth-hook runtime.
 *
 * Backs the `certops-dns-hook` executable (bin/certops-dns-hook.js) that
 * certbot and acme.sh invoke to present/clean up `_acme-challenge` TXT
 * records via the native solvers in src/dns:
 *
 *   certbot ... --manual \
 *     --manual-auth-hook    "certops-dns-hook present" \
 *     --manual-cleanup-hook "certops-dns-hook cleanup"
 *
 * Environment contract: certbot's manual-hook variables CERTBOT_DOMAIN and
 * CERTBOT_VALIDATION are read first; ACME_DOMAIN / ACME_TXT_VALUE are
 * accepted as fallbacks so a thin acme.sh dnsapi wrapper can export those
 * instead. The TXT record name is always `_acme-challenge.${domain}`.
 *
 * Policy first (ADR-0002): checkDnsProvider AND checkDnsZone must both
 * pass against the agent-local policy engine BEFORE any credential file is
 * read or any network call is made. A rejection prints the policy
 * rejection JSON ({ allowed:false, rejectionReason, detail }) to stderr
 * and exits nonzero.
 *
 * Output hygiene: this hook never prints credentials or raw provider
 * responses. Solver results only ever carry bounded, redacted excerpts
 * (src/dns excerpt rules), and those results are the only provider data
 * echoed here.
 *
 * Everything is injectable so the module is unit-testable without disk,
 * network, or process globals; bin/certops-dns-hook.js supplies the real
 * implementations.
 */

const CHALLENGE_LABEL = "_acme-challenge";
const USAGE = 'usage: certops-dns-hook <present|cleanup>';

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/** Dot-boundary zone coverage, mirroring the policy engine's rule. */
function isDomainWithinZone(domain, zone) {
  const normalizedDomain = domain.toLowerCase();
  const normalizedZone = zone.toLowerCase();
  return (
    normalizedDomain === normalizedZone ||
    normalizedDomain.endsWith(`.${normalizedZone}`)
  );
}

/**
 * Resolves which provider (and which zone) serves `domain` from the
 * config's dnsProviders section.
 *
 * Resolution order:
 *   1. Longest zoneProviderMap zone covering the domain (dot boundary).
 *   2. Otherwise, when exactly one provider is configured, that provider
 *      (zone falls back to the domain itself; provider-side zone lookups
 *      and per-provider options like zoneId/hostedZoneId/managedZone
 *      handle nesting).
 *
 * @param {object} dnsProviders validated config section
 * @param {string} domain
 * @returns {{ provider: string, zone: string, options: object }}
 */
function resolveProviderForDomain(dnsProviders, domain) {
  const zoneProviderMap = dnsProviders.zoneProviderMap || {};
  const providerIds = Object.keys(dnsProviders).filter(
    (key) => key !== "zoneProviderMap",
  );

  let bestZone = null;
  for (const zone of Object.keys(zoneProviderMap)) {
    if (!isDomainWithinZone(domain, zone)) {
      continue;
    }
    if (bestZone === null || zone.length > bestZone.length) {
      bestZone = zone;
    }
  }

  if (bestZone !== null) {
    const provider = zoneProviderMap[bestZone];
    if (!dnsProviders[provider]) {
      throw new Error(
        `certops-dns-hook: zoneProviderMap maps ${JSON.stringify(bestZone)} to ` +
          `${JSON.stringify(provider)}, but dnsProviders.${provider} is not configured`,
      );
    }
    return { provider, zone: bestZone, options: dnsProviders[provider] };
  }

  if (providerIds.length === 1) {
    return {
      provider: providerIds[0],
      zone: domain,
      options: dnsProviders[providerIds[0]],
    };
  }

  throw new Error(
    `certops-dns-hook: no zoneProviderMap entry covers ${JSON.stringify(domain)} ` +
      `and ${providerIds.length} providers are configured; add a zoneProviderMap ` +
      "entry so the provider choice is unambiguous",
  );
}

/**
 * Runs one hook invocation. Returns the process exit code (0 success,
 * nonzero failure); never throws.
 *
 * @param {object} options
 * @param {object} options.env environment (certbot/acme.sh variables).
 * @param {string[]} options.argv args after the script name; argv[0] is
 *   the mode ("present" or "cleanup").
 * @param {() => object} options.loadConfig returns the loaded agent config
 *   (src/config loadAgentConfig shape, incl. `policy` and `dnsProviders`).
 * @param {(providerId: string, config: object) => object} options.readCredentialsFile
 *   reads + parses the provider's agent-local credentials file
 *   (src/config readDnsCredentialsFile).
 * @param {Function} options.createSolver createDnsSolver-shaped factory.
 * @param {(rawPolicy: object) => { checkDnsProvider: Function, checkDnsZone: Function }} options.policyEngineFactory
 *   builds the agent-local policy engine from config.policy.
 * @param {{ write: Function }} options.stdout
 * @param {{ write: Function }} options.stderr
 * @returns {Promise<number>}
 */
async function runDnsHook({
  env,
  argv,
  loadConfig,
  readCredentialsFile,
  createSolver,
  policyEngineFactory,
  stdout,
  stderr,
} = {}) {
  const mode = Array.isArray(argv) ? argv[0] : undefined;
  if (mode !== "present" && mode !== "cleanup") {
    stderr.write(`certops-dns-hook: unknown mode ${JSON.stringify(mode)}\n${USAGE}\n`);
    return 2;
  }

  const domain = env.CERTBOT_DOMAIN || env.ACME_DOMAIN;
  const txtValue = env.CERTBOT_VALIDATION || env.ACME_TXT_VALUE;
  if (!isNonEmptyString(domain)) {
    stderr.write(
      "certops-dns-hook: CERTBOT_DOMAIN (or ACME_DOMAIN) must be set in the environment\n",
    );
    return 2;
  }
  if (!isNonEmptyString(txtValue)) {
    stderr.write(
      "certops-dns-hook: CERTBOT_VALIDATION (or ACME_TXT_VALUE) must be set in the environment\n",
    );
    return 2;
  }

  try {
    const config = loadConfig();

    const dnsProviders = config.dnsProviders;
    if (!dnsProviders || Object.keys(dnsProviders).filter((k) => k !== "zoneProviderMap").length === 0) {
      stderr.write(
        "certops-dns-hook: no dnsProviders section is configured in config.json\n",
      );
      return 1;
    }

    const { provider, zone, options } = resolveProviderForDomain(dnsProviders, domain);

    // Policy gate: BOTH checks must pass before any credential read or
    // network call. Local policy always wins over anything the caller
    // (or the control plane behind it) intended.
    const policyEngine = policyEngineFactory(config.policy || {});
    for (const rejection of [
      policyEngine.checkDnsProvider(provider),
      policyEngine.checkDnsZone(zone),
    ]) {
      if (!rejection || rejection.allowed !== true) {
        stderr.write(`${JSON.stringify(rejection)}\n`);
        return 1;
      }
    }

    const credentials = readCredentialsFile(provider, config);

    // Non-secret per-provider options from config.json (zoneId,
    // hostedZoneId, managedZone, ...) merge under the credentials file's
    // own fields; the file wins on conflicts.
    const { credentialsFile: _credentialsFile, ...nonSecretOptions } = options;
    const solver = createSolver({
      provider,
      credentials: { ...nonSecretOptions, ...credentials },
    });

    const recordName = `${CHALLENGE_LABEL}.${domain}`;
    const inputs = { zone, recordName, txtValue };
    const result =
      mode === "present"
        ? await solver.presentChallenge(inputs)
        : await solver.cleanupChallenge(inputs);

    if (!result || result.ok !== true) {
      stderr.write(`${JSON.stringify(result)}\n`);
      return 1;
    }

    stdout.write(
      `certops-dns-hook: ${mode} ok for ${recordName} via ${provider}\n`,
    );
    return 0;
  } catch (err) {
    stderr.write(
      `certops-dns-hook: ${err && err.message ? err.message : String(err)}\n`,
    );
    return 1;
  }
}

module.exports = {
  runDnsHook,
  resolveProviderForDomain,
  CHALLENGE_LABEL,
};
