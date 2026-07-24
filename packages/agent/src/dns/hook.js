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
 * read or any provider mutation. Zone discovery for unmapped domains uses
 * DNS NS walking (no credentials) so the zone policy check can run first;
 * after credentials load, a provider zone-list (when available) may refine
 * to the longest managed suffix and re-check zone policy.
 *
 * After a successful present, this hook polls authoritative (and optional
 * recursive) resolvers until the TXT value is visible before returning 0,
 * so ACME validation does not race DNS propagation. After cleanup it
 * verifies the value is gone — except for providers that declare
 * `capabilities.cleanupVerifiable: false` (e.g. acme-dns), where cleanup
 * does not delete the TXT and absence polling is skipped with status
 * `cleanup_not_applicable`. Both paths emit a single JSON evidence line
 * on stdout (no secrets).
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

const { resolveChallengeZone, findLongestManagedZone } = require("./zone.js");
const {
  normalizePropagationConfig,
  waitForTxtPresent,
  waitForTxtAbsent,
} = require("./propagate.js");
const { getDnsProviderCapabilities } = require("./index.js");

const CHALLENGE_LABEL = "_acme-challenge";
const USAGE = "usage: certops-dns-hook <present|cleanup>";

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
 * Resolves which provider serves `domain` from the config's dnsProviders
 * section. Does NOT treat the hostname as the zone: when zoneProviderMap
 * has no covering entry, `zone` is null and the caller must discover it.
 *
 * @param {object} dnsProviders validated config section
 * @param {string} domain
 * @returns {{ provider: string, zone: string|null, options: object }}
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
      zone: null,
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
  propagationDeps,
  zoneDeps,
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

    const { provider, zone: mappedZone, options } = resolveProviderForDomain(
      dnsProviders,
      domain,
    );

    const policyEngine = policyEngineFactory(config.policy || {});
    const providerVerdict = policyEngine.checkDnsProvider(provider);
    if (!providerVerdict || providerVerdict.allowed !== true) {
      stderr.write(`${JSON.stringify(providerVerdict)}\n`);
      return 1;
    }

    // Zone discovery without credentials (NS walk / mapped zone) so the
    // zone policy check can run before any credentials file is read.
    let zone = await resolveChallengeZone({
      domain,
      mappedZone,
      dnsDeps: zoneDeps,
    });

    const zoneVerdict = policyEngine.checkDnsZone(zone);
    if (!zoneVerdict || zoneVerdict.allowed !== true) {
      stderr.write(`${JSON.stringify(zoneVerdict)}\n`);
      return 1;
    }

    const credentials = readCredentialsFile(provider, config);
    const { credentialsFile: _credentialsFile, ...nonSecretOptions } = options;
    const solver = createSolver({
      provider,
      credentials: { ...nonSecretOptions, ...credentials },
    });

    // Refine to the longest provider-managed zone when the API can list
    // zones (avoids treating a delegated child NS cut as the managed zone).
    if (typeof solver.listManagedZones === "function" && mappedZone === null) {
      let managedZones;
      try {
        managedZones = await solver.listManagedZones();
      } catch {
        managedZones = null;
      }
      if (Array.isArray(managedZones) && managedZones.length > 0) {
        const normalized = new Set(
          managedZones
            .filter((name) => typeof name === "string")
            .map((name) => name.toLowerCase().replace(/\.$/, "")),
        );
        const refined = await findLongestManagedZone(domain, (candidate) =>
          normalized.has(candidate.toLowerCase().replace(/\.$/, "")),
        );
        if (refined && refined !== zone) {
          const refinedVerdict = policyEngine.checkDnsZone(refined);
          if (!refinedVerdict || refinedVerdict.allowed !== true) {
            stderr.write(`${JSON.stringify(refinedVerdict)}\n`);
            return 1;
          }
          zone = refined;
        }
      }
    }

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

    const capabilities = getDnsProviderCapabilities(provider);
    // acme-dns (and any future provider with cleanupVerifiable: false) does
    // not delete the TXT on cleanup; waiting for absence would time out.
    if (mode === "cleanup" && capabilities.cleanupVerifiable === false) {
      stdout.write(
        `${JSON.stringify({
          event: "dns.propagation",
          mode,
          provider,
          zone,
          recordName,
          ok: true,
          attempts: 0,
          elapsedMs: 0,
          servers: [],
          phase: "cleanup-verify",
          status: "cleanup_not_applicable",
        })}\n`,
      );
      stdout.write(
        `certops-dns-hook: ${mode} ok for ${recordName} via ${provider} (zone ${zone})\n`,
      );
      return 0;
    }

    const propagationConfig = normalizePropagationConfig(config.dnsPropagation);
    const waitResult =
      mode === "present"
        ? await waitForTxtPresent(
            { recordName, txtValue, config: propagationConfig },
            propagationDeps,
          )
        : await waitForTxtAbsent(
            { recordName, txtValue, config: propagationConfig },
            propagationDeps,
          );

    stdout.write(
      `${JSON.stringify({
        event: "dns.propagation",
        mode,
        provider,
        zone,
        recordName,
        ok: waitResult.ok === true,
        attempts: waitResult.attempts,
        elapsedMs: waitResult.elapsedMs,
        servers: waitResult.servers,
        phase: waitResult.phase,
        verificationMode: waitResult.verificationMode,
        serverResults: waitResult.serverResults,
      })}\n`,
    );

    if (waitResult.ok !== true) {
      stderr.write(`${JSON.stringify(waitResult)}\n`);
      return 1;
    }

    stdout.write(
      `certops-dns-hook: ${mode} ok for ${recordName} via ${provider} (zone ${zone})\n`,
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
