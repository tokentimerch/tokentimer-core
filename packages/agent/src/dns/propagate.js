"use strict";

/**
 * DNS-01 propagation wait and cleanup verification.
 *
 * After a provider confirms a TXT mutation, ACME validation must not start
 * until the expected value is visible at authoritative nameservers (and
 * optionally at configured recursive resolvers). On cleanup, the hook waits
 * until the value is gone so evidence can record both sides of the cycle.
 *
 * Each poll target (authoritative IP or configured recursive resolver) is
 * queried independently with its own dns.Resolver. Success is evaluated by
 * verificationMode: default `all` requires every target to confirm; `quorum`
 * requires at least quorumCount independent confirmations.
 *
 * Uses Node's dns.Resolver with explicit server IPs — never the process
 * default resolver alone when authoritative NS can be discovered.
 */

const dns = require("node:dns");
const { isNonEmptyString } = require("./internal.js");

const DEFAULT_TIMEOUT_MS = 120 * 1000;
const DEFAULT_INTERVAL_MS = 2 * 1000;
const DEFAULT_VERIFICATION_MODE = "all";
const VERIFICATION_MODES = new Set(["all", "quorum"]);

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isPositiveInt(value) {
  return Number.isInteger(value) && value > 0;
}

/**
 * Normalizes a dnsPropagation config block (top-level agent config).
 * Fail-loud on malformed values; returns defaults when absent/null.
 *
 * @param {unknown} raw
 * @returns {{
 *   timeoutMs: number,
 *   intervalMs: number,
 *   resolvers: string[],
 *   checkAuthoritative: boolean,
 *   verificationMode: "all"|"quorum",
 *   quorumCount: number|null,
 * }}
 */
function normalizePropagationConfig(raw) {
  if (raw === undefined || raw === null) {
    return {
      timeoutMs: DEFAULT_TIMEOUT_MS,
      intervalMs: DEFAULT_INTERVAL_MS,
      resolvers: [],
      checkAuthoritative: true,
      verificationMode: DEFAULT_VERIFICATION_MODE,
      quorumCount: null,
    };
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(
      "tokentimer-agent: dnsPropagation in config.json must be an object " +
        "({ timeoutMs?, intervalMs?, resolvers?, checkAuthoritative?, " +
        "verificationMode?, quorumCount? })",
    );
  }

  const timeoutMs =
    raw.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : raw.timeoutMs;
  const intervalMs =
    raw.intervalMs === undefined ? DEFAULT_INTERVAL_MS : raw.intervalMs;
  if (!isPositiveInt(timeoutMs)) {
    throw new Error(
      `tokentimer-agent: dnsPropagation.timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }
  if (!isPositiveInt(intervalMs)) {
    throw new Error(
      `tokentimer-agent: dnsPropagation.intervalMs must be a positive integer, got ${JSON.stringify(intervalMs)}`,
    );
  }

  let resolvers = [];
  if (raw.resolvers !== undefined) {
    if (!Array.isArray(raw.resolvers) || raw.resolvers.some((r) => !isNonEmptyString(r))) {
      throw new Error(
        "tokentimer-agent: dnsPropagation.resolvers must be an array of non-empty resolver IP strings",
      );
    }
    resolvers = [...raw.resolvers];
  }

  const checkAuthoritative =
    raw.checkAuthoritative === undefined ? true : raw.checkAuthoritative;
  if (typeof checkAuthoritative !== "boolean") {
    throw new Error(
      "tokentimer-agent: dnsPropagation.checkAuthoritative must be a boolean when provided",
    );
  }

  const verificationMode =
    raw.verificationMode === undefined
      ? DEFAULT_VERIFICATION_MODE
      : raw.verificationMode;
  if (!VERIFICATION_MODES.has(verificationMode)) {
    throw new Error(
      `tokentimer-agent: dnsPropagation.verificationMode must be "all" or "quorum", got ${JSON.stringify(verificationMode)}`,
    );
  }

  let quorumCount = null;
  if (raw.quorumCount !== undefined) {
    if (!isPositiveInt(raw.quorumCount)) {
      throw new Error(
        `tokentimer-agent: dnsPropagation.quorumCount must be a positive integer, got ${JSON.stringify(raw.quorumCount)}`,
      );
    }
    quorumCount = raw.quorumCount;
  }
  if (verificationMode === "quorum" && quorumCount === null) {
    throw new Error(
      'tokentimer-agent: dnsPropagation.quorumCount is required when verificationMode is "quorum"',
    );
  }

  return {
    timeoutMs,
    intervalMs,
    resolvers,
    checkAuthoritative,
    verificationMode,
    quorumCount,
  };
}

/**
 * Flattens dns.resolveTxt results (string[][]) into a flat list of strings.
 * @param {string[][]} records
 * @returns {string[]}
 */
function flattenTxtRecords(records) {
  if (!Array.isArray(records)) {
    return [];
  }
  return records.map((chunks) => (Array.isArray(chunks) ? chunks.join("") : String(chunks)));
}

/**
 * @param {string} hostname
 * @returns {string[]} candidate zone names, longest (most specific) first
 */
function zoneCandidatesForHostname(hostname) {
  const normalized = hostname.replace(/\.$/, "").toLowerCase();
  const labels = normalized.split(".").filter((label) => label.length > 0);
  const candidates = [];
  for (let i = 0; i < labels.length - 1; i += 1) {
    candidates.push(labels.slice(i).join("."));
  }
  return candidates;
}

/**
 * Discovers authoritative NS IPs for `recordName` by walking parent zones
 * until an NS set resolves, then resolving those NS hostnames to A/AAAA.
 *
 * @param {string} recordName
 * @param {{
 *   resolveNs?: (name: string) => Promise<string[]>,
 *   resolve4?: (name: string) => Promise<string[]>,
 *   resolve6?: (name: string) => Promise<string[]>,
 * }} [deps]
 * @returns {Promise<string[]>} resolver IPs (may be empty)
 */
async function discoverAuthoritativeResolverIps(recordName, deps = {}) {
  const resolveNs =
    deps.resolveNs ||
    ((name) =>
      new Promise((resolve, reject) => {
        dns.resolveNs(name, (err, addresses) => (err ? reject(err) : resolve(addresses || [])));
      }));
  const resolve4 =
    deps.resolve4 ||
    ((name) =>
      new Promise((resolve, reject) => {
        dns.resolve4(name, (err, addresses) => (err ? reject(err) : resolve(addresses || [])));
      }));
  const resolve6 =
    deps.resolve6 ||
    ((name) =>
      new Promise((resolve, reject) => {
        dns.resolve6(name, (err, addresses) => (err ? reject(err) : resolve(addresses || [])));
      }));

  const hostname = recordName.replace(/^\./, "").replace(/\.$/, "");
  // Strip the _acme-challenge label for zone walking when present.
  const walkRoot = hostname.startsWith("_acme-challenge.")
    ? hostname.slice("_acme-challenge.".length)
    : hostname;

  let nsHostnames = [];
  for (const candidate of zoneCandidatesForHostname(walkRoot)) {
    try {
      nsHostnames = await resolveNs(candidate);
      if (Array.isArray(nsHostnames) && nsHostnames.length > 0) {
        break;
      }
    } catch {
      // try next parent
    }
  }

  const ips = [];
  for (const nsHost of nsHostnames) {
    try {
      const v4 = await resolve4(nsHost);
      ips.push(...v4);
    } catch {
      // ignore
    }
    try {
      const v6 = await resolve6(nsHost);
      ips.push(...v6);
    } catch {
      // ignore
    }
  }
  return [...new Set(ips)];
}

/**
 * Queries TXT at `recordName` via an explicit resolver server list.
 * Prefer resolveTxtViaServer for independent per-server polls; this helper
 * remains for callers that intentionally share one Resolver across a list.
 *
 * @param {string} recordName
 * @param {string[]} servers
 * @param {{ Resolver?: typeof dns.Resolver }} [deps]
 * @returns {Promise<string[]>}
 */
async function resolveTxtViaServers(recordName, servers, deps = {}) {
  const ResolverCtor = deps.Resolver || dns.Resolver;
  const resolver = new ResolverCtor();
  if (Array.isArray(servers) && servers.length > 0) {
    resolver.setServers(servers);
  }
  return new Promise((resolve, reject) => {
    resolver.resolveTxt(recordName, (err, records) => {
      if (err) {
        // ENODATA / ENOTFOUND mean "not present yet" during present waits.
        if (err.code === "ENODATA" || err.code === "ENOTFOUND" || err.code === "SERVFAIL") {
          resolve([]);
          return;
        }
        reject(err);
        return;
      }
      resolve(flattenTxtRecords(records));
    });
  });
}

/**
 * Queries TXT at `recordName` against a single resolver IP (or the process
 * default resolver when `server` is null).
 *
 * @param {string} recordName
 * @param {string|null} server
 * @param {{ Resolver?: typeof dns.Resolver }} [deps]
 * @returns {Promise<string[]>}
 */
async function resolveTxtViaServer(recordName, server, deps = {}) {
  const servers = server === null || server === undefined ? [] : [server];
  return resolveTxtViaServers(recordName, servers, deps);
}

/**
 * @param {Array<{ matched: boolean }>} serverResults
 * @param {"all"|"quorum"} verificationMode
 * @param {number|null} quorumCount
 * @returns {boolean}
 */
function isVerificationPolicySatisfied(serverResults, verificationMode, quorumCount) {
  if (!Array.isArray(serverResults) || serverResults.length === 0) {
    return false;
  }
  const matchedCount = serverResults.filter((entry) => entry.matched === true).length;
  if (verificationMode === "quorum") {
    return matchedCount >= quorumCount;
  }
  return matchedCount === serverResults.length;
}

/**
 * Queries each poll target independently (concurrent), attributing values
 * and match status per server.
 *
 * @param {string} recordName
 * @param {string[]} servers empty => one poll against the system default
 * @param {(values: string[]) => boolean} predicate
 * @param {typeof resolveTxtViaServers} resolveTxt
 * @returns {Promise<Array<{ server: string|null, values: string[], matched: boolean, error: string|null }>>}
 */
async function queryServersIndependently(recordName, servers, predicate, resolveTxt) {
  const targets = servers.length > 0 ? servers : [null];
  return Promise.all(
    targets.map(async (server) => {
      const serverList = server === null ? [] : [server];
      try {
        const values = await resolveTxt(recordName, serverList);
        const list = Array.isArray(values) ? values : [];
        return {
          server,
          values: list,
          matched: predicate(list) === true,
          error: null,
        };
      } catch (err) {
        return {
          server,
          values: [],
          matched: false,
          error: err && err.message ? err.message : String(err),
        };
      }
    }),
  );
}

/**
 * Polls until every (or a quorum of) independent server query satisfies
 * `predicate`, or timeout.
 *
 * @param {object} options
 * @param {string} options.recordName
 * @param {string[]} options.servers
 * @param {(values: string[]) => boolean} options.predicate applied per server
 * @param {number} options.timeoutMs
 * @param {number} options.intervalMs
 * @param {"all"|"quorum"} [options.verificationMode]
 * @param {number|null} [options.quorumCount]
 * @param {(ms: number) => Promise<void>} [options.sleep]
 * @param {() => number} [options.now]
 * @param {typeof resolveTxtViaServers} [options.resolveTxt]
 * @returns {Promise<object>}
 */
async function pollTxtUntil({
  recordName,
  servers,
  predicate,
  timeoutMs,
  intervalMs,
  verificationMode = DEFAULT_VERIFICATION_MODE,
  quorumCount = null,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  resolveTxt = resolveTxtViaServers,
} = {}) {
  if (!isNonEmptyString(recordName)) {
    throw new Error("dns: pollTxtUntil requires a non-empty recordName");
  }
  if (typeof predicate !== "function") {
    throw new Error("dns: pollTxtUntil requires a predicate function");
  }

  const startedAt = now();
  let attempts = 0;
  let lastServerResults = [];

  for (;;) {
    attempts += 1;
    lastServerResults = await queryServersIndependently(
      recordName,
      servers,
      predicate,
      resolveTxt,
    );

    if (isVerificationPolicySatisfied(lastServerResults, verificationMode, quorumCount)) {
      const observedValues = [
        ...new Set(lastServerResults.flatMap((entry) => entry.values)),
      ];
      return {
        ok: true,
        observedValues,
        attempts,
        elapsedMs: now() - startedAt,
        servers,
        verificationMode,
        quorumCount,
        serverResults: lastServerResults,
      };
    }

    const elapsedMs = now() - startedAt;
    if (elapsedMs >= timeoutMs) {
      const hardErrors = lastServerResults
        .filter((entry) => entry.error)
        .map((entry) => `${entry.server ?? "default"}: ${entry.error}`);
      const detail =
        hardErrors.length === lastServerResults.length && hardErrors.length > 0
          ? `DNS poll failed: ${hardErrors.join("; ")}`
          : `DNS propagation wait timed out after ${timeoutMs} ms (${attempts} attempts)`;
      return {
        ok: false,
        detail,
        attempts,
        elapsedMs,
        servers,
        verificationMode,
        quorumCount,
        serverResults: lastServerResults,
        lastValues: [...new Set(lastServerResults.flatMap((entry) => entry.values))],
      };
    }
    await sleep(intervalMs);
  }
}

/**
 * Waits until `txtValue` is observed at the record name.
 *
 * @param {object} options
 * @param {string} options.recordName
 * @param {string} options.txtValue
 * @param {ReturnType<typeof normalizePropagationConfig>} options.config
 * @param {object} [deps] injectable DNS helpers for tests
 * @returns {Promise<object>} evidence-shaped result
 */
async function waitForTxtPresent(options, deps = {}) {
  const { recordName, txtValue, config } = options;
  const servers = await collectPollServers(recordName, config, deps);
  const result = await pollTxtUntil({
    recordName,
    servers,
    predicate: (values) => values.includes(txtValue),
    timeoutMs: config.timeoutMs,
    intervalMs: config.intervalMs,
    verificationMode: config.verificationMode,
    quorumCount: config.quorumCount,
    sleep: deps.sleep,
    now: deps.now,
    resolveTxt: deps.resolveTxt,
  });
  return { phase: "propagation", expectPresent: true, txtValue, ...result };
}

/**
 * Waits until `txtValue` is no longer observed at the record name.
 *
 * @param {object} options
 * @param {string} options.recordName
 * @param {string} options.txtValue
 * @param {ReturnType<typeof normalizePropagationConfig>} options.config
 * @param {object} [deps]
 * @returns {Promise<object>}
 */
async function waitForTxtAbsent(options, deps = {}) {
  const { recordName, txtValue, config } = options;
  const servers = await collectPollServers(recordName, config, deps);
  const result = await pollTxtUntil({
    recordName,
    servers,
    predicate: (values) => !values.includes(txtValue),
    timeoutMs: config.timeoutMs,
    intervalMs: config.intervalMs,
    verificationMode: config.verificationMode,
    quorumCount: config.quorumCount,
    sleep: deps.sleep,
    now: deps.now,
    resolveTxt: deps.resolveTxt,
  });
  return { phase: "cleanup-verify", expectPresent: false, txtValue, ...result };
}

/**
 * @param {string} recordName
 * @param {ReturnType<typeof normalizePropagationConfig>} config
 * @param {object} deps
 * @returns {Promise<string[]>}
 */
async function collectPollServers(recordName, config, deps) {
  const servers = [];
  if (config.checkAuthoritative) {
    const authIps = await (deps.discoverAuthoritativeResolverIps || discoverAuthoritativeResolverIps)(
      recordName,
      deps,
    );
    servers.push(...authIps);
  }
  if (Array.isArray(config.resolvers)) {
    servers.push(...config.resolvers);
  }
  // Deduplicate while preserving order. Empty list => system default resolver.
  return [...new Set(servers)];
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_INTERVAL_MS,
  DEFAULT_VERIFICATION_MODE,
  normalizePropagationConfig,
  zoneCandidatesForHostname,
  discoverAuthoritativeResolverIps,
  resolveTxtViaServers,
  resolveTxtViaServer,
  isVerificationPolicySatisfied,
  pollTxtUntil,
  waitForTxtPresent,
  waitForTxtAbsent,
  flattenTxtRecords,
};
