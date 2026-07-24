"use strict";

/**
 * ACME exec adapters.
 *
 * Renewal happens agent-side by shelling out to an
 * operator-installed ACME tool (certbot or acme.sh) rather than embedding an
 * ACME client library. This is a deliberate decision to avoid adding new
 * dependencies for now; the exec-adapter surface below is intentionally
 * small so an embedded client could replace it later without changing the
 * dispatch layer's contract.
 *
 * Trust and policy model:
 *   - All exec goes through the agent-local policy command allowlist. The
 *     dispatch layer resolves a command profile *name* to concrete argv via
 *     the policy engine (policy.checkCommandRef) and hands this module the
 *     resulting `{ argv: string[] }` profile. This module never receives a
 *     profile name and never consults policy config itself.
 *   - CA endpoints must be checked against the policy caEndpoints allowlist
 *     BY THE CALLER before dispatch. runRenewal additionally requires a
 *     `checkCaEndpoint` callback and re-checks the endpoint as defense in
 *     depth; a `{ allowed: false, rejectionReason, detail }` rejection from
 *     that callback is returned unchanged so dispatch reports it uniformly
 *     with every other policy rejection shape.
 *   - Commands are exec'd via child_process.execFile WITHOUT a shell. This
 *     module never builds shell strings, and it re-validates every argv
 *     element (profile, mapped arguments, typed options) against the same
 *     shell-metacharacter pattern the policy module uses, as defense in
 *     depth against a misconfigured profile or malicious job input.
 *   - There is NO generic `extraArgs` passthrough. Callers may only pass
 *     the typed options documented below; unknown keys are rejected.
 *
 * Zero-custody-preserving design (D5 / ADR-0001):
 *   - No private key is ever passed to, read by, or produced by this
 *     module. Renewal is CSR-based: the keys module generates the keypair
 *     and CSR on the host; this module only points the ACME tool at the CSR
 *     file. certbot's `--csr` mode (and acme.sh's `--signcsr`) sign an
 *     externally supplied CSR and therefore never need the private key.
 *   - DNS credentials never appear in argv or the subprocess environment:
 *     the adapter wires certbot/acme.sh to `certops-dns-hook` (and the
 *     acme.sh `dns_certops` dnsapi hook name). The hook loads credentials
 *     from agent-local 0600 files referenced only by path in config.json.
 *     argvUsed in the result is therefore safe to include in evidence by
 *     construction (EAB hmac values are redacted from argvUsed).
 *
 * Adapter argv contract (documented here as the source of truth; the exact
 * flags may be tuned when real-world testing against live CAs happens, but
 * any change must update this table and the sibling tests):
 *
 *   certbot  : profile.argv ++ [
 *                "certonly", "--non-interactive",
 *                "--preferred-challenges", "dns",
 *                "--manual",
 *                "--manual-auth-hook", "<hookPath> present",
 *                "--manual-cleanup-hook", "<hookPath> cleanup",
 *                "--csr", csrPath,
 *                "--server", caEndpoint,
 *                "-d", domain      (repeated per domain, in input order),
 *                "--cert-path", outCertPath,
 *                "--config-dir", "<stateDir>/acme/certbot/config",
 *                "--work-dir",   "<stateDir>/acme/certbot/work",
 *                "--logs-dir",   "<stateDir>/acme/certbot/logs",
 *                "--preferred-chain", preferredChain   (optional),
 *                "--eab-kid", eabKid                   (optional, with hmac),
 *                "--eab-hmac-key", eabHmacKey           (optional, with kid),
 *                // never --dry-run: certbot rejects --dry-run with --csr,
 *                // which this adapter always uses; runRenewal rejects
 *                // dryRun:true for kind === "certbot" before this point.
 *              ]
 *
 *   acme.sh  : profile.argv ++ [
 *                "--home", "<stateDir>/acme/acme.sh",
 *                "--config-home", "<stateDir>/acme/acme.sh",
 *                "--signcsr",
 *                "--csr", csrPath,
 *                "--server", caEndpoint,
 *                "-d", domain      (repeated per domain, in input order),
 *                "--dns", "dns_certops",  // hook NAME (dnsapi/dns_certops.sh)
 *                "--cert-file", outCertPath,
 *                "--preferred-chain", preferredChain   (optional),
 *                "--eab-kid", eabKid                   (optional, with hmac),
 *                "--eab-hmac-key", eabHmacKey           (optional, with kid),
 *                "--test"          (only when dryRun),
 *              ]
 *
 * Domain vs TXT record name (DNS-01):
 *   - `-d` domains passed to certbot/acme.sh are BASE domains (FQDNs from
 *     the job), never the `_acme-challenge.` TXT name.
 *   - acme.sh calls dns_certops_add/rm with the COMPLETE TXT name
 *     (`_acme-challenge.<base>`); dns_certops.sh strips that prefix before
 *     exporting ACME_DOMAIN so certops-dns-hook (which prepends
 *     `_acme-challenge.`) does not double-prefix.
 *
 * Account-key reuse: achieved by the stable stateDir paths above (certbot
 * config-dir / acme.sh --home). No separate CLI flag is required for
 * CSR-based issuance; both tools persist the ACME account under those dirs.
 *
 * This module is self-contained: it accepts plain data as function
 * parameters and does not import sibling agent modules (policy, config,
 * keys, etc.). Wiring profile resolution + policy checks + this adapter
 * together is the dispatch layer's job. Callers pass `stateDir` from
 * `resolveConfigDir()` / `TOKENTIMER_AGENT_CONFIG_DIR` (the agent state
 * directory; see COORDINATION-ACME-ADAPTER.md).
 */

const childProcess = require("node:child_process");
const path = require("node:path");
const { buildMinimalSubprocessEnv } = require("../exec-env");

/**
 * Mirrors the policy module's SHELL_METACHARACTER_PATTERN (duplicated, not
 * imported, to keep this module self-contained): ; | & $ ` > < CR LF.
 * Commands run without a shell, so this is defense in depth against
 * misconfigured profiles / hostile job input, not a shell-injection vector
 * by itself. Spaces are intentionally allowed so certbot can receive a
 * single `--manual-auth-hook` argument of the form "<hook> present".
 */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

/** Default exec timeout: ACME issuance can legitimately be slow (DNS-01
 * propagation waits, CA retries), so default generously to 10 minutes. */
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

/** Hard cap on stdout/stderr excerpt length carried into results/evidence. */
const OUTPUT_EXCERPT_MAX_CHARS = 1024;

/** Marker whose presence anywhere in an output excerpt causes the whole
 * excerpt to be replaced, never partially scrubbed: a tool that echoes key
 * material is a config problem and its output must not leak into evidence. */
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

const SUPPORTED_ADAPTER_KINDS = Object.freeze(["certbot", "acme.sh"]);

/**
 * acme.sh `--dns` hook name: basename of `dns_certops.sh` without `.sh`.
 * acme.sh sources `$LE_WORKING_DIR/dnsapi/dns_certops.sh` and calls
 * `dns_certops_add` / `dns_certops_rm`. Never an absolute path.
 */
const ACME_SH_DNS_HOOK_NAME = "dns_certops";

/** Allowlisted keys for runRenewal options (strict; unknown keys throw). */
const RUN_RENEWAL_ALLOWED_KEYS = Object.freeze([
  "caEndpoint",
  "domains",
  "csrPath",
  "outCertPath",
  "checkCaEndpoint",
  "dryRun",
  "stateDir",
  "preferredChain",
  "eabKid",
  "eabHmacKey",
]);

/**
 * Absolute path to the certops-dns-hook executable shipped with this package.
 * @returns {string}
 */
function defaultDnsHookPath() {
  return path.resolve(__dirname, "..", "..", "bin", "certops-dns-hook.js");
}

/**
 * Absolute path to the shipped acme.sh dnsapi wrapper script (source file
 * that install-agent.sh symlinks into `<stateDir>/acme/acme.sh/dnsapi/`).
 * @returns {string}
 */
function defaultAcmeDnsApiPath() {
  return path.resolve(__dirname, "..", "..", "bin", "dns_certops.sh");
}

/**
 * Resolves ACME tool state subdirectories under the agent state/config dir.
 *
 * @param {string} stateDir agent state dir (`TOKENTIMER_AGENT_CONFIG_DIR` /
 *   `resolveConfigDir()` result)
 * @returns {{
 *   certbotConfigDir: string,
 *   certbotWorkDir: string,
 *   certbotLogsDir: string,
 *   acmeShHome: string,
 * }}
 */
function resolveAcmeStatePaths(stateDir) {
  const certbotRoot = path.join(stateDir, "acme", "certbot");
  return {
    certbotConfigDir: path.join(certbotRoot, "config"),
    certbotWorkDir: path.join(certbotRoot, "work"),
    certbotLogsDir: path.join(certbotRoot, "logs"),
    acmeShHome: path.join(stateDir, "acme", "acme.sh"),
  };
}

/**
 * @returns {string[]} adapter kinds accepted by createAcmeAdapter.
 */
function listSupportedAdapters() {
  return [...SUPPORTED_ADAPTER_KINDS];
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * Throws if any element of `argv` is not a non-empty string or contains a
 * shell metacharacter. `label` names the offending input in the error so
 * misconfigurations fail loudly and legibly.
 *
 * @param {string} label
 * @param {unknown[]} argv
 * @returns {void}
 */
function assertSafeArgvElements(label, argv) {
  argv.forEach((element, index) => {
    if (!isNonEmptyString(element)) {
      throw new Error(
        `acme: ${label}[${index}] must be a non-empty string (got ${typeof element})`,
      );
    }
    if (SHELL_METACHARACTER_PATTERN.test(element)) {
      throw new Error(
        `acme: ${label}[${index}] contains a disallowed shell metacharacter: ${JSON.stringify(element)}`,
      );
    }
  });
}

/**
 * POSIX-or-Windows absolute path check without importing node:path
 * platform-specific behavior surprises: the agent primarily targets POSIX
 * hosts (plan framing) but tests run on Windows too, so accept either an
 * absolute POSIX path ("/...") or a Windows drive/UNC path.
 *
 * @param {string} candidate
 * @returns {boolean}
 */
function isAbsolutePathLike(candidate) {
  return (
    /^\//.test(candidate) ||
    /^[A-Za-z]:[\\/]/.test(candidate) ||
    /^\\\\/.test(candidate)
  );
}

/**
 * Bounds an output string to OUTPUT_EXCERPT_MAX_CHARS and redacts it
 * wholesale if it contains the PRIVATE KEY marker. Redaction is checked on
 * the FULL output (not just the excerpt window) so a key echoed past the
 * first 1024 chars still triggers redaction of what would be kept.
 *
 * @param {unknown} output raw stdout/stderr (string or Buffer or undefined)
 * @returns {string}
 */
function boundAndRedactExcerpt(output) {
  const text =
    typeof output === "string"
      ? output
      : Buffer.isBuffer(output)
        ? output.toString("utf8")
        : "";

  if (text.includes(PRIVATE_KEY_MARKER)) {
    return REDACTED_EXCERPT_PLACEHOLDER;
  }

  return text.slice(0, OUTPUT_EXCERPT_MAX_CHARS);
}

/**
 * Replaces `--eab-hmac-key` values in argv so evidence never carries the
 * External Account Binding secret.
 *
 * @param {string[]} argv
 * @returns {string[]}
 */
function redactSensitiveArgv(argv) {
  const out = [...argv];
  for (let i = 0; i < out.length - 1; i += 1) {
    if (out[i] === "--eab-hmac-key") {
      out[i + 1] = REDACTED_EXCERPT_PLACEHOLDER;
    }
  }
  return out;
}

/**
 * Builds typed optional ACME CLI flags (preferred chain + EAB). Shared by
 * certbot and acme.sh (both accept the same flag names).
 *
 * @param {{ preferredChain?: string, eabKid?: string, eabHmacKey?: string }} opts
 * @returns {string[]}
 */
function buildTypedOptionArgs({ preferredChain, eabKid, eabHmacKey }) {
  const args = [];
  if (preferredChain !== undefined) {
    args.push("--preferred-chain", preferredChain);
  }
  if (eabKid !== undefined) {
    args.push("--eab-kid", eabKid, "--eab-hmac-key", eabHmacKey);
  }
  return args;
}

/**
 * Builds the adapter-kind-specific argument tail (everything after the
 * allowlisted profile argv). See the module-level "Adapter argv contract"
 * table.
 *
 * @param {"certbot"|"acme.sh"} kind
 * @param {{
 *   caEndpoint: string,
 *   domains: string[],
 *   csrPath: string,
 *   outCertPath: string,
 *   dryRun: boolean,
 *   dnsHookPath: string,
 *   stateDir: string,
 *   preferredChain?: string,
 *   eabKid?: string,
 *   eabHmacKey?: string,
 * }} inputs
 * @returns {string[]}
 */
function buildAdapterArgs(kind, {
  caEndpoint,
  domains,
  csrPath,
  outCertPath,
  dryRun,
  dnsHookPath,
  stateDir,
  preferredChain,
  eabKid,
  eabHmacKey,
}) {
  const domainFlags = domains.flatMap((domain) => ["-d", domain]);
  const typedArgs = buildTypedOptionArgs({
    preferredChain,
    eabKid,
    eabHmacKey,
  });
  const paths = resolveAcmeStatePaths(stateDir);

  if (kind === "certbot") {
    // certbot runs the hook string via a shell-like invocation; keep the
    // mode ("present"/"cleanup") in the SAME argv element as the hook path
    // so it is not parsed as a separate certbot flag. Credentials are never
    // part of this string — only the hook binary path + mode.
    const authHook = `${dnsHookPath} present`;
    const cleanupHook = `${dnsHookPath} cleanup`;
    // No --dry-run here: certbot rejects --dry-run combined with --csr, and
    // this adapter always issues via --csr. runRenewal rejects dryRun:true
    // for kind === "certbot" before this function is ever called.
    return [
      "certonly",
      "--non-interactive",
      "--preferred-challenges",
      "dns",
      "--manual",
      "--manual-auth-hook",
      authHook,
      "--manual-cleanup-hook",
      cleanupHook,
      "--csr",
      csrPath,
      "--server",
      caEndpoint,
      ...domainFlags,
      "--cert-path",
      outCertPath,
      "--config-dir",
      paths.certbotConfigDir,
      "--work-dir",
      paths.certbotWorkDir,
      "--logs-dir",
      paths.certbotLogsDir,
      ...typedArgs,
    ];
  }

  // kind === "acme.sh" — `--dns dns_certops` is the hook NAME (basename of
  // dns_certops.sh). acme.sh sources it from `$LE_WORKING_DIR/dnsapi/`
  // (set via --home to the agent-owned state subdirectory). CERTOPS_DNS_HOOK
  // in the child env points at the Node hook; no credentials travel via
  // argv or env.
  return [
    "--home",
    paths.acmeShHome,
    "--config-home",
    paths.acmeShHome,
    "--signcsr",
    "--csr",
    csrPath,
    "--server",
    caEndpoint,
    ...domainFlags,
    "--dns",
    ACME_SH_DNS_HOOK_NAME,
    "--cert-file",
    outCertPath,
    ...typedArgs,
    ...(dryRun ? ["--test"] : []),
  ];
}

/**
 * Promise wrapper around an execFile-shaped implementation, exec'ing
 * WITHOUT a shell, resolving with exit information instead of rejecting on
 * nonzero exit / timeout (those are operational outcomes, not programmer
 * errors).
 *
 * @param {Function} execFileImpl (file, args, options, callback) => void
 * @param {string[]} argv full argv; argv[0] is the file to execute
 * @param {number} timeoutMs
 * @param {Record<string, string>} env
 * @returns {Promise<{ exitCode: number|null, stdout: unknown, stderr: unknown, execError: Error|null }>}
 */
function execWithoutShell(execFileImpl, argv, timeoutMs, env) {
  const [file, ...args] = argv;

  return new Promise((resolve) => {
    execFileImpl(
      file,
      args,
      {
        timeout: timeoutMs,
        // Explicitly no `shell` option: arguments are passed as an array to
        // the OS exec facility and are never interpreted by a shell.
        windowsHide: true,
        maxBuffer: 10 * 1024 * 1024,
        // Explicit minimal environment: the agent's own env can hold the
        // bootstrap token and other secrets that must never reach the ACME
        // tool (or the hook children it spawns). CERTOPS_DNS_HOOK is a
        // non-secret absolute path to the hook binary.
        env,
      },
      (error, stdout, stderr) => {
        if (error) {
          // error.code is the exit code for nonzero exits; null for kills
          // (timeout => SIGTERM) and spawn failures (ENOENT etc.).
          const exitCode = typeof error.code === "number" ? error.code : null;
          resolve({ exitCode, stdout, stderr, execError: error });
          return;
        }
        resolve({ exitCode: 0, stdout, stderr, execError: null });
      },
    );
  });
}

/**
 * Creates an ACME exec adapter bound to one tool kind and one allowlisted
 * command profile.
 *
 * @param {object} options
 * @param {"certbot"|"acme.sh"} options.kind which tool the profile invokes.
 * @param {{ argv: string[] }} options.commandProfile the concrete argv the
 *   dispatch layer resolved from the agent-local policy command allowlist
 *   (policy.checkCommandRef). Never a shell string.
 * @param {Function} [options.execFileImpl] injection point for tests;
 *   defaults to node:child_process.execFile. Must have the same signature.
 * @param {number} [options.timeoutMs] exec timeout, default 10 minutes.
 * @param {string} [options.dnsHookPath] absolute path to certops-dns-hook.js.
 * @param {string} [options.acmeDnsApiPath] absolute path to the shipped
 *   dns_certops.sh source (installer symlink target; not passed as --dns).
 * @returns {{ kind: string, runRenewal: Function, dnsHookPath: string, acmeDnsApiPath: string }}
 */
function createAcmeAdapter({
  kind,
  commandProfile,
  execFileImpl = childProcess.execFile,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  dnsHookPath = defaultDnsHookPath(),
  acmeDnsApiPath = defaultAcmeDnsApiPath(),
} = {}) {
  if (!SUPPORTED_ADAPTER_KINDS.includes(kind)) {
    throw new Error(
      `acme: unsupported adapter kind ${JSON.stringify(kind)}; supported: ${SUPPORTED_ADAPTER_KINDS.join(", ")}`,
    );
  }

  if (
    commandProfile === null ||
    typeof commandProfile !== "object" ||
    !Array.isArray(commandProfile.argv)
  ) {
    throw new Error(
      'acme: commandProfile must be an object with an "argv" array (as resolved by the policy engine)',
    );
  }

  if (commandProfile.argv.length === 0) {
    throw new Error("acme: commandProfile.argv must not be empty");
  }

  assertSafeArgvElements("commandProfile.argv", commandProfile.argv);

  if (typeof execFileImpl !== "function") {
    throw new Error("acme: execFileImpl must be a function");
  }

  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `acme: timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }

  if (!isNonEmptyString(dnsHookPath) || !isAbsolutePathLike(dnsHookPath)) {
    throw new Error(
      `acme: dnsHookPath must be an absolute path, got ${JSON.stringify(dnsHookPath)}`,
    );
  }
  if (!isNonEmptyString(acmeDnsApiPath) || !isAbsolutePathLike(acmeDnsApiPath)) {
    throw new Error(
      `acme: acmeDnsApiPath must be an absolute path, got ${JSON.stringify(acmeDnsApiPath)}`,
    );
  }
  assertSafeArgvElements("dnsHookPath", [dnsHookPath]);
  assertSafeArgvElements("acmeDnsApiPath", [acmeDnsApiPath]);
  // Hook command strings include a space + mode; validate they remain free
  // of shell metacharacters beyond the allowed space.
  assertSafeArgvElements("dnsHookCommands", [
    `${dnsHookPath} present`,
    `${dnsHookPath} cleanup`,
  ]);

  // Freeze a copy so a caller mutating its profile object after adapter
  // creation cannot alter what actually gets exec'd.
  const profileArgv = Object.freeze([...commandProfile.argv]);
  const resolvedDnsHookPath = dnsHookPath;
  const resolvedAcmeDnsApiPath = acmeDnsApiPath;

  /**
   * Runs one CSR-based renewal via the configured ACME tool.
   *
   * Never throws on operational failure (nonzero exit, timeout, spawn
   * error): those come back as `{ renewed: false, ... }`. Throws only on
   * programmer error (malformed inputs) and returns the callback's own
   * rejection object unchanged when the CA endpoint re-check fails.
   *
   * @param {object} options
   * @param {string} options.caEndpoint ACME directory URL. Already
   *   allowlist-checked by the caller; re-checked here via checkCaEndpoint.
   * @param {string[]} options.domains non-empty list of BASE domain names
   *   (FQDNs). Never `_acme-challenge.` TXT names.
   * @param {string} options.csrPath absolute path to the CSR file (produced
   *   by the keys module; the private key never passes through here).
   * @param {string} options.outCertPath absolute path where the tool writes
   *   the issued certificate.
   * @param {string} options.stateDir absolute agent state/config directory
   *   (`resolveConfigDir()` / `TOKENTIMER_AGENT_CONFIG_DIR`). ACME tool
   *   writable paths are derived under `<stateDir>/acme/...`.
   * @param {string} [options.preferredChain] CA preferred chain CN
   *   (e.g. "ISRG Root X1"). Maps to `--preferred-chain` for both tools.
   * @param {string} [options.eabKid] External Account Binding key id.
   *   Requires `eabHmacKey`. Maps to `--eab-kid`.
   * @param {string} [options.eabHmacKey] External Account Binding HMAC key.
   *   Requires `eabKid`. Maps to `--eab-hmac-key` (redacted in argvUsed).
   * @param {(url: string) => { allowed: boolean, rejectionReason?: string, detail?: string }} options.checkCaEndpoint
   *   defense-in-depth policy re-check (policy engine's checkCaEndpoint).
   * @param {boolean} [options.dryRun] map to --dry-run (certbot) / --test
   *   (acme.sh) so no real certificate is issued.
   * @returns {Promise<
   *   { renewed: boolean, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string, argvUsed: string[] }
   *   | { allowed: false, rejectionReason: string, detail: string }
   * >}
   */
  async function runRenewal(options = {}) {
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw new Error("acme: runRenewal options must be a plain object");
    }

    const unknownKeys = Object.keys(options).filter(
      (key) => !RUN_RENEWAL_ALLOWED_KEYS.includes(key),
    );
    if (unknownKeys.length > 0) {
      throw new Error(
        `acme: runRenewal unknown option(s): ${unknownKeys.join(", ")} ` +
          `(allowed: ${RUN_RENEWAL_ALLOWED_KEYS.join(", ")})`,
      );
    }

    const {
      caEndpoint,
      domains,
      csrPath,
      outCertPath,
      checkCaEndpoint,
      dryRun = false,
      stateDir,
      preferredChain,
      eabKid,
      eabHmacKey,
    } = options;

    // (1) Programmer-error validation: fail loudly before any policy call
    // or exec. These are bugs in the dispatch wiring, not job outcomes.
    if (!isNonEmptyString(caEndpoint)) {
      throw new Error("acme: runRenewal requires a non-empty caEndpoint string");
    }
    if (!Array.isArray(domains) || domains.length === 0) {
      throw new Error("acme: runRenewal requires a non-empty domains array");
    }
    domains.forEach((domain, index) => {
      if (!isNonEmptyString(domain)) {
        throw new Error(`acme: domains[${index}] must be a non-empty string`);
      }
    });
    if (!isNonEmptyString(csrPath) || !isAbsolutePathLike(csrPath)) {
      throw new Error(
        `acme: csrPath must be an absolute path, got ${JSON.stringify(csrPath)}`,
      );
    }
    if (!isNonEmptyString(outCertPath) || !isAbsolutePathLike(outCertPath)) {
      throw new Error(
        `acme: outCertPath must be an absolute path, got ${JSON.stringify(outCertPath)}`,
      );
    }
    if (!isNonEmptyString(stateDir) || !isAbsolutePathLike(stateDir)) {
      throw new Error(
        `acme: stateDir must be an absolute path (agent config/state dir), got ${JSON.stringify(stateDir)}`,
      );
    }
    if (typeof dryRun !== "boolean") {
      throw new Error("acme: dryRun must be a boolean when provided");
    }
    if (kind === "certbot" && dryRun === true) {
      // certbot hard-errors on `--dry-run` combined with `--csr` ("--dry-run
      // cannot be used with --csr"), and this adapter always issues via CSR
      // (zero private-key-custody: the agent generates the key/CSR locally,
      // never certbot). Surfacing that as a clear programmer/config error
      // here -- before any exec -- is far better than letting the job fail
      // with a confusing certbot CLI error after dispatch already committed
      // to a certbot-configured target.
      throw new Error(
        "acme: dryRun is not supported for the certbot adapter (certbot " +
          "rejects --dry-run together with --csr, which this adapter always " +
          "uses); route dry-run renewals to a target configured with the " +
          "acme.sh adapter instead, or omit dryRun for this target",
      );
    }
    if (preferredChain !== undefined && !isNonEmptyString(preferredChain)) {
      throw new Error("acme: preferredChain must be a non-empty string when provided");
    }
    const hasEabKid = eabKid !== undefined;
    const hasEabHmac = eabHmacKey !== undefined;
    if (hasEabKid !== hasEabHmac) {
      throw new Error(
        "acme: eabKid and eabHmacKey must be provided together (External Account Binding)",
      );
    }
    if (hasEabKid && !isNonEmptyString(eabKid)) {
      throw new Error("acme: eabKid must be a non-empty string when provided");
    }
    if (hasEabHmac && !isNonEmptyString(eabHmacKey)) {
      throw new Error("acme: eabHmacKey must be a non-empty string when provided");
    }
    if (typeof checkCaEndpoint !== "function") {
      throw new Error(
        "acme: runRenewal requires a checkCaEndpoint callback (policy engine defense-in-depth re-check)",
      );
    }

    // Validate every dynamic argv element against the shell-metacharacter
    // pattern (defense in depth; exec is shell-less regardless).
    assertSafeArgvElements("domains", domains);
    assertSafeArgvElements("paths", [csrPath, outCertPath, stateDir]);
    assertSafeArgvElements("caEndpoint", [caEndpoint]);
    if (preferredChain !== undefined) {
      assertSafeArgvElements("preferredChain", [preferredChain]);
    }
    if (hasEabKid) {
      assertSafeArgvElements("eabKid", [eabKid]);
      assertSafeArgvElements("eabHmacKey", [eabHmacKey]);
    }

    // (2) Defense-in-depth CA endpoint re-check. The caller has already
    // consulted the allowlist before dispatch; a rejection here is passed
    // through UNCHANGED so downstream result reporting handles it exactly
    // like any other policy rejection.
    const caCheck = checkCaEndpoint(caEndpoint);
    if (!caCheck || caCheck.allowed !== true) {
      return caCheck;
    }

    // (3) Final argv: allowlisted profile ++ adapter mapping (typed options
    // only; no generic extraArgs passthrough).
    const argvUsed = [
      ...profileArgv,
      ...buildAdapterArgs(kind, {
        caEndpoint,
        domains,
        csrPath,
        outCertPath,
        dryRun,
        dnsHookPath: resolvedDnsHookPath,
        stateDir,
        preferredChain,
        eabKid,
        eabHmacKey,
      }),
    ];

    // (4) Exec without a shell, with timeout, capturing bounded excerpts.
    // CERTOPS_DNS_HOOK is a non-secret path so the acme.sh dnsapi wrapper
    // (and any nested children) can locate the Node hook without relying
    // on PATH. LE_CONFIG_HOME mirrors --config-home for tools that read
    // the env before argv. Never forward credentials.
    const env = buildMinimalSubprocessEnv();
    env.CERTOPS_DNS_HOOK = resolvedDnsHookPath;
    const { acmeShHome } = resolveAcmeStatePaths(stateDir);
    env.LE_CONFIG_HOME = acmeShHome;

    const { exitCode, stdout, stderr } = await execWithoutShell(
      execFileImpl,
      argvUsed,
      timeoutMs,
      env,
    );

    // (5) Result. argvUsed is included for evidence: DNS credentials never
    // appear; EAB hmac is redacted. Account keys live under stateDir only.
    return {
      renewed: exitCode === 0,
      exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(stdout),
      stderrExcerpt: boundAndRedactExcerpt(stderr),
      argvUsed: redactSensitiveArgv(argvUsed),
    };
  }

  return {
    kind,
    runRenewal,
    dnsHookPath: resolvedDnsHookPath,
    acmeDnsApiPath: resolvedAcmeDnsApiPath,
  };
}

module.exports = {
  createAcmeAdapter,
  listSupportedAdapters,
  defaultDnsHookPath,
  defaultAcmeDnsApiPath,
  resolveAcmeStatePaths,
  ACME_SH_DNS_HOOK_NAME,
  RUN_RENEWAL_ALLOWED_KEYS,
  SHELL_METACHARACTER_PATTERN,
  OUTPUT_EXCERPT_MAX_CHARS,
  DEFAULT_TIMEOUT_MS,
};
