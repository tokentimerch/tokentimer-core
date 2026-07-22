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
 *     element (profile, mapped arguments, extraArgs) against the same
 *     shell-metacharacter pattern the policy module uses, as defense in
 *     depth against a misconfigured profile or malicious job input.
 *
 * Zero-custody-preserving design (D5 / ADR-0001):
 *   - No private key is ever passed to, read by, or produced by this
 *     module. Renewal is CSR-based: the keys module generates the keypair
 *     and CSR on the host; this module only points the ACME tool at the CSR
 *     file. certbot's `--csr` mode (and acme.sh's `--signcsr`) sign an
 *     externally supplied CSR and therefore never need the private key.
 *   - DNS credentials never appear in argv either: per the DNS-01
 *     credential-locality invariant, they live in the ACME tool's own configuration
 *     files on the host (e.g. certbot's --dns-*-credentials ini, acme.sh's
 *     account.conf), referenced at most by path through the allowlisted
 *     command profile. argvUsed in the result is therefore safe to include
 *     in evidence by construction.
 *
 * Adapter argv contract (documented here as the source of truth; the exact
 * flags may be tuned when real-world testing against live CAs happens, but
 * any change must update this table and the sibling tests):
 *
 *   certbot  : profile.argv ++ [
 *                "certonly", "--non-interactive",
 *                "--csr", csrPath,
 *                "--server", caEndpoint,
 *                "-d", domain      (repeated per domain, in input order),
 *                "--cert-path", outCertPath,
 *                "--dry-run"       (only when dryRun),
 *              ] ++ extraArgs
 *
 *   acme.sh  : profile.argv ++ [
 *                "--signcsr",
 *                "--csr", csrPath,
 *                "--server", caEndpoint,
 *                "-d", domain      (repeated per domain, in input order),
 *                "--cert-file", outCertPath,
 *                "--test"          (only when dryRun),
 *              ] ++ extraArgs
 *
 * This module is self-contained: it accepts plain data as function
 * parameters and does not import sibling agent modules (policy, config,
 * keys, etc.). Wiring profile resolution + policy checks + this adapter
 * together is the dispatch layer's job.
 */

const childProcess = require("node:child_process");

/**
 * Mirrors the policy module's SHELL_METACHARACTER_PATTERN (duplicated, not
 * imported, to keep this module self-contained): ; | & $ ` > < CR LF.
 * Commands run without a shell, so this is defense in depth against
 * misconfigured profiles / hostile job input, not a shell-injection vector
 * by itself.
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
 * Builds the adapter-kind-specific argument tail (everything after the
 * allowlisted profile argv, before extraArgs). See the module-level
 * "Adapter argv contract" table.
 *
 * @param {"certbot"|"acme.sh"} kind
 * @param {{ caEndpoint: string, domains: string[], csrPath: string, outCertPath: string, dryRun: boolean }} inputs
 * @returns {string[]}
 */
function buildAdapterArgs(kind, { caEndpoint, domains, csrPath, outCertPath, dryRun }) {
  const domainFlags = domains.flatMap((domain) => ["-d", domain]);

  if (kind === "certbot") {
    return [
      "certonly",
      "--non-interactive",
      "--csr",
      csrPath,
      "--server",
      caEndpoint,
      ...domainFlags,
      "--cert-path",
      outCertPath,
      ...(dryRun ? ["--dry-run"] : []),
    ];
  }

  // kind === "acme.sh" (createAcmeAdapter has already validated kind)
  return [
    "--signcsr",
    "--csr",
    csrPath,
    "--server",
    caEndpoint,
    ...domainFlags,
    "--cert-file",
    outCertPath,
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
 * @returns {Promise<{ exitCode: number|null, stdout: unknown, stderr: unknown, execError: Error|null }>}
 */
function execWithoutShell(execFileImpl, argv, timeoutMs) {
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
 * @returns {{ kind: string, runRenewal: Function }}
 */
function createAcmeAdapter({
  kind,
  commandProfile,
  execFileImpl = childProcess.execFile,
  timeoutMs = DEFAULT_TIMEOUT_MS,
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

  // Freeze a copy so a caller mutating its profile object after adapter
  // creation cannot alter what actually gets exec'd.
  const profileArgv = Object.freeze([...commandProfile.argv]);

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
   * @param {string[]} options.domains non-empty list of domain names.
   * @param {string} options.csrPath absolute path to the CSR file (produced
   *   by the keys module; the private key never passes through here).
   * @param {string} options.outCertPath absolute path where the tool writes
   *   the issued certificate.
   * @param {string[]} [options.extraArgs] appended last, after
   *   metacharacter validation. For per-job tuning (e.g. preferred chain).
   * @param {(url: string) => { allowed: boolean, rejectionReason?: string, detail?: string }} options.checkCaEndpoint
   *   defense-in-depth policy re-check (policy engine's checkCaEndpoint).
   * @param {boolean} [options.dryRun] map to --dry-run (certbot) / --test
   *   (acme.sh) so no real certificate is issued.
   * @returns {Promise<
   *   { renewed: boolean, exitCode: number|null, stdoutExcerpt: string, stderrExcerpt: string, argvUsed: string[] }
   *   | { allowed: false, rejectionReason: string, detail: string }
   * >}
   */
  async function runRenewal({
    caEndpoint,
    domains,
    csrPath,
    outCertPath,
    extraArgs = [],
    checkCaEndpoint,
    dryRun = false,
  } = {}) {
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
    if (!Array.isArray(extraArgs)) {
      throw new Error("acme: extraArgs must be an array of strings");
    }
    if (typeof checkCaEndpoint !== "function") {
      throw new Error(
        "acme: runRenewal requires a checkCaEndpoint callback (policy engine defense-in-depth re-check)",
      );
    }

    // Validate every dynamic argv element against the shell-metacharacter
    // pattern (defense in depth; exec is shell-less regardless).
    assertSafeArgvElements("domains", domains);
    assertSafeArgvElements("extraArgs", extraArgs);
    assertSafeArgvElements("paths", [csrPath, outCertPath]);
    assertSafeArgvElements("caEndpoint", [caEndpoint]);

    // (2) Defense-in-depth CA endpoint re-check. The caller has already
    // consulted the allowlist before dispatch; a rejection here is passed
    // through UNCHANGED so downstream result reporting handles it exactly
    // like any other policy rejection.
    const caCheck = checkCaEndpoint(caEndpoint);
    if (!caCheck || caCheck.allowed !== true) {
      return caCheck;
    }

    // (3) Final argv: allowlisted profile ++ adapter mapping ++ extraArgs.
    const argvUsed = [
      ...profileArgv,
      ...buildAdapterArgs(kind, {
        caEndpoint,
        domains,
        csrPath,
        outCertPath,
        dryRun,
      }),
      ...extraArgs,
    ];

    // (4) Exec without a shell, with timeout, capturing bounded excerpts.
    const { exitCode, stdout, stderr } = await execWithoutShell(
      execFileImpl,
      argvUsed,
      timeoutMs,
    );

    // (5) Result. argvUsed is included for evidence: it contains no secrets
    // by construction (no key material exists here; DNS credentials live in
    // the tool's own config files, never in argv).
    return {
      renewed: exitCode === 0,
      exitCode,
      stdoutExcerpt: boundAndRedactExcerpt(stdout),
      stderrExcerpt: boundAndRedactExcerpt(stderr),
      argvUsed,
    };
  }

  return { kind, runRenewal };
}

module.exports = {
  createAcmeAdapter,
  listSupportedAdapters,
  SHELL_METACHARACTER_PATTERN,
  OUTPUT_EXCERPT_MAX_CHARS,
  DEFAULT_TIMEOUT_MS,
};
