"use strict";

/**
 * Validate-then-reload service helpers.
 *
 * After a certificate deploy, the consuming service (nginx, apache/httpd,
 * haproxy) must reload its configuration. The safe sequence is always
 * validate-then-reload: run the service's config-check command first
 * (e.g. `nginx -t`), and only if it exits 0 run the reload command
 * (e.g. `systemctl reload nginx`). A broken config must never be reloaded
 * into a running service.
 *
 * Command custody (7.5/7.7, ADR-0002): this module NEVER constructs argv
 * itself and NEVER uses a shell. The dispatch layer resolves command
 * profile names via the agent-local policy engine (policy module's
 * checkCommandRef) and passes the concrete argv arrays here as
 * `commandProfiles: { validateArgv, reloadArgv }`. Commands are exec'd via
 * child_process.execFile(argv[0], argv.slice(1), { shell: false, timeout }),
 * so no shell interpretation ever happens. As defense in depth this module
 * re-rejects argv elements containing the same shell metacharacter set the
 * policy module uses (a profile that looks like shell syntax is a config
 * bug that must fail loudly).
 *
 * Output hygiene: stderr/stdout excerpts returned in results are bounded
 * (max STDERR_EXCERPT_MAX_CHARS) and passed through a scrubber that
 * replaces the WHOLE excerpt with "[redacted]" if it contains a
 * private-key marker ("PRIVATE KEY"), in the spirit of the evidence
 * module's redaction: better to lose a diagnostic line than to ever leak
 * key material into results/evidence (D5).
 *
 * Error model: command failures (nonzero exit, timeout, spawn error) are
 * RESULTS, not exceptions -- { reloaded: false, stage, exitCode, ... }.
 * This module throws only on programmer error: unknown service name,
 * malformed commandProfiles/argv, or shell metacharacters in argv.
 *
 * This module is self-contained: it accepts plain data as parameters and
 * does not import sibling agent modules. Wiring is left to src/index.js.
 */

const { execFile } = require("node:child_process");
const { buildMinimalSubprocessEnv } = require("../exec-env");

/**
 * Same set as the policy module's SHELL_METACHARACTER_PATTERN, duplicated
 * (not imported) to keep this module self-contained per package
 * convention: ; | & $ ` > < and newlines (CR or LF).
 */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

/** Services this module knows how to validate-then-reload. */
const SUPPORTED_SERVICES = Object.freeze(["nginx", "apache", "haproxy"]);

/** Default per-command timeout (30s). */
const DEFAULT_COMMAND_TIMEOUT_MS = 30000;

/** Hard bound on stderr/stdout excerpts included in results. */
const STDERR_EXCERPT_MAX_CHARS = 512;

const REDACTED_PLACEHOLDER = "[redacted]";

/**
 * Bounds and scrubs command output before it may appear in a result shape.
 * If the output contains a private-key marker anywhere, the whole excerpt
 * is replaced with "[redacted]" (simple and safe beats clever partial
 * redaction, per the evidence module's approach). Otherwise the output is
 * truncated to STDERR_EXCERPT_MAX_CHARS.
 *
 * @param {string|Buffer|undefined|null} output
 * @returns {string}
 */
function scrubExcerpt(output) {
  const text = output === undefined || output === null ? "" : String(output);
  if (/PRIVATE KEY/i.test(text)) {
    return REDACTED_PLACEHOLDER;
  }
  return text.slice(0, STDERR_EXCERPT_MAX_CHARS);
}

/**
 * Validates one argv array from a command profile. Throws on programmer
 * error (the dispatch layer handed us something the policy module should
 * never have produced).
 *
 * @param {string} label e.g. "commandProfiles.validateArgv"
 * @param {unknown} argv
 * @returns {string[]} shallow copy of argv
 */
function assertValidArgv(label, argv) {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new Error(`reload: ${label} must be a non-empty array of strings`);
  }
  argv.forEach((element, index) => {
    if (typeof element !== "string" || element.length === 0) {
      throw new Error(`reload: ${label}[${index}] must be a non-empty string`);
    }
    if (SHELL_METACHARACTER_PATTERN.test(element)) {
      throw new Error(
        `reload: ${label}[${index}] contains a disallowed shell metacharacter: ${JSON.stringify(element)}`,
      );
    }
  });
  return [...argv];
}

/**
 * Runs one argv without a shell, returning a settled outcome object (never
 * rejects for command failure). Timeout kills the process and surfaces as
 * a failure outcome.
 *
 * @param {typeof execFile} execFileImpl
 * @param {string[]} argv
 * @param {number} timeoutMs
 * @returns {Promise<{ ok: boolean, exitCode: number|null, stderr: string, stdout: string, timedOut: boolean, errorMessage: string|null }>}
 */
function runCommand(execFileImpl, argv, timeoutMs) {
  return new Promise((resolve) => {
    execFileImpl(
      argv[0],
      argv.slice(1),
      // shell: false is execFile's default, but it is set explicitly so
      // the no-shell invariant is visible at the call site and assertable
      // in tests via execFileImpl stubs. env is the explicit minimal
      // allowlist so agent secrets (e.g. the bootstrap token) never reach
      // reload/validate commands.
      { shell: false, timeout: timeoutMs, env: buildMinimalSubprocessEnv() },
      (error, stdout, stderr) => {
        if (!error) {
          resolve({
            ok: true,
            exitCode: 0,
            stdout: String(stdout ?? ""),
            stderr: String(stderr ?? ""),
            timedOut: false,
            errorMessage: null,
          });
          return;
        }
        // execFile sets error.killed/error.signal on timeout kills and
        // error.code to the numeric exit code for nonzero exits (or a
        // string like "ENOENT" for spawn failures).
        const timedOut =
          error.killed === true ||
          error.signal === "SIGTERM" ||
          error.code === "ETIMEDOUT";
        resolve({
          ok: false,
          exitCode: typeof error.code === "number" ? error.code : null,
          stdout: String(stdout ?? ""),
          stderr: String(stderr ?? ""),
          timedOut,
          errorMessage: error.message || String(error),
        });
      },
    );
  });
}

/**
 * Validate-then-reload for a supported service.
 *
 * @param {{
 *   service: "nginx"|"apache"|"haproxy",
 *   commandProfiles: { validateArgv: string[], reloadArgv: string[] },
 *     // Resolved by the dispatch layer from the agent-local policy
 *     // allowlist (policy checkCommandRef); NEVER constructed here.
 *   timeoutMs?: number,       // per-command timeout, default 30000
 *   execFileImpl?: typeof execFile, // injectable for tests
 * }} params
 * @returns {Promise<
 *   | { reloaded: true, service: string, stages: Array<{ stage: string, exitCode: number }> }
 *   | { reloaded: false, service: string, stage: "validate"|"reload", exitCode: number|null, timedOut: boolean, stderrExcerpt: string, error: string|null }
 * >}
 */
async function reloadService({
  service,
  commandProfiles,
  timeoutMs = DEFAULT_COMMAND_TIMEOUT_MS,
  execFileImpl = execFile,
} = {}) {
  if (!SUPPORTED_SERVICES.includes(service)) {
    throw new Error(
      `reload: service must be one of ${SUPPORTED_SERVICES.join(", ")} (got ${JSON.stringify(service)})`,
    );
  }
  if (
    commandProfiles === null ||
    typeof commandProfiles !== "object" ||
    Array.isArray(commandProfiles)
  ) {
    throw new Error(
      "reload: commandProfiles must be an object with validateArgv and reloadArgv " +
        "(resolved from the agent-local policy allowlist by the dispatch layer)",
    );
  }

  const validateArgv = assertValidArgv(
    "commandProfiles.validateArgv",
    commandProfiles.validateArgv,
  );
  const reloadArgv = assertValidArgv(
    "commandProfiles.reloadArgv",
    commandProfiles.reloadArgv,
  );

  const stages = [];

  const validateOutcome = await runCommand(execFileImpl, validateArgv, timeoutMs);
  if (!validateOutcome.ok) {
    return {
      reloaded: false,
      service,
      stage: "validate",
      exitCode: validateOutcome.exitCode,
      timedOut: validateOutcome.timedOut,
      stderrExcerpt: scrubExcerpt(validateOutcome.stderr || validateOutcome.stdout),
      error: validateOutcome.errorMessage,
    };
  }
  stages.push({ stage: "validate", exitCode: 0 });

  const reloadOutcome = await runCommand(execFileImpl, reloadArgv, timeoutMs);
  if (!reloadOutcome.ok) {
    return {
      reloaded: false,
      service,
      stage: "reload",
      exitCode: reloadOutcome.exitCode,
      timedOut: reloadOutcome.timedOut,
      stderrExcerpt: scrubExcerpt(reloadOutcome.stderr || reloadOutcome.stdout),
      error: reloadOutcome.errorMessage,
    };
  }
  stages.push({ stage: "reload", exitCode: 0 });

  return { reloaded: true, service, stages };
}

module.exports = {
  reloadService,
  scrubExcerpt,
  SUPPORTED_SERVICES,
  DEFAULT_COMMAND_TIMEOUT_MS,
  STDERR_EXCERPT_MAX_CHARS,
  SHELL_METACHARACTER_PATTERN,
};
