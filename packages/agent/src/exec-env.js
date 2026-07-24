"use strict";

/**
 * Minimal environment allowlist for agent-spawned subprocesses (ACME tools,
 * reload/validate commands).
 *
 * The agent process environment can carry secrets: the single-use bootstrap
 * token on first run (TOKENTIMER_AGENT_BOOTSTRAP_TOKEN via systemd
 * EnvironmentFile) and any operator-exported material. Child processes must
 * never inherit those, so instead of passing process.env through, every
 * exec call builds an explicit environment containing only what external
 * tools legitimately need:
 *
 *   - PATH / PATHEXT / SYSTEMROOT / WINDIR: binary resolution (POSIX + the
 *     Windows entries that exist only there; absent vars are skipped).
 *   - HOME / USERPROFILE: certbot/acme.sh default config + account dirs.
 *   - TMPDIR / TEMP / TMP: scratch space.
 *   - LANG / LC_ALL / TZ: locale and time, keeps tool output/parsing stable.
 *   - TOKENTIMER_AGENT_CONFIG_DIR: the certops-dns-hook child that certbot
 *     spawns resolves the agent config dir from this.
 *   - CERTOPS_DNS_HOOK: absolute path to certops-dns-hook.js (non-secret).
 *     Set by the ACME adapter so the acme.sh dns_certops.sh wrapper can
 *     locate the Node hook without putting credentials on argv/env.
 *
 * TOKENTIMER_AGENT_BOOTSTRAP_TOKEN and every other TOKENTIMER_AGENT_* /
 * arbitrary variable are deliberately NOT forwarded.
 */

const SUBPROCESS_ENV_ALLOWLIST = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "HOME",
  "USERPROFILE",
  "TMPDIR",
  "TEMP",
  "TMP",
  "LANG",
  "LC_ALL",
  "TZ",
  "TOKENTIMER_AGENT_CONFIG_DIR",
  "CERTOPS_DNS_HOOK",
]);

/**
 * Builds the explicit child-process environment from an allowlist over the
 * given source environment.
 *
 * @param {NodeJS.ProcessEnv} [sourceEnv]
 * @returns {Record<string, string>}
 */
function buildMinimalSubprocessEnv(sourceEnv = process.env) {
  const env = {};
  for (const name of SUBPROCESS_ENV_ALLOWLIST) {
    const value = sourceEnv[name];
    if (typeof value === "string" && value.length > 0) {
      env[name] = value;
    }
  }
  return env;
}

module.exports = {
  SUBPROCESS_ENV_ALLOWLIST,
  buildMinimalSubprocessEnv,
};
