"use strict";

/**
 * Platform permission enforcement and durability limits.
 *
 * POSIX hosts express "only this identity may read this file" with chmod 0600
 * / 0700, and the agent has always asserted those modes. Windows has no chmod
 * equivalent, so before this module every chmod was wrapped in an empty catch
 * and every permission preflight was skipped outright on win32. That is the
 * one thing the agent must never do: treat "this platform cannot express the
 * permission I need" as success.
 *
 * Enforcement on win32 uses `icacls`, which ships with Windows:
 *
 *   - apply: `icacls <path> /inheritance:r /grant:r <sid>:(F) ...` drops every
 *     inherited ACE and leaves exactly the agent's own identity plus SYSTEM.
 *     ADR-0012 decision 5 fixes the Windows agent service at `LocalSystem`, so
 *     SYSTEM is the principal that must read these files; the ACL's job is
 *     excluding everyone else, not excluding the service that owns the file.
 *   - verify: `icacls <path> /save <file>` writes SDDL, which is SID-based and
 *     therefore locale-independent. icacls' human-readable output is localized
 *     ("AUTORITE NT\\Systeme" on a French host) and is never parsed here.
 *
 * Both operations fail loudly: a missing icacls, a non-zero exit, or an
 * unparseable SDDL is an error, never a silent skip.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

/** Well-known SID of the local SYSTEM account (SDDL alias `SY`). */
const SYSTEM_SID = "S-1-5-18";
/** Well-known SID of the local Administrators group (SDDL alias `BA`). */
const ADMINISTRATORS_SID = "S-1-5-32-544";

/**
 * SDDL two-letter aliases the parser resolves to SIDs. Only the aliases that
 * can legitimately or dangerously appear on an agent state file are listed;
 * anything unrecognized is surfaced verbatim so verification refuses it
 * rather than silently ignoring it.
 */
const SDDL_ALIAS_SIDS = Object.freeze({
  SY: SYSTEM_SID,
  BA: ADMINISTRATORS_SID,
  // `LA` (the built-in local Administrator account, RID 500) has no fixed
  // well-known SID string: its real value is machine/domain-relative
  // (<machine-or-domain-SID>-500), so it cannot be a literal constant here.
  // It is mapped to the Administrators *group* SID instead, which is the
  // correct outcome for this allowlist's purposes: the built-in Administrator
  // account is always a member of Administrators and carries the identical
  // "accepted but never granted" trust tier this module already applies to
  // BA, for the identical reason (it can take ownership of any file on the
  // machine, so excluding it from the DACL buys no confidentiality). A
  // fabricated, syntactically invalid SID string was here before
  // (`S-1-5-32-544-administrator`), which made `icacls` fail with exit code
  // 1337 (ERROR_INVALID_SID) every time a DACL contained this alias, which
  // real Windows hosts running as a built-in Administrator account (as
  // GitHub-hosted Windows runners do) do by default.
  LA: ADMINISTRATORS_SID,
  BU: "S-1-5-32-545",
  AU: "S-1-5-11",
  WD: "S-1-1-0",
  IU: "S-1-5-4",
  AN: "S-1-5-7",
  LS: "S-1-5-19",
  NS: "S-1-5-20",
  CO: "S-1-3-0",
  OW: "S-1-3-4",
});

const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;

function isWindows(platform = process.platform) {
  return platform === "win32";
}

function buildError(message) {
  return new Error(`tokentimer-agent platform: ${message}`);
}

/**
 * Runs a Windows utility and returns its exit status plus streams. Kept behind
 * a single seam so tests can inject a fake without spawning processes.
 *
 * @param {string} file
 * @param {string[]} args
 * @param {(file: string, args: string[], options: object) => { status: number|null, stdout: string, stderr: string, error?: Error }} [spawn]
 * @returns {{ status: number|null, stdout: string, stderr: string, error?: Error }}
 */
function runTool(file, args, spawn = spawnSync) {
  const result = spawn(file, args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 30000,
  });
  if (!result || (result.error && result.error.code === "ENOENT")) {
    throw buildError(
      `${file} is not available on this host, so file permissions cannot be ` +
        "enforced; refusing to continue with unprotected state files",
    );
  }
  if (result.error) {
    throw buildError(`${file} failed to run: ${result.error.message}`);
  }
  return result;
}

let cachedUserSid = null;

/**
 * Resolves the SID of the identity this process runs as. `whoami /user` is
 * used with CSV output so the SID is machine-readable and unaffected by the
 * host language.
 *
 * @param {{ spawn?: Function, useCache?: boolean }} [options]
 * @returns {string}
 */
function currentUserSid({ spawn = spawnSync, useCache = true } = {}) {
  if (useCache && cachedUserSid !== null) return cachedUserSid;
  const result = runTool("whoami", ["/user", "/fo", "csv", "/nh"], spawn);
  if (result.status !== 0) {
    throw buildError(
      `whoami exited ${result.status} while resolving the agent's own SID`,
    );
  }
  const match = /(S-1-[0-9-]+)/.exec(String(result.stdout || ""));
  if (!match) {
    throw buildError("could not parse a SID out of whoami /user output");
  }
  if (useCache) cachedUserSid = match[1];
  return match[1];
}

/** Test helper: clears the memoized process SID. */
function resetPlatformCaches() {
  cachedUserSid = null;
}

/**
 * The principals an agent-controlled sensitive file may grant.
 *
 * SYSTEM is required (the service runs as LocalSystem). The agent's own
 * identity is required for a non-service, operator-run agent. Administrators
 * is accepted but never granted by the agent: a member of Administrators can
 * take ownership of any file on the machine, so excluding it from the DACL
 * buys no confidentiality while breaking routine operator maintenance.
 *
 * @param {string} ownSid
 * @returns {Set<string>}
 */
function allowedPrincipals(ownSid) {
  return new Set([ownSid, SYSTEM_SID, ADMINISTRATORS_SID]);
}

/**
 * Applies the restrictive ACL to a file or directory and verifies the result.
 *
 * `/grant:r` only replaces the entries of the principals it names, so a
 * pre-existing explicit ACE for someone else (an operator who ran
 * `icacls /grant`, a tool that added Everyone) survives it. Enforcement
 * therefore grants, re-reads the resulting DACL, removes every principal
 * outside the allowlist, and re-reads again. If anything foreign is still
 * there the call raises: a partially restricted credential file is not an
 * acceptable outcome of a successful write.
 *
 * Directories also get object/container inheritance so files created inside
 * them (including the temp file of an atomic write, which is created fresh on
 * every write) start out restricted instead of inheriting the parent's ACL.
 *
 * @param {string} targetPath
 * @param {{ kind?: "file"|"directory", spawn?: Function, fsImpl?: typeof fs, tmpDir?: string }} [options]
 * @returns {{ mechanism: "windows-acl", principals: string[], removed: string[], inheritance: "removed" }}
 */
function applyWindowsAcl(
  targetPath,
  { kind = "file", spawn = spawnSync, fsImpl = fs, tmpDir } = {},
) {
  const ownSid = currentUserSid({ spawn });
  const rights = kind === "directory" ? "(OI)(CI)(F)" : "(F)";
  const granted = [SYSTEM_SID, ownSid].filter(
    (sid, index, all) => all.indexOf(sid) === index,
  );
  const grantResult = runTool(
    "icacls",
    [
      targetPath,
      "/inheritance:r",
      "/grant:r",
      ...granted.map((sid) => `*${sid}:${rights}`),
    ],
    spawn,
  );
  if (grantResult.status !== 0) {
    throw buildError(
      `icacls exited ${grantResult.status} while restricting ${targetPath}; ` +
        "the file remains unprotected, so this is treated as a failure",
    );
  }

  const allowed = allowedPrincipals(ownSid);
  const foreign = parseDaclSddl(readWindowsSddl(targetPath, { spawn, fsImpl, tmpDir }))
    .aces.map((ace) => ace.sid)
    .filter((sid) => !allowed.has(sid))
    .filter((sid, index, all) => all.indexOf(sid) === index);

  if (foreign.length > 0) {
    const removeResult = runTool(
      "icacls",
      [
        targetPath,
        ...foreign.flatMap((sid) => ["/remove:g", `*${sid}`, "/remove:d", `*${sid}`]),
      ],
      spawn,
    );
    if (removeResult.status !== 0) {
      throw buildError(
        `icacls exited ${removeResult.status} while removing ${foreign.join(", ")} ` +
          `from ${targetPath}`,
      );
    }
    const stillForeign = parseDaclSddl(
      readWindowsSddl(targetPath, { spawn, fsImpl, tmpDir }),
    )
      .aces.map((ace) => ace.sid)
      .filter((sid) => !allowed.has(sid));
    if (stillForeign.length > 0) {
      throw buildError(
        `could not restrict ${targetPath}: it still grants ` +
          `${stillForeign.join(", ")} after enforcement`,
      );
    }
  }

  assertTrustedOwner(targetPath, allowed, { label: targetPath, spawn });

  return {
    mechanism: "windows-acl",
    principals: granted,
    removed: foreign,
    inheritance: "removed",
  };
}

/**
 * Reads a path's DACL as SDDL via `icacls /save`. The saved file is UTF-16LE
 * and holds one `name` line followed by one SDDL line per processed path.
 *
 * @param {string} targetPath
 * @param {{ spawn?: Function, fsImpl?: typeof fs, tmpDir?: string }} [options]
 * @returns {string} the SDDL descriptor
 */
function readWindowsSddl(
  targetPath,
  { spawn = spawnSync, fsImpl = fs, tmpDir = os.tmpdir() } = {},
) {
  const savePath = path.join(
    tmpDir,
    `tokentimer-acl-${process.pid}-${crypto.randomBytes(6).toString("hex")}.sddl`,
  );
  try {
    const result = runTool("icacls", [targetPath, "/save", savePath], spawn);
    if (result.status !== 0) {
      throw buildError(
        `icacls exited ${result.status} while reading the ACL of ${targetPath}`,
      );
    }
    const saved = fsImpl.readFileSync(savePath, "utf16le");
    const sddl = /(D:[^\r\n]*)/.exec(String(saved).replace(/\uFEFF/g, ""));
    if (!sddl) {
      throw buildError(
        `icacls did not report a DACL for ${targetPath}; refusing to assume ` +
          "the path is protected",
      );
    }
    return sddl[1].trim();
  } finally {
    try {
      fsImpl.unlinkSync(savePath);
    } catch (_err) {
      // The save file may never have been created.
    }
  }
}

/**
 * Parses the DACL portion of an SDDL string.
 *
 * @param {string} sddl
 * @returns {{ protectedDacl: boolean, autoInherited: boolean, aces: Array<{ type: string, flags: string, sid: string, inherited: boolean }> }}
 */
function parseDaclSddl(sddl) {
  const daclStart = sddl.indexOf("D:");
  if (daclStart === -1) throw buildError(`SDDL has no DACL: ${sddl}`);
  const body = sddl.slice(daclStart + 2);
  const flagsEnd = body.indexOf("(");
  const flags = (flagsEnd === -1 ? body : body.slice(0, flagsEnd)).trim();
  const aces = [];
  const acePattern = /\(([^)]*)\)/g;
  let match;
  while ((match = acePattern.exec(body))) {
    const fields = match[1].split(";");
    const rawSid = (fields[5] || "").trim();
    if (rawSid.length === 0) continue;
    const aceFlags = (fields[1] || "").trim().toUpperCase();
    aces.push({
      type: (fields[0] || "").trim().toUpperCase(),
      flags: aceFlags,
      sid: SDDL_ALIAS_SIDS[rawSid.toUpperCase()] || rawSid,
      inherited: aceFlags.includes("ID"),
    });
  }
  return {
    protectedDacl: flags.toUpperCase().includes("P"),
    autoInherited: flags.toUpperCase().includes("AI"),
    aces,
  };
}

/**
 * Reads the owner SID of a path via .NET's `ObjectSecurity.GetOwner`,
 * translated to a `SecurityIdentifier` rather than an `NTAccount`.
 * Requesting the SID type directly (instead of reading the display name
 * `Get-Acl` normally prints and translating it back) means the result is
 * correct even on a localized host and even for an owner whose display
 * name cannot be resolved (an orphaned SID from a deleted account).
 *
 * `icacls /save` was evaluated for this and rejected: its saved SDDL only
 * ever contains the `D:` (DACL) component on this codebase's target OS
 * versions, never `O:` (owner), so owner cannot be recovered from it.
 *
 * The path is passed through an environment variable rather than
 * interpolated into the PowerShell command string, so a path containing
 * quotes or `$` cannot affect what the script executes.
 *
 * That same environment is also where a subtler, host-dependent failure
 * lives: Windows PowerShell 5.1 (`powershell.exe`) resolves `Get-Acl`
 * through module auto-loading, and it trusts an inherited `PSModulePath`
 * as-is rather than recomputing it the way `pwsh` (PowerShell 7+) does. On
 * GitHub-hosted Windows runners (and any host where this process was
 * itself launched from, or inherited environment from, a PowerShell 7
 * parent), `PSModulePath` can list PowerShell 7's Core-edition module
 * paths ahead of Windows PowerShell's own Desktop-edition ones. `Get-Acl`
 * then autoloads the Core-edition `Microsoft.PowerShell.Security` binary
 * module into the Desktop CLR, which cannot load it, and fails closed with
 * `CouldNotAutoloadMatchingModule`. Deleting `PSModulePath` from the child
 * environment (rather than trying to reorder or filter it) makes
 * `powershell.exe` compute its own default, version-correct search path
 * exactly as it would with no ancestor process at all.
 *
 * @param {string} targetPath
 * @param {{ spawn?: Function }} [options]
 * @returns {string} the owner SID
 */
function readWindowsOwnerSid(targetPath, { spawn = spawnSync } = {}) {
  const script =
    "$p = $env:TOKENTIMER_ACL_PATH; " +
    "$acl = Get-Acl -LiteralPath $p; " +
    "$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value";
  const env = { ...process.env, TOKENTIMER_ACL_PATH: targetPath };
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === "psmodulepath") delete env[key];
  }
  const result = spawn(
    "powershell",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30000,
      env,
    },
  );
  if (!result || (result.error && result.error.code === "ENOENT")) {
    throw buildError(
      "powershell is not available on this host, so the owner of " +
        `${targetPath} cannot be verified; refusing to trust an unverifiable owner`,
    );
  }
  if (result.error) {
    throw buildError(
      `powershell failed to run while reading the owner of ${targetPath}: ${result.error.message}`,
    );
  }
  if (result.status !== 0) {
    throw buildError(
      `powershell exited ${result.status} while reading the owner of ${targetPath}: ` +
        `${String(result.stderr || "").trim()}`,
    );
  }
  const match = /(S-1-[0-9-]+)/.exec(String(result.stdout || ""));
  if (!match) {
    throw buildError(`could not parse an owner SID for ${targetPath}`);
  }
  return match[1];
}

/**
 * Validates that a path's owner SID is inside the trusted allowlist,
 * raising with the same fail-closed severity as a foreign DACL entry: an
 * untrusted owner can rewrite the DACL at will (`WRITE_DAC`/`WRITE_OWNER`
 * semantics), which makes a DACL check that ignores the owner no
 * protection at all.
 *
 * @param {string} targetPath
 * @param {Set<string>} allowed
 * @param {{ label?: string, spawn?: Function }} [options]
 * @returns {string} the validated owner SID
 */
function assertTrustedOwner(targetPath, allowed, { label = targetPath, spawn = spawnSync } = {}) {
  const ownerSid = readWindowsOwnerSid(targetPath, { spawn });
  if (!allowed.has(ownerSid)) {
    throw buildError(
      `refusing to use ${label}: its owner is ${ownerSid}, which is not one ` +
        "of the trusted owners (the agent's own identity, SYSTEM, or " +
        "Administrators); an untrusted owner can rewrite the ACL at will, " +
        "which makes the DACL check above meaningless",
    );
  }
  return ownerSid;
}

/**
 * Verifies that a path's DACL grants nothing outside the allowlist. Every
 * failure mode (unreadable ACL, unparseable SDDL, an extra principal) raises,
 * so a caller can never mistake "could not check" for "checked and fine".
 *
 * `requireProtected` is for paths the agent creates itself, where inheritance
 * removal is guaranteed. It stays off for operator-provided credential files:
 * a file that inherits owner-plus-SYSTEM from a locked-down parent is exactly
 * as confidential as one with an explicit DACL, and refusing it would be a
 * false rejection. The principal allowlist is the security property; the
 * protected flag is a durability-of-intent property.
 *
 * @param {string} targetPath
 * @param {{ label?: string, requireProtected?: boolean, spawn?: Function, fsImpl?: typeof fs, tmpDir?: string }} [options]
 * @returns {{ mechanism: "windows-acl", principals: string[], protectedDacl: boolean, sddl: string }}
 */
function assertWindowsAcl(
  targetPath,
  {
    label = targetPath,
    requireProtected = false,
    spawn = spawnSync,
    fsImpl = fs,
    tmpDir,
  } = {},
) {
  const sddl = readWindowsSddl(targetPath, { spawn, fsImpl, tmpDir });
  const parsed = parseDaclSddl(sddl);
  const allowed = allowedPrincipals(currentUserSid({ spawn }));

  if (requireProtected && !parsed.protectedDacl) {
    throw buildError(
      `refusing to use ${label}: its ACL still inherits from its parent ` +
        "directory (run icacls with /inheritance:r, or let the agent create it)",
    );
  }
  if (parsed.aces.length === 0) {
    throw buildError(
      `refusing to use ${label}: its DACL is empty or could not be read, so ` +
        "the agent cannot confirm who has access",
    );
  }
  const foreign = parsed.aces
    .filter((ace) => !allowed.has(ace.sid))
    .map((ace) => ace.sid);
  if (foreign.length > 0) {
    throw buildError(
      `refusing to use ${label}: its ACL grants access to ` +
        `${foreign.join(", ")} (only the agent's own identity, SYSTEM and ` +
        "Administrators are allowed)",
    );
  }
  assertTrustedOwner(targetPath, allowed, { label, spawn });
  return {
    mechanism: "windows-acl",
    principals: parsed.aces.map((ace) => ace.sid),
    protectedDacl: parsed.protectedDacl,
    sddl,
  };
}

/**
 * Applies the strongest permission the platform can express: POSIX modes on
 * POSIX hosts, a restricted ACL on win32. Unlike the previous best-effort
 * chmod, a failure here propagates.
 *
 * @param {string} targetPath
 * @param {{ kind?: "file"|"directory", mode?: number, platform?: string, spawn?: Function, fsImpl?: typeof fs }} [options]
 * @returns {{ mechanism: "posix-mode"|"windows-acl", principals?: string[], mode?: number }}
 */
function applyRestrictivePermissions(
  targetPath,
  {
    kind = "file",
    mode,
    platform = process.platform,
    spawn = spawnSync,
    fsImpl = fs,
    tmpDir,
  } = {},
) {
  if (isWindows(platform)) {
    return applyWindowsAcl(targetPath, { kind, spawn, fsImpl, tmpDir });
  }
  const posixMode =
    typeof mode === "number" ? mode : kind === "directory" ? DIRECTORY_MODE : FILE_MODE;
  fsImpl.chmodSync(targetPath, posixMode);
  return { mechanism: "posix-mode", mode: posixMode };
}

/**
 * Verifies that a path the agent is about to read secrets from is not exposed
 * to other principals. POSIX: regular non-symlink file, no group/other bits,
 * owned by this user or root. win32: allowlisted DACL.
 *
 * @param {string} targetPath
 * @param {{ label: string, requireProtected?: boolean, platform?: string, spawn?: Function, fsImpl?: typeof fs, tmpDir?: string }} options
 * @returns {{ mechanism: "posix-mode"|"windows-acl" }}
 */
function assertRestrictivePermissions(
  targetPath,
  {
    label,
    requireProtected = false,
    platform = process.platform,
    spawn = spawnSync,
    fsImpl = fs,
    tmpDir,
  } = {},
) {
  const name = label || targetPath;
  let stats;
  try {
    stats = fsImpl.lstatSync(targetPath);
  } catch (err) {
    throw new Error(
      `tokentimer-agent: failed to stat ${name} ${targetPath}: ${err.message}`,
    );
  }
  if (stats.isSymbolicLink() || !stats.isFile()) {
    throw new Error(
      `tokentimer-agent: ${name} ${targetPath} must be a regular non-symlink file`,
    );
  }

  if (isWindows(platform)) {
    assertWindowsAcl(targetPath, {
      label: `${name} ${targetPath}`,
      requireProtected,
      spawn,
      fsImpl,
      tmpDir,
    });
    return { mechanism: "windows-acl" };
  }

  if ((stats.mode & 0o077) !== 0) {
    throw new Error(
      `tokentimer-agent: refusing to read ${name} ${targetPath}: ` +
        "it is readable by group/other (chmod 600 it)",
    );
  }
  if (typeof process.getuid === "function") {
    const uid = process.getuid();
    if (stats.uid !== uid && stats.uid !== 0) {
      throw new Error(
        `tokentimer-agent: refusing to read ${name} ${targetPath}: ` +
          "it is not owned by the agent user or root",
      );
    }
  }
  return { mechanism: "posix-mode" };
}

/** Must exactly match install-agent.ps1's $ServiceName; a mismatch here
 * would mean the scrub below silently touches nothing while the real
 * spent token sits untouched in the registry. */
const SERVICE_NAME = "TokenTimerAgent";
const SERVICE_ENVIRONMENT_REGISTRY_KEY = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${SERVICE_NAME}`;

/**
 * Rewrites the Windows service's registry `Environment` value (written by
 * install-agent.ps1's `Set-ServiceEnvironment`) to drop the single-use
 * bootstrap token immediately after it has been exchanged for a stored
 * credential, leaving only `TOKENTIMER_AGENT_CONFIG_DIR` behind. Without
 * this, a secret documented and enforced everywhere else as single-use
 * would otherwise sit in `HKLM` in cleartext for the entire lifetime of
 * the install, readable by anything that can read a LocalSystem service's
 * configuration (Administrators).
 *
 * Reuses reg.exe rather than a registry-editing npm dependency, matching
 * this codebase's "native Windows tooling only" policy (see the icacls
 * and sc.exe usage elsewhere) and check-shipped-sources.js's zero-runtime
 * dependency rule.
 *
 * Queries before writing so this can never *create* a Services key that
 * did not already exist: a `reg.exe add` alone would silently fabricate
 * `HKLM\SYSTEM\CurrentControlSet\Services\TokenTimerAgent` on a host
 * where the service was never installed (a manual/dev run of the agent),
 * which is a strictly worse outcome than leaving an already-scrubbed
 * environment (this process's own, and bootstrap.env) alone.
 *
 * Best-effort and Windows-only: clearing a bonus copy of an
 * already-consumed, already-rotated-out secret must never be allowed to
 * fail agent startup or registration, which is guarded by assertions with
 * much higher stakes (the ACL checks elsewhere in this module). Every
 * failure mode here is reported back to the caller for logging, never
 * thrown.
 *
 * @param {{ configDir: string, spawn?: Function, platform?: string }} options
 * @returns {{ attempted: boolean, cleared: boolean, reason?: string }}
 */
function clearWindowsServiceBootstrapToken({
  configDir,
  spawn = spawnSync,
  platform = process.platform,
} = {}) {
  if (!isWindows(platform)) {
    return { attempted: false, cleared: false, reason: "not running on Windows" };
  }

  const runRegExe = (args) =>
    spawn("reg.exe", args, { encoding: "utf8", windowsHide: true, timeout: 30000 });

  const queryResult = runRegExe(["query", SERVICE_ENVIRONMENT_REGISTRY_KEY, "/v", "Environment"]);
  if (!queryResult || (queryResult.error && queryResult.error.code === "ENOENT")) {
    return { attempted: true, cleared: false, reason: "reg.exe is not available on this host" };
  }
  if (queryResult.status !== 0) {
    // No such key/value: this process is not running as the installed
    // Windows service (a manual/dev run, or the service predates this
    // registry value), so there is no registry copy of the token to clear.
    return {
      attempted: true,
      cleared: false,
      reason: "no service Environment registry value is present",
    };
  }
  if (!/TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=/.test(String(queryResult.stdout || ""))) {
    return { attempted: true, cleared: false, reason: "registry value already has no token" };
  }

  const addResult = runRegExe([
    "add",
    SERVICE_ENVIRONMENT_REGISTRY_KEY,
    "/v",
    "Environment",
    "/t",
    "REG_MULTI_SZ",
    "/d",
    `TOKENTIMER_AGENT_CONFIG_DIR=${configDir}`,
    "/f",
  ]);
  if (!addResult || addResult.status !== 0) {
    return {
      attempted: true,
      cleared: false,
      reason: `reg.exe add exited ${addResult ? addResult.status : "(no result)"}`,
    };
  }
  return { attempted: true, cleared: true };
}

module.exports = {
  ADMINISTRATORS_SID,
  SYSTEM_SID,
  applyRestrictivePermissions,
  applyWindowsAcl,
  assertRestrictivePermissions,
  assertTrustedOwner,
  assertWindowsAcl,
  clearWindowsServiceBootstrapToken,
  currentUserSid,
  isWindows,
  parseDaclSddl,
  readWindowsOwnerSid,
  readWindowsSddl,
  resetPlatformCaches,
};
