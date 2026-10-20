"use strict";

// Where the runtime credential lives on disk, and how it gets there safely.
//
// The credential is a long-lived secret, so the file is created exclusively
// (never overwriting something unexpected), readable only by the current user,
// and written through a temporary file so a crash cannot leave a half-written
// credential. On POSIX that is mode 0600 inside a 0700 directory. On Windows
// the inherited permissions are removed and only the current user is granted
// access; if that cannot be done, the file is deleted and the write fails,
// rather than leaving a credential others might read.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const childProcess = require("node:child_process");

class CredentialStoreError extends Error {
  constructor(message) {
    super(message);
    this.name = "CredentialStoreError";
  }
}

function defaultCredentialPath({ env = process.env, platform = process.platform, home = os.homedir() } = {}) {
  if (platform === "win32") {
    const base = env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(base, "TokenTimer", "mcp", "credential");
  }
  const base = env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(base, "tokentimer", "mcp", "credential");
}

function windowsAccount(env) {
  const user = env.USERNAME || os.userInfo().username;
  if (!user || /["\r\n:()]/.test(user)) {
    throw new CredentialStoreError("The current user name cannot be used to restrict file access");
  }
  const domain = env.USERDOMAIN || "";
  return domain && !/["\r\n:()]/.test(domain) ? `${domain}\\${user}` : user;
}

function restrictToCurrentUserWindows(file, { env, execFileSync }) {
  // execFile, not a shell: nothing here is ever interpreted as a command line.
  execFileSync("icacls", [file, "/inheritance:r", "/grant:r", `${windowsAccount(env)}:(R,W)`], {
    stdio: "ignore",
    windowsHide: true,
  });
}

function ensureDirectory(directory, platform) {
  fs.mkdirSync(directory, { recursive: true, mode: platform === "win32" ? undefined : 0o700 });
}

// Reports whether a credential could be written here, without writing anything.
// Setup runs this before spending a one-time code, so a path problem cannot burn it.
function checkDestination(file, { replace = false } = {}) {
  const resolved = path.resolve(file);
  let existing = null;
  try {
    existing = fs.lstatSync(resolved);
  } catch (error) {
    // A path below a regular file is ENOTDIR on POSIX and ENOENT on Windows;
    // both mean the same thing here.
    if (error.code === "ENOTDIR") throw new CredentialStoreError("The credential location is not a directory");
    if (error.code !== "ENOENT") throw new CredentialStoreError("The credential file could not be inspected");
  }
  if (existing) {
    if (existing.isSymbolicLink()) {
      throw new CredentialStoreError("The credential path is a symbolic link; refusing to write through it");
    }
    if (!replace) {
      throw new CredentialStoreError("A credential file already exists here; use --replace to overwrite it");
    }
  }
  // Walk up to the nearest directory that exists and make sure it is writable.
  let directory = path.dirname(resolved);
  for (let depth = 0; depth < 64; depth += 1) {
    try {
      const stat = fs.statSync(directory);
      if (!stat.isDirectory()) throw new CredentialStoreError("The credential location is not a directory");
      fs.accessSync(directory, fs.constants.W_OK);
      return resolved;
    } catch (error) {
      if (error instanceof CredentialStoreError) throw error;
      if (error.code !== "ENOENT") throw new CredentialStoreError("The credential location is not writable");
      const parent = path.dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
  // No ancestor directory exists at all (a bad root), so nothing can be created.
  throw new CredentialStoreError("The credential location is not writable");
}

// A stored credential is bound to the server that issued it. The binding sits
// in the file beside the secret, so the two cannot be separated or half-written.
//
//   ttopc_...                       the credential
//   api=https://tokentimer.example  the server it was issued by (optional)
//
// A file with no binding line (a hand-made one, a mounted secret) still works
// when given explicitly, but is never picked up automatically.
const BINDING_LINE = /^api=(\S+)$/;

function formatCredentialFile(secret, binding) {
  return binding ? `${secret}\napi=${binding}\n` : `${secret}\n`;
}

function parseCredentialFile(text) {
  const lines = String(text).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0 || lines.length > 2) return { credential: "", binding: null, valid: false };
  const credential = lines[0];
  if (lines.length === 1) return { credential, binding: null, valid: true };
  const match = BINDING_LINE.exec(lines[1]);
  return match ? { credential, binding: match[1], valid: true } : { credential, binding: null, valid: false };
}

// Writes the credential and returns the path. Refuses to replace an existing
// file unless asked to, so running setup twice cannot silently discard a
// working credential.
function writeCredential(
  file,
  secret,
  { replace = false, binding = null, platform = process.platform, env = process.env, execFileSync = childProcess.execFileSync } = {},
) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new CredentialStoreError("There is no credential to store");
  }
  if (binding !== null && !/^\S+$/.test(String(binding))) {
    throw new CredentialStoreError("The server address to bind the credential to is not valid");
  }
  const resolved = checkDestination(file, { replace });
  ensureDirectory(path.dirname(resolved), platform);

  const temporary = `${resolved}.${process.pid}.${Date.now()}.tmp`;
  let created = false;
  try {
    // "wx" fails if the name exists, so a pre-placed file or link is never followed.
    fs.closeSync(fs.openSync(temporary, "wx", 0o600));
    created = true;
    // Access is restricted while the file is still empty, so the secret never
    // exists under inherited permissions. (POSIX mode 0600 applied at creation.)
    if (platform === "win32") restrictToCurrentUserWindows(temporary, { env, execFileSync });
    const fd = fs.openSync(temporary, "r+");
    try {
      fs.writeSync(fd, formatCredentialFile(secret, binding));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temporary, resolved);
    created = false;
  } catch (error) {
    if (created) {
      try {
        fs.rmSync(temporary, { force: true });
      } catch (_ignored) {
        /* best effort */
      }
    }
    if (error instanceof CredentialStoreError) throw error;
    // Never include the path or the underlying message: either could be sensitive.
    throw new CredentialStoreError("The credential file could not be written safely");
  }
  return resolved;
}

// Refuses a credential file that other users could read. Windows access is
// controlled by ACLs that Node cannot inspect, so it is not checked there.
function assertPrivateFile(file, { platform = process.platform } = {}) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (_error) {
    throw new CredentialStoreError("The credential file could not be read");
  }
  if (stat.isSymbolicLink()) {
    throw new CredentialStoreError("The credential file is a symbolic link");
  }
  if (platform !== "win32" && (stat.mode & 0o077) !== 0) {
    throw new CredentialStoreError(
      "The credential file is readable by other users; run chmod 600 on it",
    );
  }
}

module.exports = {
  CredentialStoreError,
  assertPrivateFile,
  checkDestination,
  defaultCredentialPath,
  formatCredentialFile,
  parseCredentialFile,
  restrictToCurrentUserWindows,
  windowsAccount,
  writeCredential,
};
