"use strict";

/**
 * Windows machine certificate store and http.sys binding discovery
 * (ADR-0012, Wave 2b). Observe-only inventory, the Windows-host analogue of
 * the existing filesystem discovery module (../discovery): reports what
 * certificates exist in a Windows machine certificate store and what
 * http.sys bindings reference them, without ever exporting, reading, or
 * returning private key bytes.
 *
 * Key-presence without export: a machine-store certificate's "has a private
 * key" fact is read from `certutil -store`'s own text report (the presence
 * of a `Key Container =` / `Provider =` line for that certificate's block),
 * never by attempting to export, unlock, or otherwise touch the key
 * material itself. This mirrors the filesystem discovery module's own
 * "detect key presence without reading content" contract, adapted to the
 * CNG/machine-store world where there is no file to peek at in the first
 * place: the key never leaves the store, so there is nothing this module
 * could read even if it wanted to.
 *
 * Implementation choice, not contract: `certutil -store` and
 * `netsh http show sslcert` are this module's CURRENT way of asking
 * Windows these two questions (matching the sibling ../windows-cert-store
 * and ../windows-iis modules' own "netsh is an implementation detail, not
 * the contract" stance). Both tools emit fixed-format human-readable text
 * with no JSON/CSV mode, so this module parses that text; a future move to
 * a structured API (CertEnumCertificatesInStore via a native binding,
 * IIS's own WebAdministration binding enumeration) would change the
 * parsing internals without changing this module's return shapes.
 *
 * Module style follows the sibling modules: CommonJS, node builtins only,
 * self-contained plain-data functions, exec via child_process.execFile
 * WITHOUT a shell, every dynamic argv element re-validated against a
 * shell-metacharacter pattern as defense in depth.
 *
 * Status: the text parsers below are written against certutil/netsh's
 * documented and previously-observed output format, but have NOT yet been
 * run against a real certutil.exe/netsh.exe on a real Windows host with
 * real store contents. That real-host verification is tracked separately
 * (see the Wave 2b todo list) and this module must not be advertised as
 * verified until it completes.
 */

const childProcess = require("node:child_process");

/** Mirrors the sibling modules' shell-metacharacter pattern. */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

const DEFAULT_TIMEOUT_MS = 30 * 1000;
const OUTPUT_EXCERPT_MAX_CHARS = 1024;
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

/** Windows machine certificate store name. Mirrors the sibling modules'
 * STORE_NAME_PATTERN copies. */
const STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;
const THUMBPRINT_PATTERN = /^[0-9A-Fa-f]{40}$/;

function buildError(message, code) {
  const error = new Error(`tokentimer-agent windows-discovery: ${message}`);
  if (code) error.code = code;
  return error;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

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

function assertSafeArgvElements(label, argv) {
  argv.forEach((element, index) => {
    if (!isNonEmptyString(element)) {
      throw buildError(
        `${label}[${index}] must be a non-empty string (got ${typeof element})`,
      );
    }
    if (SHELL_METACHARACTER_PATTERN.test(element)) {
      throw buildError(
        `${label}[${index}] contains a disallowed shell metacharacter: ${JSON.stringify(element)}`,
      );
    }
  });
}

/**
 * Promise wrapper around an execFile-shaped implementation. Mirrors the
 * sibling modules' execWithoutShell exactly.
 * @param {Function} execFileImpl
 * @param {string[]} argv
 * @param {number} timeoutMs
 * @returns {Promise<{exitCode: number|null, stdout: unknown, stderr: unknown}>}
 */
function execWithoutShell(execFileImpl, argv, timeoutMs) {
  const [file, ...args] = argv;
  return new Promise((resolve) => {
    execFileImpl(
      file,
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          const exitCode = typeof error.code === "number" ? error.code : null;
          resolve({ exitCode, stdout, stderr });
          return;
        }
        resolve({ exitCode: 0, stdout, stderr });
      },
    );
  });
}

/**
 * Splits `certutil -store` output into one text block per certificate
 * entry. certutil delimits each entry with a
 * "================ Certificate N ================" banner line; the text
 * before the first banner (a store-name header line) is discarded.
 * @param {string} stdout
 * @returns {string[]}
 */
function splitCertutilStoreBlocks(stdout) {
  const bannerPattern = /^={2,}\s*Certificate\s+\d+\s*={2,}\s*$/m;
  if (!bannerPattern.test(stdout)) return [];
  return stdout
    .split(/^={2,}\s*Certificate\s+\d+\s*={2,}\s*$/m)
    .slice(1)
    .map((block) => block.trim())
    .filter((block) => block.length > 0);
}

/**
 * Parses one certutil certificate block into a plain-data record. Never
 * throws on a partially-recognizable block: fields it cannot find are
 * simply null, since a warning-and-skip posture (matching the filesystem
 * discovery module's onWarning convention) is more useful to an operator
 * than aborting the entire store enumeration over one malformed entry.
 *
 * hasPrivateKey is read from the presence of a "Key Container ="
 * (CNG-native) or "Provider =" line -- never by attempting to access the
 * key itself.
 *
 * @param {string} block
 * @returns {{
 *   thumbprint: string|null,
 *   subject: string|null,
 *   issuer: string|null,
 *   notBefore: string|null,
 *   notAfter: string|null,
 *   serialNumber: string|null,
 *   hasPrivateKey: boolean,
 *   keyContainer: string|null,
 *   keyProvider: string|null,
 * }}
 */
function parseCertutilStoreBlock(block) {
  const thumbprintMatch = /Cert Hash\(sha1\)\s*:\s*([0-9A-Fa-f ]{40,})/i.exec(block);
  const thumbprint = thumbprintMatch
    ? thumbprintMatch[1].replace(/\s+/g, "").toUpperCase()
    : null;

  const subjectMatch = /^Subject:\s*(.+)$/m.exec(block);
  const issuerMatch = /^Issuer:\s*(.+)$/m.exec(block);
  const notBeforeMatch = /^\s*NotBefore:\s*(.+)$/m.exec(block);
  const notAfterMatch = /^\s*NotAfter:\s*(.+)$/m.exec(block);
  const serialMatch = /^Serial Number:\s*(.+)$/m.exec(block);
  const containerMatch = /^\s*Key Container\s*=\s*(.+)$/m.exec(block);
  const providerMatch = /^\s*Provider\s*=\s*(.+)$/m.exec(block);

  return {
    thumbprint,
    subject: subjectMatch ? subjectMatch[1].trim() : null,
    issuer: issuerMatch ? issuerMatch[1].trim() : null,
    notBefore: notBeforeMatch ? notBeforeMatch[1].trim() : null,
    notAfter: notAfterMatch ? notAfterMatch[1].trim() : null,
    serialNumber: serialMatch ? serialMatch[1].trim() : null,
    hasPrivateKey: Boolean(containerMatch || providerMatch),
    keyContainer: containerMatch ? containerMatch[1].trim() : null,
    keyProvider: providerMatch ? providerMatch[1].trim() : null,
  };
}

/**
 * Parses `netsh http show sslcert` output (no ipport filter: the full
 * binding list) into one record per binding. Each binding block in
 * netsh's output is separated by a blank line and keyed by EITHER an
 * "IP:port" line (address-keyed bindings) OR a "Hostname:port" line
 * (SNI-keyed bindings, added via `hostnameport=` -- see ../windows-iis's
 * formatBindingSelector). Both forms must be recognized: a real-host run
 * (2026-08-05) against a genuine SNI binding created by ../windows-iis
 * found the original version of this function silently dropped every
 * hostname-keyed block, because its filter only matched "IP:port :". That
 * is a real discovery gap, not cosmetic: any host using an SNI binding
 * would have that certificate's binding invisibly missing from both
 * `listHttpSysBindings` and the cross-referenced inventory's `boundAt`,
 * with no error raised anywhere.
 *
 * The returned `ipPort` field is populated for BOTH forms (kept under
 * this name for backward compatibility with existing callers, since
 * discoverWindowsCertificateInventory's cross-reference keys on this
 * field regardless of which selector netsh used to create the binding);
 * `keyedBy` distinguishes which selector form the real binding actually
 * used, for callers that need to reconstruct the original ipport= vs
 * hostnameport= selector (e.g. to delete or rebind it later).
 *
 * @param {string} stdout
 * @returns {{ ipPort: string|null, keyedBy: "ipport"|"hostnameport", thumbprint: string|null, storeName: string|null, appId: string|null }[]}
 */
function parseNetshSslcertBindings(stdout) {
  const blocks = stdout
    .split(/\r?\n\r?\n/)
    .map((block) => block.trim())
    .filter((block) => /^\s*(IP:port|Hostname:port)\s*:/im.test(block));

  return blocks.map((block) => {
    const ipPortMatch = /^\s*IP:port\s*:\s*(\S+)/im.exec(block);
    const hostnamePortMatch = /^\s*Hostname:port\s*:\s*(\S+)/im.exec(block);
    const thumbprintMatch = /Certificate Hash\s*:\s*([0-9A-Fa-f]{40})/i.exec(block);
    const storeMatch = /Certificate Store Name\s*:\s*(.+)/i.exec(block);
    const appIdMatch = /Application ID\s*:\s*(\{[0-9a-fA-F-]+\})/i.exec(block);
    return {
      ipPort: ipPortMatch ? ipPortMatch[1].trim() : hostnamePortMatch ? hostnamePortMatch[1].trim() : null,
      keyedBy: hostnamePortMatch ? "hostnameport" : "ipport",
      thumbprint: thumbprintMatch ? thumbprintMatch[1].toUpperCase() : null,
      storeName: storeMatch ? storeMatch[1].trim() : null,
      appId: appIdMatch ? appIdMatch[1] : null,
    };
  });
}

/**
 * Runs `certutil -store <store>` and returns every certificate entry found,
 * each annotated with hasPrivateKey (read from certutil's own report, never
 * from touching the key itself). A nonzero exit (e.g. an empty/nonexistent
 * store) is not an error: it is reported as `ok: true, certificates: []`,
 * matching queryCurrentBinding's "nothing there yet is not a failure"
 * posture in ../windows-iis.
 *
 * @param {object} input
 * @param {string} input.store Windows certificate store name (e.g. "My").
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, certificates: ReturnType<typeof parseCertutilStoreBlock>[] }
 *   | { ok: false, exitCode: number|null, stderrExcerpt: string }
 * >}
 */
async function listMachineStoreCertificates({
  store,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(store) || !STORE_NAME_PATTERN.test(store)) {
    throw buildError(`store must be a valid Windows certificate store name (got ${JSON.stringify(store)})`);
  }
  assertSafeArgvElements("certutilPath", [certutilPath]);
  const argv = [certutilPath, "-store", store];
  assertSafeArgvElements("argv", argv);

  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  const stdoutText = typeof stdout === "string" ? stdout : String(stdout ?? "");

  if (exitCode !== 0) {
    // An empty or nonexistent store is certutil's normal "nothing here"
    // outcome for this command, not a real failure; anything else is.
    if (/cannot find|does not exist|no certificates/i.test(stdoutText) ||
        /cannot find|does not exist|no certificates/i.test(String(stderr ?? ""))) {
      return { ok: true, certificates: [] };
    }
    return {
      ok: false,
      exitCode,
      stderrExcerpt: boundAndRedactExcerpt(stderr || stdout),
    };
  }

  const certificates = splitCertutilStoreBlocks(stdoutText).map(parseCertutilStoreBlock);
  return { ok: true, certificates };
}

/**
 * Runs `netsh http show sslcert` (no ipport filter) and returns every
 * binding on the host. A nonzero exit meaning "no bindings configured at
 * all" is reported as `ok: true, bindings: []`, same posture as
 * listMachineStoreCertificates above.
 *
 * @param {object} input
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.netshPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, bindings: ReturnType<typeof parseNetshSslcertBindings> }
 *   | { ok: false, exitCode: number|null, stderrExcerpt: string }
 * >}
 */
async function listHttpSysBindings({
  execFileImpl = childProcess.execFile,
  netshPath = "netsh.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  assertSafeArgvElements("netshPath", [netshPath]);
  const argv = [netshPath, "http", "show", "sslcert"];
  assertSafeArgvElements("argv", argv);

  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  const stdoutText = typeof stdout === "string" ? stdout : String(stdout ?? "");

  if (exitCode !== 0) {
    if (/cannot find|no ssl certificate/i.test(stdoutText) || /cannot find|no ssl certificate/i.test(String(stderr ?? ""))) {
      return { ok: true, bindings: [] };
    }
    return {
      ok: false,
      exitCode,
      stderrExcerpt: boundAndRedactExcerpt(stderr || stdout),
    };
  }

  return { ok: true, bindings: parseNetshSslcertBindings(stdoutText) };
}

/**
 * Combines the machine store and http.sys binding enumerations into one
 * inventory: each certificate found in the store, cross-referenced with
 * every binding that currently references its thumbprint. Mirrors the
 * shape of the filesystem discovery module's per-certificate result
 * objects (subject/issuer/validity/serial/hasPrivateKey-style fields) so a
 * caller feeding both discovery sources into one evidence/inventory report
 * does not have to reconcile two unrelated shapes.
 *
 * Partial failure: if either sub-enumeration fails outright (ok: false),
 * that failure is surfaced directly rather than silently treated as
 * "nothing found" (an operator needs to know the difference between
 * "the store is empty" and "we could not ask the store at all").
 *
 * @param {object} input
 * @param {string} input.store
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath]
 * @param {string} [input.netshPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, certificates: (ReturnType<typeof parseCertutilStoreBlock> & { boundAt: string[] })[] }
 *   | { ok: false, code: "STORE_QUERY_FAILED"|"BINDING_QUERY_FAILED", detail: string }
 * >}
 */
async function discoverWindowsCertificateInventory({
  store,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  netshPath = "netsh.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const storeResult = await listMachineStoreCertificates({ store, execFileImpl, certutilPath, timeoutMs });
  if (!storeResult.ok) {
    return {
      ok: false,
      code: "STORE_QUERY_FAILED",
      detail: `certutil -store ${store} failed: ${storeResult.stderrExcerpt}`,
    };
  }

  const bindingsResult = await listHttpSysBindings({ execFileImpl, netshPath, timeoutMs });
  if (!bindingsResult.ok) {
    return {
      ok: false,
      code: "BINDING_QUERY_FAILED",
      detail: `netsh http show sslcert failed: ${bindingsResult.stderrExcerpt}`,
    };
  }

  const bindingsByThumbprint = new Map();
  for (const binding of bindingsResult.bindings) {
    if (!binding.thumbprint || !binding.ipPort) continue;
    const existing = bindingsByThumbprint.get(binding.thumbprint) || [];
    existing.push(binding.ipPort);
    bindingsByThumbprint.set(binding.thumbprint, existing);
  }

  const certificates = storeResult.certificates.map((cert) => ({
    ...cert,
    boundAt: cert.thumbprint ? bindingsByThumbprint.get(cert.thumbprint) || [] : [],
  }));

  return { ok: true, certificates };
}

module.exports = {
  SHELL_METACHARACTER_PATTERN,
  STORE_NAME_PATTERN,
  THUMBPRINT_PATTERN,
  DEFAULT_TIMEOUT_MS,
  OUTPUT_EXCERPT_MAX_CHARS,
  boundAndRedactExcerpt,
  assertSafeArgvElements,
  execWithoutShell,
  splitCertutilStoreBlocks,
  parseCertutilStoreBlock,
  parseNetshSslcertBindings,
  listMachineStoreCertificates,
  listHttpSysBindings,
  discoverWindowsCertificateInventory,
};

