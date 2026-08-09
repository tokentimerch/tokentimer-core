"use strict";

/**
 * Windows machine certificate store and http.sys binding discovery
 * (ADR-0012). Observe-only inventory, the Windows-host analogue of
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
 * Status: the text parsers below have been real-host verified against a
 * live certutil.exe/netsh.exe on Windows Server, exercising a populated
 * machine store and real http.sys SNI bindings, with one exception noted
 * where it applies: Subject Alternative Name parsing (added after that
 * verification pass, to close a real gap against this module's documented
 * contract) has only been exercised against hand-authored fixtures, not a
 * captured real `certutil -store -v` transcript.
 *
 * `site` is deliberately always null. Unlike thumbprint/subject/expiry,
 * an IIS site name has no representation in `certutil`'s or `netsh http`'s
 * output: http.sys bindings are keyed by IP:port or hostname:port, never by
 * IIS site, matching ../windows-iis's own documented stance that `site` is
 * caller-supplied evidence/addressing metadata, not something `netsh http`
 * itself understands. Resolving a real site name would require a separate
 * IIS-configuration query (e.g. `appcmd list site`) this module does not
 * perform; the field exists on every record so callers can rely on its
 * presence, but it is honestly null rather than guessed or omitted.
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
 * subjectAlternativeNames is read from the "Subject Alternative Name"
 * extension section that `-v` (verbose) adds to certutil's output. Real
 * certutil transcripts vary between one `Name=value` entry per line and a
 * single comma-separated line, so both forms are matched by one regex
 * scoped to just that section (bounded by the next blank line or the next
 * `NN.NN.NN.NN:` OID-prefixed extension heading, whichever comes first) so
 * a later, unrelated extension's own "Name=" style fields are never
 * accidentally swept in.
 *
 * @param {string} block
 * @returns {{
 *   thumbprint: string|null,
 *   subject: string|null,
 *   issuer: string|null,
 *   notBefore: string|null,
 *   notAfter: string|null,
 *   serialNumber: string|null,
 *   subjectAlternativeNames: string[],
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
    subjectAlternativeNames: parseSubjectAlternativeNames(block),
    hasPrivateKey: Boolean(containerMatch || providerMatch),
    keyContainer: containerMatch ? containerMatch[1].trim() : null,
    keyProvider: providerMatch ? providerMatch[1].trim() : null,
  };
}

/**
 * Extracts DNS/IP subject-alternative-name entries from a certutil `-v`
 * extension dump. Returns `[]` (not null) when the section is absent --
 * either because the certificate has no SAN extension, or because
 * `-v` was not used -- so callers never have to null-check before
 * iterating.
 *
 * @param {string} block
 * @returns {string[]}
 */
function parseSubjectAlternativeNames(block) {
  const headingMatch = /Subject Alternative Name[^\r\n]*\r?\n/i.exec(block);
  if (!headingMatch) return [];

  const sectionStart = headingMatch.index + headingMatch[0].length;
  const rest = block.slice(sectionStart);
  const sectionEndMatch = /\r?\n\s*\r?\n|\r?\n\S/.exec(rest);
  const section = sectionEndMatch ? rest.slice(0, sectionEndMatch.index) : rest;

  const names = [];
  const namePattern = /(?:DNS Name|IP Address)\s*=\s*([^\r\n,]+)/gi;
  let match;
  while ((match = namePattern.exec(section)) !== null) {
    const value = match[1].trim();
    if (value) names.push(value);
  }
  return names;
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
 * Runs one `certutil -store <store>` invocation (verbose or not) and
 * classifies the result. Factored out of listMachineStoreCertificates so
 * that function can retry without `-v` on a genuine verbose-mode failure
 * (see its own doc comment) without duplicating the exit-code
 * classification logic.
 *
 * @param {object} input
 * @param {string} input.store
 * @param {Function} input.execFileImpl
 * @param {string} input.certutilPath
 * @param {number} input.timeoutMs
 * @param {boolean} input.verbose
 * @returns {Promise<
 *   | { ok: true, certificates: ReturnType<typeof parseCertutilStoreBlock>[] }
 *   | { ok: false, exitCode: number|null, stderrExcerpt: string }
 * >}
 */
async function runCertutilStoreQuery({ store, execFileImpl, certutilPath, timeoutMs, verbose }) {
  // -v (verbose) is what gets certutil to dump extensions, including
  // Subject Alternative Name; without it the per-certificate block only
  // ever carries the fields already present before this flag was added.
  const argv = verbose
    ? [certutilPath, "-store", store, "-v"]
    : [certutilPath, "-store", store];
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

  const certificates = splitCertutilStoreBlocks(stdoutText).map((block) => ({
    ...parseCertutilStoreBlock(block),
    store,
  }));
  return { ok: true, certificates };
}

/**
 * Runs `certutil -store <store>` and returns every certificate entry found,
 * each annotated with hasPrivateKey (read from certutil's own report, never
 * from touching the key itself). A nonzero exit (e.g. an empty/nonexistent
 * store) is not an error: it is reported as `ok: true, certificates: []`,
 * matching queryCurrentBinding's "nothing there yet is not a failure"
 * posture in ../windows-iis.
 *
 * Falls back to a non-verbose query on a genuine verbose-mode failure: a
 * 2026-08-08 real-host finding (two independent Windows Server 2022 VMs,
 * different SKUs/images) showed `certutil -store <name> -v` can fail
 * outright with NTE_NOT_FOUND -- on every store, every certificate, even a
 * certificate created seconds earlier -- while the exact same store queried
 * WITHOUT `-v` succeeds and returns every field except the Subject
 * Alternative Name extension (which only `-v` prints). Treating that as a
 * total STORE_QUERY_FAILED would silently drop this host's entire Windows
 * discovery, not just its SAN data. The caller-side adapter
 * (../discovery/windows.js) independently recovers SANs from each
 * certificate's own raw bytes -- which it already fetches for SHA-256
 * fingerprint completion -- so no discovery capability is actually lost
 * even on a host hitting this bug; falling back here only avoids losing
 * subject/issuer/dates/serial/thumbprint/key-presence too.
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

  const verboseResult = await runCertutilStoreQuery({ store, execFileImpl, certutilPath, timeoutMs, verbose: true });
  if (verboseResult.ok) return verboseResult;

  const plainResult = await runCertutilStoreQuery({ store, execFileImpl, certutilPath, timeoutMs, verbose: false });
  if (plainResult.ok) return plainResult;

  // Both the verbose and the non-verbose query failed: report the
  // verbose attempt's failure, since it is the one this function's
  // contract (and its argv-shape test) documents as the primary call.
  return verboseResult;
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
 * Parses `appcmd list site` output into one record per IIS site, with its
 * binding list decoded into structured `{ protocol, address, port,
 * hostHeader }` entries. Best-effort only: this is auxiliary evidence used
 * to resolve a binding's `site` name, not part of this module's core
 * certutil/netsh contract, so a caller must never treat a parse miss on
 * one line as reason to fail the whole call -- unrecognized `SITE` lines
 * are silently skipped rather than thrown.
 *
 * Real `appcmd list site` line shape:
 *   SITE "Default Web Site" (id:1,bindings:http/*:80:,https/*:443:www.example.com,state:Started)
 *
 * @param {string} stdout
 * @returns {{ name: string, id: string, state: string, bindings: { protocol: string, address: string, port: string, hostHeader: string }[] }[]}
 */
function parseAppcmdSiteListOutput(stdout) {
  const sitePattern = /^SITE\s+"([^"]+)"\s+\(id:(\d+),bindings:(.*?),state:([^)]*)\)\s*$/gim;
  const sites = [];
  let match;
  while ((match = sitePattern.exec(stdout)) !== null) {
    const [, name, id, bindingsField, state] = match;
    const bindings = bindingsField
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry) => {
        const bindingMatch = /^([A-Za-z]+)\/([^:]*):(\d+):(.*)$/.exec(entry);
        if (!bindingMatch) return null;
        const [, protocol, address, port, hostHeader] = bindingMatch;
        return { protocol, address, port, hostHeader };
      })
      .filter((binding) => binding !== null);
    sites.push({ name, id, state: state.trim(), bindings });
  }
  return sites;
}

/**
 * Runs `appcmd list site` and returns the parsed site/binding list. Unlike
 * listMachineStoreCertificates/listHttpSysBindings, a failure here (missing
 * appcmd, IIS management tools not installed, access denied) is reported as
 * `ok: true, sites: []` rather than `ok: false`: site-name resolution is
 * supplementary evidence layered on top of the real http.sys binding facts,
 * and a host running plain http.sys without the IIS management console
 * feature installed is a normal configuration, not an error condition.
 *
 * Not yet real-host verified: unit-tested against a hand-authored fixture
 * modeled on the documented `appcmd list site` line format, not a captured
 * transcript from a real IIS host.
 *
 * @param {object} input
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.appcmdPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true, sites: ReturnType<typeof parseAppcmdSiteListOutput> }>}
 */
async function listIisSites({
  execFileImpl = childProcess.execFile,
  appcmdPath = `${process.env.SystemRoot || "C:\\Windows"}\\System32\\inetsrv\\appcmd.exe`,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  assertSafeArgvElements("appcmdPath", [appcmdPath]);
  const argv = [appcmdPath, "list", "site"];
  assertSafeArgvElements("argv", argv);

  const { exitCode, stdout } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  const stdoutText = typeof stdout === "string" ? stdout : String(stdout ?? "");
  if (exitCode !== 0) {
    return { ok: true, sites: [] };
  }
  return { ok: true, sites: parseAppcmdSiteListOutput(stdoutText) };
}

/**
 * Resolves the IIS site name(s) whose bindings match a given http.sys
 * binding, by port plus either host header (hostname-keyed / SNI bindings)
 * or address (IP-keyed bindings restricted to sites with no host header,
 * since an IP-keyed cert binding carries no SNI signal to disambiguate
 * between sites sharing a wildcard address). Returns `[]` when no site's
 * bindings match, which is a normal outcome (e.g. a binding created
 * directly via `netsh` with no matching IIS site), not a parse failure.
 *
 * @param {ReturnType<typeof parseAppcmdSiteListOutput>} sites
 * @param {{ ipPort: string|null, keyedBy: "ipport"|"hostnameport" }} binding
 * @returns {string[]}
 */
function findSitesForBinding(sites, binding) {
  if (!binding.ipPort) return [];
  const lastColon = binding.ipPort.lastIndexOf(":");
  if (lastColon === -1) return [];
  const addressOrHost = binding.ipPort.slice(0, lastColon);
  const port = binding.ipPort.slice(lastColon + 1);

  const matches = [];
  for (const site of sites) {
    const matched = site.bindings.some((siteBinding) => {
      if (siteBinding.port !== port) return false;
      if (binding.keyedBy === "hostnameport") {
        return siteBinding.hostHeader.toLowerCase() === addressOrHost.toLowerCase();
      }
      if (siteBinding.hostHeader) return false;
      return (
        siteBinding.address === "*" ||
        siteBinding.address === addressOrHost ||
        addressOrHost === "0.0.0.0"
      );
    });
    if (matched) matches.push(site.name);
  }
  return matches;
}

/**
 * Combines the machine store and http.sys binding enumerations into one
 * inventory: each certificate found in the store, cross-referenced with
 * every binding that currently references its thumbprint, and (best-effort)
 * every IIS site name whose own binding matches that same address/port.
 * Mirrors the shape of the filesystem discovery module's per-certificate
 * result objects (subject/issuer/validity/serial/hasPrivateKey-style
 * fields) so a caller feeding both discovery sources into one
 * evidence/inventory report does not have to reconcile two unrelated
 * shapes.
 *
 * Partial failure: if either the store or the binding sub-enumeration
 * fails outright (ok: false), that failure is surfaced directly rather
 * than silently treated as "nothing found" (an operator needs to know the
 * difference between "the store is empty" and "we could not ask the store
 * at all"). Site-name resolution is intentionally exempt from this
 * strictness: `listIisSites` never returns `ok: false` (see its own doc
 * comment), so `boundSites` is simply `[]` on a host with no IIS
 * management tools installed, which is a normal outcome, not a failure.
 *
 * @param {object} input
 * @param {string} input.store
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath]
 * @param {string} [input.netshPath]
 * @param {string} [input.appcmdPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, certificates: (ReturnType<typeof parseCertutilStoreBlock> & { boundAt: string[], boundSites: string[] })[] }
 *   | { ok: false, code: "STORE_QUERY_FAILED"|"BINDING_QUERY_FAILED", detail: string }
 * >}
 */
async function discoverWindowsCertificateInventory({
  store,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  netshPath = "netsh.exe",
  appcmdPath,
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

  const sitesResult = await listIisSites(
    appcmdPath ? { execFileImpl, appcmdPath, timeoutMs } : { execFileImpl, timeoutMs },
  );

  const bindingsByThumbprint = new Map();
  const sitesByThumbprint = new Map();
  for (const binding of bindingsResult.bindings) {
    if (!binding.thumbprint || !binding.ipPort) continue;
    const existingBindings = bindingsByThumbprint.get(binding.thumbprint) || [];
    existingBindings.push(binding.ipPort);
    bindingsByThumbprint.set(binding.thumbprint, existingBindings);

    const matchedSites = findSitesForBinding(sitesResult.sites, binding);
    if (matchedSites.length > 0) {
      const existingSites = sitesByThumbprint.get(binding.thumbprint) || new Set();
      matchedSites.forEach((siteName) => existingSites.add(siteName));
      sitesByThumbprint.set(binding.thumbprint, existingSites);
    }
  }

  const certificates = storeResult.certificates.map((cert) => ({
    ...cert,
    boundAt: cert.thumbprint ? bindingsByThumbprint.get(cert.thumbprint) || [] : [],
    boundSites: cert.thumbprint ? Array.from(sitesByThumbprint.get(cert.thumbprint) || []) : [],
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
  parseSubjectAlternativeNames,
  parseNetshSslcertBindings,
  parseAppcmdSiteListOutput,
  findSitesForBinding,
  listMachineStoreCertificates,
  listHttpSysBindings,
  listIisSites,
  discoverWindowsCertificateInventory,
};

