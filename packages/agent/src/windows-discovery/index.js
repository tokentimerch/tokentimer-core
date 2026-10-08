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
 * key" fact is its own `HasPrivateKey` property, never read by attempting
 * to export, unlock, or otherwise touch the key material itself. This
 * mirrors the filesystem discovery module's own "detect key presence
 * without reading content" contract, adapted to the CNG/machine-store
 * world where there is no file to peek at in the first place: the key
 * never leaves the store, so there is nothing this module could read even
 * if it wanted to.
 *
 * Implementation choice, not contract: certificate fields come from
 * PowerShell's Cert: provider as JSON, and only the key container and
 * provider names come from `certutil -store`, matched by thumbprint and by
 * line structure rather than by its labels. certutil's labels, banners and
 * dates follow the host's display language, so nothing here reads them.
 * `netsh http show sslcert` is still parsed as English text. A future move
 * to a structured API would change these internals without changing this
 * module's return shapes.
 *
 * Module style follows the sibling modules: CommonJS, node builtins only,
 * self-contained plain-data functions, exec via child_process.execFile
 * WITHOUT a shell, every dynamic argv element re-validated against a
 * shell-metacharacter pattern as defense in depth.
 *
 * Status: the store query and key-container parsing are real-host verified
 * on Windows Server 2019 and 2022 (en-US) and 2025 (de-DE); the netsh
 * parser on English hosts only, including real http.sys SNI bindings.
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
const { X509Certificate } = require("node:crypto");

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
 * sibling modules' execWithoutShell, plus optional extra execFile options.
 * @param {Function} execFileImpl
 * @param {string[]} argv
 * @param {number} timeoutMs
 * @param {object} [extraOptions]
 * @returns {Promise<{exitCode: number|null, stdout: unknown, stderr: unknown}>}
 */
function execWithoutShell(execFileImpl, argv, timeoutMs, extraOptions = {}) {
  const [file, ...args] = argv;
  return new Promise((resolve) => {
    execFileImpl(
      file,
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 10 * 1024 * 1024, ...extraOptions },
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
 * PowerShell that lists one LocalMachine store through the Cert: provider,
 * so no field depends on the host's display language. It only reads
 * properties, casts and calls ConvertTo-Json, which all work under
 * Constrained Language Mode. Subject and issuer travel as UTF-16 code units
 * because stdout uses the OEM code page, which that mode cannot change.
 *
 * @param {string} store validated against STORE_NAME_PATTERN, so it is
 *   inert inside a single-quoted PowerShell string.
 * @returns {string}
 */
function buildStoreQueryScript(store) {
  return [
    "$ErrorActionPreference = 'Stop'",
    `$path = 'Cert:\\LocalMachine\\${store}'`,
    "$items = @()",
    "if (Test-Path -LiteralPath $path) {",
    "  $items = @(Get-ChildItem -LiteralPath $path | ForEach-Object {",
    "    @{",
    "      thumbprint = $_.Thumbprint",
    "      subject = [int[]][char[]]$_.Subject",
    "      issuer = [int[]][char[]]$_.Issuer",
    "      notBefore = $_.NotBefore",
    "      notAfter = $_.NotAfter",
    "      serialNumber = $_.SerialNumber",
    "      hasPrivateKey = $_.HasPrivateKey",
    "      rawData = [int[]]$_.RawData",
    "    }",
    "  })",
    "}",
    "ConvertTo-Json -InputObject @{ items = $items } -Compress -Depth 4",
  ].join("\n");
}

// An inherited PowerShell 7 PSModulePath can stop Windows PowerShell from
// loading the module that provides the Cert: drive.
function buildPowerShellEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === "psmodulepath") delete env[key];
  }
  return env;
}

function decodeCodeUnits(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  if (!value.every((unit) => Number.isInteger(unit) && unit >= 0 && unit <= 0xffff)) return null;
  return String.fromCharCode(...value);
}

// Windows PowerShell 5.1 serializes DateTime as "/Date(<epoch ms>)/".
function parsePowerShellDate(value) {
  if (typeof value !== "string") return null;
  const epochMatch = /^\/Date\((-?\d+)\)\/$/.exec(value);
  const time = epochMatch ? Number(epochMatch[1]) : Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

// Same form certutil printed (lowercase, no DER sign byte), so inventory
// already reported for a certificate keeps its serial number.
function normalizeSerialNumber(value) {
  if (typeof value !== "string" || !/^[0-9A-Fa-f]+$/.test(value)) return null;
  let serial = value.toLowerCase();
  while (serial.length > 2 && serial.startsWith("00")) serial = serial.slice(2);
  return serial;
}

/**
 * Parses Node's `X509Certificate#subjectAltName` string (e.g.
 * `"DNS:example.com, DNS:www.example.com, IP Address:10.0.0.5"`) into bare
 * values. Commas inside JSON-quoted values are not entry separators.
 *
 * @param {string|undefined} subjectAltName
 * @returns {string[]}
 */
function parseNodeSubjectAltName(subjectAltName) {
  if (typeof subjectAltName !== "string" || !subjectAltName) return [];
  const entries = [];
  let start = 0;
  let inQuotedValue = false;
  let escaped = false;
  for (let index = 0; index <= subjectAltName.length; index += 1) {
    const char = subjectAltName[index];
    if (inQuotedValue) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        inQuotedValue = false;
      }
    } else if (char === '"') {
      inQuotedValue = true;
    }
    if (index === subjectAltName.length || (char === "," && !inQuotedValue)) {
      entries.push(subjectAltName.slice(start, index).trim());
      start = index + 1;
    }
  }

  const values = [];
  for (const entry of entries) {
    const match = /^(?:DNS|IP Address|URI|email)\s*:\s*(.+)$/i.exec(entry);
    if (!match) continue;
    let value = match[1].trim();
    if (value.startsWith('"')) {
      try {
        const decoded = JSON.parse(value);
        if (typeof decoded !== "string") continue;
        value = decoded;
      } catch (_error) {
        continue;
      }
    }
    if (value) values.push(value);
  }
  return values;
}

function readSubjectAltNames(der) {
  try {
    return parseNodeSubjectAltName(new X509Certificate(der).subjectAltName);
  } catch (_error) {
    return [];
  }
}

/**
 * Parses buildStoreQueryScript's JSON into certificate records. Entries
 * without a valid thumbprint are dropped.
 *
 * @param {string} stdout
 * @returns {{
 *   thumbprint: string,
 *   subject: string|null,
 *   issuer: string|null,
 *   notBefore: string|null,
 *   notAfter: string|null,
 *   serialNumber: string|null,
 *   subjectAlternativeNames: string[],
 *   hasPrivateKey: boolean,
 * }[]}
 * @throws when stdout is not the expected JSON.
 */
function parseStoreQueryOutput(stdout) {
  const parsed = JSON.parse(stdout);
  if (parsed === null || typeof parsed !== "object" || !("items" in parsed)) {
    throw new Error("store query output has no items field");
  }
  const items = Array.isArray(parsed.items) ? parsed.items : parsed.items === null ? [] : [parsed.items];
  return items.flatMap((item) => {
    const thumbprint = typeof item?.thumbprint === "string" ? item.thumbprint.toUpperCase() : "";
    if (!THUMBPRINT_PATTERN.test(thumbprint)) return [];
    const rawData = Array.isArray(item.rawData) ? item.rawData : null;
    return [
      {
        thumbprint,
        subject: decodeCodeUnits(item.subject),
        issuer: decodeCodeUnits(item.issuer),
        notBefore: parsePowerShellDate(item.notBefore),
        notAfter: parsePowerShellDate(item.notAfter),
        serialNumber: normalizeSerialNumber(item.serialNumber),
        subjectAlternativeNames: rawData ? readSubjectAltNames(Buffer.from(rawData)) : [],
        hasPrivateKey: item.hasPrivateKey === true,
      },
    ];
  });
}

// "================ Certificate 0 ================"; only the word is
// localized ("Zertifikat", "Certificat").
const CERTUTIL_BANNER_PATTERN = /^={2,}[^=\r\n]*\d[^=\r\n]*={2,}[ \t]*$/m;

/**
 * Splits `certutil -store` output into one text block per certificate
 * entry; the text before the first banner (a store-name header) is
 * discarded.
 * @param {string} stdout
 * @returns {string[]}
 */
function splitCertutilStoreBlocks(stdout) {
  if (!CERTUTIL_BANNER_PATTERN.test(stdout)) return [];
  return stdout
    .split(CERTUTIL_BANNER_PATTERN)
    .slice(1)
    .map((block) => block.trim())
    .filter((block) => block.length > 0);
}

/**
 * Reads each certificate's key container and provider from `certutil
 * -store` output without its localized labels. In every display language
 * the SHA-1 hash is the last value on its line, and the indented
 * "<label> = <value>" lines right after it are the key container, then
 * the provider. Blocks are matched to `thumbprints` by that hash. Labels
 * may arrive mangled by the console code page, which does not matter here.
 *
 * @param {string} stdout
 * @param {Set<string>} thumbprints uppercase thumbprints to look for.
 * @returns {Map<string, { keyContainer: string|null, keyProvider: string|null }>}
 */
function parseCertutilKeyInfo(stdout, thumbprints) {
  const keyInfo = new Map();
  for (const block of splitCertutilStoreBlocks(stdout)) {
    const lines = block.split(/\r?\n/);
    let thumbprint = null;
    const hashIndex = lines.findIndex((line) => {
      const match = /(?:^|[^0-9A-Fa-f])((?:[0-9A-Fa-f]{2} ?){19}[0-9A-Fa-f]{2})\s*$/.exec(line);
      const candidate = match ? match[1].replace(/ /g, "").toUpperCase() : null;
      if (candidate === null || !thumbprints.has(candidate)) return false;
      thumbprint = candidate;
      return true;
    });
    if (hashIndex === -1) continue;

    // The label may end in a non-breaking space (French) and the "unique
    // container name" line in between uses a colon, not "=".
    const values = [];
    for (const line of lines.slice(hashIndex + 1)) {
      if (!/^[ \t]/.test(line)) break;
      const match = /^[ \t]+[^=:\s][^=:]*=(.*)$/.exec(line);
      if (match) values.push(match[1].trim() || null);
    }
    // A lone recognized line could be either one; report neither.
    keyInfo.set(
      thumbprint,
      values.length >= 2
        ? { keyContainer: values[0], keyProvider: values[1] }
        : { keyContainer: null, keyProvider: null },
    );
  }
  return keyInfo;
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
 * Lists every certificate in one LocalMachine store, each annotated with
 * hasPrivateKey and, for keyed certificates, the key container and
 * provider. A store that does not exist is reported as
 * `ok: true, certificates: []`.
 *
 * Fails closed: the orphan-container sweep and the retention gates treat a
 * container that no certificate claims as free to delete, so a keyed
 * certificate whose container cannot be read fails the whole query rather
 * than coming back with a null keyContainer.
 *
 * @param {object} input
 * @param {string} input.store Windows certificate store name (e.g. "My").
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.certutilPath]
 * @param {string} [input.powershellPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, certificates: (ReturnType<typeof parseStoreQueryOutput>[number] & {
 *       keyContainer: string|null, keyProvider: string|null, store: string })[] }
 *   | { ok: false, exitCode: number|null, stderrExcerpt: string }
 * >}
 */
async function listMachineStoreCertificates({
  store,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  powershellPath = "powershell.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!isNonEmptyString(store) || !STORE_NAME_PATTERN.test(store) || /^\.+$/.test(store)) {
    throw buildError(`store must be a valid Windows certificate store name (got ${JSON.stringify(store)})`);
  }
  assertSafeArgvElements("certutilPath", [certutilPath]);
  assertSafeArgvElements("powershellPath", [powershellPath]);

  // The script carries PowerShell syntax by design; the store name is its
  // only variable part and is validated above.
  const powershellArgv = [powershellPath, "-NoProfile", "-NonInteractive", "-Command"];
  assertSafeArgvElements("argv", powershellArgv);
  const query = await execWithoutShell(
    execFileImpl,
    [...powershellArgv, buildStoreQueryScript(store)],
    timeoutMs,
    { env: buildPowerShellEnv() },
  );
  if (query.exitCode !== 0) {
    return { ok: false, exitCode: query.exitCode, stderrExcerpt: boundAndRedactExcerpt(query.stderr || query.stdout) };
  }
  let certificates;
  try {
    certificates = parseStoreQueryOutput(typeof query.stdout === "string" ? query.stdout : String(query.stdout ?? ""));
  } catch (error) {
    return { ok: false, exitCode: null, stderrExcerpt: boundAndRedactExcerpt(`unreadable store query output: ${error.message}`) };
  }

  const keyed = certificates.filter((certificate) => certificate.hasPrivateKey);
  let keyInfo = new Map();
  if (keyed.length > 0) {
    const argv = [certutilPath, "-store", store];
    assertSafeArgvElements("argv", argv);
    const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);
    if (exitCode !== 0) {
      return { ok: false, exitCode, stderrExcerpt: boundAndRedactExcerpt(stderr || stdout) };
    }
    keyInfo = parseCertutilKeyInfo(
      typeof stdout === "string" ? stdout : String(stdout ?? ""),
      new Set(keyed.map((certificate) => certificate.thumbprint)),
    );
    const unresolved = keyed.find((certificate) => !keyInfo.get(certificate.thumbprint)?.keyContainer);
    if (unresolved) {
      return {
        ok: false,
        exitCode: null,
        stderrExcerpt: `certutil -store ${store} reported no key container for ${unresolved.thumbprint}`,
      };
    }
  }

  return {
    ok: true,
    certificates: certificates.map((certificate) => ({
      ...certificate,
      keyContainer: keyInfo.get(certificate.thumbprint)?.keyContainer ?? null,
      keyProvider: keyInfo.get(certificate.thumbprint)?.keyProvider ?? null,
      store,
    })),
  };
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
 * @param {string} [input.powershellPath]
 * @param {string} [input.netshPath]
 * @param {string} [input.appcmdPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, certificates: (Extract<Awaited<ReturnType<typeof listMachineStoreCertificates>>, { ok: true }>["certificates"][number] & { boundAt: string[], boundSites: string[] })[] }
 *   | { ok: false, code: "STORE_QUERY_FAILED"|"BINDING_QUERY_FAILED", detail: string }
 * >}
 */
async function discoverWindowsCertificateInventory({
  store,
  execFileImpl = childProcess.execFile,
  certutilPath = "certutil.exe",
  powershellPath = "powershell.exe",
  netshPath = "netsh.exe",
  appcmdPath,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const storeResult = await listMachineStoreCertificates({ store, execFileImpl, certutilPath, powershellPath, timeoutMs });
  if (!storeResult.ok) {
    return {
      ok: false,
      code: "STORE_QUERY_FAILED",
      detail: `store query for ${store} failed: ${storeResult.stderrExcerpt}`,
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
  buildStoreQueryScript,
  parseStoreQueryOutput,
  parseNodeSubjectAltName,
  splitCertutilStoreBlocks,
  parseCertutilKeyInfo,
  parseNetshSslcertBindings,
  parseAppcmdSiteListOutput,
  findSitesForBinding,
  listMachineStoreCertificates,
  listHttpSysBindings,
  listIisSites,
  discoverWindowsCertificateInventory,
};
