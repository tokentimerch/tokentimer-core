"use strict";

/**
 * IIS binding deploy executor (ADR-0012 decisions 13 and 9).
 *
 * Deploy is: import the certificate into the machine store (handled by the
 * sibling ../windows-cert-store module for CNG-native enrollment, or by a
 * PFX-import fallback landing separately), record the outgoing thumbprint
 * currently bound, rebind via `netsh http add sslcert` (replacing any
 * existing binding at that IP:port), verify by a REAL TLS handshake against
 * the binding's own local address/port (never a DNS-resolved name), and roll
 * back to the recorded outgoing thumbprint on any verification failure.
 *
 * Binding contract (decision 13, restated so it stays enforceable in code,
 * not only in prose): `(site, port, optional SNI host, store name)` keyed on
 * certificate thumbprint. `netsh http` is this module's IMPLEMENTATION
 * choice, not the contract; nothing outside this file may assume `netsh`
 * specifically, so a later switch to `IISAdministration`/`WebAdministration`
 * is not a breaking change. `site` is carried for evidence/addressing
 * purposes (which IIS site a binding belongs to) but `netsh http` itself
 * binds at the http.sys (IP:port[:hostname]) level, not through IIS's own
 * object model; this module talks to http.sys directly, matching decision
 * 13's explicit "no iisreset, a binding change is picked up by http.sys with
 * no restart at all".
 *
 * Non-SNI/specific-IP/SNI binding scope (clarified 2026-08-06, PR review --
 * see deployIisBinding's own doc comment for the full explanation): a
 * binding with `sniHost` set scopes by HOSTNAME across every IP http.sys
 * listens on at that port; `binding.address` in that case only picks the
 * real interface this module's own post-bind verification handshake
 * dials, it does NOT restrict which IP the SNI binding applies to. A
 * binding WITHOUT `sniHost` scopes by the literal `(address, port)` pair
 * (or by "every IP" for the three wildcard address forms) and, per
 * http.sys's own documented precedence rule, always wins over any SNI
 * binding on the same port for a client connecting to that address --
 * deployIisBinding surfaces this as a non-fatal `precedenceWarning` when
 * it detects the shape most likely to trip an operator up (deploying an
 * SNI binding while a wildcard non-SNI binding already exists on the same
 * port).
 *
 * Verification reuses ../verify's verifyDeployedCertificate (fingerprint
 * pinning over a real TLS handshake, rejectUnauthorized: false is correct
 * there for the same reason it is correct here: this is byte-identity
 * pinning, not chain-of-trust). This module supplies the loopback-probe
 * addressing decision 13 requires for wildcard bindings and never connects
 * to a DNS-resolved name.
 *
 * Zero-custody preserving: this module never receives, generates, or
 * returns private key material. It operates purely on thumbprints (public
 * identifiers) and PEM certificate bytes for the parts of the flow that
 * need them (writing a plain sibling .cer copy for evidence-friendly re-
 * verification is NOT done here; only thumbprint strings cross this
 * boundary). Every returned value is passed through the shared
 * private-key-material detector as a last-resort guard, mirroring the
 * sibling windows-cert-store and keys modules.
 *
 * Module style follows the sibling acme/keys/windows-cert-store modules:
 * CommonJS, node builtins only, self-contained plain-data functions, exec
 * via child_process.execFile WITHOUT a shell, every dynamic argv element
 * re-validated against a shell-metacharacter pattern as defense in depth.
 *
 * Status: real-host verified end to end against genuine IIS sites and real
 * http.sys bindings on Windows Server 2019, 2022, and 2025 (see
 * docs/certops/agent.md's platform matrix and the real-host verification
 * runbook), including real rebind, rollback-on-failure, and SNI-precision
 * scenarios. `iis-binding-v1` is advertised accordingly in
 * ../capabilities/qualified-capabilities.json; see that module's own doc
 * comment for the build-time gate mechanism that ties advertisement to
 * this evidence.
 */

const childProcess = require("node:child_process");
const crypto = require("node:crypto");

const {
  assertNoPrivateKeyMaterial,
} = require("../../vendor/log-scrub/secret-material.js");
const { verifyDeployedCertificate, computeCertificateFingerprint } = require("../verify/index.js");
const { computeSha1ThumbprintFromPem } = require("../windows-cert-store/index.js");

/** Mirrors the sibling modules' shell-metacharacter pattern. */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

const DEFAULT_TIMEOUT_MS = 30 * 1000;
const OUTPUT_EXCERPT_MAX_CHARS = 1024;
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

/** Default handshake verification budget after a rebind. */
const DEFAULT_VERIFY_TIMEOUT_MS = 10 * 1000;

/** SHA-1 hex thumbprint: 40 hex chars, case-insensitive on input, normalized
 * to uppercase on output (the Windows store/netsh convention). Mirrors
 * deploy/index.js's WINDOWS_THUMBPRINT_PATTERN (duplicated per this
 * package's self-contained-module convention). */
const THUMBPRINT_PATTERN = /^[0-9A-Fa-f]{40}$/;

/** IIS site identifier: name or numeric id. Mirrors deploy/index.js's
 * WINDOWS_IIS_SITE_PATTERN. */
const SITE_PATTERN = /^[A-Za-z0-9 _.:-]{1,256}$/;

/** Windows machine certificate store name. Mirrors deploy/index.js's
 * WINDOWS_STORE_NAME_PATTERN and windows-cert-store's copy of the same. */
const STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;

/** RFC 1123-ish hostname for the optional SNI host on a binding. */
const SNI_HOST_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** The three wildcard address forms decision 13 names explicitly. Each maps
 * to its own defined loopback probe address, never a DNS-resolved name. */
const WILDCARD_BINDING_ADDRESSES = Object.freeze({
  "*": "127.0.0.1",
  "0.0.0.0": "127.0.0.1",
  "[::]": "::1",
});

function buildError(message, code) {
  const error = new Error(`tokentimer-agent windows-iis: ${message}`);
  if (code) error.code = code;
  return error;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function guardReturnValue(value) {
  for (const item of Object.values(value)) {
    assertNoPrivateKeyMaterial(item);
  }
  return value;
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

function normalizeThumbprint(value) {
  if (!isNonEmptyString(value) || !THUMBPRINT_PATTERN.test(value)) {
    throw buildError(
      `thumbprint must be a 40-hex-char SHA-1 string (got ${JSON.stringify(value)})`,
    );
  }
  return value.toUpperCase();
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

/**
 * Validates the typed binding descriptor shared by every function below.
 * Mirrors deploy/index.js's validateWindowsIisTarget field-level rules so
 * the two do not silently diverge on what a binding may look like.
 *
 * @param {object} binding
 * @param {string} binding.address IP literal, or one of the three wildcard
 *   forms in WILDCARD_BINDING_ADDRESSES ("*", "0.0.0.0", "[::]").
 * @param {number} binding.port 1-65535.
 * @param {string} [binding.sniHost] optional SNI hostname.
 * @param {string} binding.store Windows certificate store name.
 * @param {string} binding.site IIS site name or numeric id (evidence/
 *   addressing only; see module header).
 * @returns {void} throws on any violation.
 */
function assertValidBinding(binding) {
  if (binding === null || typeof binding !== "object") {
    throw buildError("binding must be an object");
  }
  if (!isNonEmptyString(binding.address)) {
    throw buildError("binding.address must be a non-empty string");
  }
  if (
    !Object.prototype.hasOwnProperty.call(WILDCARD_BINDING_ADDRESSES, binding.address) &&
    !/^[0-9.:a-fA-F\[\]]+$/.test(binding.address)
  ) {
    throw buildError(
      `binding.address must be an IP literal or one of ${Object.keys(WILDCARD_BINDING_ADDRESSES).join(", ")} (got ${JSON.stringify(binding.address)})`,
    );
  }
  if (!Number.isInteger(binding.port) || binding.port < 1 || binding.port > 65535) {
    throw buildError(
      `binding.port must be an integer in [1, 65535] (got ${JSON.stringify(binding.port)})`,
    );
  }
  if (binding.sniHost !== undefined && binding.sniHost !== null) {
    if (!isNonEmptyString(binding.sniHost) || !SNI_HOST_PATTERN.test(binding.sniHost)) {
      throw buildError(
        `binding.sniHost must be a valid hostname when provided (got ${JSON.stringify(binding.sniHost)})`,
      );
    }
  }
  if (!isNonEmptyString(binding.store) || !STORE_NAME_PATTERN.test(binding.store)) {
    throw buildError(
      `binding.store must be a valid Windows certificate store name (got ${JSON.stringify(binding.store)})`,
    );
  }
  if (!isNonEmptyString(binding.site) || !SITE_PATTERN.test(binding.site)) {
    throw buildError(
      `binding.site must be a valid IIS site name or id (got ${JSON.stringify(binding.site)})`,
    );
  }
}

/**
 * Resolves the real TCP address+SNI decision 13's verification handshake
 * must use for a given binding: the binding's own address when it is a
 * concrete IP, or the defined loopback probe when it is one of the three
 * wildcard forms. Never returns a DNS name.
 * @param {{ address: string, sniHost?: string }} binding
 * @returns {{ host: string, servername: string|undefined }}
 */
function resolveVerificationTarget(binding) {
  const loopback = WILDCARD_BINDING_ADDRESSES[binding.address];
  const host = loopback !== undefined ? loopback : stripIpv6Brackets(binding.address);
  return { host, servername: binding.sniHost || undefined };
}

/** @param {string} address @returns {string} */
function stripIpv6Brackets(address) {
  const match = /^\[(.+)\]$/.exec(address);
  return match ? match[1] : address;
}

/**
 * Formats the netsh http binding-selector argument for one binding.
 *
 * When `binding.sniHost` is set, the correct http.sys selector is
 * `hostnameport=<sniHost>:<port>` -- SNI-based dispatch in http.sys is a
 * property of a HOSTNAME-keyed binding, not an attribute layered onto an
 * IP-keyed one. `sslctlidentifier` (this module's original approach for
 * the sniHost case) is unrelated: it names a certificate TRUST LIST for
 * verifying CLIENT certificates, not a mechanism for server-side SNI
 * selection, confirmed by `netsh http add sslcert help`'s own parameter
 * description ("List the certificate issuers that can be trusted") during
 * a real-host run (2026-08-05) that surfaced this as a genuine binding-key
 * defect: the sslctlidentifier-based "SNI" bind was silently a no-op SNI
 * mechanism, masked in unit tests because they only assert on the argv
 * this module ITSELF constructs, not on http.sys's real interpretation of
 * it.
 *
 * Without an sniHost, the selector stays `ipport=<address>:<port>`,
 * unchanged from before.
 *
 * @param {{ address: string, port: number, sniHost?: string }} binding
 * @returns {string} e.g. "ipport=0.0.0.0:8443" or
 *   "hostnameport=example.com:8443"
 */
function formatBindingSelector(binding) {
  if (binding.sniHost) {
    return `hostnameport=${binding.sniHost}:${binding.port}`;
  }
  return `ipport=${formatIpPort(binding)}`;
}

/**
 * Formats the `ipport=` value netsh http expects: IPv6 literals keep their
 * brackets, IPv4/wildcard forms do not. Used directly only for the
 * non-SNI case; see formatBindingSelector for the selector netsh actually
 * receives.
 * @param {{ address: string, port: number }} binding
 * @returns {string}
 */
function formatIpPort(binding) {
  return `${binding.address}:${binding.port}`;
}

/**
 * Generates a fresh appid GUID for `netsh http add sslcert`, which requires
 * one but does not attach any real meaning to it for this module's
 * purposes (it is netsh's own bookkeeping key, conventionally the owning
 * application's GUID; this agent has no natural GUID identity registered
 * anywhere else, so a fresh random one is generated per call rather than
 * hardcoding a single constant that would misleadingly suggest shared
 * ownership across unrelated installs).
 * @returns {string}
 */
function generateAppId() {
  return `{${crypto.randomUUID()}}`;
}

/**
 * Promise wrapper around an execFile-shaped implementation. Mirrors the
 * sibling acme/windows-cert-store modules' execWithoutShell exactly.
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
 * Queries the certificate currently bound at a given binding selector via
 * `netsh http show sslcert ipport=<addr:port>` (or `hostnameport=<host:port>`
 * when the binding carries an sniHost -- see formatBindingSelector),
 * parsing the human-readable output for the `Certificate Hash` line.
 * Returns null (not an error) when nothing is bound there yet, which is
 * the normal state for a first-ever deploy: decision 13's
 * rollback-to-outgoing-thumbprint step is a no-op in that case, not a
 * failure.
 *
 * Parses netsh's fixed-format key/value output rather than any structured
 * format, because `netsh http show sslcert` has no JSON/CSV output mode.
 * This is exactly the kind of implementation detail decision 13 says must
 * stay swappable: a future move to a structured API removes this parser
 * without changing this function's return contract.
 *
 * @param {object} input
 * @param {{ address: string, port: number, sniHost?: string }} input.binding
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.netshPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true, thumbprint: string|null } | { ok: false, exitCode: number|null, stderrExcerpt: string }>}
 */
async function queryCurrentBinding({
  binding,
  execFileImpl = childProcess.execFile,
  netshPath = "netsh.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  assertSafeArgvElements("netshPath", [netshPath]);
  const argv = [
    netshPath,
    "http",
    "show",
    "sslcert",
    formatBindingSelector(binding),
  ];
  assertSafeArgvElements("argv", argv);

  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, argv, timeoutMs);

  // netsh exits nonzero when nothing is bound at this selector ("The
  // system cannot find the file specified" is its real message for this
  // case, for both the ipport and hostnameport forms); that is the normal
  // "nothing bound yet" state, not an error.
  const stdoutText = typeof stdout === "string" ? stdout : String(stdout ?? "");
  if (exitCode !== 0) {
    if (/cannot find/i.test(stdoutText) || /cannot find/i.test(String(stderr ?? ""))) {
      return { ok: true, thumbprint: null };
    }
    return {
      ok: false,
      exitCode,
      stderrExcerpt: boundAndRedactExcerpt(stderr || stdout),
    };
  }

  const match = /Certificate Hash\s*:\s*([0-9A-Fa-f]{40})/.exec(stdoutText);
  return {
    ok: true,
    thumbprint: match ? match[1].toUpperCase() : null,
    parameters: parseSslcertParameters(stdoutText),
  };
}

/**
 * Parses the non-thumbprint parameters an operator may have configured on
 * an existing binding out of `netsh http show sslcert`'s human-readable
 * output: revocation checking, CTL-based issuer restriction, DS mapper
 * usage, and client-certificate negotiation. `bindCertificate`'s
 * delete-then-add rebind (decision 13) would otherwise silently reset
 * every one of these to netsh's own default on every renewal, since `add
 * sslcert` only ever sees the flags a given call explicitly passes it --
 * found during PR review as a real gap, not yet exercised on the E2E VM
 * (which never customizes these on its throwaway binding).
 *
 * Only fields this function can positively read back are included in the
 * returned object; a label it does not find is simply omitted, never
 * defaulted to true/false/0 by guesswork. formatPreservedParamArgs then
 * only ever emits a flag for a key that is actually present, so an
 * unparsed field falls back to netsh's own default exactly as it did
 * before this fix -- strictly no worse, not a new failure mode.
 *
 * These eight are the parameters `netsh http add sslcert help` has
 * accepted since Windows Server 2012 (excluding certhash/appid/
 * certstorename, which the caller always sets explicitly to the new
 * certificate's own identity, never preserved from the outgoing one).
 * Newer per-Windows-version add sslcert options (rejectconnections,
 * disablehttp2, disablequic, disableocspstapling, enabletokenbinding) are
 * intentionally not covered: they simply fall through to netsh's default
 * on every rebind, unchanged from this module's behavior before this fix.
 *
 * @param {string} stdoutText raw `netsh http show sslcert` stdout.
 * @returns {{
 *   verifyClientCertRevocation?: boolean,
 *   verifyRevocationWithCachedClientCertOnly?: boolean,
 *   usageCheck?: boolean,
 *   revocationFreshnessTime?: number,
 *   urlRetrievalTimeout?: number,
 *   ctlIdentifier?: string|null,
 *   ctlStoreName?: string|null,
 *   dsMapperUsage?: boolean,
 *   negotiateClientCert?: boolean,
 * }}
 */
function parseSslcertParameters(stdoutText) {
  const readEnabledDisabled = (label) => {
    const found = new RegExp(`${label}\\s*:\\s*(Enabled|Disabled)`, "i").exec(stdoutText);
    return found ? found[1].toLowerCase() === "enabled" : undefined;
  };
  const readInteger = (label) => {
    const found = new RegExp(`${label}\\s*:\\s*(\\d+)`, "i").exec(stdoutText);
    return found ? Number(found[1]) : undefined;
  };
  const readNullableString = (label) => {
    const found = new RegExp(`${label}\\s*:\\s*(.+)`, "i").exec(stdoutText);
    if (!found) return undefined;
    const value = found[1].trim();
    return value === "" || value === "(null)" ? null : value;
  };

  const params = {};
  const assign = (key, value) => {
    if (value !== undefined) params[key] = value;
  };

  assign("verifyClientCertRevocation", readEnabledDisabled("Verify Client Certificate Revocation"));
  assign(
    "verifyRevocationWithCachedClientCertOnly",
    readEnabledDisabled("Verify Revocation Using Cached Client Certificate Only"),
  );
  assign("usageCheck", readEnabledDisabled("Usage Check"));
  assign("revocationFreshnessTime", readInteger("Revocation Freshness Time"));
  assign("urlRetrievalTimeout", readInteger("URL Retrieval Timeout"));
  assign("ctlIdentifier", readNullableString("Ctl Identifier"));
  assign("ctlStoreName", readNullableString("Ctl Store Name"));
  assign("dsMapperUsage", readEnabledDisabled("DS Mapper Usage"));
  assign("negotiateClientCert", readEnabledDisabled("Negotiate Client Certificate"));

  return params;
}

/**
 * Turns a parseSslcertParameters result back into the `netsh http add
 * sslcert` flags that reproduce it, so bindCertificate's rebind can pass
 * them alongside the new certhash/appid/certstorename and genuinely
 * preserve an operator's prior revocation/CTL/negotiation configuration
 * instead of silently resetting it to netsh's default on every renewal.
 * A key absent from `parameters` (never positively read back) contributes
 * no flag at all, which is exactly netsh's own default-on-omission
 * behavior -- the same as before this fix, for that one field.
 *
 * @param {ReturnType<typeof parseSslcertParameters>} parameters
 * @returns {string[]} zero or more `name=value` netsh argv elements.
 */
function formatPreservedParamArgs(parameters = {}) {
  const flag = (value) => (value ? "enable" : "disable");
  const args = [];

  if (parameters.verifyClientCertRevocation !== undefined) {
    args.push(`verifyclientcertrevocation=${flag(parameters.verifyClientCertRevocation)}`);
  }
  if (parameters.verifyRevocationWithCachedClientCertOnly !== undefined) {
    args.push(
      `verifyrevocationwithcachedclientcertonly=${flag(parameters.verifyRevocationWithCachedClientCertOnly)}`,
    );
  }
  if (parameters.usageCheck !== undefined) {
    args.push(`usagecheck=${flag(parameters.usageCheck)}`);
  }
  if (parameters.revocationFreshnessTime !== undefined) {
    args.push(`revocationfreshnesstime=${parameters.revocationFreshnessTime}`);
  }
  if (parameters.urlRetrievalTimeout !== undefined) {
    args.push(`urlretrievaltimeout=${parameters.urlRetrievalTimeout}`);
  }
  // A real, non-"(null)" ctlIdentifier is meaningless without its paired
  // store name and vice versa, so both are gated on ctlIdentifier alone
  // being present and non-null -- matching netsh's own pairing of the two
  // in `add sslcert help`.
  if (parameters.ctlIdentifier) {
    args.push(`sslctlidentifier=${parameters.ctlIdentifier}`);
    if (parameters.ctlStoreName) {
      args.push(`sslctlstorename=${parameters.ctlStoreName}`);
    }
  }
  if (parameters.dsMapperUsage !== undefined) {
    args.push(`dsmapperusage=${flag(parameters.dsMapperUsage)}`);
  }
  if (parameters.negotiateClientCert !== undefined) {
    args.push(`clientcertnegotiation=${flag(parameters.negotiateClientCert)}`);
  }
  return args;
}

/**
 * Binds (or rebinds) a certificate at a binding selector via netsh http.
 * Always deletes any existing binding at that exact selector first
 * (netsh's own `add sslcert` refuses to overwrite one in place with exit
 * code ERROR_ALREADY_EXISTS), then adds the new one — this delete-then-add
 * pair is the actual "rebind", and is what decision 13 means by "http.sys
 * picks up a binding change with no restart at all": the window between
 * delete and add is sub-second and does not require iisreset or any
 * IIS-level action, only http.sys's own binding table.
 *
 * SNI dispatch (2026-08-05 fix): when `binding.sniHost` is set, the
 * selector netsh receives is `hostnameport=<sniHost>:<port>`, NOT
 * `ipport=<address>:<port>` plus an `sslctlidentifier` flag -- see
 * formatBindingSelector's doc comment for why the original
 * sslctlidentifier-based approach was a real defect, not just cosmetic.
 *
 * `preserveParameters` (optional, from a prior queryCurrentBinding call
 * against this same selector) carries forward any revocation/CTL/
 * negotiation settings an operator configured on the OUTGOING binding via
 * formatPreservedParamArgs, so the delete-then-add pair does not silently
 * reset them to netsh's default on every renewal. Omitted entirely
 * (equivalent to `{}`) for a first-ever bind, where there is nothing to
 * preserve.
 *
 * @param {object} input
 * @param {{ address: string, port: number, sniHost?: string }} input.binding
 * @param {string} input.thumbprint 40-hex-char SHA-1, any case.
 * @param {string} input.store Windows certificate store name.
 * @param {ReturnType<typeof parseSslcertParameters>} [input.preserveParameters]
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.netshPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true } | { ok: false, exitCode: number|null, stderrExcerpt: string }>}
 */
async function bindCertificate({
  binding,
  thumbprint,
  store,
  preserveParameters = {},
  execFileImpl = childProcess.execFile,
  netshPath = "netsh.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const normalizedThumbprint = normalizeThumbprint(thumbprint);
  if (!isNonEmptyString(store) || !STORE_NAME_PATTERN.test(store)) {
    throw buildError(`store must be a valid Windows certificate store name (got ${JSON.stringify(store)})`);
  }
  assertSafeArgvElements("netshPath", [netshPath]);

  const selector = formatBindingSelector(binding);

  // Best-effort delete of whatever is there today; "nothing to delete" is
  // not a failure (first-ever bind at this selector), so its exit code is
  // never inspected. Deleting unconditionally rather than only when
  // queryCurrentBinding found something avoids a second, redundant query
  // call and a TOCTOU window between that query and this delete.
  await execWithoutShell(
    execFileImpl,
    [netshPath, "http", "delete", "sslcert", selector],
    timeoutMs,
  );

  const addArgs = [
    netshPath,
    "http",
    "add",
    "sslcert",
    selector,
    `certhash=${normalizedThumbprint}`,
    `appid=${generateAppId()}`,
    `certstorename=${store}`,
    ...formatPreservedParamArgs(preserveParameters),
  ];
  assertSafeArgvElements("argv", addArgs);

  const { exitCode, stdout, stderr } = await execWithoutShell(execFileImpl, addArgs, timeoutMs);
  if (exitCode !== 0) {
    return {
      ok: false,
      exitCode,
      stderrExcerpt: boundAndRedactExcerpt(stderr || stdout),
    };
  }
  return { ok: true };
}

/**
 * Attempts to restore `outgoingThumbprint` on `binding` via a real
 * `netsh http add sslcert` call, then independently re-queries the binding
 * to confirm it actually landed rather than trusting netsh's exit code
 * alone. Shared by both of deployIisBinding's rollback sites (VERIFY_FAILED
 * and BIND_FAILED below): `bindCertificate`'s delete-then-add discipline
 * means EITHER failure mode can leave the ipport genuinely unbound on a
 * real host, not just "still on the outgoing cert" -- an add failure runs
 * after the unconditional delete already succeeded, so the endpoint is
 * unbound at that point exactly as much as a post-bind verify failure
 * leaves it on the new (bad) cert. This was found by a real-host run
 * against a certificate whose key association had been broken (added
 * 2026-08-05): netsh's own add path validates key usability and rejects
 * such a certificate outright, which surfaced that the BIND_FAILED branch
 * had never attempted to restore the prior binding at all.
 *
 * @param {object} input
 * @param {{ address: string, port: number, sniHost?: string, store: string }} input.binding
 * @param {string} input.outgoingThumbprint non-null; caller checks null first.
 * @param {ReturnType<typeof parseSslcertParameters>} [input.preserveParameters]
 * @param {Function} input.execFileImpl
 * @param {string} input.netshPath
 * @param {number} input.timeoutMs
 * @returns {Promise<{ rolledBack: boolean, rollbackDetail?: string, rollbackVerifyDetail?: string }>}
 */
async function attemptRollback({
  binding,
  outgoingThumbprint,
  preserveParameters = {},
  execFileImpl,
  netshPath,
  timeoutMs,
}) {
  const rollbackResult = await bindCertificate({
    binding,
    thumbprint: outgoingThumbprint,
    store: binding.store,
    preserveParameters,
    execFileImpl,
    netshPath,
    timeoutMs,
  });

  if (!rollbackResult.ok) {
    return {
      rolledBack: false,
      rollbackDetail: `rollback bind also failed: ${rollbackResult.stderrExcerpt}`,
    };
  }

  const rollbackVerifyResult = await queryCurrentBinding({
    binding,
    execFileImpl,
    netshPath,
    timeoutMs,
  });
  const rollbackVerifyDetail =
    rollbackVerifyResult.ok && rollbackVerifyResult.thumbprint === outgoingThumbprint
      ? undefined
      : rollbackVerifyResult.ok
        ? `post-rollback query reports ${rollbackVerifyResult.thumbprint} instead of the expected outgoing thumbprint ${outgoingThumbprint}`
        : `post-rollback query failed: ${rollbackVerifyResult.stderrExcerpt}`;

  return {
    rolledBack: true,
    ...(rollbackVerifyDetail !== undefined ? { rollbackVerifyDetail } : {}),
  };
}

/**
 * Non-SNI (`ipport=`) bindings take precedence over SNI (`hostnameport=`)
 * bindings for any client connecting to an IP that also has its own
 * ipport binding on the same port -- confirmed http.sys/IIS platform
 * behavior (Microsoft's own SNI-scalability docs, corroborated by
 * multiple independent reports of exactly this precedence order), not
 * something either binding's own configuration can override. Concretely:
 * deploying binding.sniHost cleanly here does NOT guarantee it is what a
 * client actually receives, if a non-SNI binding also exists on the same
 * port for the address family the client connects over.
 *
 * This module cannot prevent that precedence rule (it is http.sys's, not
 * this module's), only detect when it may be silently shadowing the SNI
 * binding just deployed, and surface that as a non-fatal warning rather
 * than staying silent about a real, non-obvious gotcha. Checks the IPv4
 * (0.0.0.0) and IPv6 ([::]) wildcard forms, since either stack's wildcard
 * ipport binding shadows every hostnameport binding on that port for
 * clients on that stack -- the common real-world shape of this conflict
 * (an operator/IIS Manager created a default "no SNI" binding on the port
 * before, or alongside, this SNI one).
 *
 * A query failure here is swallowed (no warning returned): this check is
 * purely informational and must never fail an otherwise-successful SNI
 * deploy over an inability to positively confirm the absence of a
 * conflict.
 *
 * @param {object} input
 * @param {{ port: number, sniHost: string }} input.binding
 * @param {Function} input.execFileImpl
 * @param {string} input.netshPath
 * @param {number} input.timeoutMs
 * @returns {Promise<string|undefined>}
 */
async function checkSniPrecedenceConflict({ binding, execFileImpl, netshPath, timeoutMs }) {
  for (const wildcardAddress of ["0.0.0.0", "[::]"]) {
    let result;
    try {
      result = await queryCurrentBinding({
        binding: { address: wildcardAddress, port: binding.port },
        execFileImpl,
        netshPath,
        timeoutMs,
      });
    } catch {
      continue;
    }
    if (result.ok && result.thumbprint !== null) {
      return (
        `an existing non-SNI certificate binding at ipport=${wildcardAddress}:${binding.port} may take ` +
        `precedence over this SNI binding (hostnameport=${binding.sniHost}:${binding.port}) for clients ` +
        `connecting over that address family: http.sys evaluates ipport bindings before hostnameport ` +
        `bindings on the same port, regardless of the client's SNI value`
      );
    }
  }
  return undefined;
}

/**
 * Deploys a certificate onto an IIS/http.sys binding with the full
 * decision-13 discipline: record the outgoing thumbprint, rebind to the
 * new one, verify with a real TLS handshake against the binding's own
 * address (never a DNS-resolved name), and roll back to the outgoing
 * thumbprint if verification fails. The outgoing thumbprint is always
 * returned (even null, meaning "nothing was bound before") so the caller
 * can hand it to the retention ledger (decision 18) regardless of outcome.
 *
 * Non-SNI vs specific-IP vs SNI binding scope (clarified 2026-08-06, PR
 * review): the three binding shapes this module accepts scope
 * completely differently at the http.sys level, which is NOT obvious
 * from the binding descriptor's field names alone:
 *   - Non-SNI, wildcard address (no sniHost; address is "*"/"0.0.0.0"/
 *     "[::]"): binds EVERY IP at this port -- http.sys's "default
 *     certificate for this port" concept. This is what most single-site
 *     IIS installs use.
 *   - Non-SNI, specific IP (no sniHost; address is a concrete literal):
 *     binds ONLY that one IP at this port. A DIFFERENT certificate may be
 *     bound to a different specific IP, or to the wildcard, on the SAME
 *     port, without conflict.
 *   - SNI (sniHost set): binds by HOSTNAME at this port, ACROSS EVERY IP
 *     http.sys listens on at that port -- `binding.address` in this case
 *     is used ONLY to choose which real interface THIS FUNCTION's own
 *     post-bind verification handshake dials (decision 13's "verify
 *     against the binding's own real address, never a DNS name"); it
 *     does NOT scope which IP the SNI binding itself applies to. There
 *     is no netsh syntax this module uses that restricts a hostnameport
 *     binding to one IP.
 *   - Precedence gotcha (see checkSniPrecedenceConflict): a non-SNI
 *     binding on the same port takes precedence over ANY SNI binding on
 *     that port for a client connecting to that non-SNI binding's IP,
 *     REGARDLESS of the SNI value sent. Surfaced as `precedenceWarning`
 *     on a successful SNI deploy, never as a hard failure -- an operator
 *     may have deliberately configured this coexistence, and this module
 *     has no way to distinguish "deliberate" from "accidental" from here.
 *
 * certificatePem (not just a thumbprint) is required: verification is a
 * real TLS handshake compared against the certificate's sha256(DER)
 * fingerprint (../verify's fingerprint-pinning contract), which is a
 * different digest of different input than the SHA-1-of-DER thumbprint
 * netsh/the certificate store use, and deliberately not derivable from one
 * another. Passing only a thumbprint here would make it possible to
 * "verify" against the wrong certificate's sha256 by mistake; requiring
 * the PEM keeps bind-target and verify-target provably the same bytes.
 *
 * Locking: callers are expected to hold the sibling ../windows-cert-store
 * module's acquireStoreLock(stateDir, binding.store) for the duration of
 * this call (decision 13: "the per-target mutex covers the store as well
 * as the binding"). Not acquired here so a single lock covers this
 * function together with the CNG enrollment step that produced the
 * incoming thumbprint, without this module needing to know the caller's
 * state directory layout.
 *
 * @param {object} input
 * @param {{ address: string, port: number, sniHost?: string, store: string, site: string }} input.binding
 * @param {string} input.certificatePem the certificate to bind, PEM. Must
 *   already be present (imported) in binding.store — this function binds
 *   and verifies, it does not import (see ../windows-cert-store for CNG
 *   enrollment / a future PFX-import fallback for that step).
 * @param {Function} [input.execFileImpl] injection point for tests.
 * @param {string} [input.netshPath]
 * @param {number} [input.timeoutMs] budget for each netsh invocation.
 * @param {number} [input.verifyTimeoutMs] budget for the post-bind TLS
 *   handshake, default DEFAULT_VERIFY_TIMEOUT_MS.
 * @param {Function} [input.connectImpl] injection point forwarded to
 *   ../verify's verifyDeployedCertificate.
 * Idempotency: if the queried outgoing thumbprint already equals the
 * certificate being deployed, the delete-then-add mutation is skipped
 * entirely (added 2026-08-05, after a review pass against comparable
 * production Windows-target connectors in the wider ecosystem, which
 * short-circuit on an equivalent already-bound probe specifically to
 * avoid an unnecessary destructive cycle on a retried/duplicate-dispatched
 * job). Skipping the mutation still does NOT skip verification: a real
 * TLS handshake is performed regardless, so a store/http.sys desync
 * (thumbprint matches but the handshake does not) is still caught rather
 * than trusted blindly. This also keeps decision 13's "no outage reload"
 * property honest against a job retry, not only against a single first
 * run: an unconditional delete+add on every retry would open the same
 * brief unbound window decision 13 exists to avoid, on every duplicate
 * dispatch.
 *
 * Rollback verification: after a rollback bind, this function re-queries
 * the binding (added in the same 2026-08-05 pass, for the same reason)
 * rather than trusting netsh's own exit code alone. Disagreement is
 * carried in `rollbackVerifyDetail` as a non-fatal warning signal (the
 * rollback bind already reported success; this is corroborating evidence,
 * not a second failure mode), never thrown and never turned into a
 * different `code`.
 *
 * BIND_FAILED also attempts a rollback (added 2026-08-05, found via a real
 * VM run against a certificate whose key association was broken): the
 * delete-then-add pair inside bindCertificate runs an unconditional delete
 * BEFORE the add that can fail, so a failed add can leave the ipport
 * genuinely unbound, exactly the same "was mutated away from
 * outgoingThumbprint" state a post-bind VERIFY_FAILED leaves it in. Both
 * failure branches now share one attemptRollback helper for this reason.
 *
 * @returns {Promise<
 *   | { ok: true, outgoingThumbprint: string|null, boundThumbprint: string, verifiedAt: { host: string, port: number }, skippedMutation?: true, precedenceWarning?: string }
 *   | { ok: false, code: string, detail: string, outgoingThumbprint: string|null, rolledBack: boolean, rollbackDetail?: string, rollbackVerifyDetail?: string }
 * >}
 */
async function deployIisBinding({
  binding,
  certificatePem,
  execFileImpl = childProcess.execFile,
  netshPath = "netsh.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
  verifyTimeoutMs = DEFAULT_VERIFY_TIMEOUT_MS,
  connectImpl,
} = {}) {
  assertValidBinding(binding);
  if (!isNonEmptyString(certificatePem)) {
    throw buildError("certificatePem must be a non-empty PEM string");
  }

  const newThumbprint = computeSha1ThumbprintFromPem(certificatePem);
  const expectedFingerprintSha256 = computeCertificateFingerprint(certificatePem);

  const currentBindingResult = await queryCurrentBinding({
    binding,
    execFileImpl,
    netshPath,
    timeoutMs,
  });
  if (!currentBindingResult.ok) {
    return guardReturnValue({
      ok: false,
      code: "QUERY_FAILED",
      detail: `netsh http show sslcert failed: ${currentBindingResult.stderrExcerpt}`,
      outgoingThumbprint: null,
      rolledBack: false,
    });
  }
  const outgoingThumbprint = currentBindingResult.thumbprint;
  // Only meaningful when there is an existing binding to preserve settings
  // from at all; queryCurrentBinding's own parameters field is `{}` for a
  // never-bound selector, which formatPreservedParamArgs already treats as
  // "add no preservation flags", so this default costs nothing either way.
  const outgoingParameters = currentBindingResult.parameters || {};
  const alreadyBound = outgoingThumbprint === newThumbprint;

  if (!alreadyBound) {
    const bindResult = await bindCertificate({
      binding,
      thumbprint: newThumbprint,
      store: binding.store,
      preserveParameters: outgoingParameters,
      execFileImpl,
      netshPath,
      timeoutMs,
    });
    if (!bindResult.ok) {
      // The preceding delete (inside bindCertificate) already ran
      // unconditionally, so a failed add can leave this ipport genuinely
      // unbound, not merely "still on the outgoing cert" -- attempt to
      // restore outgoingThumbprint when there is one to restore.
      const rollback =
        outgoingThumbprint === null
          ? { rolledBack: false }
          : await attemptRollback({
              binding,
              outgoingThumbprint,
              preserveParameters: outgoingParameters,
              execFileImpl,
              netshPath,
              timeoutMs,
            });
      return guardReturnValue({
        ok: false,
        code: "BIND_FAILED",
        detail: `netsh http add sslcert failed: ${bindResult.stderrExcerpt}`,
        outgoingThumbprint,
        ...rollback,
      });
    }
  }

  const { host, servername } = resolveVerificationTarget(binding);
  const verifyResult = await verifyDeployedCertificate({
    host,
    port: binding.port,
    servername,
    expectedFingerprintSha256,
    timeoutMs: verifyTimeoutMs,
    ...(connectImpl !== undefined ? { connectImpl } : {}),
  });

  if (verifyResult.verified) {
    const precedenceWarning = binding.sniHost
      ? await checkSniPrecedenceConflict({ binding, execFileImpl, netshPath, timeoutMs })
      : undefined;
    return guardReturnValue({
      ok: true,
      outgoingThumbprint,
      boundThumbprint: newThumbprint,
      verifiedAt: { host, port: binding.port },
      ...(alreadyBound ? { skippedMutation: true } : {}),
      ...(precedenceWarning !== undefined ? { precedenceWarning } : {}),
    });
  }

  // Verification failed: roll back to whatever was bound before, per
  // decision 13. When nothing was bound before (first-ever deploy to this
  // ipport), or the target was already bound to the certificate being
  // deployed (no mutation occurred above), there is nothing to roll back
  // TO/FROM; the failed state is simply left in place for the
  // operator/control-plane to see and act on, since deleting it would
  // leave the binding entirely unset, which is a worse failure mode than
  // "bound to a cert that failed verification".
  if (outgoingThumbprint === null || alreadyBound) {
    return guardReturnValue({
      ok: false,
      code: "VERIFY_FAILED",
      detail: verifyResult.detail,
      outgoingThumbprint,
      rolledBack: false,
    });
  }

  const rollback = await attemptRollback({
    binding,
    outgoingThumbprint,
    preserveParameters: outgoingParameters,
    execFileImpl,
    netshPath,
    timeoutMs,
  });
  return guardReturnValue({
    ok: false,
    code: "VERIFY_FAILED",
    detail: verifyResult.detail,
    outgoingThumbprint,
    ...rollback,
  });
}

module.exports = {
  SHELL_METACHARACTER_PATTERN,
  THUMBPRINT_PATTERN,
  SITE_PATTERN,
  STORE_NAME_PATTERN,
  SNI_HOST_PATTERN,
  WILDCARD_BINDING_ADDRESSES,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_VERIFY_TIMEOUT_MS,
  OUTPUT_EXCERPT_MAX_CHARS,
  normalizeThumbprint,
  assertValidBinding,
  resolveVerificationTarget,
  boundAndRedactExcerpt,
  assertSafeArgvElements,
  guardReturnValue,
  formatIpPort,
  formatBindingSelector,
  generateAppId,
  parseSslcertParameters,
  formatPreservedParamArgs,
  checkSniPrecedenceConflict,
  queryCurrentBinding,
  bindCertificate,
  deployIisBinding,
};



