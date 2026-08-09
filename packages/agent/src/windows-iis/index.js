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
const { listHttpSysBindings } = require("../windows-discovery/index.js");

/** Mirrors the sibling modules' shell-metacharacter pattern. */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

const DEFAULT_TIMEOUT_MS = 30 * 1000;
const OUTPUT_EXCERPT_MAX_CHARS = 1024;
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

/**
 * `netsh http add sslcert` can fail with "The parameter is incorrect"
 * immediately after a CNG `certreq -accept` for the same certificate,
 * even though the identical command succeeds if retried a moment later
 * (real-host finding, Windows Server 2025 build 26100: SChannel's private
 * key association for a just-written CNG key container is not always
 * visible to netsh's own lookup on the very first call after the key
 * lands in the store). These are bounded, short retries of the ADD call
 * only (never the preceding DELETE, which is best-effort and idempotent
 * either way) to absorb that specific, transient settle delay; a genuine
 * BIND_FAILED (bad thumbprint, wrong store, real parameter error) fails
 * exactly the same after exhausting them, just slightly slower.
 *
 * Widened 2026-08-08 (real-host finding against the same Windows Server
 * 2025 build, on a `renew` job specifically): the original [300, 700,
 * 1500] budget (2.5s of added delay across 4 total attempts) was not
 * always sufficient -- two independent real renewal runs against a
 * freshly key-rotated CNG certificate still failed after exhausting it,
 * while a manual retry of the exact same `netsh add sslcert` call a
 * couple of minutes later succeeded immediately, confirming the
 * underlying condition really is transient settle delay, just with a
 * longer tail than originally measured. Widened to a slower-growing,
 * longer-total schedule (up to ~15.75s of added delay across 6 total
 * attempts) to cover that observed tail without materially changing
 * behavior for the common case, which still resolves on an early retry.
 *
 * A second, deterministic (not transient) failure mode was misdiagnosed
 * against this same retry budget on 2026-08-08 (real-host testing on
 * `certops/agent-health-windows-integration`): two renewal jobs against
 * the same SNI binding exhausted this entire budget and still failed,
 * which first looked like "the transient tail is even longer than
 * measured" and briefly motivated widening this schedule further. It was
 * not that -- root-caused instead to `formatPreservedParamArgs` replaying
 * an outgoing binding's `revocationFreshnessTime`/`urlRetrievalTimeout` of
 * `0` verbatim into the next `add sslcert` call, which this exact netsh
 * build rejects outright regardless of how many times or how long it is
 * retried (see that function's own doc comment). Fixed at the source
 * there; this retry budget stays at the schedule above, which remains
 * correct for the genuine transient settle delay it targets.
 */
const BIND_ADD_RETRY_DELAYS_MS = [300, 700, 1500, 3000, 5000, 5250];

/** Default real-time delay implementation, overridable in tests. */
function defaultDelayImpl(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

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
 * usage, client-certificate negotiation, and the newer per-connection
 * policy flags (reject, HTTP/2, QUIC, legacy-TLS/TLS1.2/TLS1.3, OCSP
 * stapling, token binding, extended-event logging, session ticket/id).
 * `bindCertificate`'s delete-then-add rebind (decision 13) would otherwise
 * silently reset every one of these to netsh's own default on every
 * renewal, since `add sslcert` only ever sees the flags a given call
 * explicitly passes it -- found during PR review as a real gap.
 *
 * Only fields this function can positively read back are included in the
 * returned object; a label it does not find, or one netsh reports as
 * "Not Set" (its own tri-state default for the newer per-connection flags
 * below, distinct from Enabled/Disabled), is simply omitted, never
 * defaulted to true/false by guesswork. formatPreservedParamArgs then only
 * ever emits a flag for a key that is actually present, so an unparsed (or
 * "Not Set") field falls back to netsh's own default exactly as it did
 * before this fix -- strictly no worse, not a new failure mode.
 *
 * `disableLegacyTls` specifically uses a DIFFERENT vocabulary than every
 * other per-connection policy flag: Microsoft's own documentation reports
 * this one field as "Set"/"Not Set", not "Enabled"/"Disabled"/"Not Set" --
 * a PR review found (2026-08-07) that treating it the same as its siblings
 * meant an outgoing binding with legacy TLS genuinely disabled was never
 * recognized as such, so that restriction was silently dropped (not reset,
 * simply never preserved) on every rebind. See readSetOrEnabledOrNotSet's
 * own doc comment below.
 *
 * These are every parameter `netsh http add sslcert help` accepts as of
 * Windows Server 2022/2025 (excluding certhash/appid/certstorename, which
 * the caller always sets explicitly to the new certificate's own identity,
 * never preserved from the outgoing one): the eight classic ones (Windows
 * Server 2012+) plus the newer per-connection policy flags Server 2019+
 * added (reject/disablehttp2/disablequic/disablelegacytls/disabletls12/
 * disabletls13/disableocspstapling/enabletokenbinding/logextendedevents/
 * enablesessionticket/disablesessionid). A netsh binary older than the
 * host this runs on would simply never emit these newer labels in its
 * `show sslcert` output, so readEnabledDisabledOrNotSet naturally omits
 * them for that host too -- no version detection needed.
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
 *   rejectConnections?: boolean,
 *   disableHttp2?: boolean,
 *   disableQuic?: boolean,
 *   disableLegacyTls?: boolean,
 *   disableTls12?: boolean,
 *   disableTls13?: boolean,
 *   disableOcspStapling?: boolean,
 *   enableTokenBinding?: boolean,
 *   logExtendedEvents?: boolean,
 *   enableSessionTicket?: boolean,
 *   disableSessionId?: boolean,
 * }}
 */
function parseSslcertParameters(stdoutText) {
  const readEnabledDisabled = (label) => {
    const found = new RegExp(`${label}\\s*:\\s*(Enabled|Disabled)`, "i").exec(stdoutText);
    return found ? found[1].toLowerCase() === "enabled" : undefined;
  };
  // The newer per-connection policy flags report a third state, "Not Set"
  // (netsh's own "never explicitly configured" default), alongside
  // Enabled/Disabled -- distinct from the classic fields above, which only
  // ever report Enabled/Disabled. "Not Set" is treated the same as "not
  // found": omitted, so formatPreservedParamArgs falls back to netsh's own
  // default on rebind rather than forcing a value that was never actually
  // configured.
  const readEnabledDisabledOrNotSet = (label) => {
    const found = new RegExp(`${label}\\s*:\\s*(Enabled|Disabled|Not Set)`, "i").exec(stdoutText);
    if (!found) return undefined;
    const value = found[1].toLowerCase();
    if (value === "not set") return undefined;
    return value === "enabled";
  };
  // "Disable Legacy TLS Versions" specifically -- unlike every sibling
  // per-connection policy flag above, which real captured `netsh show
  // sslcert` output reports as Enabled/Disabled/Not Set -- is documented by
  // Microsoft itself with a DIFFERENT, two-state vocabulary: "Set" (the
  // restriction is active) / "Not Set" (default, never configured), with
  // no separate "Disabled" text ever shown
  // (learn.microsoft.com/security/engineering/disable-legacy-tls: "Watch
  // for Disable Legacy TLS Versions: Set/Not Set"). A PR review found
  // (2026-08-07) that readEnabledDisabledOrNotSet's Enabled/Disabled/Not-Set
  // regex never matches a bare "Set", so an outgoing binding with legacy
  // TLS genuinely disabled had that setting silently DROPPED (not reset,
  // simply omitted -- formatPreservedParamArgs then emits no
  // `disablelegacytls=` flag at all) on every rebind, quietly re-exposing
  // legacy TLS on a binding an operator had deliberately hardened. Accepts
  // BOTH vocabularies defensively, in case a future Windows build ever
  // reports Enabled/Disabled for this one field too: "Set" and "Enabled"
  // both mean the restriction is active; "Not Set" and "Disabled" are both
  // omitted (never forced), matching every sibling flag's own "do not
  // force a value that was not observed as explicitly enabled" rule.
  const readSetOrEnabledOrNotSet = (label) => {
    const found = new RegExp(`${label}\\s*:\\s*(Not Set|Set|Enabled|Disabled)`, "i").exec(stdoutText);
    if (!found) return undefined;
    const value = found[1].toLowerCase();
    return value === "set" || value === "enabled" ? true : undefined;
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
  assign("rejectConnections", readEnabledDisabledOrNotSet("Reject Connections"));
  assign("disableHttp2", readEnabledDisabledOrNotSet("Disable HTTP2"));
  assign("disableQuic", readEnabledDisabledOrNotSet("Disable QUIC"));
  assign("disableLegacyTls", readSetOrEnabledOrNotSet("Disable Legacy TLS Versions"));
  assign("disableTls12", readEnabledDisabledOrNotSet("Disable TLS1\\.2"));
  assign("disableTls13", readEnabledDisabledOrNotSet("Disable TLS1\\.3"));
  assign("disableOcspStapling", readEnabledDisabledOrNotSet("Disable OCSP Stapling"));
  assign("enableTokenBinding", readEnabledDisabledOrNotSet("Enable Token Binding"));
  assign("logExtendedEvents", readEnabledDisabledOrNotSet("Log Extended Events"));
  assign("enableSessionTicket", readEnabledDisabledOrNotSet("Enable Session Ticket"));
  assign("disableSessionId", readEnabledDisabledOrNotSet("Disable Session ID"));

  return params;
}

/**
 * Turns a parseSslcertParameters result back into the `netsh http add
 * sslcert` flags that reproduce it, so bindCertificate's rebind can pass
 * them alongside the new certhash/appid/certstorename and genuinely
 * preserve an operator's prior revocation/CTL/negotiation/connection-policy
 * configuration instead of silently resetting it to netsh's default on
 * every renewal. A key absent from `parameters` (never positively read
 * back, including a netsh "Not Set" tri-state for the newer flags) simply
 * contributes no flag at all, which is exactly netsh's own
 * default-on-omission behavior -- the same as before this fix, for that
 * one field.
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
  // Real-host finding (Windows Server 2025 build 26100.32860): `add
  // sslcert` rejects an explicit `revocationfreshnesstime=0` or
  // `urlretrievaltimeout=0` with "The parameter is incorrect", even though
  // `add sslcert help` documents 0 as a legal value ("If this value is 0,
  // then the new CRL is updated only if the previous one expires") and even
  // though every *other* integer value (1, 3600, 1000, ...) is accepted
  // without error. 0 is also netsh's own default for both fields when they
  // are omitted entirely from `add sslcert` -- confirmed by binding a
  // certificate with neither flag present and observing `show sslcert`
  // still report 0 for both -- so an outgoing binding that reports 0 was
  // never explicitly customized away from the default in the first place.
  // Omitting the flag here reproduces that exact same effective value (0,
  // via netsh's own default-on-omission) without ever hitting the buggy
  // explicit-0 codepath, so this is strictly no worse than before for the
  // only value it changes behavior for, and it is what fixed a 100%
  // reproducible rebind failure on every renewal following an
  // never-customized initial bind (the common case: nothing before this
  // fix ever explicitly set these two fields to a non-zero value).
  if (parameters.revocationFreshnessTime !== undefined && parameters.revocationFreshnessTime !== 0) {
    args.push(`revocationfreshnesstime=${parameters.revocationFreshnessTime}`);
  }
  if (parameters.urlRetrievalTimeout !== undefined && parameters.urlRetrievalTimeout !== 0) {
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
  // Newer per-connection policy flags (Windows Server 2019+; see
  // parseSslcertParameters' doc comment for the version-agnostic
  // omit-if-absent rationale, which applies identically here).
  if (parameters.rejectConnections !== undefined) {
    args.push(`reject=${flag(parameters.rejectConnections)}`);
  }
  if (parameters.disableHttp2 !== undefined) {
    args.push(`disablehttp2=${flag(parameters.disableHttp2)}`);
  }
  if (parameters.disableQuic !== undefined) {
    args.push(`disablequic=${flag(parameters.disableQuic)}`);
  }
  if (parameters.disableLegacyTls !== undefined) {
    args.push(`disablelegacytls=${flag(parameters.disableLegacyTls)}`);
  }
  if (parameters.disableTls12 !== undefined) {
    args.push(`disabletls12=${flag(parameters.disableTls12)}`);
  }
  if (parameters.disableTls13 !== undefined) {
    args.push(`disabletls13=${flag(parameters.disableTls13)}`);
  }
  if (parameters.disableOcspStapling !== undefined) {
    args.push(`disableocspstapling=${flag(parameters.disableOcspStapling)}`);
  }
  if (parameters.enableTokenBinding !== undefined) {
    args.push(`enabletokenbinding=${flag(parameters.enableTokenBinding)}`);
  }
  if (parameters.logExtendedEvents !== undefined) {
    args.push(`logextendedevents=${flag(parameters.logExtendedEvents)}`);
  }
  if (parameters.enableSessionTicket !== undefined) {
    args.push(`enablesessionticket=${flag(parameters.enableSessionTicket)}`);
  }
  if (parameters.disableSessionId !== undefined) {
    args.push(`disablesessionid=${flag(parameters.disableSessionId)}`);
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
  delayImpl = defaultDelayImpl,
  addRetryDelaysMs = BIND_ADD_RETRY_DELAYS_MS,
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

  // See BIND_ADD_RETRY_DELAYS_MS's doc comment: a just-accepted CNG
  // certificate can transiently fail netsh's own key-association lookup
  // immediately after `certreq -accept`, real-host finding, not a fixture
  // artifact. Only ever retries this ADD call, with a fresh appid each
  // attempt (netsh's own bookkeeping key, no correctness meaning); the
  // preceding DELETE above already ran exactly once, unconditionally.
  const attemptDelaysMs = [0, ...addRetryDelaysMs];
  let lastResult = null;
  for (let attempt = 0; attempt < attemptDelaysMs.length; attempt += 1) {
    if (attemptDelaysMs[attempt] > 0) {
      await delayImpl(attemptDelaysMs[attempt]);
    }

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
    if (exitCode === 0) {
      return { ok: true };
    }

    lastResult = {
      ok: false,
      exitCode,
      stderrExcerpt: boundAndRedactExcerpt(stderr || stdout),
    };

    const isTransientParameterError = /parameter is incorrect/i.test(String(stderr ?? "") + String(stdout ?? ""));
    if (!isTransientParameterError) {
      break;
    }
  }
  return lastResult;
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
  delayImpl,
}) {
  const rollbackResult = await bindCertificate({
    binding,
    thumbprint: outgoingThumbprint,
    store: binding.store,
    preserveParameters,
    execFileImpl,
    netshPath,
    timeoutMs,
    ...(delayImpl !== undefined ? { delayImpl } : {}),
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
 * port for the address (or address family) the client connects over.
 *
 * This module cannot prevent that precedence rule (it is http.sys's, not
 * this module's), only detect when it may be silently shadowing the SNI
 * binding just deployed, and surface that as a non-fatal warning rather
 * than staying silent about a real, non-obvious gotcha. Checks THREE
 * shapes of shadowing ipport binding:
 *   1. The IPv4 wildcard (0.0.0.0) -- shadows every hostnameport binding
 *      on that port for every IPv4 client.
 *   2. The IPv6 wildcard ([::]) -- same, for every IPv6 client.
 *   3. Any OTHER, concrete-IP ipport binding on the same port -- shadows
 *      the SNI binding only for clients connecting to that exact IP, but
 *      is otherwise the identical precedence rule (a PR review found,
 *      2026-08-07, that checking only the two wildcard forms misses this
 *      shape entirely, even though this module's own binding-scope doc
 *      comment on deployIisBinding already explains specific-IP bindings
 *      take precedence too). Enumerated via a full, unfiltered
 *      `netsh http show sslcert` listing (../windows-discovery's
 *      listHttpSysBindings) rather than a targeted query, since the
 *      conflicting address is not known in advance.
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

  // Concrete-IP ipport bindings shadow the SNI binding for clients
  // connecting to that exact IP only, but are otherwise the same
  // precedence rule as the two wildcard forms above -- see this
  // function's doc comment.
  try {
    const allBindings = await listHttpSysBindings({ execFileImpl, netshPath, timeoutMs });
    if (allBindings.ok === true) {
      for (const existing of allBindings.bindings) {
        if (existing.keyedBy !== "ipport" || !existing.thumbprint || !existing.ipPort) continue;
        const parsed = splitIpPortLiteral(existing.ipPort);
        if (!parsed || parsed.port !== binding.port) continue;
        if (parsed.address === "0.0.0.0" || parsed.address === "[::]" || parsed.address === "*") {
          // Already covered by the wildcard checks above.
          continue;
        }
        return (
          `an existing non-SNI certificate binding at ipport=${parsed.address}:${binding.port} may take ` +
          `precedence over this SNI binding (hostnameport=${binding.sniHost}:${binding.port}) for clients ` +
          `connecting to that specific IP: http.sys evaluates ipport bindings before hostnameport bindings ` +
          `on the same port, regardless of the client's SNI value`
        );
      }
    }
  } catch {
    // Purely informational; see doc comment above.
  }
  return undefined;
}

/**
 * Splits a `netsh http show sslcert`-reported `ipPort` literal (an
 * `IP:port` or `Hostname:port` string, per ../windows-discovery's own
 * `keyedBy` field) into `{ address, port }`, on the LAST colon so a
 * bracketed IPv6 literal (`[::1]:443`) is not mis-split on one of its own
 * embedded colons. Mirrors index.js's own splitIpPortLiteral (duplicated
 * per this package's self-contained-module convention).
 * @param {string} ipPort
 * @returns {{ address: string, port: number }|null} null if unparseable.
 */
function splitIpPortLiteral(ipPort) {
  if (!isNonEmptyString(ipPort)) return null;
  const lastColon = ipPort.lastIndexOf(":");
  if (lastColon <= 0 || lastColon === ipPort.length - 1) return null;
  const address = ipPort.slice(0, lastColon);
  const port = Number(ipPort.slice(lastColon + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { address, port };
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
  delayImpl = defaultDelayImpl,
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
      delayImpl,
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
              delayImpl,
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
    delayImpl,
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
  BIND_ADD_RETRY_DELAYS_MS,
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



