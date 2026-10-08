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
 * Canonical form of an `ipport`/`hostnameport` selector value, so a binding
 * descriptor and http.sys's own key compare equal: hostnames and IPv6
 * literals case-insensitively, IPv6 in its compressed form, and "*" as the
 * 0.0.0.0 wildcard it stands for.
 * @param {string} selectorValue e.g. "[2001:DB8::1]:443", "Example.com:443"
 * @returns {string}
 */
function canonicalSelectorValue(selectorValue) {
  const lastColon = selectorValue.lastIndexOf(":");
  if (lastColon <= 0) return selectorValue.toLowerCase();
  let host = selectorValue.slice(0, lastColon).toLowerCase();
  const port = selectorValue.slice(lastColon + 1);
  if (host === "*") host = "0.0.0.0";
  const ipv6 = /^\[(.+)\]$/.exec(host);
  if (ipv6) {
    try {
      host = new URL(`http://[${ipv6[1]}]/`).hostname;
    } catch {
      // Left as written; it then simply matches nothing.
    }
  }
  return `${host}:${port}`;
}

/**
 * Reads the certificate currently bound at a binding's selector
 * (`ipport=<addr:port>`, or `hostnameport=<host:port>` when it carries an
 * sniHost -- see formatBindingSelector) from http.sys's configuration,
 * plus the settings a rebind has to carry over (see decodeHttpSysSettings).
 * `thumbprint: null` (not an error) means nothing is bound there yet, the
 * normal state for a first-ever deploy: decision 13's
 * rollback-to-outgoing-thumbprint step is a no-op in that case.
 *
 * @param {object} input
 * @param {{ address: string, port: number, sniHost?: string }} input.binding
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.powershellPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<
 *   | { ok: true, thumbprint: null }
 *   | { ok: true, thumbprint: string, parameters: ReturnType<typeof decodeHttpSysSettings>["parameters"], unsupportedSettings?: string[] }
 *   | { ok: false, exitCode: number|null, stderrExcerpt: string }
 * >}
 */
async function queryCurrentBinding({
  binding,
  execFileImpl = childProcess.execFile,
  powershellPath = "powershell.exe",
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const listed = await listHttpSysBindings({ execFileImpl, powershellPath, timeoutMs });
  if (!listed.ok) {
    return { ok: false, exitCode: listed.exitCode, stderrExcerpt: listed.stderrExcerpt };
  }

  const keyedBy = binding.sniHost ? "hostnameport" : "ipport";
  const wanted = canonicalSelectorValue(
    binding.sniHost ? `${binding.sniHost}:${binding.port}` : formatIpPort(binding),
  );
  const current = listed.bindings.find(
    (entry) => entry.keyedBy === keyedBy && entry.ipPort && canonicalSelectorValue(entry.ipPort) === wanted,
  );
  if (!current) {
    return { ok: true, thumbprint: null };
  }
  if (!current.thumbprint) {
    return {
      ok: false,
      exitCode: null,
      stderrExcerpt: `the binding at ${formatBindingSelector(binding)} has no readable certificate hash`,
    };
  }

  const { parameters, unsupported } = decodeHttpSysSettings(current.settings);
  return {
    ok: true,
    thumbprint: current.thumbprint,
    parameters,
    ...(unsupported.length > 0 ? { unsupportedSettings: unsupported } : {}),
  };
}

/**
 * http.sys's own flag values (HTTP_SERVICE_CONFIG_SSL_FLAG_*) for the
 * per-connection options `netsh http add sslcert` can set, each confirmed on
 * Windows Server 2019, 2022 and 2025 by setting that netsh option alone.
 */
const SSL_FLAG_DS_MAPPER = 0x1;
const SSL_FLAG_NEGOTIATE_CLIENT_CERT = 0x2;
const NEWER_SSL_FLAGS = Object.freeze([
  [0x8, "rejectConnections"],
  [0x10, "disableHttp2"],
  [0x20, "disableQuic"],
  [0x40, "disableTls13"],
  [0x80, "disableOcspStapling"],
  [0x100, "enableTokenBinding"],
  [0x200, "logExtendedEvents"],
  [0x400, "disableLegacyTls"],
  [0x800, "enableSessionTicket"],
  [0x1000, "disableTls12"],
  [0x4000, "disableSessionId"],
]);
const SSL_FLAGS_MASK = NEWER_SSL_FLAGS.reduce(
  (mask, [bit]) => mask | bit,
  SSL_FLAG_DS_MAPPER | SSL_FLAG_NEGOTIATE_CLIENT_CERT,
);

/** DefaultSslCertCheckMode bits, confirmed the same way. */
const CERT_CHECK_NO_REVOCATION = 0x1;
const CERT_CHECK_CACHED_CLIENT_CERT_ONLY = 0x2;
const CERT_CHECK_FRESHNESS_TIME = 0x4;
const CERT_CHECK_NO_USAGE_CHECK = 0x10000;
const CERT_CHECK_MASK =
  CERT_CHECK_NO_REVOCATION | CERT_CHECK_CACHED_CLIENT_CERT_ONLY | CERT_CHECK_FRESHNESS_TIME | CERT_CHECK_NO_USAGE_CHECK;

// The CTL names follow the observed naming but were never seen on a real
// host; if http.sys uses other names, those bindings fail closed instead.
const HTTPSYS_SETTING_NAMES = new Set([
  "DefaultFlags",
  "DefaultSslCertCheckMode",
  "DefaultSslRevocationFreshnessTime",
  "DefaultSslRevocationUrlRetrievalTimeout",
  "DefaultSslCtlIdentifier",
  "DefaultSslCtlStoreName",
]);

/**
 * Turns an existing binding's http.sys settings (../windows-discovery's
 * `settings`) into the parameters formatPreservedParamArgs replays on a
 * rebind, because `bindCertificate`'s delete-then-add (decision 13) would
 * otherwise reset every one of them to netsh's default on each renewal.
 *
 * Anything netsh cannot set back is listed in `unsupported` rather than
 * dropped: an unknown value name or flag bit, a value of the wrong type, a
 * freshness time without its check-mode bit (or the reverse), or a CTL
 * store without a CTL. The caller must not rebind such a binding.
 *
 * The classic options are always present (false/0/null when unset, as
 * netsh reports them); the newer per-connection flags only when set, since
 * an older netsh does not know them at all.
 *
 * @param {Record<string, unknown>} [settings]
 * @returns {{ unsupported: string[], parameters: {
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
 * } }}
 */
function decodeHttpSysSettings(settings = {}) {
  const unsupported = Object.keys(settings).filter((name) => !HTTPSYS_SETTING_NAMES.has(name));
  const readNumber = (name) => {
    const value = settings[name];
    if (value === undefined) return 0;
    if (Number.isInteger(value) && value >= 0 && value <= 0xffffffff) return value;
    unsupported.push(name);
    return 0;
  };
  const readText = (name) => {
    const value = settings[name];
    if (value === undefined) return null;
    if (typeof value === "string") return value || null;
    unsupported.push(name);
    return null;
  };

  const flags = readNumber("DefaultFlags");
  const checkMode = readNumber("DefaultSslCertCheckMode");
  const freshnessTime = readNumber("DefaultSslRevocationFreshnessTime");
  const ctlIdentifier = readText("DefaultSslCtlIdentifier");
  const ctlStoreName = readText("DefaultSslCtlStoreName");
  const unknownFlags = (flags & ~SSL_FLAGS_MASK) >>> 0;
  if (unknownFlags !== 0) unsupported.push(`DefaultFlags 0x${unknownFlags.toString(16)}`);
  const unknownCheckMode = (checkMode & ~CERT_CHECK_MASK) >>> 0;
  if (unknownCheckMode !== 0) unsupported.push(`DefaultSslCertCheckMode 0x${unknownCheckMode.toString(16)}`);
  // netsh sets the freshness bit exactly when it is given a non-zero time.
  if (Boolean(checkMode & CERT_CHECK_FRESHNESS_TIME) !== freshnessTime > 0) {
    unsupported.push("DefaultSslRevocationFreshnessTime");
  }
  if (ctlStoreName !== null && ctlIdentifier === null) unsupported.push("DefaultSslCtlStoreName");

  const parameters = {
    verifyClientCertRevocation: (checkMode & CERT_CHECK_NO_REVOCATION) === 0,
    verifyRevocationWithCachedClientCertOnly: (checkMode & CERT_CHECK_CACHED_CLIENT_CERT_ONLY) !== 0,
    usageCheck: (checkMode & CERT_CHECK_NO_USAGE_CHECK) === 0,
    revocationFreshnessTime: freshnessTime,
    urlRetrievalTimeout: readNumber("DefaultSslRevocationUrlRetrievalTimeout"),
    ctlIdentifier,
    ctlStoreName,
    dsMapperUsage: (flags & SSL_FLAG_DS_MAPPER) !== 0,
    negotiateClientCert: (flags & SSL_FLAG_NEGOTIATE_CLIENT_CERT) !== 0,
  };
  for (const [bit, key] of NEWER_SSL_FLAGS) {
    if ((flags & bit) !== 0) parameters[key] = true;
  }
  return { parameters, unsupported };
}

/**
 * Turns decodeHttpSysSettings' parameters back into the `netsh http add
 * sslcert` flags that reproduce them, so bindCertificate's rebind can pass
 * them alongside the new certhash/appid/certstorename and preserve an
 * operator's prior revocation/CTL/negotiation/connection-policy
 * configuration instead of resetting it to netsh's default on every
 * renewal. A key absent from `parameters` contributes no flag at all,
 * which is netsh's own default-on-omission behavior.
 *
 * @param {ReturnType<typeof decodeHttpSysSettings>["parameters"]} parameters
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
  // Newer per-connection policy flags; see findUnsupportedNetshParams for
  // the hosts whose netsh lacks some of them.
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

/** Accepted by every netsh this agent runs against (Windows Server 2019+). */
const CLASSIC_NETSH_PARAMS = new Set([
  "verifyclientcertrevocation",
  "verifyrevocationwithcachedclientcertonly",
  "usagecheck",
  "revocationfreshnesstime",
  "urlretrievaltimeout",
  "sslctlidentifier",
  "sslctlstorename",
  "dsmapperusage",
  "clientcertnegotiation",
]);

/**
 * Returns the newer `add sslcert` parameters among `args` that this host's
 * netsh does not list in its own help. netsh exits 0 WITHOUT creating the
 * binding when a parameter is unknown to it or rejected by http.sys (both
 * seen on Windows Server 2019). Settings read back from http.sys were
 * accepted by it, so only the first case can come up on a rebind, and
 * replaying such a parameter would leave the endpoint unbound, the
 * rollback (same settings) included. The help's parameter names are not
 * localized.
 *
 * @param {object} input
 * @param {string[]} input.args formatPreservedParamArgs output.
 * @param {Function} input.execFileImpl
 * @param {string} input.netshPath
 * @param {number} input.timeoutMs
 * @returns {Promise<string[]>}
 */
async function findUnsupportedNetshParams({ args, execFileImpl, netshPath, timeoutMs }) {
  const names = args.map((arg) => arg.slice(0, arg.indexOf("="))).filter((name) => !CLASSIC_NETSH_PARAMS.has(name));
  if (names.length === 0) return [];
  const argv = [netshPath, "http", "add", "sslcert", "help"];
  assertSafeArgvElements("argv", argv);
  const { stdout } = await execWithoutShell(execFileImpl, argv, timeoutMs);
  const helpText = typeof stdout === "string" ? stdout : String(stdout ?? "");
  const listed = new Set(Array.from(helpText.matchAll(/\[([a-z0-9]+)=/g), (match) => match[1]));
  return names.filter((name) => !listed.has(name));
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
 * @param {ReturnType<typeof decodeHttpSysSettings>["parameters"]} [input.preserveParameters]
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
 * @param {ReturnType<typeof decodeHttpSysSettings>["parameters"]} [input.preserveParameters]
 * @param {Function} input.execFileImpl
 * @param {string} input.netshPath
 * @param {string} input.powershellPath
 * @param {number} input.timeoutMs
 * @returns {Promise<{ rolledBack: boolean, rollbackDetail?: string, rollbackVerifyDetail?: string }>}
 */
async function attemptRollback({
  binding,
  outgoingThumbprint,
  preserveParameters = {},
  execFileImpl,
  netshPath,
  powershellPath,
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
    powershellPath,
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
 *      take precedence too).
 * All three come from one full binding listing (../windows-discovery's
 * listHttpSysBindings), since a concrete conflicting address is not known
 * in advance; wildcards are reported first.
 *
 * A query failure here is swallowed (no warning returned): this check is
 * purely informational and must never fail an otherwise-successful SNI
 * deploy over an inability to positively confirm the absence of a
 * conflict.
 *
 * @param {object} input
 * @param {{ port: number, sniHost: string }} input.binding
 * @param {Function} input.execFileImpl
 * @param {string} input.powershellPath
 * @param {number} input.timeoutMs
 * @returns {Promise<string|undefined>}
 */
async function checkSniPrecedenceConflict({ binding, execFileImpl, powershellPath, timeoutMs }) {
  let listed;
  try {
    listed = await listHttpSysBindings({ execFileImpl, powershellPath, timeoutMs });
  } catch {
    return undefined;
  }
  if (listed.ok !== true) return undefined;

  const shadowingAddresses = listed.bindings.flatMap((existing) => {
    if (existing.keyedBy !== "ipport" || !existing.thumbprint || !existing.ipPort) return [];
    const parsed = splitIpPortLiteral(canonicalSelectorValue(existing.ipPort));
    return parsed && parsed.port === binding.port ? [parsed.address] : [];
  });
  const wildcardAddress = ["0.0.0.0", "[::]"].find((address) => shadowingAddresses.includes(address));
  if (wildcardAddress) {
    return (
      `an existing non-SNI certificate binding at ipport=${wildcardAddress}:${binding.port} may take ` +
      `precedence over this SNI binding (hostnameport=${binding.sniHost}:${binding.port}) for clients ` +
      `connecting over that address family: http.sys evaluates ipport bindings before hostnameport ` +
      `bindings on the same port, regardless of the client's SNI value`
    );
  }
  const concreteAddress = shadowingAddresses[0];
  if (concreteAddress) {
    return (
      `an existing non-SNI certificate binding at ipport=${concreteAddress}:${binding.port} may take ` +
      `precedence over this SNI binding (hostnameport=${binding.sniHost}:${binding.port}) for clients ` +
      `connecting to that specific IP: http.sys evaluates ipport bindings before hostnameport bindings ` +
      `on the same port, regardless of the client's SNI value`
    );
  }
  return undefined;
}

/**
 * Splits an http.sys `ipPort` literal (an
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
 * @param {string} [input.powershellPath] runs the http.sys binding query.
 * @param {number} [input.timeoutMs] budget for each netsh/PowerShell invocation.
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
 * UNSUPPORTED_BINDING_SETTINGS: the outgoing binding has a setting netsh
 * cannot set back (see decodeHttpSysSettings and
 * findUnsupportedNetshParams). The binding is left untouched rather than
 * rebound without that setting.
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
  powershellPath = "powershell.exe",
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
    powershellPath,
    timeoutMs,
  });
  if (!currentBindingResult.ok) {
    return guardReturnValue({
      ok: false,
      code: "QUERY_FAILED",
      detail: `http.sys binding query failed: ${currentBindingResult.stderrExcerpt}`,
      outgoingThumbprint: null,
      rolledBack: false,
    });
  }
  const outgoingThumbprint = currentBindingResult.thumbprint;
  // No parameters when nothing is bound yet: nothing to carry over.
  const outgoingParameters = currentBindingResult.parameters || {};
  const alreadyBound = outgoingThumbprint === newThumbprint;

  if (!alreadyBound) {
    const unsupported = [
      ...(currentBindingResult.unsupportedSettings || []),
      ...(await findUnsupportedNetshParams({
        args: formatPreservedParamArgs(outgoingParameters),
        execFileImpl,
        netshPath,
        timeoutMs,
      })).map((name) => `${name} (not supported by this host's netsh)`),
    ];
    if (unsupported.length > 0) {
      return guardReturnValue({
        ok: false,
        code: "UNSUPPORTED_BINDING_SETTINGS",
        detail:
          `the current binding has settings the agent cannot carry over to the new certificate, so it was left ` +
          `unchanged: ${unsupported.join(", ")}`,
        outgoingThumbprint,
        rolledBack: false,
      });
    }

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
              powershellPath,
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
      ? await checkSniPrecedenceConflict({ binding, execFileImpl, powershellPath, timeoutMs })
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
    powershellPath,
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
  canonicalSelectorValue,
  decodeHttpSysSettings,
  formatPreservedParamArgs,
  findUnsupportedNetshParams,
  checkSniPrecedenceConflict,
  queryCurrentBinding,
  bindCertificate,
  deployIisBinding,
};



