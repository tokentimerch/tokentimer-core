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
 * Status: real, tested against a stubbed netsh/TLS layer, NOT yet verified
 * end-to-end against a real IIS site and real http.sys bindings. Do not
 * advertise iis-binding-v1 until that real-host run is complete (see the
 * module doc comment in ../capabilities/gated-capabilities.js).
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
  return { ok: true, thumbprint: match ? match[1].toUpperCase() : null };
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
 * @param {object} input
 * @param {{ address: string, port: number, sniHost?: string }} input.binding
 * @param {string} input.thumbprint 40-hex-char SHA-1, any case.
 * @param {string} input.store Windows certificate store name.
 * @param {Function} [input.execFileImpl]
 * @param {string} [input.netshPath]
 * @param {number} [input.timeoutMs]
 * @returns {Promise<{ ok: true } | { ok: false, exitCode: number|null, stderrExcerpt: string }>}
 */
async function bindCertificate({
  binding,
  thumbprint,
  store,
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
 * @param {Function} input.execFileImpl
 * @param {string} input.netshPath
 * @param {number} input.timeoutMs
 * @returns {Promise<{ rolledBack: boolean, rollbackDetail?: string, rollbackVerifyDetail?: string }>}
 */
async function attemptRollback({ binding, outgoingThumbprint, execFileImpl, netshPath, timeoutMs }) {
  const rollbackResult = await bindCertificate({
    binding,
    thumbprint: outgoingThumbprint,
    store: binding.store,
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
 * Deploys a certificate onto an IIS/http.sys binding with the full
 * decision-13 discipline: record the outgoing thumbprint, rebind to the
 * new one, verify with a real TLS handshake against the binding's own
 * address (never a DNS-resolved name), and roll back to the outgoing
 * thumbprint if verification fails. The outgoing thumbprint is always
 * returned (even null, meaning "nothing was bound before") so the caller
 * can hand it to the retention ledger (decision 18) regardless of outcome.
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
 *   | { ok: true, outgoingThumbprint: string|null, boundThumbprint: string, verifiedAt: { host: string, port: number }, skippedMutation?: true }
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
  const alreadyBound = outgoingThumbprint === newThumbprint;

  if (!alreadyBound) {
    const bindResult = await bindCertificate({
      binding,
      thumbprint: newThumbprint,
      store: binding.store,
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
          : await attemptRollback({ binding, outgoingThumbprint, execFileImpl, netshPath, timeoutMs });
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
    return guardReturnValue({
      ok: true,
      outgoingThumbprint,
      boundThumbprint: newThumbprint,
      verifiedAt: { host, port: binding.port },
      ...(alreadyBound ? { skippedMutation: true } : {}),
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

  const rollback = await attemptRollback({ binding, outgoingThumbprint, execFileImpl, netshPath, timeoutMs });
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
  queryCurrentBinding,
  bindCertificate,
  deployIisBinding,
};



