"use strict";

/**
 * Windows OS-store / IIS / http.sys certificate discovery (observe-only).
 *
 * Fills the product gap this feature exists to close: filesystem discovery
 * (./index.js) feeds `certificate.observed` evidence into the control
 * plane's Observed Locations, but a certificate that lives only in the
 * Windows machine certificate store (bound to an IIS site, or bound
 * directly via http.sys/`netsh http add sslcert`) never has been reported
 * at all, so it is invisible in Observed Locations even though it is real,
 * active, and possibly auto-renew-enabled.
 *
 * Same zero-custody contract as ./index.js: every function here only ever
 * reads certificate *metadata* (thumbprint, subject, issuer, validity,
 * SANs, store/site/binding coordinates, and the boolean `HasPrivateKey`
 * fact) plus the certificate's own public DER bytes (`.RawData`/
 * `RawCertificateBase64`, used only to compute a real SHA-256 fingerprint
 * the same way ./index.js does for filesystem certificates).
 * `HasPrivateKey` is read as a plain boolean property on the certificate
 * object; nothing here ever requests a private key handle, exports a PFX,
 * or reads the key bytes themselves. PowerShell's own `Cert:\` provider
 * does not require touching key material to read either of these fields,
 * so there is no "convenient" path here that would even tempt it.
 *
 * Every function degrades gracefully (empty array + a warning) rather than
 * throwing when a prerequisite is missing (PowerShell absent, WebAdministration
 * module not installed, `netsh` absent) -- a host that only has some of these
 * surfaces (e.g. a plain Windows box with no IIS) must not fail its entire
 * discovery cycle over a feature it does not use. Filesystem discovery
 * evidence-reporting keeps flowing regardless of what happens here (see
 * src/index.js's runDiscoveryScan, which now merges this module's results
 * in as a `try`-isolated best-effort step per surface).
 */

const { spawnSync } = require("node:child_process");
const { X509Certificate } = require("node:crypto");

const POWERSHELL_TIMEOUT_MS = 30000;
const MAX_STDOUT_BYTES = 4 * 1024 * 1024;

/**
 * Runs a PowerShell script and parses its stdout as JSON.
 *
 * The script MUST assign its result list to `$out` and end with the literal
 * line `EMIT_ITEMS` (this function substitutes the actual emit statement).
 * This module always emits via `@{ items = @($out) } | ConvertTo-Json`
 * rather than the more common unary-comma trick (`,$out | ConvertTo-Json`).
 * That trick was tried first and found unreliable on Windows PowerShell
 * 5.1: for a single item it collapses to a bare object (not an array), and
 * for 2+ items it was observed here to serialize as `{"value":[...],
 * "Count":N}` (the ETS wrapper for certain enumerable shapes) rather than a
 * plain JSON array. Explicitly wrapping in a hashtable with a named `items`
 * array property is unambiguous in every case (0, 1, or N items) and needs
 * no post-hoc shape-guessing on the Node side.
 *
 * @param {string} assignOutScript PowerShell statements that assign to `$out`
 * @param {{ spawn?: Function, onWarning?: (message: string) => void, context: string }} options
 * @returns {any[]} parsed items, or [] on any failure (never throws)
 */
function runPowerShellJson(assignOutScript, { spawn = spawnSync, onWarning = () => {}, context }) {
  const script = `${assignOutScript}\n@{ items = @($out) } | ConvertTo-Json -Compress -Depth 6`;
  let result;
  try {
    // PSModulePath deletion mirrors platform/index.js's readWindowsOwnerSid:
    // a PowerShell 7 ancestor process can leave Core-edition module paths
    // ahead of Desktop-edition ones in the inherited environment, which
    // breaks Windows PowerShell 5.1's module auto-loading (e.g. for
    // WebAdministration) with a confusing CouldNotAutoloadMatchingModule
    // error. Deleting it lets powershell.exe compute its own correct default.
    const env = { ...process.env };
    for (const key of Object.keys(env)) {
      if (key.toLowerCase() === "psmodulepath") delete env[key];
    }
    result = spawn("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      windowsHide: true,
      timeout: POWERSHELL_TIMEOUT_MS,
      maxBuffer: MAX_STDOUT_BYTES,
      env,
    });
  } catch (err) {
    onWarning(`windows discovery (${context}): failed to spawn powershell: ${err?.message || err}`);
    return [];
  }
  if (!result || (result.error && result.error.code === "ENOENT")) {
    onWarning(`windows discovery (${context}): powershell is not available on this host`);
    return [];
  }
  if (result.error) {
    onWarning(`windows discovery (${context}): powershell failed to run: ${result.error.message}`);
    return [];
  }
  if (result.status !== 0) {
    onWarning(
      `windows discovery (${context}): powershell exited ${result.status}: ` +
        `${String(result.stderr || "").trim().slice(0, 500)}`,
    );
    return [];
  }
  const stdout = String(result.stdout || "").trim();
  if (!stdout) return [];
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    onWarning(`windows discovery (${context}): could not parse powershell JSON output: ${err?.message || err}`);
    return [];
  }
  const items = parsed && parsed.items;
  if (items === null || items === undefined) return [];
  return Array.isArray(items) ? items : [items];
}

/**
 * Enumerates certificates in a Windows machine certificate store
 * (default `Cert:\LocalMachine\My`, the conventional home for a machine's
 * own TLS server certificates). Returns public metadata only: thumbprint,
 * subject, issuer, serial, validity window, DNS SANs, and the DER-encoded
 * public certificate bytes (`rawCertificateBase64`, from `.RawData`).
 * `.RawData` on a .NET `X509Certificate2` is always just the ASN.1-encoded
 * certificate structure -- the same bytes a TLS peer receives on the wire --
 * and is populated identically whether or not the entry `HasPrivateKey`;
 * there is no key-bearing counterpart this reads instead. It is included so
 * the caller can compute a real SHA-256 fingerprint (`fingerprintSha256`,
 * required by the control plane's observation contract) with Node's own
 * `crypto.X509Certificate`, since `.Thumbprint` here is SHA-1, matching
 * .NET's/Windows' own (legacy but unchanged) convention for this property.
 *
 * @param {{ storeLocation?: string, storeName?: string, spawn?: Function, onWarning?: (m: string) => void }} [options]
 * @returns {Array<{ thumbprint: string, subject: string, issuer: string, serialNumber: string, notBefore: string, notAfter: string, subjectAltNames: string, storeLocation: string, storeName: string, rawCertificateBase64: string|null, keyPresent: boolean }>}
 */
function listMachineStoreCertificates({
  storeLocation = "LocalMachine",
  storeName = "My",
  spawn = spawnSync,
  onWarning = () => {},
} = {}) {
  // storeLocation/storeName are agent-config-controlled (not remotely
  // supplied), but are still validated against a strict allowlist pattern
  // before being interpolated into the PS1 path, matching this codebase's
  // "never string-build a shell command from unchecked input" posture.
  if (!/^[A-Za-z]+$/.test(storeLocation) || !/^[A-Za-z0-9 ]+$/.test(storeName)) {
    onWarning(`windows discovery (windows_store): invalid storeLocation/storeName, skipping`);
    return [];
  }
  const script = `
$certs = Get-ChildItem -Path 'Cert:\\${storeLocation}\\${storeName}' -ErrorAction Stop
$out = foreach ($c in $certs) {
  [PSCustomObject]@{
    Thumbprint = $c.Thumbprint
    Subject = $c.Subject
    Issuer = $c.Issuer
    SerialNumber = $c.SerialNumber
    NotBefore = $c.NotBefore.ToUniversalTime().ToString('o')
    NotAfter = $c.NotAfter.ToUniversalTime().ToString('o')
    SubjectAltNames = (($c.DnsNameList | ForEach-Object { $_.Unicode }) -join ',')
    RawCertificateBase64 = [Convert]::ToBase64String($c.RawData)
    HasPrivateKey = $c.HasPrivateKey
  }
}
`.trim();
  const items = runPowerShellJson(script, { spawn, onWarning, context: "windows_store" });
  return items
    .filter((item) => item && typeof item.Thumbprint === "string" && item.Thumbprint)
    .map((item) => ({
      thumbprint: String(item.Thumbprint).toLowerCase(),
      subject: item.Subject || null,
      issuer: item.Issuer || null,
      serialNumber: item.SerialNumber || null,
      notBefore: item.NotBefore || null,
      notAfter: item.NotAfter || null,
      subjectAltNames: item.SubjectAltNames || "",
      storeLocation,
      storeName,
      rawCertificateBase64: item.RawCertificateBase64 || null,
      // HasPrivateKey is a boolean property on X509Certificate2 itself: it
      // answers "does a key handle for this certificate exist in this
      // store/provider" without opening, exporting, or reading the key.
      // Same fact PowerShell's `Cert:\` provider already exposes for every
      // certificate regardless of provider (Microsoft Software KSP,
      // hardware KSP, or none) -- there is no lower-privilege way to ask
      // this question that this module would be skipping.
      keyPresent: item.HasPrivateKey === true,
    }));
}

/**
 * Enumerates HTTPS IIS site bindings via the WebAdministration module and
 * resolves each binding's certificate hash against the machine store
 * (`RootStore` on a binding is the store the certificate is bound from,
 * `My` unless an operator chose otherwise). Returns [] (with a warning)
 * when IIS/WebAdministration is not installed -- a completely normal state
 * for a non-IIS Windows host, not an error.
 *
 * @param {{ spawn?: Function, onWarning?: (m: string) => void }} [options]
 * @returns {Array<{ siteName: string, port: number, sniHost: string|null, thumbprint: string|null, storeLocation: string, storeName: string }>}
 */
function listIisBindings({ spawn = spawnSync, onWarning = () => {} } = {}) {
  const script = `
Import-Module WebAdministration -ErrorAction Stop
$out = foreach ($site in Get-Website) {
  foreach ($binding in $site.Bindings.Collection) {
    if ($binding.protocol -ne 'https') { continue }
    $info = $binding.bindingInformation -split ':'
    [PSCustomObject]@{
      SiteName = $site.Name
      Port = $info[1]
      SniHost = $info[2]
      Thumbprint = ([System.BitConverter]::ToString($binding.certificateHash) -replace '-','')
      StoreName = $binding.certificateStoreName
    }
  }
}
`.trim();
  const items = runPowerShellJson(script, { spawn, onWarning, context: "iis_binding" });
  return items
    .filter((item) => item && item.SiteName)
    .map((item) => ({
      siteName: String(item.SiteName),
      port: Number.parseInt(item.Port, 10) || 443,
      sniHost: item.SniHost && String(item.SniHost).trim() ? String(item.SniHost).trim() : null,
      thumbprint: item.Thumbprint ? String(item.Thumbprint).toLowerCase() : null,
      storeLocation: "LocalMachine",
      storeName: item.StoreName || "My",
    }));
}

/**
 * Enumerates http.sys SSL certificate bindings (`netsh http show sslcert`),
 * the same surface `netsh http add sslcert` writes to. This is how a
 * non-IIS Windows service (a raw HTTP.sys listener, WinRM-over-HTTPS, etc.)
 * binds a certificate to an IP:port without going through IIS at all, so it
 * is discovered independently of listIisBindings rather than layered on it.
 *
 * netsh has no JSON output mode and, critically, its labels are localized
 * (e.g. "Certificate Hash" becomes "Hachage du certificat" on a French-
 * language Windows install) -- platform/index.js already documents and
 * avoids exactly this problem for icacls by parsing SDDL/SIDs instead of
 * human-readable text. This parser follows the same principle: it never
 * matches a label string. Each binding block's field *order* is fixed and
 * has been stable since Windows Server 2008 R2 (IP:port, then certificate
 * hash, then application id, then store name, ...), so each value is
 * identified by its own shape (an "address:port" pair, a 40-hex-char SHA-1
 * thumbprint) rather than by the locale-dependent label preceding it.
 *
 * @param {{ spawn?: Function, onWarning?: (m: string) => void }} [options]
 * @returns {Array<{ hostname: string, port: number, thumbprint: string|null }>}
 */
function listHttpSysBindings({ spawn = spawnSync, onWarning = () => {} } = {}) {
  let result;
  try {
    result = spawn("netsh", ["http", "show", "sslcert"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: POWERSHELL_TIMEOUT_MS,
    });
  } catch (err) {
    onWarning(`windows discovery (http_sys): failed to spawn netsh: ${err?.message || err}`);
    return [];
  }
  if (!result || (result.error && result.error.code === "ENOENT")) {
    onWarning(`windows discovery (http_sys): netsh is not available on this host`);
    return [];
  }
  if (result.error || result.status !== 0) {
    onWarning(`windows discovery (http_sys): netsh did not succeed, skipping`);
    return [];
  }

  const text = String(result.stdout || "");
  // Blank-line-separated blocks, one per binding. Within a block, identify
  // the "<label> : <value>" line whose value is an address:port pair (the
  // binding's own IP:port/Hostname:port line, always first) and the line
  // whose value is a bare 40-hex-char string (the certificate's SHA-1
  // thumbprint) -- by shape, never by the label text before the colon.
  //
  // The label/value separator is a colon with whitespace on BOTH sides
  // (`\s+:\s+`); a naive split on every colon breaks on this locale's own
  // label text, since "IP:port"/"Hostname:port" contains a colon with no
  // surrounding whitespace, and the value itself ("0.0.0.0:44300") does too.
  const LABEL_VALUE_SEPARATOR = /\s+:\s+/;
  const ADDRESS_PORT_VALUE = /^\[?[^\s:]+\]?:(\d{1,5})$/;
  const THUMBPRINT_VALUE = /^[0-9a-fA-F]{40}$/;
  const blocks = text.split(/\r?\n\r?\n/);
  const out = [];
  for (const block of blocks) {
    let hostPort = null;
    let thumbprint = null;
    for (const line of block.split(/\r?\n/)) {
      const sepMatch = line.match(LABEL_VALUE_SEPARATOR);
      if (!sepMatch) continue;
      const candidate = line.slice(sepMatch.index + sepMatch[0].length).trim();
      if (!hostPort && ADDRESS_PORT_VALUE.test(candidate)) {
        hostPort = candidate;
        continue;
      }
      if (!thumbprint && THUMBPRINT_VALUE.test(candidate)) {
        thumbprint = candidate.toLowerCase();
      }
    }
    if (!hostPort) continue;
    const lastColon = hostPort.lastIndexOf(":");
    const hostPart = hostPort.slice(0, lastColon).replace(/^\[|\]$/g, "").trim();
    const portPart = Number.parseInt(hostPort.slice(lastColon + 1), 10);
    if (!hostPart || !Number.isFinite(portPart)) continue;
    out.push({ hostname: hostPart, port: portPart, thumbprint });
  }
  return out;
}

/**
 * Extracts the CN attribute from a raw X.509 subject string (e.g.
 * "CN=example.com, O=Example Inc"). Mirrors agentObservations.js's
 * commonNameFromSubject on the control-plane side.
 */
function commonNameFromSubject(subject) {
  const text = typeof subject === "string" ? subject.trim() : "";
  if (!text) return null;
  const match = text.match(/(?:^|,\s*)CN\s*=\s*([^,]+)/i);
  return match?.[1]?.trim() || null;
}

/**
 * Computes the schema's fingerprintSha256 (lowercase, no-colon, 64-hex-char
 * SHA-256) from a base64 DER certificate blob, the same way ./index.js's
 * discoverCertificatesInDirectory does for filesystem certificates -- via
 * node:crypto's own X509Certificate, never a hand-rolled hash. Returns null
 * (with a warning) rather than throwing on malformed input, since a single
 * bad store entry must not abort the whole discovery cycle.
 *
 * @param {string|null} rawCertificateBase64
 * @param {(m: string) => void} onWarning
 * @returns {string|null}
 */
function computeFingerprintSha256(rawCertificateBase64, onWarning = () => {}) {
  if (!rawCertificateBase64 || typeof rawCertificateBase64 !== "string") return null;
  try {
    const der = Buffer.from(rawCertificateBase64, "base64");
    const cert = new X509Certificate(der);
    return String(cert.fingerprint256 || "")
      .replace(/:/g, "")
      .toLowerCase();
  } catch (err) {
    onWarning(`windows discovery: could not compute fingerprint from certificate bytes: ${err?.message || err}`);
    return null;
  }
}

/**
 * Cross-references IIS/http.sys bindings (SHA-1 thumbprint only) against the
 * machine store enumeration (which carries the full DER bytes) to produce a
 * flat list of observation inputs, one per discovered location, ready to be
 * turned into `certificate.observed` evidence items by the caller. Every
 * entry here always carries a real fingerprintSha256 (computed from the
 * certificate's own DER bytes, never the SHA-1 thumbprint) since that field
 * is required by the control-plane observation contract.
 *
 * `locationSlot` (the per-location stable identity used for reconciliation
 * across renewals, task #15) is deliberately never derived from the
 * thumbprint/fingerprint -- both rotate at renewal -- and instead uses:
 *   - windows_store: the certificate's own Subject CN (or first SAN as a
 *     fallback for a CN-less cert), since the store itself has no path-like
 *     coordinate; a renewal reissuing the same CN into the same store
 *     resolves to the same slot, exactly like a stable file path would.
 *   - iis_binding: the site/port/SNI-host binding coordinate, which is the
 *     IIS configuration's OWN stable identity regardless of which
 *     certificate is currently bound there.
 *   - http_sys: the bound hostname/IP:port coordinate, http.sys's own
 *     stable binding identity.
 *
 * A binding whose thumbprint cannot be resolved against the store (e.g. the
 * certificate lives in a different store the agent isn't configured to
 * read) is skipped with a warning rather than reported with a synthetic
 * fingerprint.
 *
 * @param {{ storeLocation?: string, storeName?: string, spawn?: Function, onWarning?: (m: string) => void }} [options]
 * @returns {Array<object>} observation inputs (locationKind, locationSlot, fingerprintSha256, subject, issuer, serialNumber, notBefore, notAfter, subjectAltNames, plus location-kind-specific fields)
 */
function collectWindowsDiscoveryObservations({
  storeLocation = "LocalMachine",
  storeName = "My",
  spawn = spawnSync,
  onWarning = () => {},
} = {}) {
  const storeCerts = listMachineStoreCertificates({ storeLocation, storeName, spawn, onWarning });
  const byThumbprint = new Map(storeCerts.map((cert) => [cert.thumbprint, cert]));

  const observations = [];

  for (const cert of storeCerts) {
    const fingerprintSha256 = computeFingerprintSha256(cert.rawCertificateBase64, onWarning);
    if (!fingerprintSha256) continue;
    const slotIdentity =
      commonNameFromSubject(cert.subject) ||
      (cert.subjectAltNames || "").split(",").map((s) => s.trim()).filter(Boolean)[0] ||
      cert.thumbprint;
    observations.push({
      locationKind: "windows_store",
      locationSlot: `${cert.storeLocation}/${cert.storeName}/${slotIdentity}`,
      fingerprintSha256,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      subjectAltNames: cert.subjectAltNames,
      storeLocation: cert.storeLocation,
      storeName: cert.storeName,
      thumbprint: cert.thumbprint,
      keyPresent: cert.keyPresent,
    });
  }

  for (const binding of listIisBindings({ spawn, onWarning })) {
    const cert = binding.thumbprint ? byThumbprint.get(binding.thumbprint) : null;
    if (!cert) {
      onWarning(
        `windows discovery (iis_binding): site "${binding.siteName}:${binding.port}" ` +
          `bound thumbprint not found in ${storeLocation}\\${storeName}, skipping`,
      );
      continue;
    }
    const fingerprintSha256 = computeFingerprintSha256(cert.rawCertificateBase64, onWarning);
    if (!fingerprintSha256) continue;
    observations.push({
      locationKind: "iis_binding",
      locationSlot: `${binding.siteName}:${binding.port}${binding.sniHost ? `#${binding.sniHost}` : ""}`,
      fingerprintSha256,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      subjectAltNames: cert.subjectAltNames,
      storeLocation: binding.storeLocation,
      storeName: binding.storeName,
      siteName: binding.siteName,
      port: binding.port,
      sniHost: binding.sniHost,
      thumbprint: binding.thumbprint,
      // A binding's key presence is the underlying store entry's, since the
      // binding itself never holds a key handle -- it references the store
      // entry by thumbprint. Cross-referenced from the same machine-store
      // enumeration used to resolve subject/issuer/validity above.
      keyPresent: cert.keyPresent,
    });
  }

  for (const binding of listHttpSysBindings({ spawn, onWarning })) {
    const cert = binding.thumbprint ? byThumbprint.get(binding.thumbprint) : null;
    if (!cert) {
      onWarning(
        `windows discovery (http_sys): binding "${binding.hostname}:${binding.port}" ` +
          `bound thumbprint not found in ${storeLocation}\\${storeName}, skipping`,
      );
      continue;
    }
    const fingerprintSha256 = computeFingerprintSha256(cert.rawCertificateBase64, onWarning);
    if (!fingerprintSha256) continue;
    observations.push({
      locationKind: "http_sys",
      locationSlot: `${binding.hostname}:${binding.port}`,
      fingerprintSha256,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      subjectAltNames: cert.subjectAltNames,
      storeLocation: cert.storeLocation,
      storeName: cert.storeName,
      port: binding.port,
      thumbprint: binding.thumbprint,
      keyPresent: cert.keyPresent,
    });
  }

  return observations;
}

module.exports = {
  listMachineStoreCertificates,
  listIisBindings,
  listHttpSysBindings,
  collectWindowsDiscoveryObservations,
};
