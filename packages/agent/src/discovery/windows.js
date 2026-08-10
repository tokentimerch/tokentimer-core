"use strict";

/**
 * Windows OS-store / IIS / http.sys certificate discovery -> `certificate.observed`
 * evidence adapter.
 *
 * This module is NOT a second Windows scanner. All actual enumeration
 * (machine-store `certutil`, http.sys `netsh`, IIS-site `appcmd`) is owned by
 * the canonical ../windows-discovery module (real-host verified against
 * Windows Server 2019/2022/2025). This module's only job is to normalize
 * that canonical output into the same observation shape ./index.js's
 * discoverCertificates already produces for filesystem certificates, so a
 * single generalized pipeline (runWindowsDiscoveryScan in ../index.js ->
 * agentObservations.js -> certificate_targets -> certificate_instances)
 * handles both without a Windows-specific inventory table or API.
 *
 * One real gap exists at the adapter boundary: ../windows-discovery's
 * `certutil -store -v` text parser reports a certificate's SHA-1
 * `Cert Hash(sha1)` (Windows' own legacy thumbprint convention), never the
 * certificate's raw DER bytes, because certutil's text report has no
 * base64/DER dump mode. The control-plane observation contract requires a
 * real SHA-256 `fingerprintSha256` (see ../evidence's FINGERPRINT_SHA256_PATTERN),
 * which cannot be derived from a SHA-1 hex string. This module closes that
 * gap with a minimal, read-only PowerShell call that fetches each store
 * certificate's own public `.RawData` (the same DER bytes a TLS peer
 * receives on the wire) purely to compute the SHA-256 fingerprint locally
 * via node:crypto's X509Certificate. It never touches key material and
 * never duplicates ../windows-discovery's own subject/issuer/date/
 * key-presence/binding/site parsing -- those fields always come from the
 * canonical module.
 *
 * Subject Alternative Names are also derived from those already-fetched
 * public bytes when available. The canonical scanner uses certutil's
 * documented global-option ordering (`certutil -v -store <name>`), while
 * DER parsing remains an independent defense-in-depth path if verbose text
 * output is unavailable or differs across supported Windows versions.
 */

const { spawnSync } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const {
  listMachineStoreCertificates,
  listHttpSysBindings,
  listIisSites,
  findSitesForBinding,
} = require("../windows-discovery");

const POWERSHELL_TIMEOUT_MS = 30000;
const MAX_STDOUT_BYTES = 4 * 1024 * 1024;
const STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;
const MAX_DISCOVERY_STORES = 32;

/**
 * Runs a PowerShell script and parses its stdout as JSON. Scoped to exactly
 * one purpose in this module: fetching `{ Thumbprint, RawCertificateBase64 }`
 * pairs for SHA-256 fingerprint completion (see module doc comment). This is
 * deliberately NOT a general-purpose Windows enumeration helper -- subject,
 * issuer, SANs, dates, key presence, bindings, and sites all come from
 * ../windows-discovery, never from this script.
 *
 * @param {string} assignOutScript PowerShell statements that assign to `$out`
 * @param {{ spawn?: Function, onWarning?: (message: string) => void }} options
 * @returns {any[]} parsed items, or [] on any failure (never throws)
 */
function runPowerShellJson(assignOutScript, { spawn = spawnSync, onWarning = () => {} }) {
  const script = `${assignOutScript}\n@{ items = @($out) } | ConvertTo-Json -Compress -Depth 4`;
  let result;
  try {
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
    onWarning(`windows discovery (fingerprint completion): failed to spawn powershell: ${err?.message || err}`);
    return [];
  }
  if (!result || (result.error && result.error.code === "ENOENT")) {
    onWarning("windows discovery (fingerprint completion): powershell is not available on this host");
    return [];
  }
  if (result.error || result.status !== 0) {
    onWarning(
      `windows discovery (fingerprint completion): powershell did not succeed` +
        (result.status !== undefined ? ` (exit ${result.status})` : ""),
    );
    return [];
  }
  const stdout = String(result.stdout || "").trim();
  if (!stdout) return [];
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    onWarning(`windows discovery (fingerprint completion): could not parse powershell JSON output: ${err?.message || err}`);
    return [];
  }
  const items = parsed && parsed.items;
  if (items === null || items === undefined) return [];
  return Array.isArray(items) ? items : [items];
}

/**
 * Fetches `{ thumbprint (lowercase), rawCertificateBase64 }` pairs for every
 * certificate in a Windows machine store, for SHA-256 fingerprint
 * completion only. storeLocation/storeName are agent-config-controlled (not
 * remotely supplied) but are still validated against a strict allowlist
 * before interpolation, matching this codebase's "never string-build a
 * shell command from unchecked input" posture.
 *
 * @param {{ storeLocation?: string, storeName?: string, spawn?: Function, onWarning?: (m: string) => void }} [options]
 * @returns {Map<string, string>} thumbprint (lowercase) -> base64 DER bytes
 */
function fetchRawCertificateDerByThumbprint({
  storeLocation = "LocalMachine",
  storeName = "My",
  spawn = spawnSync,
  onWarning = () => {},
} = {}) {
  if (!/^[A-Za-z]+$/.test(storeLocation) || !STORE_NAME_PATTERN.test(storeName)) {
    onWarning("windows discovery (fingerprint completion): invalid storeLocation/storeName, skipping");
    return new Map();
  }
  const script = `
$certs = Get-ChildItem -Path 'Cert:\\${storeLocation}\\${storeName}' -ErrorAction Stop
$out = foreach ($c in $certs) {
  [PSCustomObject]@{
    Thumbprint = $c.Thumbprint
    RawCertificateBase64 = [Convert]::ToBase64String($c.RawData)
  }
}
`.trim();
  const items = runPowerShellJson(script, { spawn, onWarning });
  const byThumbprint = new Map();
  for (const item of items) {
    if (!item || typeof item.Thumbprint !== "string" || !item.Thumbprint) continue;
    if (typeof item.RawCertificateBase64 !== "string" || !item.RawCertificateBase64) continue;
    byThumbprint.set(item.Thumbprint.toLowerCase(), item.RawCertificateBase64);
  }
  return byThumbprint;
}

/**
 * Computes the schema's fingerprintSha256 (lowercase, no-colon, 64-hex-char
 * SHA-256) from a base64 DER certificate blob, the same way ../index.js's
 * discoverCertificatesInDirectory does for filesystem certificates -- via
 * node:crypto's own X509Certificate, never a hand-rolled hash. Returns null
 * (with a warning) rather than throwing, since one bad entry must not abort
 * the whole discovery cycle.
 *
 * @param {string|null|undefined} rawCertificateBase64
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
 * Parses Node's own `X509Certificate#subjectAltName` string format (e.g.
 * `"DNS:example.com, DNS:www.example.com, IP Address:10.0.0.5"`) into a
 * plain array of bare name values, matching ../windows-discovery's
 * `parseSubjectAlternativeNames` output shape (no "DNS:"/"IP Address:"
 * prefix) so a caller never has to know which parser produced a given
 * subjectAltNames array. Deliberately a separate parser rather than a
 * reuse of that function: the two tools format the same extension
 * differently ("DNS Name=" with a space+equals vs "DNS:" with a colon).
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

/**
 * Reads Subject Alternative Names directly off a certificate's own raw DER
 * bytes via Node's `X509Certificate#subjectAltName`, rather than relying on
 * ../windows-discovery's parse of certutil's `-v` text dump.
 *
 * Deriving SANs from the already-fetched public bytes keeps SAN reporting
 * independent from certutil's verbose text format and costs no additional
 * certificate-store access.
 *
 * @param {string|null|undefined} rawCertificateBase64
 * @param {(m: string) => void} onWarning
 * @returns {string[]}
 */
function readSubjectAltNamesFromDer(rawCertificateBase64, onWarning = () => {}) {
  if (!rawCertificateBase64 || typeof rawCertificateBase64 !== "string") return [];
  try {
    const der = Buffer.from(rawCertificateBase64, "base64");
    const cert = new X509Certificate(der);
    return parseNodeSubjectAltName(cert.subjectAltName);
  } catch (err) {
    onWarning(`windows discovery: could not read subject alternative names from certificate bytes: ${err?.message || err}`);
    return [];
  }
}

/**
 * Resolves the subjectAltNames field for one certificate, preferring the
 * raw-bytes-derived list (see readSubjectAltNamesFromDer above) and only
 * falling back to ../windows-discovery's own certutil-text-parsed list when
 * the raw-bytes derivation is unavailable (e.g. the fingerprint-completion
 * PowerShell step itself is unavailable on this host). Either source, once
 * chosen, remains an array so commas inside legitimate SAN values are not
 * mistaken for entry delimiters downstream.
 *
 * @param {ReturnType<typeof parseCertutilStoreBlock>} cert
 * @param {string|undefined} rawCertificateBase64
 * @param {(m: string) => void} onWarning
 * @returns {string[]}
 */
function resolveSubjectAltNames(cert, rawCertificateBase64, onWarning) {
  const fromDer = readSubjectAltNamesFromDer(rawCertificateBase64, onWarning);
  if (fromDer.length > 0) return fromDer;
  return Array.isArray(cert.subjectAlternativeNames)
    ? cert.subjectAlternativeNames.filter((value) => typeof value === "string" && value)
    : [];
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
 * Splits an ../windows-discovery `ipPort` literal (`IP:port` or
 * `Hostname:port`) into `{ address, port }`. Splits on the LAST colon so a
 * bracketed IPv6 literal (`[::1]:443`) is not mis-split.
 * @param {string} ipPort
 * @returns {{ address: string, port: number }|null}
 */
function splitIpPortLiteral(ipPort) {
  if (typeof ipPort !== "string" || !ipPort) return null;
  const lastColon = ipPort.lastIndexOf(":");
  if (lastColon <= 0 || lastColon === ipPort.length - 1) return null;
  const address = ipPort.slice(0, lastColon).replace(/^\[|\]$/g, "").trim();
  const port = Number.parseInt(ipPort.slice(lastColon + 1), 10);
  if (!address || !Number.isFinite(port)) return null;
  return { address, port };
}

/**
 * Bridges ../windows-discovery's canonical machine-store/http.sys/IIS-site
 * enumeration into the same observation-input shape ../index.js's
 * runWindowsDiscoveryScan turns into `certificate.observed` evidence for
 * filesystem certificates, so both sources feed one generalized pipeline.
 *
 * `locationSlot` (the per-location stable identity used for reconciliation
 * across renewals) is never derived from the thumbprint/fingerprint -- both
 * rotate at renewal -- and instead uses:
 *   - windows_store: the certificate's own Subject CN (or first SAN as a
 *     fallback), since the store itself has no path-like coordinate.
 *   - iis_binding: the site/port/SNI-host binding coordinate, IIS's own
 *     stable configuration identity regardless of which certificate is
 *     currently bound there.
 *   - http_sys: the bound hostname/IP:port coordinate, http.sys's own
 *     stable binding identity.
 *
 * A binding whose thumbprint cannot be resolved against the store, or whose
 * certificate has no fingerprint available (fingerprint-completion
 * PowerShell unavailable), is skipped with a warning rather than reported
 * with a synthetic/missing identity: fingerprintSha256 is required by the
 * control-plane observation contract.
 *
 * @param {{
 *   store?: string,
 *   execFileImpl?: Function,
 *   spawn?: Function,
 *   onWarning?: (m: string) => void,
 * }} [options]
 * @returns {Promise<object[]>} observation inputs, same shape as before:
 *   locationKind, locationSlot, fingerprintSha256, subject, issuer,
 *   serialNumber, notBefore, notAfter, subjectAltNames, storeLocation,
 *   storeName, thumbprint, keyPresent, plus siteName/port/sniHost
 *   (iis_binding) or boundAddress/port (http_sys).
 */
async function collectWindowsDiscoveryObservations({
  store,
  stores,
  execFileImpl,
  spawn = spawnSync,
  onWarning = () => {},
} = {}) {
  const storeLocation = "LocalMachine";
  const execOpts = execFileImpl ? { execFileImpl } : {};
  const configuredStores = Array.isArray(stores)
    ? stores
    : [store || "My"];
  if (
    configuredStores.length < 1 ||
    configuredStores.length > MAX_DISCOVERY_STORES ||
    configuredStores.some((name) => typeof name !== "string" || !STORE_NAME_PATTERN.test(name))
  ) {
    throw new Error("windows discovery: stores must contain 1 to 32 safe Windows store names");
  }

  // Bindings are enumerated first because they can reference a safe store an
  // operator did not explicitly configure. Those stores are added to this
  // scan so WebHosting and custom-store bindings remain resolvable.
  const bindingsResult = await listHttpSysBindings({ ...execOpts });
  if (!bindingsResult.ok) {
    onWarning(`windows discovery (http_sys/iis_binding): ${bindingsResult.stderrExcerpt || "netsh query failed"}`);
  }
  const bindings = bindingsResult.ok ? bindingsResult.bindings : [];

  const sitesResult = await listIisSites({ ...execOpts });
  const sites = sitesResult.ok ? sitesResult.sites : [];
  const effectiveStores = [];
  const seenStores = new Set();
  const addStore = (name) => {
    if (typeof name !== "string" || !STORE_NAME_PATTERN.test(name)) return;
    const key = name.toLowerCase();
    if (seenStores.has(key)) return;
    if (effectiveStores.length >= MAX_DISCOVERY_STORES) return;
    seenStores.add(key);
    effectiveStores.push(name);
  };
  configuredStores.forEach(addStore);
  bindings.forEach((binding) => addStore(binding.storeName));

  const inventories = [];
  const byStoreAndThumbprint = new Map();
  const byThumbprint = new Map();
  for (const storeName of effectiveStores) {
    const storeResult = await listMachineStoreCertificates({
      store: storeName,
      ...execOpts,
    });
    if (!storeResult.ok) {
      onWarning(
        `windows discovery (windows_store ${storeName}): ${storeResult.stderrExcerpt || "certutil query failed"}`,
      );
      continue;
    }
    const rawDerByThumbprint = fetchRawCertificateDerByThumbprint({
      storeLocation,
      storeName,
      spawn,
      onWarning,
    });
    for (const cert of storeResult.certificates) {
      const thumbprint = cert.thumbprint?.toLowerCase() || null;
      if (!thumbprint) continue;
      const entry = {
        cert,
        storeName,
        rawCertificateBase64: rawDerByThumbprint.get(thumbprint),
      };
      const exactKey = `${storeName.toLowerCase()}\0${thumbprint}`;
      if (byStoreAndThumbprint.has(exactKey)) continue;
      byStoreAndThumbprint.set(exactKey, entry);
      const candidates = byThumbprint.get(thumbprint) || [];
      candidates.push(entry);
      byThumbprint.set(thumbprint, candidates);
      inventories.push(entry);
    }
  }

  const observations = [];

  for (const { cert, storeName, rawCertificateBase64 } of inventories) {
    const thumbprint = cert.thumbprint ? cert.thumbprint.toLowerCase() : null;
    const fingerprintSha256 = computeFingerprintSha256(
      rawCertificateBase64,
      onWarning,
    );
    if (!fingerprintSha256) {
      onWarning(`windows discovery (windows_store): no fingerprint available for ${thumbprint || "unknown"}, skipping`);
      continue;
    }
    const subjectAltNames = resolveSubjectAltNames(cert, rawCertificateBase64, onWarning);
    const slotIdentity =
      commonNameFromSubject(cert.subject) ||
      subjectAltNames[0] ||
      thumbprint;
    observations.push({
      locationKind: "windows_store",
      locationSlot: `${storeLocation}/${storeName}/${slotIdentity}`,
      fingerprintSha256,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      subjectAltNames,
      storeLocation,
      storeName,
      thumbprint,
      keyPresent: cert.hasPrivateKey === true,
    });
  }

  for (const binding of bindings) {
    if (!binding.thumbprint || !binding.ipPort) continue;
    const thumbprint = binding.thumbprint.toLowerCase();
    if (
      typeof binding.storeName === "string" &&
      binding.storeName.length > 0 &&
      !STORE_NAME_PATTERN.test(binding.storeName)
    ) {
      onWarning(
        `windows discovery (binding): binding ${JSON.stringify(binding.ipPort)} has an unsafe store name, skipping`,
      );
      continue;
    }
    const bindingStore =
      typeof binding.storeName === "string" && STORE_NAME_PATTERN.test(binding.storeName)
        ? binding.storeName
        : null;
    const exact = bindingStore
      ? byStoreAndThumbprint.get(`${bindingStore.toLowerCase()}\0${thumbprint}`)
      : null;
    const entry = bindingStore
      ? exact
      : (byThumbprint.get(thumbprint) || [])[0];
    if (!entry) {
      onWarning(
        `windows discovery (binding): binding ${JSON.stringify(binding.ipPort)} thumbprint was not found in a scanned store, skipping`,
      );
      continue;
    }
    const { cert, storeName, rawCertificateBase64 } = entry;
    const fingerprintSha256 = computeFingerprintSha256(rawCertificateBase64, onWarning);
    if (!fingerprintSha256) continue;

    const parsed = splitIpPortLiteral(binding.ipPort);
    if (!parsed) continue;

    const subjectAltNames = resolveSubjectAltNames(cert, rawCertificateBase64, onWarning);
    const base = {
      fingerprintSha256,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      subjectAltNames,
      storeLocation,
      storeName,
      thumbprint,
      // A binding's key presence is the underlying store entry's: the
      // binding itself never holds a key handle, only a thumbprint
      // reference to the store entry resolved above.
      keyPresent: cert.hasPrivateKey === true,
    };

    const matchedSites = findSitesForBinding(sites, binding);
    if (matchedSites.length > 0) {
      const siteName = matchedSites[0];
      const sniHost = binding.keyedBy === "hostnameport" ? parsed.address : null;
      observations.push({
        ...base,
        locationKind: "iis_binding",
        locationSlot: `${siteName}:${parsed.port}${sniHost ? `#${sniHost}` : ""}`,
        siteName,
        port: parsed.port,
        sniHost,
      });
    } else {
      observations.push({
        ...base,
        locationKind: "http_sys",
        locationSlot: `${parsed.address}:${parsed.port}`,
        boundAddress: parsed.address,
        port: parsed.port,
      });
    }
  }

  return observations;
}

module.exports = {
  collectWindowsDiscoveryObservations,
  fetchRawCertificateDerByThumbprint,
  computeFingerprintSha256,
  parseNodeSubjectAltName,
  readSubjectAltNamesFromDer,
  resolveSubjectAltNames,
};
