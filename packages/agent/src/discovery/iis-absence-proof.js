"use strict";

// The ordinary discovery adapters are intentionally best effort. An absence
// proof must use its own fail-closed IIS enumeration and strict HTTP.sys read.
const childProcess = require("node:child_process");
const { createHash } = require("node:crypto");
const { isIP } = require("node:net");
const { execWithoutShell, listHttpSysBindings, canonicalIisAddress } = require("../windows-discovery");

const IIS_SNAPSHOT_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "Import-Module WebAdministration -ErrorAction Stop",
  "$sites = @(Get-Website -ErrorAction Stop)",
  "$items = @(foreach ($site in $sites) {",
  "  foreach ($b in @(Get-WebBinding -Name $site.Name -ErrorAction Stop)) {",
  "    if ($b.protocol -eq 'https') { if ($null -eq $b.sslFlags) { throw 'Missing IIS SSL flags' }; @{ site = [string]$site.Name; binding = [string]$b.bindingInformation; flags = [int]$b.sslFlags } }",
  "  }",
  "})",
  "ConvertTo-Json -InputObject @{ sites = @($sites | ForEach-Object { [string]$_.Name }); items = $items } -Compress -Depth 5",
].join("\n");
const STORE_SNAPSHOT_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$items = @(Get-ChildItem -Path 'Cert:\\LocalMachine\\My' -ErrorAction Stop | ForEach-Object { @{ thumbprint = [string]$_.Thumbprint; rawData = [int[]]$_.RawData; hasPrivateKey = [bool]$_.HasPrivateKey } })",
  "ConvertTo-Json -InputObject @{ items = $items } -Compress -Depth 4",
].join("\n");

function isConcreteAddress(value) {
  if (typeof value !== "string" || value.includes("%")) return false;
  const family = isIP(value);
  if (family === 4) return value !== "0.0.0.0";
  if (family !== 6) return false;
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1,-1);
  return canonical !== "::" && !canonical.startsWith("::ffff:");
}

function selector(value) {
  if (typeof value !== "string") return null;
  const m = /^(.*):(\d+):(.*)$/.exec(value);
  if (!m || !m[1] || Number(m[2]) < 1 || Number(m[2]) > 65535) return null;
  const address = canonicalIisAddress(m[1]);
  if (address === null) return null;
  return { address, port: Number(m[2]), hostname: m[3] };
}

function parseIisSnapshot(stdout) {
  const data = JSON.parse(stdout);
  if (!data || !Array.isArray(data.sites) || !Array.isArray(data.items) || data.sites.length > 1000 || data.items.length > 5000 ||
      data.sites.some(site => typeof site !== "string" || !site) || new Set(data.sites.map(s => s.toLowerCase())).size !== data.sites.length) throw new Error("Incomplete IIS snapshot");
  const sites = new Set(data.sites.map(s => s.toLowerCase()));
  return data.items.map(row => {
    const parsed = selector(row?.binding);
    if (typeof row?.site !== "string" || !sites.has(row.site.toLowerCase()) || !parsed || !Number.isSafeInteger(row.flags) || row.flags < 0) throw new Error("Invalid IIS binding snapshot");
    return { site: row.site, ...parsed, flags: row.flags };
  });
}

function provesWildcardAbsent(observation, iis, http, certificates) {
  const address = canonicalIisAddress(observation?.boundAddress);
  const port = observation?.port;
  if (observation?.locationKind !== "iis_binding" || !isConcreteAddress(address) ||
      !Number.isInteger(port) || !observation.siteName || !/^[a-f0-9]{40}$/i.test(observation.thumbprint || "")) return false;
  if (!Array.isArray(iis) || !Array.isArray(http) || !Array.isArray(certificates)) return false;
  const matchingCertificates=certificates.filter(cert => cert.thumbprint.toLowerCase() === observation.thumbprint.toLowerCase());
  if (matchingCertificates.length !== 1 || matchingCertificates[0].hasPrivateKey !== true || matchingCertificates[0].fingerprintSha256 !== observation.fingerprintSha256) return false;
  const matchingIis = iis.filter(b => b.site.toLowerCase() === observation.siteName.toLowerCase() && b.address === address && b.port === port && !b.hostname && (b.flags & 3) === 0);
  if (matchingIis.length !== 1 || iis.some(b => b.port === port && (b.address === "*" || !isConcreteAddress(b.address)))) return false;
  const matchingHttp = http.filter(b => {
    if (b.keyedBy !== "ipport" || typeof b.ipPort !== "string") return false;
    const split = b.ipPort.lastIndexOf(":");
    return split > 0 && Number(b.ipPort.slice(split + 1)) === port && canonicalIisAddress(b.ipPort.slice(0,split)) === address;
  });
  if (matchingHttp.length !== 1 || String(matchingHttp[0].thumbprint || "").toLowerCase() !== observation.thumbprint.toLowerCase()) return false;
  if (String(matchingHttp[0].storeName || "").toLowerCase() !== "my") return false;
  return !http.some(b => {
    if (b.keyedBy !== "ipport") return false;
    const value=String(b.ipPort || ""); const split=value.lastIndexOf(":");
    return split > 0 && Number(value.slice(split+1)) === port && !isConcreteAddress(canonicalIisAddress(value.slice(0,split)));
  });
}

async function captureIisSnapshot({ execFileImpl = childProcess.execFile, timeoutMs = 15000, signal } = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === "psmodulepath") delete env[key];
  const result = await execWithoutShell(execFileImpl, ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", IIS_SNAPSHOT_SCRIPT], timeoutMs, { env, ...(signal ? { signal } : {}) });
  if (result.exitCode !== 0) throw new Error("IIS snapshot unavailable");
  return parseIisSnapshot(String(result.stdout || ""));
}

async function readAbsenceSnapshot({ execFileImpl, signal } = {}) {
  const options = { ...(execFileImpl ? { execFileImpl } : {}), ...(signal ? { signal } : {}) };
  const iis = await captureIisSnapshot(options);
  const http = await listHttpSysBindings({ ...options, strict: true });
  if (!http.ok) throw new Error("HTTP.sys snapshot unavailable");
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === "psmodulepath") delete env[key];
  const store = await execWithoutShell(execFileImpl || childProcess.execFile, ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", STORE_SNAPSHOT_SCRIPT], 15000, { env, ...(signal ? { signal } : {}) });
  if (store.exitCode !== 0) throw new Error("Certificate store snapshot unavailable");
  let certificates;
  try { certificates = JSON.parse(String(store.stdout || "")).items; } catch { throw new Error("Invalid certificate store snapshot"); }
  if (!Array.isArray(certificates) || certificates.length > 10000 || certificates.some(c =>
    !/^[a-f0-9]{40}$/i.test(c?.thumbprint || "") || typeof c?.hasPrivateKey !== "boolean" ||
    !Array.isArray(c?.rawData) || c.rawData.length < 1 || c.rawData.length > 1024 * 1024 ||
    !c.rawData.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255))) {
    throw new Error("Invalid certificate store snapshot");
  }
  certificates = certificates.map(c => ({
    thumbprint: c.thumbprint,
    hasPrivateKey: c.hasPrivateKey,
    fingerprintSha256: createHash("sha256").update(Buffer.from(c.rawData)).digest("hex"),
  }));
  return { iis, http: http.bindings, certificates };
}

function snapshotIdentity(snapshot) {
  const iis = snapshot.iis.map(row => JSON.stringify([row.site.toLowerCase(), row.address, row.port, row.hostname, row.flags])).sort();
  const http = snapshot.http.map(row => {
    const value = String(row.ipPort || ""); const split = value.lastIndexOf(":");
    const canonical = row.keyedBy === "ipport" && split > 0 ? canonicalIisAddress(value.slice(0,split)) : null;
    return JSON.stringify([row.keyedBy, canonical ? `${canonical}:${value.slice(split+1)}` : value.toLowerCase(), row.thumbprint?.toLowerCase(), row.storeName?.toLowerCase()]);
  }).sort();
  const certificates = snapshot.certificates.map(row => JSON.stringify([row.thumbprint.toLowerCase(), row.fingerprintSha256, row.hasPrivateKey])).sort();
  return JSON.stringify([iis, http, certificates]);
}

// Two equal, strict reads reject a change that happens while either native
// surface is being enumerated. This is a point-in-time observation, not a
// lock on configuration changes made after it.
async function readStableAbsenceSnapshot({ read = readAbsenceSnapshot, execFileImpl, signal } = {}) {
  const first = await read({ execFileImpl, signal });
  const second = await read({ execFileImpl, signal });
  if (snapshotIdentity(first) !== snapshotIdentity(second)) throw new Error("IIS bindings changed during observation");
  return second;
}

module.exports = { parseIisSnapshot, provesWildcardAbsent, readAbsenceSnapshot, readStableAbsenceSnapshot };
