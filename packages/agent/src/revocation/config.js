"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const execFileAsync = promisify(execFile);

function validateObservedRevocation(value) {
  if (value === undefined || value === null) return { enabled: false, allowedOrigins: [], trustAnchorFiles: [], intermediateFiles: [] };
  if (typeof value !== "object" || Array.isArray(value)) throw new Error("observedRevocation must be an object");
  const supported = new Set(["enabled", "allowedOrigins", "trustAnchorFiles", "intermediateFiles"]);
  if (Object.keys(value).some((key) => !supported.has(key))) throw new Error("observedRevocation contains an unknown property");
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") throw new Error("observedRevocation.enabled must be a boolean");
  const list = (key, max) => {
    const array = value[key] ?? [];
    if (!Array.isArray(array) || array.length > max || array.some((item) => typeof item !== "string" || !item.trim() || item.length > 2048)) throw new Error(`observedRevocation.${key} must be a bounded string array`);
    return [...new Set(array)];
  };
  const allowedOrigins = list("allowedOrigins", 128);
  for (const origin of allowedOrigins) {
    let u; try { u = new URL(origin); } catch (_) { throw new Error("observedRevocation.allowedOrigins contains an invalid origin"); }
    if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || u.search || u.hash || u.pathname !== "/") throw new Error("observedRevocation.allowedOrigins must contain HTTP(S) origins without paths or credentials");
  }
  const result = { enabled: value.enabled === true, allowedOrigins, trustAnchorFiles: list("trustAnchorFiles", 32), intermediateFiles: list("intermediateFiles", 32) };
  if (result.enabled && allowedOrigins.length === 0) throw new Error("observedRevocation.enabled requires an explicit allowedOrigins list");
  return result;
}

function readCertificateBundle(file, io = fs) {
  const flags = io.constants.O_RDONLY | (io.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    if (io.lstatSync(file).isSymbolicLink()) throw new Error("certificate bundle cannot be a symbolic link");
    fd = io.openSync(file, flags);
    const stat = io.fstatSync(fd);
    if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error("certificate bundle is not a bounded regular file");
    const bytes = Buffer.alloc(1024 * 1024 + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = io.readSync(fd, bytes, count, bytes.length - count, null);
      if (!read) break;
      count += read;
    }
    if (count > 1024 * 1024) throw new Error("certificate bundle exceeds size limit");
    const content = bytes.subarray(0, count).toString("utf8");
    const blocks = content.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n\s]+-----END CERTIFICATE-----/g) || [];
    if (!blocks.length || content.replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n\s]+-----END CERTIFICATE-----/g, "").trim()) throw new Error("certificate bundle contains non-certificate material");
    return blocks.map((block) => new X509Certificate(block).toString());
  } finally { if (fd !== undefined) io.closeSync(fd); }
}

// Node caches system roots within a process. A fresh child observes trust-store
// changes on each scan instead of continuing to trust a removed CA indefinitely.
async function freshSystemRoots({ run = execFileAsync, executable = process.execPath } = {}) {
  // A single-executable application may set execPath to the agent itself; it
  // must never recursively launch another agent with Node CLI arguments.
  if (!/^node(?:\.exe)?$/i.test(path.basename(executable))) throw new Error("system trust enumeration requires the Node executable");
  const script = "const t=require('node:tls');process.stdout.write(JSON.stringify(typeof t.getCACertificates==='function'?t.getCACertificates('system'):[]))";
  let result;
  try { result = await run(executable, ["-e", script], { encoding: "utf8", windowsHide: true, timeout: 20000, maxBuffer: 2 * 1024 * 1024, shell: false }); }
  catch (_) { throw new Error("system trust enumeration failed"); }
  let roots; try { roots = JSON.parse(result.stdout); } catch (_) { throw new Error("invalid system trust response"); }
  if (!Array.isArray(roots) || roots.some((value) => typeof value !== "string")) throw new Error("invalid system trust response");
  return roots;
}

async function freshWindowsIntermediates({ run = execFileAsync } = {}) {
  const script = "$ErrorActionPreference='Stop'; $out=@{}; foreach($name in @('CA','Disallowed')) { $out[$name]=@(Get-ChildItem -Path ('Cert:\\LocalMachine\\'+$name) | ForEach-Object { @{ Thumbprint=$_.Thumbprint; RawData=[int[]]$_.RawData } }) }; $out | ConvertTo-Json -Compress -Depth 5";
  const env = { ...process.env }; for (const key of Object.keys(env)) if (key.toLowerCase() === "psmodulepath") delete env[key];
  let result;
  const powershell = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  try { result = await run(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", windowsHide: true, timeout: 30000, maxBuffer: 4 * 1024 * 1024, shell: false, env }); }
  catch (_) { throw new Error("Windows trust stores unavailable"); }
  let stores; try { stores = JSON.parse(result.stdout); } catch (_) { throw new Error("Windows trust stores unavailable"); }
  if (!Array.isArray(stores.CA) || !Array.isArray(stores.Disallowed)) throw new Error("Windows trust stores unavailable");
  const parse = (entries) => {
    const out = new Map();
    for (const item of entries) {
      if (!item || typeof item.Thumbprint !== "string" || !/^[a-f0-9]{40}$/i.test(item.Thumbprint) || !Array.isArray(item.RawData) || item.RawData.length === 0 || item.RawData.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) throw new Error("Windows trust store entry invalid");
      const parsed = new X509Certificate(Buffer.from(item.RawData));
      if (parsed.fingerprint.replace(/:/g, "").toLowerCase() !== item.Thumbprint.toLowerCase()) throw new Error("Windows trust store fingerprint mismatch");
      out.set(item.Thumbprint.toLowerCase(), parsed.toString());
    }
    return out;
  };
  return { denied: parse(stores.Disallowed), ca: parse(stores.CA) };
}

async function loadTrustMaterial(config, { io = fs, systemRoots = freshSystemRoots, platform = process.platform, windowsStores = freshWindowsIntermediates } = {}) {
  if (!config?.enabled) return { roots: [], intermediates: [] };
  let roots = await systemRoots();
  for (const file of config.trustAnchorFiles) roots.push(...readCertificateBundle(file, io));
  const intermediates = [];
  let denied = new Map();
  if (platform === "win32") {
    let ca;
    ({ denied, ca } = await windowsStores());
    if (!(denied instanceof Map) || !(ca instanceof Map)) throw new Error("Windows trust stores unavailable");
    roots = roots.filter((pem) => !denied.has(new X509Certificate(pem).fingerprint.replace(/:/g, "").toLowerCase()));
    for (const [thumbprint, pem] of ca) if (!denied.has(thumbprint)) intermediates.push(pem);
  }
  for (const file of config.intermediateFiles) intermediates.push(...readCertificateBundle(file, io));
  roots = [...new Set(roots)];
  const uniqueIntermediates = [...new Set(intermediates)].filter((pem) => !denied.has(new X509Certificate(pem).fingerprint.replace(/:/g, "").toLowerCase()));
  if (!roots.length || roots.length > 512 || uniqueIntermediates.length > 256) throw new Error("observed revocation trust material unavailable or exceeds limits");
  return { roots, intermediates: uniqueIntermediates };
}

module.exports = { validateObservedRevocation, readCertificateBundle, freshSystemRoots, freshWindowsIntermediates, loadTrustMaterial };
