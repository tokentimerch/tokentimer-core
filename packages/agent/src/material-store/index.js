"use strict";

// Customer-side only. Never import this module from API/worker code.
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const http = require("node:http");
const crypto = require("node:crypto");
const { assertRestrictivePermissions, applyRestrictivePermissions, assertWindowsAcl } = require("../platform");
const { fsyncDirectorySync } = require("../platform/durability");
const { validateCertificateForDeploy, parseDnsSans, computeCertificateFingerprint } = require("../verify");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALIAS = /^[A-Za-z0-9_-]{1,64}$/;
const SEGMENT = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_BUNDLE_BYTES = 256 * 1024;
const BUNDLE_FIELDS = new Set(["schemaVersion", "workspaceId", "groupId", "materialVersionId", "certificatePem", "privateKeyPem", "fingerprintSha256", "sans"]);

function failure(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function safePath(value) {
  return typeof value === "string" && value.length <= 512 && value.split("/").every((part) => SEGMENT.test(part));
}

function sameSans(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    left.length > 0 && left.length <= 100 && left.length === right.length &&
    new Set(left).size === left.length &&
    JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

// No arbitrary secret files and no symlink following. Local configuration is
// trusted authority, but a replaced token/staging file must still fail closed.
function readProtectedFile(file, maxBytes = MAX_BUNDLE_BYTES) {
  if (!path.isAbsolute(file)) throw failure("material_local_path_invalid");
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) throw failure("material_local_file_invalid");
  assertRestrictivePermissions(file, { isDirectory: false });
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd);
    if (opened.ino !== stat.ino || opened.dev !== stat.dev || opened.size > maxBytes) throw failure("material_local_file_changed");
    return fs.readFileSync(fd, "utf8");
  } finally { fs.closeSync(fd); }
}

function protectDirectory(directory) {
  if (!path.isAbsolute(directory)) throw failure("material_local_path_invalid");
  // Reject any existing symlink ancestor, including a substituted state root.
  let current = path.parse(directory).root;
  for (const segment of directory.slice(current.length).split(path.sep)) {
    current = path.join(current, segment);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw failure("material_local_symlink");
  }
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  applyRestrictivePermissions(directory, { kind: "directory" });
  if (process.platform === "win32") assertWindowsAcl(directory);
  else if ((fs.statSync(directory).mode & 0o077) !== 0) throw failure("material_local_permissions");
}

function writeProtectedFile(file, value) {
  protectDirectory(path.dirname(file));
  const temporary = `${file}.${crypto.randomBytes(12).toString("hex")}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    applyRestrictivePermissions(temporary, { isDirectory: false });
    fs.writeFileSync(fd, value);
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  try {
    fs.renameSync(temporary, file);
    fsyncDirectorySync(path.dirname(file));
  } finally { fs.rmSync(temporary, { force: true }); }
}

function writeProtectedJson(file, value) { writeProtectedFile(file, JSON.stringify(value)); }

function validateBundle(bundle, intent, scope) {
  try {
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle) ||
      Object.keys(bundle).some((key) => !BUNDLE_FIELDS.has(key)) ||
      Buffer.byteLength(JSON.stringify(bundle)) > MAX_BUNDLE_BYTES ||
      bundle.schemaVersion !== 1 || bundle.workspaceId !== intent.workspaceId ||
      bundle.groupId !== intent.groupId || bundle.materialVersionId !== intent.materialVersionId ||
      !sameSans(bundle.sans, scope.sans) || typeof bundle.privateKeyPem !== "string") throw failure("material_bundle_invalid");
    const chain = typeof bundle.certificatePem === "string" ? bundle.certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) : null;
    if (!chain?.length || chain.length>16 || bundle.certificatePem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, "").trim()) throw failure("material_bundle_invalid");
    for (const pem of chain) new crypto.X509Certificate(pem);
    const validation = validateCertificateForDeploy({
      certificatePem: bundle.certificatePem, privateKeyPem: bundle.privateKeyPem,
      requestedSans: scope.sans, clockSkewSeconds: 0,
    });
    // verify module uses explicit field names; check independently as well to
    // prevent key-match bypass if the optional-key legacy path changes.
    const certificate = new crypto.X509Certificate(bundle.certificatePem);
    const key = crypto.createPrivateKey(bundle.privateKeyPem);
    if (!validation.valid || !certificate.checkPrivateKey(key) || certificate.ca ||
      !sameSans(parseDnsSans(certificate.subjectAltName), scope.sans) ||
      certificate.publicKey.asymmetricKeyType !== scope.keyAlgorithm ||
      Date.parse(certificate.validFrom) > Date.now() || Date.parse(certificate.validTo) <= Date.now()) throw failure("material_bundle_invalid");
    if (scope.keyAlgorithm === "rsa" && certificate.publicKey.asymmetricKeyDetails.modulusLength < 2048) throw failure("material_bundle_invalid");
    const fingerprint = computeCertificateFingerprint(bundle.certificatePem);
    if (fingerprint !== bundle.fingerprintSha256 || (intent.fingerprintSha256 && fingerprint !== intent.fingerprintSha256)) throw failure("material_fingerprint_mismatch");
    return { fingerprintSha256: fingerprint, validTo: new Date(certificate.validTo).toISOString() };
  } catch (error) {
    if (error.code === "material_fingerprint_mismatch") throw error;
    throw failure("material_bundle_invalid");
  }
}

function resolveStore(stores, intent, { fixtureLoopbackHttp = false } = {}) {
  if (!intent || !UUID.test(intent.workspaceId) || !UUID.test(intent.groupId) ||
    !UUID.test(intent.materialVersionId) || !ALIAS.test(intent.materialStoreRef)) throw failure("material_intent_invalid");
  const config = Object.hasOwn(stores || {}, intent.materialStoreRef) ? stores[intent.materialStoreRef] : null;
  const scope = config && Object.hasOwn(config.groups || {}, intent.groupId) ? config.groups[intent.groupId] : null;
  if (!scope || scope.workspaceId !== intent.workspaceId || !safePath(scope.prefix) ||
    !["rsa", "ec"].includes(scope.keyAlgorithm) || !sameSans(scope.sans, scope.sans)) throw failure("material_scope_denied");
  let address;
  try { address = new URL(config.address); } catch { throw failure("material_store_config_invalid"); }
  const fixtureHttp = fixtureLoopbackHttp && address.protocol === "http:" &&
    (address.hostname === "127.0.0.1" || address.hostname === "[::1]");
  if ((!fixtureHttp && address.protocol !== "https:") || address.username || address.password ||
    address.search || address.hash || address.pathname !== "/" || !SEGMENT.test(config.mount) ||
    (config.namespace && !safePath(config.namespace))) throw failure("material_store_config_invalid");
  const timeoutMs = config.timeoutMs ?? 10000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) throw failure("material_store_config_invalid");
  const objectRef = `${scope.prefix}/bundles/${intent.materialVersionId}`;
  return { config, scope, address, objectRef, timeoutMs, fixtureHttp };
}

function createVaultStore(stores, intent, options = {}) {
  const resolved = resolveStore(stores, intent, options);
  const { config, scope, address, objectRef, timeoutMs, fixtureHttp } = resolved;
  const apiPath = `/v1/${config.mount}/data/${objectRef}`;

  async function request(method, suffix = "", body = null) {
    let token;
    let ca;
    try {
      token = readProtectedFile(config.tokenFile, 4096).trim();
      if (!/^[A-Za-z0-9_.-]{8,4096}$/.test(token)) throw failure("material_auth_unavailable");
      ca = config.caFile ? fs.readFileSync(config.caFile) : undefined;
    } catch { throw failure("material_auth_unavailable"); }
    const payload = body === null ? null : Buffer.from(JSON.stringify(body));
    const transport = fixtureHttp ? http : https;
    return new Promise((resolve, reject) => {
      const req = transport.request(new URL(apiPath + suffix, address), {
        method, ca, rejectUnauthorized: true,
        headers: { "X-Vault-Token": token,
          ...(config.namespace ? { "X-Vault-Namespace": config.namespace } : {}),
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}) },
      }, (response) => {
        let length = 0;
        const chunks = [];
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > MAX_BUNDLE_BYTES + 16384) { req.destroy(); reject(failure("material_response_too_large")); return; }
          chunks.push(chunk);
        });
        response.on("error", () => reject(failure("material_store_unavailable")));
        response.on("end", () => {
          // Never forward Vault bodies/errors, headers, tokens or URLs.
          if (response.statusCode === 404) { resolve({ missing: true }); return; }
          if (response.statusCode === 400 && method === "POST") { resolve({ conflict: true }); return; }
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(failure(response.statusCode === 403 ? "material_auth_denied" : "material_store_unavailable")); return;
          }
          try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
          catch { reject(failure("material_response_invalid")); }
        });
      });
      // Absolute deadline, including stalled response bodies, DNS and TLS.
      const timer = setTimeout(() => req.destroy(), timeoutMs);
      req.on("close", () => clearTimeout(timer));
      req.on("error", () => reject(failure("material_store_unavailable")));
      if (payload) req.write(payload);
      req.end();
    });
  }

  async function fetch(providerVersion) {
    if (!Number.isSafeInteger(providerVersion) || providerVersion < 1) throw failure("material_provider_version_invalid");
    const response = await request("GET", `?version=${providerVersion}`);
    if (response.missing || response.data?.metadata?.destroyed || response.data?.metadata?.deletion_time || response.data?.metadata?.version !== providerVersion) throw failure("material_version_unavailable");
    const bundle = response.data?.data;
    validateBundle(bundle, intent, scope);
    return bundle;
  }

  async function publish(bundle) {
    const facts = validateBundle(bundle, intent, scope);
    let response;
    try { response = await request("POST", "", { options: { cas: 0 }, data: bundle }); }
    catch { response = { uncertain: true }; }
    if (response.data?.version !== 1 && !response.conflict && !response.uncertain) throw failure("material_publication_uncertain");
    let stored;
    try { stored = await fetch(1); } catch { throw failure(response.conflict ? "material_cas_conflict" : "material_publication_uncertain"); }
    // Matching public fingerprint alone is insufficient: verify the exact key
    // and complete bundle belong to this logical publication, never adopt a
    // conflicting existing object after CAS failure or a lost response.
    if (stored.privateKeyPem !== bundle.privateKeyPem || stored.certificatePem !== bundle.certificatePem) throw failure("material_cas_conflict");
    return { schemaVersion: 1, workspaceId: intent.workspaceId, groupId: intent.groupId,
      materialVersionId: intent.materialVersionId, materialStoreRef: intent.materialStoreRef,
      providerVersion: 1, fingerprintSha256: facts.fingerprintSha256,
      validTo: facts.validTo };
  }

  return Object.freeze({ publish, fetch, scope, objectRef });
}

module.exports = { createVaultStore, resolveStore, validateBundle, readProtectedFile, writeProtectedFile, writeProtectedJson, protectDirectory, sameSans, failure, UUID, ALIAS, MAX_BUNDLE_BYTES };
