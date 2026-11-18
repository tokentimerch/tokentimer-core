"use strict";
const fs = require("node:fs");
const path = require("node:path").posix;
const { createHash } = require("node:crypto");
const { loadCredential } = require("./azure-role-certificate-credentials.cjs");
const { crossExchange, exchangeAssertion } = require("./cross-role-probes.cjs");
const { createTokenSink } = require("./token-sink-writer.cjs");
const { check: checkSinks } = require("./sink-isolation.cjs");

const REPOSITORY = "tokentimerch/tokentimer-core";
const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const AUDIENCE = "api://AzureADTokenExchange";
const ROLES = ["issuer", "consumer"];
const UID = { issuer: 10001, consumer: 10002 };
const MISMATCH_CODES = [70021, 700213];
const CERTIFICATE_MISMATCH_CODE = 700027;
const GUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const ID = /^[1-9][0-9]{0,15}$/;
const SHA = /^[a-f0-9]{40}$/;
const MIN_REMAINING_MS = 30_000;
const RENEW_BEFORE_MS = 120_000;
const digest = value => createHash("sha256").update(value).digest("hex");

function requireCondition(value, code) {
  if (!value) throw new Error(code);
}

// Each projection comes from a different protected main-only environment.
// Azure verifies JWT signatures on exchange. Inspect claims only to bind that
// exchange to the approved role, workflow, commit and first attempt.
function roleTrust(binding, role) {
  const environment = "certops-azure-operator-" + role;
  const repo = binding.subjectFormat === "immutable"
    ? `tokentimerch@${binding.ownerId}/tokentimer-core@${binding.repositoryId}` : REPOSITORY;
  return { environment, subject: `repo:${repo}:environment:${environment}` };
}

function validateAssertion(value, binding, role, now) {
  const bad = "AZURE_BROKER_ASSERTION_REFUSED";
  requireCondition(typeof value === "string" && value.length <= 16384 &&
    /^[\w-]+\.[\w-]+\.[\w-]+$/.test(value), bad);
  let claims;
  try { claims = JSON.parse(Buffer.from(value.split(".")[1], "base64url").toString("utf8")); }
  catch { throw new Error(bad); }
  const { environment, subject } = roleTrust(binding, role);
  requireCondition(claims?.iss === GITHUB_ISSUER && claims.aud === AUDIENCE && claims.sub === subject &&
    (claims.environment === undefined || claims.environment === environment) &&
    claims.repository === REPOSITORY && claims.repository_id === binding.repositoryId &&
    claims.repository_owner_id === binding.ownerId &&
    claims.workflow_ref === binding.workflowRef && claims.event_name === "workflow_dispatch" &&
    claims.ref === "refs/heads/main" && claims.sha === binding.sourceSha &&
    claims.run_id === binding.runId && claims.run_attempt === "1" &&
    typeof claims.jti === "string" && claims.jti.length > 0 &&
    Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) &&
    claims.iat * 1000 <= now + MIN_REMAINING_MS && claims.exp > claims.iat &&
    claims.exp * 1000 > now + MIN_REMAINING_MS, bad);
  return claims.jti;
}

// Core's provider transport intentionally discards every error body. This
// exchange-only adapter recognizes a closed set of Entra rejection codes and
// keeps bodies and OAuth diagnostics out of errors, logs and observations.
async function requestEntra(url, { method, headers, body, timeoutMs, maxBytes }, fetchImpl = fetch) {
  const bad = "AZURE_BROKER_ENTRA_REFUSED";
  requireCondition(url.origin === "https://login.microsoftonline.com" &&
    GUID.test(url.pathname.split("/")[1]) && url.pathname.endsWith("/oauth2/v2.0/token") &&
    url.pathname.split("/").length === 5 && !url.username && !url.password && !url.search && !url.hash &&
    method === "POST" && maxBytes === 32768 && timeoutMs === 10000 &&
    process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0", bad);
  try {
    const response = await fetchImpl(url, { method, headers, body, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
    if (![200, 400, 401].includes(response.status)) {
      await response.body?.cancel();
      return { status: response.status, json: null };
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      requireCondition(size <= maxBytes, bad);
      chunks.push(chunk);
    }
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (response.status === 200) {
      return { status: 200, json: { access_token: value.access_token, expires_in: value.expires_in,
        expires_on: value.expires_on } };
    }
    return { status: response.status, json: { error: value.error === "invalid_client" ? "invalid_client" : null,
      error_codes: Array.isArray(value.error_codes)
        ? value.error_codes.filter(code => MISMATCH_CODES.includes(code) || code === CERTIFICATE_MISMATCH_CODE)
        : [] } };
  } catch {
    throw new Error(bad);
  }
}

function pinnedDirectory(root, uid, owner, io) {
  requireCondition(typeof root === "string" && path.isAbsolute(root), "AZURE_BROKER_DIRECTORY_REFUSED");
  const first = io.lstatSync(root);
  const parent = path.dirname(root), parentStat = io.lstatSync(parent);
  requireCondition(io.realpathSync(parent) === parent && parentStat.isDirectory() && !parentStat.isSymbolicLink() &&
    parentStat.uid === owner && (parentStat.mode & 0o022) === 0, "AZURE_BROKER_PARENT_REFUSED");
  requireCondition(io.realpathSync(root) === root && first.isDirectory() &&
    !first.isSymbolicLink() && first.uid === uid && (first.mode & 0o777) === 0o700,
  "AZURE_BROKER_DIRECTORY_REFUSED");
  return () => {
    const current = io.lstatSync(root);
    requireCondition(io.realpathSync(root) === root && current.isDirectory() && !current.isSymbolicLink() &&
      current.uid === uid && (current.mode & 0o777) === 0o700 && current.dev === first.dev && current.ino === first.ino,
    "AZURE_BROKER_DIRECTORY_CHANGED");
  };
}

function readProjection(file, owner, io) {
  const fd = io.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = io.fstatSync(fd);
    requireCondition(stat.isFile() && stat.uid === owner && stat.nlink === 1 &&
      [0o400, 0o600].includes(stat.mode & 0o777) && stat.size > 0 && stat.size <= 16384,
    "AZURE_BROKER_PROJECTION_REFUSED");
    const bytes = Buffer.alloc(16385);
    const length = io.readSync(fd, bytes, 0, bytes.length, 0);
    requireCondition(length === stat.size, "AZURE_BROKER_PROJECTION_CHANGED");
    return bytes.subarray(0, length).toString("utf8").trim();
  } finally { io.closeSync(fd); }
}

function certificateSource({ roleConfig, credentialRoot, read, now, deadlineMs }) {
  const credentials = Object.fromEntries(ROLES.map(role => [role, loadCredential({
    identity: roleConfig[role],
    certificatePem: read(path.join(credentialRoot, role + ".cert.pem")),
    privateKeyPem: read(path.join(credentialRoot, role + ".key.pem")),
    now: now(),
    deadlineMs,
  })]));
  requireCondition(credentials.issuer.keyFingerprint !== credentials.consumer.keyFingerprint,
    "AZURE_BROKER_SHARED_CERTIFICATE_KEY_REFUSED");
  return {
    acquire: role => credentials[role].assertion(roleConfig[role], now()),
    subjectSha256: role => credentials[role].subjectSha256,
    async verifyRoleIsolation(send) {
      for (const role of ROLES) {
        const target = roleConfig[role];
        const { assertion } = credentials[role].assertion(target, now());
        const response = await exchangeAssertion(target, assertion, send);
        requireCondition(response.status === 200 && typeof response.json?.access_token === "string" &&
          response.json.access_token.length >= 20, "AZURE_BROKER_OWN_CERTIFICATE_EXCHANGE_REFUSED");
      }
      for (const [source, targetRole] of [["issuer", "consumer"], ["consumer", "issuer"]]) {
        const target = roleConfig[targetRole];
        const { assertion } = credentials[source].assertion(target, now());
        const response = await exchangeAssertion(target, assertion, send);
        requireCondition([400, 401].includes(response.status) && response.json?.error === "invalid_client" &&
          response.json.error_codes?.includes(CERTIFICATE_MISMATCH_CODE), "AZURE_BROKER_CERTIFICATE_ISOLATION_REFUSED");
      }
    },
  };
}

function projectionSource({ binding, roleConfig, credentialRoot, read, now }) {
  for (const role of ROLES) roleConfig[role].assertionFile = path.join(credentialRoot, role + ".jwt");
  function acquire(role) {
    const assertion = read(roleConfig[role].assertionFile);
    return { assertion, jti: validateAssertion(assertion, binding, role, now()) };
  }
  return {
    acquire,
    subjectSha256: role => digest(roleTrust(binding, role).subject),
    async verifyRoleIsolation(send) {
      const assertions = new Map(ROLES.map(role => [roleConfig[role].assertionFile, acquire(role)]));
      const [left, right] = [...assertions.values()];
      requireCondition(left.jti !== right.jti && left.assertion !== right.assertion, "AZURE_BROKER_SHARED_ASSERTION_REFUSED");
      await crossExchange({ ...roleConfig, federationMismatchCodes: MISMATCH_CODES,
        readAssertion: file => assertions.get(file).assertion, requestJson: send });
    },
  };
}

function createBroker(options) {
  return broker(options, {
    io: fs, platform: process.platform, owner: process.geteuid?.(), now: Date.now, setTimeout, clearTimeout,
    request: requestEntra, createSink: createTokenSink,
  });
}

function broker({ binding, projectionRoot, certificateRoot, deadlineMs, issuer, consumer }, deps) {
  const { io, platform, owner, now, request } = deps;
  requireCondition(platform === "linux" && Number.isSafeInteger(owner), "AZURE_BROKER_LINUX_REQUIRED");
  requireCondition((projectionRoot === undefined) !== (certificateRoot === undefined),
    "AZURE_BROKER_CREDENTIAL_SOURCE_REFUSED");
  requireCondition(binding && ID.test(binding.runId) && ID.test(binding.repositoryId) &&
    ID.test(binding.ownerId) && SHA.test(binding.sourceSha) &&
    ["legacy", "immutable"].includes(binding.subjectFormat) &&
    binding.workflowRef === REPOSITORY + "/.github/workflows/certops-azure-operator-qualification.yml@refs/heads/main",
  "AZURE_BROKER_RUN_BINDING_REFUSED");
  requireCondition(Number.isSafeInteger(deadlineMs) && deadlineMs - now() > MIN_REMAINING_MS &&
    deadlineMs - now() <= 2 ** 31 - 1, "AZURE_BROKER_DEADLINE_REFUSED");
  binding = { ...binding };
  const sources = { issuer, consumer };
  for (const source of [issuer, consumer])
    requireCondition(GUID.test(source?.tenantId) && GUID.test(source?.clientId), "AZURE_BROKER_IDENTITY_REFUSED");
  requireCondition(issuer.tenantId === consumer.tenantId && issuer.clientId !== consumer.clientId,
    "AZURE_BROKER_IDENTITIES_MUST_DIFFER");
  const credentialRoot = certificateRoot ?? projectionRoot;
  const dirs = [credentialRoot, issuer.directory, consumer.directory];
  const [checkCredentialDir, ...checkDirs] = dirs.map((dir, index) =>
    pinnedDirectory(dir, index ? UID[ROLES[index - 1]] : owner, owner, io));
  for (const left of dirs) for (const right of dirs) {
    if (left !== right) requireCondition(!right.startsWith(left + "/"), "AZURE_BROKER_DIRECTORY_OVERLAP");
  }
  requireCondition(new Set(dirs).size === dirs.length, "AZURE_BROKER_DIRECTORY_OVERLAP");

  const roleConfig = Object.fromEntries(ROLES.map(role => [role, { ...sources[role] }]));
  const read = file => {
    checkCredentialDir();
    return readProjection(file, owner, io);
  };
  const sourceOptions = { binding, roleConfig, credentialRoot, read, now, deadlineMs };
  const credential = certificateRoot === undefined ? projectionSource(sourceOptions) : certificateSource(sourceOptions);

  let phase = "idle", admission, expiryTimer;
  const controller = new AbortController();
  const state = Object.fromEntries(ROLES.map(role => [role, { renewals: 0 }]));

  function finish(next) {
    phase = next;
    deps.clearTimeout(expiryTimer);
    for (const row of Object.values(state)) deps.clearTimeout(row.timer);
    controller.abort(new Error(next === "stopped" ? "AZURE_BROKER_STOPPED" : "AZURE_BROKER_UNHEALTHY"));
  }
  function live() {
    requireCondition(["starting", "running"].includes(phase) && now() + 10000 < deadlineMs,
      "AZURE_BROKER_DEADLINE_OR_STOP");
  }
  const send = (url, options) => {
    live();
    return request(url, options);
  };

  const sinks = Object.fromEntries(ROLES.map((role, index) => {
    const row = state[role], directory = roleConfig[role].directory, uid = UID[role];
    return [role, deps.createSink({
      directory, now,
      prepareOwner(fd) {
        checkDirs[index]();
        io.fchownSync(fd, uid, uid);
        io.fchmodSync(fd, 0o600);
        const stat = io.fstatSync(fd);
        requireCondition(stat.uid === uid && (stat.mode & 0o777) === 0o600, "AZURE_BROKER_SINK_OWNER_REFUSED");
      },
      async acquire() {
        live();
        const { assertion, jti } = credential.acquire(role);
        const response = await exchangeAssertion(roleConfig[role], assertion, send);
        live();
        const { access_token: accessToken, expires_in: lifetime, expires_on: expiry } = response.json || {};
        requireCondition(response.status === 200 && typeof accessToken === "string" &&
          /^[A-Za-z0-9_.~-]{20,11999}$/.test(accessToken), "AZURE_BROKER_ACCESS_TOKEN_REFUSED");
        const expiresOn = expiry === undefined ? now() + Number(lifetime) * 1000 : Number(expiry) * 1000;
        const tokenSha = digest(accessToken);
        requireCondition(Number.isSafeInteger(expiresOn) && expiresOn > now() + MIN_REMAINING_MS &&
          (!row.last || (row.last.jti !== jti && row.last.tokenSha !== tokenSha && row.last.expiresOn < expiresOn)),
        "AZURE_BROKER_RENEWAL_REFUSED");
        row.pending = { expiresOn, tokenSha, jti };
        return { accessToken, expiresOn };
      },
    })];
  }));

  function refresh(role) {
    live();
    requireCondition(ROLES.includes(role), "AZURE_BROKER_ROLE_REFUSED");
    const row = state[role];
    if (row.inFlight) return row.inFlight;
    deps.clearTimeout(row.timer);
    row.inFlight = sinks[role].refresh().then(({ expiresOn }) => {
      if (row.last) row.renewals++;
      row.last = row.pending;
      if (phase === "running") schedule(role, expiresOn);
      return { role, expiresOn, tokenRenewals: row.renewals };
    }).catch(() => {
      if (phase !== "stopped") finish("failed");
      throw new Error("AZURE_BROKER_REFRESH_FAILED");
    }).finally(() => {
      row.pending = undefined;
      row.inFlight = undefined;
    });
    return row.inFlight;
  }
  function schedule(role, expiresOn) {
    const remaining = expiresOn - now();
    const delay = remaining - Math.min(RENEW_BEFORE_MS, Math.floor(remaining / 2));
    if (now() + delay + 10000 < deadlineMs) state[role].timer = deps.setTimeout(() => {
      Promise.resolve().then(() => refresh(role)).catch(() => { if (phase === "running") finish("failed"); });
    }, Math.max(1, delay));
  }
  function start() {
    requireCondition(phase === "idle", "AZURE_BROKER_ALREADY_STARTED");
    phase = "starting";
    expiryTimer = deps.setTimeout(() => finish("failed"), deadlineMs - now());
    admission = (async () => {
      await credential.verifyRoleIsolation(send);
      await Promise.all(ROLES.map(refresh));
      live();
      checkSinks({ issuer, consumer }, io, platform);
      phase = "running";
      ROLES.forEach(role => schedule(role, state[role].last.expiresOn));
    })().catch(async () => {
      if (phase !== "stopped") finish("failed");
      await Promise.allSettled(ROLES.map(role => state[role].inFlight));
      throw new Error("AZURE_BROKER_ADMISSION_FAILED");
    });
    return admission;
  }
  async function stop() {
    finish("stopped");
    await Promise.allSettled([admission, ...ROLES.map(role => state[role].inFlight)]);
  }
  function observations() {
    live();
    requireCondition(phase === "running" && ROLES.every(role => state[role].last.expiresOn > now()),
      "AZURE_BROKER_NOT_READY");
    return ROLES.map(role => ({ role, subjectSha256: credential.subjectSha256(role),
      tokenRenewals: state[role].renewals, crossRoleDenials: 1, crossRoleDeniedOperation: "opposite-identity-acquisition" }));
  }
  return { start, refresh(role) {
    requireCondition(phase === "running", "AZURE_BROKER_NOT_READY");
    return refresh(role);
  }, stop, observations, signal: controller.signal };
}

module.exports = { createBroker, _offline: { broker, validateAssertion, requestEntra, roleTrust, certificateSource } };
