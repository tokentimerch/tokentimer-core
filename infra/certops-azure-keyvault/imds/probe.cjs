"use strict";

const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { gunzipSync } = require("node:zlib");

const IMDS = "http://169.254.169.254";
const TOKEN_PATH = "/metadata/identity/oauth2/token";
const AUDIENCE = "https://vault.azure.net";
const TIMEOUT_MS = 10000;
const GUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const VERSION = /^[a-f0-9]{32}$/;
const ROLE_NAMES = ["issuer", "consumer"];

function check(ok, code) {
  if (!ok) throw new Error(code);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validatePlan(plan) {
  const { runId, attempt, sourceSha, tenantId, subscriptionId, group, vault, secret,
    pinnedVersion, newerVersion, valueSha256, expiresAt, deadlineAt, role, hosts } = plan;
  check(/^[1-9][0-9]{0,15}$/.test(runId) && attempt === "1" &&
    /^[a-f0-9]{40}$/.test(sourceSha), "IMDS_RUN_INVALID");
  check(GUID.test(tenantId) && GUID.test(subscriptionId) && group === "tt-imds-" + runId + "-1" &&
    /^ttimds[a-f0-9]{18}$/.test(vault) && /^tt-imds-[a-f0-9]{32}$/.test(secret),
    "IMDS_SCOPE_INVALID");
  check(VERSION.test(pinnedVersion) && VERSION.test(newerVersion) && pinnedVersion !== newerVersion &&
    SHA.test(valueSha256) && Number.isSafeInteger(expiresAt) && Number.isSafeInteger(deadlineAt) &&
    deadlineAt <= expiresAt - 600000 && Date.now() + 5 * TIMEOUT_MS < deadlineAt &&
    expiresAt <= Date.now() + 7200000, "IMDS_PIN_OR_DEADLINE_INVALID");
  check(ROLE_NAMES.includes(role) && ROLE_NAMES.every(name => hosts?.[name]) &&
    Object.keys(hosts).length === 2, "IMDS_ROLES_INVALID");
  for (const field of ["vmId", "clientId", "principalId"]) {
    check(ROLE_NAMES.every(name => GUID.test(hosts[name][field])) &&
      hosts.issuer[field] !== hosts.consumer[field], "IMDS_ROLE_BOUNDARY_INVALID");
  }
}

function expectedImdsRequest(url, options, clientId) {
  check(url.origin === IMDS && url.pathname === TOKEN_PATH && !url.hash &&
    !url.username && !url.password && url.searchParams.size === 3 &&
    url.searchParams.get("api-version") === "2018-02-01" &&
    url.searchParams.get("resource") === AUDIENCE && url.searchParams.get("client_id") === clientId &&
    options.headers.Metadata === "true" && (options.method || "GET") === "GET",
  "IMDS_TOKEN_REQUEST_INVALID");
}

// The product transport discards error bodies. Examine only the expected
// structured denial here, and keep all response content out of probe output.
async function requestDenial(url, { method = "GET", headers, body }, status, matchesError) {
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  const client = url.protocol === "https:" ? https : http;
  await new Promise((resolve, reject) => {
    const refused = () => reject(new Error("IMDS_DENIAL_NOT_OBSERVED"));
    const req = client.request(url, {
      method,
      agent: false,
      rejectUnauthorized: true,
      headers: { ...headers, ...(payload && { "Content-Length": payload.length }) },
    }, res => {
      if (res.statusCode !== status) {
        req.destroy();
        refused();
        return;
      }
      const chunks = [];
      let size = 0;
      res.on("data", chunk => {
        size += chunk.length;
        if (size <= 16384) chunks.push(chunk);
        else req.destroy();
      });
      res.on("error", refused);
      res.on("aborted", refused);
      res.on("end", () => {
        try {
          if (size <= 16384 && matchesError(JSON.parse(Buffer.concat(chunks)))) resolve();
          else refused();
        } catch {
          refused();
        }
      });
    });
    const timer = setTimeout(() => req.destroy(), TIMEOUT_MS);
    req.on("close", () => clearTimeout(timer));
    req.on("error", refused);
    req.end(payload);
  });
  return { status, json: null };
}

function tokenMatches(token, tenantId, identity) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return claims.tid === tenantId && claims.oid === identity.principalId &&
      (claims.appid ?? claims.azp) === identity.clientId && claims.aud === AUDIENCE;
  } catch {
    return false;
  }
}

async function observe(plan, { credential, requestJson, deny = requestDenial }) {
  validatePlan(plan);
  const { role, hosts } = plan;
  const own = hosts[role];
  const opposite = hosts[role === "issuer" ? "consumer" : "issuer"];
  const metadata = await requestJson(new URL("/metadata/instance/compute?api-version=2021-02-01", IMDS), {
    timeoutMs: TIMEOUT_MS, maxBytes: 65536, headers: { Metadata: "true" },
  });
  const resourceId = "/subscriptions/" + plan.subscriptionId + "/resourceGroups/" + plan.group +
    "/providers/Microsoft.Compute/virtualMachines/tt-imds-" + role;
  check(metadata.status === 200 && typeof metadata.json?.resourceId === "string" &&
    metadata.json.resourceId.toLowerCase() === resourceId.toLowerCase() &&
    metadata.json.vmId?.toLowerCase() === own.vmId && /^linux$/i.test(metadata.json.osType),
  "IMDS_HOST_IDENTITY_MISMATCH");

  let ownTokenStatus;
  let oppositeIdentityTokenStatus;
  let imdsRequests = 0;
  const access = (clientId, request) => credential(
    { auth: { type: "managed-identity", clientId } }, TIMEOUT_MS,
    (url, options) => {
      expectedImdsRequest(url, options, clientId);
      imdsRequests++;
      return request(url, options);
    },
  )(true);
  const token = await access(own.clientId, async (url, options) => {
    const response = await requestJson(url, options);
    ownTokenStatus = response.status;
    return response;
  });
  check(ownTokenStatus === 200 && tokenMatches(token, plan.tenantId, own), "IMDS_OWN_IDENTITY_INVALID");

  const oppositeDenied = await access(opposite.clientId, async (url, options) => {
    const response = await deny(url, options, 400,
      json => json.error === "invalid_request");
    oppositeIdentityTokenStatus = response.status;
    return response;
  }).then(() => false, error => error?.code === "material_auth_unavailable");
  check(oppositeDenied && oppositeIdentityTokenStatus === 400, "IMDS_OPPOSITE_IDENTITY_DENIAL_MISSING");

  const headers = { Authorization: "Bearer " + token, "Content-Type": "application/json" };
  const secretUrl = new URL("/secrets/" + plan.secret, "https://" + plan.vault + ".vault.azure.net");
  const pinned = new URL(secretUrl.pathname + "/" + plan.pinnedVersion, secretUrl);
  const exactId = pinned.href;
  pinned.searchParams.set("api-version", "7.4");
  const read = await requestJson(pinned, { timeoutMs: TIMEOUT_MS, headers });
  check(read.status === 200 && read.json?.id === exactId &&
    typeof read.json.value === "string" && sha256(read.json.value) === plan.valueSha256,
  "IMDS_EXACT_VERSION_READ_FAILED");
  let azureConsumerWriteStatus = null;
  if (role === "consumer") {
    // The scope owner records this single disposable PUT before starting either command.
    secretUrl.searchParams.set("api-version", "7.4");
    const write = await deny(secretUrl, { method: "PUT", headers, body: { value: "imds-denial-probe" } },
      403, json => json.error?.code === "Forbidden" && json.error?.innererror?.code === "ForbiddenByRbac");
    check(write.status === 403, "IMDS_CONSUMER_WRITE_DENIAL_MISSING");
    azureConsumerWriteStatus = write.status;
  }
  return {
    identity: {
      role, hostIdSha256: sha256(own.vmId), identitySha256: sha256(own.principalId),
      oppositeIdentitySha256: sha256(opposite.principalId), imdsRequests, ownTokenStatus, oppositeIdentityTokenStatus,
    },
    azureReadStatus: read.status, azureConsumerWriteStatus, pinnedVersion: plan.pinnedVersion,
  };
}

async function runHost(planFile, expectedPlanSha256, deadlineAt) {
  check(process.platform === "linux" && process.getuid() !== 0 &&
    !process.env.NODE_TLS_REJECT_UNAUTHORIZED && !process.env.NODE_USE_ENV_PROXY && !process.env.NODE_OPTIONS,
  "IMDS_LINUX_ROLE_PROCESS_REQUIRED");
  const { inspect, verifyIdentity } = require("../../../scripts/certops-azure-keyvault-package.cjs");
  const { extractVerified, verifyInstalled } = require("../../../scripts/certops-agent-package.js");
  check(typeof planFile === "string" && path.isAbsolute(planFile), "IMDS_PLAN_FILE_REQUIRED");
  check(path.normalize(planFile) === planFile && fs.realpathSync(planFile) === planFile,
    "IMDS_PROTECTED_PLAN_REQUIRED");
  for (let directory = path.dirname(planFile); directory !== "/"; directory = path.dirname(directory)) {
    const owner = fs.statSync(directory);
    check(owner.uid === 0 && (owner.mode & 0o022) === 0, "IMDS_PROTECTED_PLAN_REQUIRED");
  }
  const stat = fs.statSync(planFile);
  check(stat.isFile() && stat.uid === 0 && (stat.mode & 0o022) === 0 && stat.size < 16384, "IMDS_PROTECTED_PLAN_REQUIRED");
  const bytes = fs.readFileSync(planFile);
  check(SHA.test(expectedPlanSha256) && sha256(bytes) === expectedPlanSha256, "IMDS_PROTECTED_PLAN_DIGEST_MISMATCH");
  const staged = JSON.parse(bytes);
  check(!Object.hasOwn(staged, "deadlineAt"), "IMDS_UNTRUSTED_DEADLINE_DENIED");
  const plan = { ...staged, deadlineAt: Number(deadlineAt) };
  validatePlan(plan);
  const identity = verifyIdentity(plan.packageArtifact);
  const { archive } = inspect(path.join(path.dirname(planFile), "artifacts"), identity.candidateSha, identity.packageSha256);
  gunzipSync(fs.readFileSync(archive), { maxOutputLength: 64 * 1024 * 1024 });
  const temp = fs.mkdtempSync("/tmp/tt-imds-probe-");
  try {
    const candidate = extractVerified({ tarball: archive, expectedSha256: identity.packageSha256,
      destination: path.join(temp, "extracted") });
    const { credential } = require(path.join(candidate.root, "src/material-store/azure.js"));
    const { requestJson } = require(path.join(candidate.root, "src/material-store/transport.js"));
    const result = await observe(plan, { credential, requestJson });
    verifyInstalled(candidate.files, candidate.root);
    return { runId: plan.runId, attempt: plan.attempt, sourceSha: plan.sourceSha,
      packageArtifact: identity, ...result };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

module.exports = { observe, runHost, sha256 };
if (require.main === module) runHost(...process.argv.slice(2)).then(
  report => process.stdout.write(JSON.stringify(report) + "\n"),
  () => {
    process.stderr.write("CERTOPS_IMDS_PROBE_FAILED\n");
    process.exitCode = 1;
  },
);
