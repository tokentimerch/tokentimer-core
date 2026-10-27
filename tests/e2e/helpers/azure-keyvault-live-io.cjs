"use strict";
// Test-only boundary. Every HTTP response still comes from Microsoft Azure;
// faults discard real responses or interrupt sockets, never synthesize a server.
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");
const crypto = require("node:crypto");
const {
  fail,
  REPOSITORY,
  LAB_ENV,
  trustedRef,
} = require("../../../infra/certops-azure-keyvault/policy");
const { save, sleep } = require("../../../infra/certops-azure-keyvault/lab");

function check(value, code = "AZURE_KV_ASSERTION_FAILED") {
  if (!value) fail(code);
}
async function rejects(task, codes) {
  try {
    await task();
  } catch (error) {
    check(codes.includes(error.code), "AZURE_KV_REJECTION_DIAGNOSTIC_MISMATCH");
    return;
  }
  fail("AZURE_KV_EXPECTED_REJECTION_MISSING");
}
async function eventually(task, code, timeoutMs = 600000) {
  const deadline = Date.now() + timeoutMs;
  do {
    if (await task()) return;
    await sleep(5000);
  } while (Date.now() < deadline);
  fail(code);
}
async function assertion(root, env = process.env) {
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  check(
    url.protocol === "https:" &&
      url.hostname.endsWith(".actions.githubusercontent.com") &&
      !url.username &&
      !url.password,
    "AZURE_KV_OIDC_AUTHORITY_DENIED",
  );
  url.searchParams.set("audience", "api://AzureADTokenExchange");
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
    headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` },
  });
  check(response.status === 200, "AZURE_KV_GITHUB_OIDC_UNAVAILABLE");
  const { value } = await response.json();
  check(
    /^[A-Za-z0-9_.-]{20,16384}$/.test(value || ""),
    "AZURE_KV_GITHUB_OIDC_INVALID",
  );
  const claims = JSON.parse(Buffer.from(value.split(".")[1], "base64url"));
  check(
    claims.iss === "https://token.actions.githubusercontent.com" &&
      claims.aud === "api://AzureADTokenExchange" &&
      claims.sub === `repo:${REPOSITORY}:environment:${LAB_ENV}` &&
      trustedRef(env) &&
      claims.ref === env.GITHUB_REF &&
      claims.sha === env.GITHUB_SHA &&
      Number.isFinite(claims.exp),
    "AZURE_KV_GITHUB_OIDC_CONTEXT_DENIED",
  );
  // Entra verifies the JWT signature. This local check only bounds our context.
  process.stdout.write(`::add-mask::${value}\n`);
  const file = path.join(root, "assertion.jwt");
  fs.writeFileSync(file, value, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return { file, expiresAt: claims.exp * 1000 };
}

class FaultBoundary {
  constructor(host) {
    check(
      /^ttkv[a-f0-9]{20}\.vault\.azure\.net$/.test(host),
      "AZURE_KV_FAULT_SCOPE_DENIED",
    );
    this.host = host;
    this.original = https.request;
    this.events = [];
    this.puts = new Map();
    this.fault = null;
  }
  install() {
    const self = this;
    https.request = function (url, options, callback) {
      const target = new URL(url),
        owned = target.hostname === self.host;
      const method = options.method || "GET",
        pathname = target.pathname;
      if (owned) {
        check(
          target.protocol === "https:" &&
            !target.port &&
            options.rejectUnauthorized !== false,
          "AZURE_KV_TLS_REQUIRED",
        );
        if (method === "PUT")
          self.puts.set(pathname, (self.puts.get(pathname) || 0) + 1);
      }
      const fault = owned && self.fault?.path === pathname ? self.fault : null;
      let corrupt = false;
      if (fault?.kind === "real-401" && !fault.used && method === "GET") {
        fault.used = true;
        corrupt = true;
        options = {
          ...options,
          headers: {
            ...options.headers,
            Authorization: "Bearer qualification-invalid-access-token",
          },
        };
      }
      let req;
      req = self.original.call(https, url, options, (response) => {
        if (owned || target.hostname === "login.microsoftonline.com") {
          self.events.push({
            kind: owned ? "vault" : "entra",
            method,
            status: response.statusCode,
            corrupt,
          });
        }
        const losePut =
          fault?.kind === "ambiguous-put" &&
          method === "PUT" &&
          response.statusCode >= 200 &&
          response.statusCode < 300;
        const loseGet =
          ["reset-get", "timeout-get"].includes(fault?.kind) &&
          !fault.used &&
          method === "GET" &&
          response.statusCode === 200;
        if (losePut || loseGet) {
          fault.used = true;
          response.on("error", () => {});
          response.resume();
          response.on("end", () => {
            if (losePut) fault.committed = true;
            const disconnect = () => {
              const error = Object.assign(
                new Error("qualification transport interruption"),
                {
                  code:
                    fault.kind === "timeout-get" ? "ETIMEDOUT" : "ECONNRESET",
                },
              );
              req.destroy(error);
              // The upstream may already have closed after draining. Deliver
              // the lost-response error to our caller even in that ordering.
              req.emit("error", error);
            };
            // A bounded, deliberately lost response after actual Azure success.
            // The deadline is at this client boundary, not an invented Azure 408.
            if (fault.kind === "timeout-get") setTimeout(disconnect, 100);
            else disconnect();
          });
          return;
        }
        callback(response);
      });
      if (
        owned &&
        method === "GET" &&
        self.fault?.kind === "ambiguous-put" &&
        self.fault.committed &&
        self.fault.blockReads
      ) {
        // Recovery is temporarily disconnected too: success must remain unknown.
        process.nextTick(() =>
          req.destroy(
            Object.assign(new Error("qualification recovery disconnected"), {
              code: "ECONNRESET",
            }),
          ),
        );
      }
      return req;
    };
    return this;
  }
  restore() {
    https.request = this.original;
    this.fault = null;
  }
  set(kind, pathname, extra = {}) {
    this.fault = { kind, path: pathname, used: false, ...extra };
    return this.fault;
  }
  clear() {
    this.fault = null;
  }
}

function makeMaterial(root) {
  const dir = path.join(root, "test-ca");
  fs.mkdirSync(dir, { mode: 0o700 });
  function openssl(args) {
    const result = cp.spawnSync("openssl", args, {
      cwd: dir,
      encoding: "utf8",
      timeout: 30000,
      windowsHide: true,
    });
    check(
      !result.error && result.status === 0,
      "AZURE_KV_FIXTURE_CA_GENERATION_FAILED",
    );
  }
  // Ephemeral test CA, not an ACME/AD CS issuance qualification. All keys stay
  // in the protected customer-side runner directory and the disposable vault.
  fs.writeFileSync(
    path.join(dir, "leaf.ext"),
    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:valid.example.com,DNS:www.valid.example.com\n",
  );
  fs.writeFileSync(
    path.join(dir, "ca.ext"),
    "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n",
  );
  openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "root.key",
    "-out",
    "root.pem",
    "-days",
    "2",
    "-subj",
    "/CN=Ephemeral KV Qualification Root",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
  ]);
  openssl([
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "ca.key",
    "-out",
    "ca.csr",
    "-subj",
    "/CN=Ephemeral KV Qualification Intermediate",
  ]);
  openssl([
    "x509",
    "-req",
    "-in",
    "ca.csr",
    "-CA",
    "root.pem",
    "-CAkey",
    "root.key",
    "-set_serial",
    "2",
    "-out",
    "ca.pem",
    "-days",
    "2",
    "-extfile",
    "ca.ext",
  ]);
  openssl([
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "leaf.key",
    "-out",
    "leaf.csr",
    "-subj",
    "/CN=valid.example.com",
  ]);
  for (const n of [1, 2])
    openssl([
      "x509",
      "-req",
      "-in",
      "leaf.csr",
      "-CA",
      "ca.pem",
      "-CAkey",
      "ca.key",
      "-set_serial",
      String(100 + n),
      "-out",
      `leaf${n}.pem`,
      "-days",
      "1",
      "-extfile",
      "leaf.ext",
    ]);
  for (const file of fs.readdirSync(dir))
    fs.chmodSync(path.join(dir, file), 0o600);
  const read = (name) => fs.readFileSync(path.join(dir, name), "utf8");
  const materials = [1, 2].map((n) => ({
    certificatePem: read(`leaf${n}.pem`) + read("ca.pem") + read("root.pem"),
    privateKeyPem: read("leaf.key"),
  }));
  for (const material of materials) verifyMaterial(material);
  return materials;
}
function verifyMaterial(bundle) {
  const blocks = bundle.certificatePem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  check(blocks?.length === 3, "AZURE_KV_FULL_CHAIN_MISSING");
  const certs = blocks.map((block) => new crypto.X509Certificate(block));
  check(
    certs[0].checkPrivateKey(crypto.createPrivateKey(bundle.privateKeyPem)) &&
      certs[0].verify(certs[1].publicKey) &&
      certs[1].ca &&
      certs[1].verify(certs[2].publicKey) &&
      certs[2].ca &&
      certs[2].verify(certs[2].publicKey),
    "AZURE_KV_MATERIAL_ASSOCIATION_FAILED",
  );
  return crypto.createHash("sha256").update(certs[0].raw).digest("hex");
}
function safeCode(error) {
  return /^AZURE_KV_[A-Z0-9_]{1,180}$/.test(error?.code || "")
    ? error.code
    : "AZURE_KV_SCENARIO_FAILED_SENSITIVE_DETAILS_SUPPRESSED";
}
module.exports = {
  check,
  rejects,
  eventually,
  assertion,
  FaultBoundary,
  makeMaterial,
  verifyMaterial,
  safeCode,
  save,
};
