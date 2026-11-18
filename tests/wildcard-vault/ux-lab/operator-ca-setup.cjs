"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { randomBytes, X509Certificate } = require("node:crypto");
const { lookup } = require("node:dns/promises");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { setTimeout: delay } = require("node:timers/promises");

const origin = "https://ca.wildcard.test:8200";
const pki = "/v1/pki";
const dnsService = "operator-dns";
const zone = "wildcard.test";
const keyName = "tt-operator.";
const role = "operator";
const issuerName = "operator-ca";
const write = (file, data, mode = 0o600) => fs.writeFileSync(file, data, { flag: "wx", mode });

function create(privateDirectory, outputDirectory) {
  assert.ok(path.isAbsolute(privateDirectory) && path.isAbsolute(outputDirectory));
  assert.notEqual(privateDirectory, outputDirectory);
  fs.mkdirSync(privateDirectory, { mode: 0o700 });
  fs.mkdirSync(outputDirectory, { mode: 0o755 });
  fs.chmodSync(outputDirectory, 0o755);
  try {
    for (const directory of ["bao", "dns"]) fs.mkdirSync(path.join(privateDirectory, directory), { mode: 0o700 });
    const bao = path.join(privateDirectory, "bao");
    const dns = path.join(privateDirectory, "dns");
    const transport = path.join(outputDirectory, "transport.pem");
    const privateKey = path.join(bao, "transport.key");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
      "-subj", "/CN=ca.wildcard.test", "-addext", "subjectAltName=DNS:ca.wildcard.test",
      "-keyout", privateKey, "-out", path.join(bao, "transport.pem"),
    ], { stdio: "ignore" });
    fs.copyFileSync(path.join(bao, "transport.pem"), transport, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(transport, 0o644);
    write(path.join(bao, "bao.hcl"), [
      'api_addr = "' + origin + '"',
      'storage "inmem" {}',
      'listener "tcp" {',
      '  address = "0.0.0.0:8200"',
      '  tls_cert_file = "/inputs/transport.pem"',
      '  tls_key_file = "/inputs/transport.key"',
      '}',
    ].join("\n") + "\n");
    for (const file of ["bao.hcl", "transport.key", "transport.pem"]) {
      // The service runs as the pinned image's dedicated OpenBao account.
      fs.chownSync(path.join(bao, file), 100, 1000);
    }
    fs.chownSync(bao, 100, 1000);
    const keySecretBase64 = randomBytes(32).toString("base64");
    const challengeLabels = ["_acme-challenge", "_acme-challenge.nginx", "_acme-challenge.haproxy"];
    write(path.join(dns, "named.conf"), [
      'options { directory "/tmp/zone"; listen-on { any; }; listen-on-v6 { none; };',
      '    recursion no; allow-query { any; }; minimal-responses no; };',
      `key "${keyName}" { algorithm hmac-sha256; secret "${keySecretBase64}"; };`,
      `zone "${zone}." { type primary; file "/tmp/zone/${zone}"; update-policy {`,
      ...challengeLabels.map(label => `    grant ${keyName} name ${label}.${zone}. TXT;`),
      '}; };',
    ].join("\n") + "\n");
    write(path.join(dns, zone), [
      "$TTL 1",
      "@ IN SOA ns.wildcard.test. hostmaster.wildcard.test. (1 60 30 3600 1)",
      "@ IN NS ns.wildcard.test.",
      "ns IN A 127.0.0.1",
    ].join("\n") + "\n");
    write(path.join(outputDirectory, "dns.json"), JSON.stringify({ server: dnsService, keyName, keySecretBase64 }) + "\n");
  } catch (cause) {
    throw new Error("Owned operator CA preparation failed", { cause });
  }
}

function ownedRun(privateDirectory, outputDirectory) {
  assert.ok(path.isAbsolute(privateDirectory) && path.isAbsolute(outputDirectory));
  assert.equal(path.basename(outputDirectory), "operator-ca");
  const run = path.dirname(outputDirectory);
  assert.match(path.basename(run), /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  assert.equal(privateDirectory, run + "-operator-ca-private");
  return run;
}

function dispose(privateDirectory, outputDirectory) {
  ownedRun(privateDirectory, outputDirectory);
  const remove = (file, directory) => {
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat) return false;
    assert.ok(directory ? stat.isDirectory() : stat.isFile());
    if (!directory) fs.unlinkSync(file);
    return true;
  };
  if (remove(privateDirectory, true)) {
    const files = { bao: ["bao.hcl", "transport.key", "transport.pem"], dns: ["named.conf", zone] };
    for (const [subdirectory, names] of Object.entries(files)) {
      const directory = path.join(privateDirectory, subdirectory);
      if (!remove(directory, true)) continue;
      for (const name of names) remove(path.join(directory, name), false);
      fs.rmdirSync(directory);
    }
    fs.rmdirSync(privateDirectory);
  }
  if (remove(outputDirectory, true)) remove(path.join(outputDirectory, "dns.json"), false);
}

function apiClient(ca) {
  const agent = new https.Agent({ ca });
  let token;
  return {
    authenticate(value) { token = value; },
    close() { agent.destroy(); },
    async request(method, route, value, accepted = [200, 204]) {
      const body = value === undefined ? undefined : Buffer.from(JSON.stringify(value));
      return new Promise((resolve, reject) => {
        const request = https.request(origin + route, {
          agent, method, timeout: 5000,
          headers: {
            ...(token ? { "X-Vault-Token": token } : {}),
            ...(body ? { "Content-Type": "application/json", "Content-Length": body.length } : {}),
          },
        }, response => {
          const chunks = [];
          let bytes = 0;
          response.on("data", chunk => {
            bytes += chunk.length;
            if (bytes > 131072) request.destroy(new Error("Operator CA response exceeds bound"));
            else chunks.push(chunk);
          });
          response.on("error", reject);
          response.on("end", () => {
            try {
              assert.ok(accepted.includes(response.statusCode), "Operator CA rejected " + route);
              resolve(bytes ? JSON.parse(Buffer.concat(chunks)) : {});
            } catch (error) { reject(error); }
          });
        });
        request.on("timeout", () => request.destroy(new Error("Operator CA request timed out")));
        request.on("error", reject);
        request.end(body);
      });
    },
  };
}

async function initialize(outputDirectory) {
  const transport = fs.readFileSync(path.join(outputDirectory, "transport.pem"));
  const api = apiClient(transport);
  try {
    for (let attempt = 0; ; attempt++) {
      try { await api.request("GET", "/v1/sys/health", undefined, [501]); break; }
      catch (error) {
        if (attempt >= 30) throw error;
        await delay(500);
      }
    }
    const initial = await api.request("PUT", "/v1/sys/init", { secret_shares: 1, secret_threshold: 1 });
    await api.request("PUT", "/v1/sys/unseal", { key: initial.keys[0] });
    api.authenticate(initial.root_token);
    await api.request("POST", "/v1/sys/mounts/pki", { type: "pki" }, [204]);
    await api.request("POST", "/v1/sys/mounts/pki/tune", {
      allowed_response_headers: ["Replay-Nonce", "Link", "Location"],
      passthrough_request_headers: ["If-Modified-Since"],
    }, [204]);
    const { data } = await api.request("POST", pki + "/root/generate/internal", {
      common_name: "TokenTimer isolated operator qualification CA", issuer_name: issuerName, ttl: "48h",
    });
    await api.request("POST", pki + "/config/cluster", { path: origin + pki, aia_path: origin + pki });
    await api.request("POST", pki + "/roles/" + role, {
      allowed_domains: [zone], allow_bare_domains: true, allow_subdomains: true,
      allow_wildcard_certificates: true, allow_ip_sans: false, server_flag: true,
      no_store: false, key_type: "ec", key_bits: 256, max_ttl: "1h",
    });
    const { address } = await lookup(dnsService, { family: 4 });
    assert.match(address, /^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/);
    await api.request("POST", pki + "/config/acme", {
      enabled: true, dns_resolver: address + ":53", allowed_roles: [role],
      allowed_issuers: [issuerName], default_directory_policy: "forbid",
    });
    await api.request("POST", "/v1/auth/token/revoke-self", {}, [204]);
    api.authenticate(undefined);
    const descriptor = await api.request("GET", pki + "/roles/" + role + "/acme/directory");
    for (const name of ["newAccount", "newNonce", "newOrder"]) {
      const endpoint = new URL(descriptor[name]);
      assert.equal(endpoint.origin, origin);
      assert.ok(endpoint.pathname.startsWith(pki + "/"));
    }
    const issuer = new X509Certificate(data.certificate);
    assert.ok(issuer.ca && issuer.checkIssued(issuer) && issuer.verify(issuer.publicKey));
    assert.notEqual(issuer.fingerprint256, new X509Certificate(transport).fingerprint256);
    write(path.join(outputDirectory, "issuer.pem"), data.certificate + "\n", 0o644);
    fs.chmodSync(path.join(outputDirectory, "issuer.pem"), 0o644);
  } finally {
    api.close();
  }
}

async function main([action, directory, output]) {
  if (action === "create") return create(directory, output);
  if (action === "create-owned") {
    const run = ownedRun(directory, output);
    assert.equal(fs.realpathSync(run), run, "The owned run directory must be canonical");
    assert.ok(fs.lstatSync(run).isDirectory());
    return create(directory, output);
  }
  if (action === "dispose") return dispose(directory, output);
  assert.equal(action, "initialize");
  assert.ok(path.isAbsolute(directory));
  return initialize(directory);
}

if (require.main === module) main(process.argv.slice(2)).catch(error => {
  const action = ["create", "create-owned", "initialize", "dispose"].includes(process.argv[2]) ? process.argv[2] : "invalid";
  const code = error.cause?.code || error.code || error.name;
  const kind = /^[A-Za-z0-9_]{1,32}$/.test(code || "") ? code : "Error";
  process.stderr.write(`OPENBAO_CA_SETUP_FAILED ${action} ${kind}\n`);
  process.exitCode = 1;
});

module.exports = { dispose };
