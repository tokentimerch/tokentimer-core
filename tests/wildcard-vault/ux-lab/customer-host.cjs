"use strict";
// Customer-side lab controls only: local policy, process lifecycle and network
// faults. Never imports control-plane services or connects to PostgreSQL.
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const dns = require("node:dns/promises");
const { spawn, spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");
const root = "/lab",
  build = "/lab/experimental-agent";
const source = "/repo/packages/agent";
const agents = new Map();
const fault = {
  armed: false,
  path: null,
  blockedReads: false,
  droppedWrites: 0,
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function json(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}
function run(command, args) {
  const r = spawnSync(command, args, { encoding: "utf8" });
  if (r.status !== 0) throw new Error(command + ": " + r.stderr);
  return r.stdout;
}
function reply(res, value, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(value));
}
function forward(req, res, host, port, { vault = false } = {}) {
  if (
    vault &&
    fault.blockedReads &&
    req.method === "GET" &&
    req.url.split("?")[0] === fault.path
  ) {
    req.resume();
    req.socket.destroy();
    return;
  }
  const drop =
    vault &&
    fault.armed &&
    req.method === "POST" &&
    req.url.includes("/data/") &&
    req.url.includes("/bundles/");
  if (drop) {
    fault.armed = false;
    fault.path = req.url;
    fault.blockedReads = true;
  }
  const up = http.request(
    {
      host,
      port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host },
    },
    (r) => {
      if (drop && r.statusCode === 200) {
        r.resume();
        r.once("end", () => {
          fault.droppedWrites++;
          req.socket.destroy();
        });
        return;
      }
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    },
  );
  up.on("error", () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  req.pipe(up);
}
async function stopAgent(name) {
  const child = agents.get(name);
  if (child && child.exitCode === null) {
    child.kill("SIGTERM");
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      sleep(10000),
    ]);
    assert.notEqual(child.exitCode, null, "agent must stop cleanly");
  }
  agents.delete(name);
}
async function startAgent(name, token) {
  assert.ok(["issuer", "nginx", "haproxy", "cancel-issuer"].includes(name));
  await stopAgent(name);
  const dir = path.join(root, name),
    out = fs.openSync(path.join(dir, "agent.log"), "a", 0o600);
  const env = {
    ...process.env,
    TOKENTIMER_AGENT_CONFIG_DIR: dir,
    NODE_EXTRA_CA_CERTS: "/lab/transport.crt",
    REQUESTS_CA_BUNDLE: "/repo/.scratch/wildcard-ux/pebble-ca.pem",
  };
  if (token) env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN = token;
  const child = spawn(process.execPath, [build + "/bin/tokentimer-agent.js"], {
    env,
    stdio: ["ignore", out, out],
  });
  fs.closeSync(out);
  agents.set(name, child);
  return { started: true, name };
}
function config(name, extra = {}) {
  const dir = path.join(root, name),
    file = path.join(dir, "config.json");
  const old = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
  const base = {
    serverUrl: "https://customers:18443",
    caBundlePath: "/lab/transport.crt",
    heartbeatIntervalMs: 2000,
    pollIntervalMs: 1500,
    declaredTargetSelectors: ["*.wildcard.test", "wildcard.test"],
    declaredCommandProfileNames: ["certbot"],
    policy: {
      allowedTargetSelectors: ["*"],
      allowedPaths: [dir],
      allowedCaEndpoints: ["https://pebble:14000/dir"],
      allowedDnsZones: ["wildcard.test"],
      allowedDnsProviders: ["pebble-challtestsrv"],
      allowedCommands: {
        certbot: {
          argv: [
            "node",
            "/repo/tests/wildcard-vault/ux-lab/certbot-record.cjs",
            "--no-verify-ssl",
            "--agree-tos",
            "--register-unsafely-without-email",
          ],
        },
      },
    },
    execution: {
      enabled: false,
      dryRun: false,
      keysDir: dir + "/custom-issuer-custody",
    },
    dnsProviders: {
      "pebble-challtestsrv": { credentialsFile: dir + "/dns.json" },
      zoneProviderMap: { "wildcard.test": "pebble-challtestsrv" },
    },
    dnsPropagation: {
      checkAuthoritative: false,
      resolvers: [process.env.LAB_DNS_IP + ":8053"],
      timeoutMs: 20000,
      intervalMs: 200,
    },
  };
  json(file, { ...base, ...old, ...extra });
  json(dir + "/dns.json", {
    baseUrl: "http://127.0.0.1:18055",
    allowInsecureLocalHttp: true,
  });
  return JSON.parse(fs.readFileSync(file));
}
function store(workspaceId, groupId, wireId, issuer) {
  return {
    customer: {
      address: "https://127.0.0.1:18200",
      caFile: "/lab/transport.crt",
      mount: "secret",
      tokenFile: "/lab/vault-token",
      timeoutMs: 2000,
      groups: {
        [groupId]: {
          workspaceId,
          prefix: workspaceId + "/" + groupId,
          sans: ["*.wildcard.test", "wildcard.test"],
          keyAlgorithm: "ec",
          ...(issuer
            ? {
                issuerAgentId: wireId,
                issuanceProfileRef: "wildcard",
                profileRevision: 1,
                caEndpoint: "https://pebble:14000/dir",
                dnsProvider: "pebble-challtestsrv",
                dnsZone: "wildcard.test",
              }
            : {}),
        },
      },
    },
  };
}
async function control(body) {
  const { action, name = "issuer" } = body;
  assert.ok(["issuer", "nginx", "haproxy", "cancel-issuer"].includes(name));
  if (action === "enroll") {
    config(
      name,
      body.selectors ? { declaredTargetSelectors: body.selectors } : {},
    );
    return startAgent(name, body.token);
  }
  if (action === "stop") {
    await stopAgent(name);
    return { stopped: true };
  }
  if (action === "start") return startAgent(name);
  if (action === "configure") {
    await stopAgent(name);
    const old = config(name),
      wireId = old.agentId;
    assert.ok(wireId, "normal enrollment must persist wire agent ID");
    const dir = "/lab/" + name;
    const update = {
      materialStores: store(
        body.workspaceId,
        body.groupId,
        wireId,
        name.includes("issuer"),
      ),
      execution: { ...old.execution, enabled: true },
    };
    if (!name.includes("issuer")) {
      const { bindingId, authorizationRevision = 1 } = body;
      update.declaredTargetSelectors = [bindingId];
      update.materialBindings = {
        [bindingId]: {
          workspaceId: body.workspaceId,
          groupId: body.groupId,
          agentId: wireId,
          materialStoreRef: "customer",
          deploymentProfileRef: name,
          profileRevision: 1,
          authorizationRevision,
          verificationPolicy: "trust",
          reloadService: name,
          reloadCommandRefs: {
            validate: "service-validate",
            reload: "service-reload",
          },
          target: {
            type: "endpoint",
            reference: name,
            certPath: dir + "/cert.pem",
            keyPath: dir + "/key.pem",
          },
          probes: [
            {
              dialAddress: "127.0.0.1",
              port: name === "nginx" ? 8443 : 9443,
              sni: name + ".wildcard.test",
              trustCaFile: "/lab/issuer-root.pem",
            },
          ],
        },
      };
      update.policy = {
        ...old.policy,
        allowedCommands: {
          "service-validate": {
            argv: [
              "node",
              "/repo/tests/wildcard-vault/ux-lab/reload.cjs",
              name,
              "validate",
            ],
          },
          "service-reload": {
            argv: [
              "node",
              "/repo/tests/wildcard-vault/ux-lab/reload.cjs",
              name,
              "reload",
            ],
          },
        },
      };
    }
    config(name, update);
    return { configured: true, name, wireId };
  }
  if (action === "fault") {
    fault.armed = true;
    return { armed: true };
  }
  if (action === "clear-fault") {
    fault.armed = false;
    fault.blockedReads = false;
    return { cleared: true };
  }
  if (action === "facts") {
    const c = config(name),
      dir = "/lab/" + name;
    const facts = {
      wireId: c.agentId,
      running: agents.get(name)?.exitCode === null,
      fault: { ...fault },
      orders: fs.existsSync("/lab/orders.jsonl")
        ? fs
            .readFileSync("/lab/orders.jsonl", "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map(JSON.parse)
        : [],
    };
    if (body.certificateId) {
      assert.match(body.certificateId, /^[0-9a-f-]{36}$/);
      const file = path.join(
        c.execution.keysDir,
        body.certificateId + ".key.pem",
      );
      if (fs.existsSync(file)) {
        facts.canonicalPublicKeySha256 = crypto
          .createHash("sha256")
          .update(
            crypto
              .createPublicKey(crypto.createPrivateKey(fs.readFileSync(file)))
              .export({ type: "spki", format: "der" }),
          )
          .digest("hex");
        facts.canonicalMode = (fs.statSync(file).mode & 0o777).toString(8);
      }
      facts.defaultKeyExists = fs.existsSync(
        path.join(dir, "keys", body.certificateId + ".key.pem"),
      );
    }
    return facts;
  }
  throw new Error("unknown lab customer action");
}
async function main() {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  // Disposable artifact only. The repository/shipped capability files are read-only.
  if (!fs.existsSync(build))
    fs.cpSync(source, build, {
      recursive: true,
      filter: (p) => !p.includes("node_modules"),
    });
  const { renderGeneratedModule } = require(
    source + "/scripts/build-qualified-capabilities.js",
  );
  fs.writeFileSync(
    build + "/src/capabilities/qualified-capabilities.generated.js",
    renderGeneratedModule([
      "material-store-vault-kv2-v1",
      "certificate-publication-v1",
      "deploy-from-store-v1",
    ]),
  );
  if (!fs.existsSync(root + "/transport.crt"))
    run("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      root + "/transport.key",
      "-out",
      root + "/transport.crt",
      "-days",
      "7",
      "-subj",
      "/CN=customers",
      "-addext",
      "subjectAltName=DNS:customers,DNS:localhost,IP:127.0.0.1",
    ]);
  fs.chmodSync(root + "/transport.key", 0o600);
  fs.writeFileSync(root + "/vault-token", "ux-lab-only-vault-token", {
    mode: 0o600,
  });
  process.env.LAB_DNS_IP = (await dns.lookup("challtestsrv")).address;
  const tls = {
    key: fs.readFileSync(root + "/transport.key"),
    cert: fs.readFileSync(root + "/transport.crt"),
  };
  https
    .createServer(tls, (req, res) => forward(req, res, "api", 4000))
    .listen(18443, "0.0.0.0");
  https
    .createServer(tls, (req, res) =>
      forward(req, res, "vault", 8200, { vault: true }),
    )
    .listen(18200, "127.0.0.1");
  http
    .createServer((req, res) => forward(req, res, "challtestsrv", 8055))
    .listen(18055, "127.0.0.1");
  // Public throwaway CA root only, retrieved on this isolated bridge.
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const pem = await new Promise((resolve, reject) =>
        https
          .get(
            "https://pebble:15000/roots/0",
            { rejectUnauthorized: false },
            (r) => {
              let s = "";
              r.on("data", (b) => (s += b));
              r.on("end", () => resolve(s));
            },
          )
          .on("error", reject),
      );
      assert.match(pem, /BEGIN CERTIFICATE/);
      fs.writeFileSync("/lab/issuer-root.pem", pem);
      break;
    } catch (e) {
      if (attempt === 59) throw e;
      await sleep(1000);
    }
  }
  http
    .createServer(async (req, res) => {
      try {
        if (req.method === "GET")
          return reply(res, {
            lab: "wildcard-ux",
            databaseAccess: false,
            experimentalArtifact: true,
          });
        let raw = "";
        for await (const b of req) {
          raw += b;
          if (raw.length > 16384) throw new Error("body too large");
        }
        reply(res, await control(JSON.parse(raw)));
      } catch (e) {
        reply(res, { error: e.message }, 400);
      }
    })
    .listen(8085, "0.0.0.0");
  http
    .createServer((req, res) => {
      if (req.url.startsWith("/api/") || req.url.startsWith("/auth/"))
        return forward(req, res, "api", 4000);
      if (req.url === "/env.js") {
        res.setHeader("Content-Type", "application/javascript");
        return res.end('window.__ENV__={API_URL:"http://127.0.0.1:58801"};');
      }
      const relative = decodeURIComponent(req.url.split("?")[0]),
        dist = "/repo/apps/dashboard/dist";
      const requested = path.resolve(dist, "." + relative);
      if (!requested.startsWith(dist + path.sep) && requested !== dist) {
        res.writeHead(403);
        return res.end();
      }
      const file =
        fs.existsSync(requested) && fs.statSync(requested).isFile()
          ? requested
          : dist + "/index.html";
      const types = {
        ".js": "application/javascript",
        ".css": "text/css",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".html": "text/html",
      };
      res.setHeader(
        "Content-Type",
        types[path.extname(file)] || "application/octet-stream",
      );
      res.setHeader("Cache-Control", "no-store");
      fs.createReadStream(file)
        .on("error", () => {
          res.writeHead(503);
          res.end("Build dashboard first");
        })
        .pipe(res);
    })
    .listen(8080, "0.0.0.0");
  console.log(
    "Customer lab ready; no database access. Experimental enrolled agent artifact is volume-local.",
  );
}
main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
process.on("SIGTERM", async () => {
  for (const name of agents.keys()) await stopAgent(name);
  process.exit(0);
});
