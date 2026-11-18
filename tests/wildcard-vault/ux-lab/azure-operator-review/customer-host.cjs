"use strict";
// Customer-side lab controls only: local policy, process lifecycle and network
// faults. Never imports control-plane services or connects to PostgreSQL.
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");
const crypto = require("node:crypto");
const dns = require("node:dns/promises");
const { spawn, spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");
const { capabilityForProvider } = require("./azure-ux-adapter.cjs");
const { tokenFileConfig } = require("./azure-isolated-role.cjs");
const { observationPath, readEvents } = require("./azure-operator-vault-observation.cjs");
const privateCa = process.env.TT_UX_OPERATOR_CA === "openbao-pki" ? require("../operator-ca.cjs") : null;
const root = "/lab";
let build = "/lab/experimental-agent", acceptance, azurePackage;
const roleBuilds = new Map();
const azureObservations = new Map();
const signedJobs = new Map();
const packageMode = process.env.TT_UX_PACKAGE_ACCEPTANCE === "1";
const source = "/repo/packages/agent";
const agents = new Map();
const agentAccounts = new Set();
const roleUid = process.env.TT_UX_ISOLATED_ROLE === "consumer" ? 10002 : 10001;
const processAccount = packageMode ? { uid: roleUid, gid: roleUid } : {};
const scannerRequests = [];
// Retain only genuine signed dispatches, in customer memory. The adversarial
// transport re-delivers these bytes; it never signs jobs or fabricates results.
const dispatches = new Map(), credentials = new Map();
const transportFault = { armed: false, injected: 0, mode: null, target: null, source: null };
const certificateSans = process.env.TT_UX_CERTIFICATE_MODE === "wildcard"
  ? ["*.wildcard.test", "wildcard.test"]
  : process.env.TT_UX_CERTIFICATE_MODE === "ordinary" ? ["nginx.wildcard.test"]
  : ["nginx.wildcard.test", "haproxy.wildcard.test"];
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
  if (packageMode) { fs.chownSync(path.dirname(file), roleUid, roleUid); fs.chownSync(file, roleUid, roleUid); }
}
function run(command, args) {
  const service = command === process.execPath && args[0] === "/repo/tests/wildcard-vault/ux-lab/reload.cjs";
  const r = spawnSync(command, args, { encoding: "utf8", ...(service ? processAccount : {}) });
  if (r.status !== 0) throw new Error(command + ": " + r.stderr);
  return r.stdout;
}
function reply(res, value, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(value));
}
function observeSignedDispatch(envelope, name, expectedId) {
  const build = roleBuilds.get(name);
  const { readSigningKeyPin } = require(path.join(build, "src/config"));
  const { verifyJobEnvelope } = require(path.join(build, "src/signing"));
  const pin = readSigningKeyPin(path.join(root, name));
  if (!pin) return;
  const verdict = verifyJobEnvelope({ claimed: envelope, publicKeyPem: pin.publicKeyPem,
    pinnedSigningKeyId: pin.signingKeyId });
  const jobId = verdict.job?.jobId;
  if (!verdict.allowed || verdict.job.agentId !== expectedId || !/^[a-f0-9-]{36}$/.test(jobId || "")) return;
  assert.ok(signedJobs.size < 128 || signedJobs.has(jobId), "Azure signed dispatch limit exceeded");
  signedJobs.set(jobId, { agent: name, signerKeyIdSha256: crypto.createHash("sha256").update(pin.signingKeyId).digest("hex") });
}
function forward(req, res, host, port, { vault = false } = {}) {
  const claim = host === "api" && req.url === "/api/v1/certops/agent/jobs/claim";
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
      headers: { ...req.headers, host, ...(claim ? { "accept-encoding": "identity" } : {}) },
    },
    (r) => {
      if (claim && r.statusCode === 200) {
        const chunks = [];
        let size = 0;
        r.on("data", chunk => { size += chunk.length; if (size > 2097152) r.destroy(); else chunks.push(chunk); });
        r.on("end", () => {
          try {
            const result = JSON.parse(Buffer.concat(chunks));
            for (const envelope of result.jobs || []) {
              const signed = envelope.envelopeVersion === 2
                ? JSON.parse(Buffer.from(envelope.payloadB64, "base64")) : envelope;
              const names = azurePackage ? roleBuilds.keys() : ["nginx", "haproxy"];
              for (const name of names) {
                const file = path.join(root, name, "config.json");
                if (fs.existsSync(file) && JSON.parse(fs.readFileSync(file, "utf8")).agentId === signed.agentId) {
                  if (azurePackage) observeSignedDispatch(envelope, name, signed.agentId);
                  if (!signed.materialDeployment) continue;
                  dispatches.set(name, structuredClone(envelope));
                  credentials.set(name, req.headers.authorization);
                }
              }
            }
            const f = transportFault;
            // Only idle polls are attacked: never discard a newly claimed job.
            if (f.armed && result.jobs?.length === 0 && req.headers.authorization === credentials.get(f.target)) {
              const envelope = structuredClone(dispatches.get(f.source));
              assert.ok(envelope, "A genuine distribution dispatch must have been captured");
              if (f.mode === "signature") {
                const field = envelope.envelopeVersion === 2 ? "signatureB64" : "signature";
                envelope[field] = Buffer.alloc(64, 1).toString("base64");
              } else if (f.mode === "payload") {
                if (envelope.envelopeVersion === 2) {
                  const signed = JSON.parse(Buffer.from(envelope.payloadB64, "base64"));
                  signed.materialDeployment.materialVersionId = crypto.randomUUID();
                  envelope.payloadB64 = Buffer.from(JSON.stringify(signed)).toString("base64");
                } else envelope.materialDeployment.materialVersionId = crypto.randomUUID();
              }
              result.jobs = [envelope];
              f.armed = false;
              f.injected++;
            }
            const headers = { ...r.headers };
            delete headers["content-length"]; delete headers.etag;
            res.writeHead(r.statusCode, headers);
            res.end(JSON.stringify(result));
          } catch { res.writeHead(502); res.end(); }
        });
        r.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end(); });
        return;
      }
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
  if (acceptance) acceptance.verify(build);
  if (azurePackage) azurePackage.verify(name);
  const agentBuild = roleBuilds.get(name) || build;
  const dir = path.join(root, name),
    out = fs.openSync(path.join(dir, "agent.log"), "a", 0o600);
  const env = {
    ...process.env,
    TOKENTIMER_AGENT_CONFIG_DIR: dir,
    NODE_EXTRA_CA_CERTS: "/lab/transport.crt",
    REQUESTS_CA_BUNDLE: privateCa?.transportCa || "/lab-input/pebble-ca.pem",
    ...(packageMode ? { HOME: dir } : {}),
  };
  if (token) env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN = token;
  delete env.TT_UX_AZURE_PROVIDER_OBSERVATION;
  const args = [agentBuild + "/bin/tokentimer-agent.js"];
  if (azureObservations.has(name)) {
    env.TT_UX_AZURE_PROVIDER_OBSERVATION = JSON.stringify(azureObservations.get(name));
    args.unshift("--require", path.join(__dirname, "azure-operator-vault-observation.cjs"));
  }
  const child = spawn(process.execPath, args, {
    env,
    stdio: ["ignore", out, out],
    ...processAccount,
  });
  if (packageMode) {
    fs.fchownSync(out, roleUid, roleUid);
    assert.match(fs.readFileSync(`/proc/${child.pid}/status`, "utf8"), new RegExp(`^Uid:\\s+${roleUid}\\s+${roleUid}\\s+${roleUid}\\s+${roleUid}$`, "m"));
    agentAccounts.add(name);
  }
  fs.closeSync(out);
  agents.set(name, child);
  return { started: true, name };
}
function config(name, extra = {}) {
  const dir = path.join(root, name),
    file = path.join(dir, "config.json");
  const old = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
  const base = {
    serverUrl: process.env.TT_UX_ISOLATED_ROLE ? "https://127.0.0.1:18443" : "https://customers:18443",
    caBundlePath: "/lab/transport.crt",
    heartbeatIntervalMs: 2000,
    pollIntervalMs: 1500,
    declaredTargetSelectors: certificateSans,
    declaredCommandProfileNames: ["certbot"],
    policy: {
      allowedTargetSelectors: ["*"],
      allowedPaths: [dir],
      allowedCaEndpoints: [privateCa?.caEndpoint || "https://pebble:14000/dir"],
      allowedDnsZones: ["wildcard.test"],
      allowedDnsProviders: [privateCa?.dnsProvider || "pebble-challtestsrv"],
      allowedCommands: {
        certbot: {
          argv: [
            "node",
            "/repo/tests/wildcard-vault/ux-lab/certbot-record.cjs",
            ...(packageMode ? [] : ["--no-verify-ssl"]),
            "--agree-tos",
            "--register-unsafely-without-email",
          ],
        },
      },
    },
    execution: {
      enabled: false,
      dryRun: packageMode,
      keysDir: dir + "/custom-issuer-custody",
    },
    ...(!privateCa || name === "issuer" ? {
      dnsProviders: {
        [privateCa?.dnsProvider || "pebble-challtestsrv"]: { credentialsFile: dir + "/dns.json" },
        zoneProviderMap: { "wildcard.test": privateCa?.dnsProvider || "pebble-challtestsrv" },
      },
      dnsPropagation: {
        checkAuthoritative: false,
        resolvers: [privateCa ? privateCa.dnsResolver(process.env.LAB_DNS_IP) : process.env.LAB_DNS_IP + ":8053"],
        timeoutMs: 20000, intervalMs: 200,
      },
    } : {}),
  };
  json(file, { ...base, ...old, ...extra });
  if (!privateCa || name === "issuer") json(dir + "/dns.json", privateCa?.dnsCredentials() || {
    baseUrl: "http://127.0.0.1:18055", allowInsecureLocalHttp: true,
  });
  return JSON.parse(fs.readFileSync(file));
}
function store(workspaceId, groupId, wireId, issuer, name) {
  if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault") {
    // Configuration descriptors contain identity IDs and protected file paths,
    // never credentials. Actual role grants must be proven by the campaign.
    const descriptor = JSON.parse(fs.readFileSync("/lab-azure-input/role.json", "utf8"));
    const scope = { prefix: (packageMode ? "tokentimer/" : "") + workspaceId + "/" + groupId,
      sans: certificateSans, keyAlgorithm: "ec", ...(issuer ? { issuerAgentId: wireId,
        issuanceProfileRef: "wildcard", profileRevision: 1, caEndpoint: privateCa?.caEndpoint || "https://pebble:14000/dir",
        dnsProvider: privateCa?.dnsProvider || "pebble-challtestsrv", dnsZone: "wildcard.test" } : {}) };
    return tokenFileConfig({ descriptor, role: process.env.TT_UX_ISOLATED_ROLE, name, groupId, workspaceId, scope });
  }
  return {
    customer: {
      provider: process.env.TT_UX_MATERIAL_PROVIDER || "vault-kv2",
      address: "https://127.0.0.1:18200",
      caFile: "/lab/transport.crt",
      mount: "secret",
      tokenFile: "/lab/"+name+"/material-token",
      timeoutMs: 10000,
      groups: {
        [groupId]: {
          workspaceId,
          prefix: (packageMode ? "tokentimer/" : "") + workspaceId + "/" + groupId,
          sans: certificateSans,
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
async function vaultApi(route, method, body) {
  const response = await fetch("http://vault:8200/v1"+route,{method,headers:{"X-Vault-Token":"ux-lab-only-vault-token","Content-Type":"application/json"},body:JSON.stringify(body)});
  assert.ok(response.ok,"Customer-local Vault control failed");
  return response.status===204 ? {} : response.json();
}
async function rotateMaterialToken(name, workspaceId, groupId) {
  if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault") {
    const role=process.env.TT_UX_ISOLATED_ROLE;
    assert.ok(role === "issuer" ? name === "issuer" : role === "consumer" && ["nginx","haproxy"].includes(name));
    // Read under the actual agent UID. The broker alone refreshes this bind;
    // a successful check is not a claim that rotation was exercised.
    const file=role === "issuer" ? "/run/tt-issuer/token.json" : "/run/tt-consumer/token.json";
    const probe=spawnSync(process.execPath,["-e",`const fs=require('node:fs');const v=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));if(typeof v.accessToken!=='string'||!v.accessToken||!(v.expiresOn>Date.now()))process.exit(1)`,file],{...processAccount,timeout:10000,stdio:"ignore"});
    assert.equal(probe.status,0,"role token sink unavailable or expired");
    return;
  }
  if (acceptance) return acceptance.rotate(name, workspaceId, groupId);
  const policy="qualification-"+name+"-"+crypto.randomUUID();
  const capabilities=name.includes("issuer") ? ["create","read"] : ["read"];
  await vaultApi("/sys/policies/acl/"+policy,"PUT",{policy:`path "secret/data/${workspaceId}/${groupId}/bundles/*" { capabilities = ${JSON.stringify(capabilities)} }`});
  const issued=await vaultApi("/auth/token/create","POST",{policies:[policy],no_default_policy:true,ttl:"2h"});
  const history = "/lab/" + name + "/credential-history";
  fs.mkdirSync(history, { recursive: true, mode: 0o700 });
  fs.writeFileSync(history + "/" + crypto.randomUUID() + ".vault-token", issued.auth.client_token, { mode: 0o600 });
  fs.writeFileSync("/lab/"+name+"/material-token",issued.auth.client_token,{mode:0o600});
  fs.chmodSync("/lab/"+name+"/material-token",0o600);
}
async function control(body) {
  if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault") {
    assert.ok(["issuer", "consumer"].includes(process.env.TT_UX_ISOLATED_ROLE), "isolated role required");
    require("./role-dispatch.cjs").authorizeRole(body, process.env.TT_UX_ISOLATED_ROLE);
  }

  if (action === "azure-provider-observe") {
    assert.ok(azurePackage, "exact Azure package acceptance required");
    const c = config(name);
    const { groupId, materialVersionId, phase, workspaceId } = body;
    const build = roleBuilds.get(name);
    const { createMaterialStore } = require(path.join(build, "src/material-store"));
    const provider = "azure-key-vault";
    const store = createMaterialStore(c.materialStores, { provider, groupId, materialVersionId,
      materialStoreRef: "customer", workspaceId });
    const selected = { name, objectName: store.objectRef, phase,
      vaultHost: new URL(c.materialStores.customer.address).hostname };
    assert.equal(fs.existsSync(observationPath(selected)), false, "Azure observation already exists");
    const existing = azureObservations.get(name);
    if (phase === "resume") {
      assert.equal(existing?.phase, "interrupt");
      assert.equal(existing?.objectName, selected.objectName);
      const first = readEvents(existing);
      assert.equal(first.filter(row => row.event === "commit-lost").length, 1);
      assert.ok(first.some(row => row.event === "read-blocked"));
    } else {
      assert.equal(existing, undefined, "a role may observe only one owned Azure provider object");
    }
    await stopAgent(name);
    azureObservations.set(name, selected);
    return { selected: true, objectName: selected.objectName };
  }
  if (action === "azure-provider-events") {
    assert.ok(azurePackage && azureObservations.has(name));
    const selected = azureObservations.get(name);
    const candidates = selected.phase === "resume" ? ["interrupt", "resume"] : [selected.phase];
    return Object.fromEntries(candidates.map(phase => [phase, readEvents({ ...selected, phase })]));
  }
  if (action === "signed-job-proof") {
    assert.ok(azurePackage && /^[a-f0-9-]{36}$/.test(body.jobId || ""));
    const proof = signedJobs.get(body.jobId);
    assert.equal(proof?.agent, name, "verified signed dispatch for requested agent absent");
    return { signerKeyIdSha256: proof.signerKeyIdSha256 };
  }
  const { action, name = "issuer" } = body;
  assert.ok(["issuer", "nginx", "haproxy", "cancel-issuer"].includes(name));
  if (action === "package-proof") {
    if (azurePackage) {
      const names=process.env.TT_UX_ISOLATED_ROLE === "issuer" ? ["issuer"] : ["nginx","haproxy"];
      assert.ok(names.every(role=>agentAccounts.has(role)),"role agent UID not observed");
      for (const role of names) azurePackage.verify(role);
      return { ...azurePackage.selected, packageSha256:azurePackage.selected.archiveSha256,
        role:process.env.TT_UX_ISOLATED_ROLE, agentAccountUid:roleUid, packageFilesUnmodified:true,
        releaseQualification:"not-established" };
    }
    assert.ok(acceptance, "Package acceptance was not requested");
    assert.ok(["issuer", "nginx", "haproxy"].every(role => agentAccounts.has(role)));
    return { ...acceptance.proof(build), agentAccountUid: 10001 };
  }
  if (action === "transport-fault") {
    assert.ok(["signature", "payload", "replay", "foreign-agent"].includes(body.mode));
    assert.ok(["nginx", "haproxy"].includes(name));
    const source = body.mode === "foreign-agent" ? (name === "nginx" ? "haproxy" : "nginx") : name;
    assert.ok(dispatches.has(source) && credentials.has(name));
    assert.equal(transportFault.armed, false);
    Object.assign(transportFault, { armed: true, mode: body.mode, target: name, source });
    return { armed: true, injected: transportFault.injected };
  }
  if (["hold-reload", "release-reload"].includes(action)) {
    assert.ok(["nginx", "haproxy"].includes(name));
    const file = "/lab/" + name + "/hold-reload";
    if (action === "hold-reload") fs.writeFileSync(file, "owned lab barrier", { mode: 0o600 });
    else fs.rmSync(file, { force: true });
    return { held: action === "hold-reload" };
  }
  if (action === "replace-local-material") {
    // Customer-controlled filesystem drift: fetch the retained version locally;
    // neither private material nor the Vault token leaves this customer host.
    assert.ok(["nginx", "haproxy"].includes(name));
    assert.match(body.materialVersionId || "", /^[0-9a-f-]{36}$/);
    await stopAgent(name);
    const c = config(name), groupId = Object.keys(c.materialStores.customer.groups)[0];
    const scope = c.materialStores.customer.groups[groupId];
    let material;
    if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault") {
      assert.match(body.providerVersion || "", /^[a-f0-9]{32}$/);
      const roleBuild = roleBuilds.get(name); assert.ok(roleBuild, "verified role package required");
      const { createMaterialStore } = require(path.join(roleBuild, "src/material-store"));
      [material] = await require("./azure-ux-adapter.cjs").readRetainedAzureBundles({ createMaterialStore, materialStores: c.materialStores,
        workspaceId: scope.workspaceId, groupId, versions: [{ materialVersionId: body.materialVersionId, providerVersion: body.providerVersion }] });
    } else {
      const token = fs.readFileSync("/lab/" + name + "/material-token", "utf8");
      const response = await fetch(`http://vault:8200/v1/secret/data/${scope.prefix}/bundles/${body.materialVersionId}?version=1`, { headers: { "X-Vault-Token": token } });
      assert.equal(response.status, 200);
      material = (await response.json()).data.data;
    }
    assert.equal(material.materialVersionId, body.materialVersionId);
    fs.writeFileSync("/lab/" + name + "/cert.pem", material.certificatePem, { mode: 0o600 });
    fs.writeFileSync("/lab/" + name + "/key.pem", material.privateKeyPem, { mode: 0o600 });
    run(process.execPath, ["/repo/tests/wildcard-vault/ux-lab/reload.cjs", name, "reload"]);
    return { replaced: true, fingerprint: material.fingerprintSha256 };
  }
  if (action === "scanner-requests") return { requests: [...scannerRequests] };
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
  if (action === "enable-discovery") {
    assert.ok(["nginx", "haproxy"].includes(name));
    await stopAgent(name);
    config(name, { discovery: { directories: ["/lab/" + name], intervalMs: 30000 } });
    return startAgent(name);
  }
  if (action === "tls-proof") {
    assert.ok(["nginx", "haproxy"].includes(name));
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: name === "nginx" ? 8443 : 9443,
        servername: process.env.TT_UX_CERTIFICATE_MODE === "ordinary" ? "nginx.wildcard.test" : name + ".wildcard.test",
        ca: fs.readFileSync("/lab/issuer-root.pem"), rejectUnauthorized: true });
      socket.setTimeout(5000, () => socket.destroy(new Error("TLS proof timed out")));
      socket.once("error", reject);
      socket.once("secureConnect", () => {
        const cert = socket.getPeerCertificate();
        resolve({ name, authorized: socket.authorized, fingerprintSha256: cert.fingerprint256.replace(/:/g, "").toLowerCase(),
          subjectAltName: cert.subjectaltname, protocol: socket.getProtocol(), observedAt: new Date().toISOString() });
        socket.destroy();
      });
    });
  }
  if (action === "prepare-signed-dry-run") {
    assert.ok(acceptance || azurePackage, "Signed operator preview is package acceptance only");
    await stopAgent(name);
    const credential = fs.readFileSync(path.join(root, name, "credential"));
    const old = config(name);
    config(name, { execution: { ...old.execution, enabled: true, dryRun: true } });
    await startAgent(name);
    assert.deepEqual(fs.readFileSync(path.join(root, name, "credential")), credential);
    return { prepared: true };
  }
  if (action === "revoke-material-token") {
    if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault")
      throw new Error("Azure revocation requires an independently supplied, scoped fault mechanism");
    if (acceptance) { await acceptance.revoke(name); return { revoked: true }; }
    await vaultApi("/auth/token/revoke","POST",{token:fs.readFileSync("/lab/"+name+"/material-token","utf8")});
    return {revoked:true};
  }
  if (action === "rotate-material-token") {
    if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault")
      throw new Error("Azure rotation must be observed and controlled by the host broker");
    const c=config(name),groupId=Object.keys(c.materialStores.customer.groups)[0];
    await rotateMaterialToken(name,c.materialStores.customer.groups[groupId].workspaceId,groupId);
    return {rotated:true};
  }
  if (["fail-reload", "repair-reload", "reconcile-binding"].includes(action)) {
    assert.ok(["nginx", "haproxy"].includes(name));
    const dir = path.join(root, name);
    if (action === "fail-reload") {
      fs.writeFileSync(path.join(dir, "fail-reload"), "lab-only reload fault", { mode: 0o600 });
      return { armed: true };
    }
    if (action === "repair-reload") {
      fs.rmSync(path.join(dir, "fail-reload"), { force: true });
      run(process.execPath, ["/repo/tests/wildcard-vault/ux-lab/reload.cjs", name, "reload"]);
      return { repaired: true };
    }
    assert.match(body.bindingId || "", /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    await stopAgent(name);
    const result = spawnSync(process.execPath, [(roleBuilds.get(name) || build) + "/bin/reconcile-material-binding.js", body.bindingId], {
      encoding: "utf8", env: { ...process.env, TOKENTIMER_AGENT_CONFIG_DIR: dir },
      ...processAccount,
    });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  }
  if (action === "configure") {
    await stopAgent(name);
    const old = config(name),
      wireId = old.agentId;
    assert.ok(wireId, "normal enrollment must persist wire agent ID");
    const dir = "/lab/" + name;
    await rotateMaterialToken(name,body.workspaceId,body.groupId);
    const update = {
      materialStores: store(
        body.workspaceId,
        body.groupId,
        wireId,
        name.includes("issuer"),
        name,
      ),
      execution: { ...old.execution, enabled: true, dryRun: false },
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
              sni: process.env.TT_UX_CERTIFICATE_MODE === "ordinary" ? "nginx.wildcard.test" : name + ".wildcard.test",
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
      transport: { ...transportFault },
      publicTrustCaPem: fs.readFileSync("/lab/issuer-root.pem", "utf8"),
      orders: fs.existsSync("/lab/orders.jsonl")
        ? fs
            .readFileSync("/lab/orders.jsonl", "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map(JSON.parse)
        : [],
    };
    const log = fs.existsSync(dir + "/agent.log") ? fs.readFileSync(dir + "/agent.log", "utf8") : "";
    facts.security = {
      signatureRejected: (log.match(/failed signature verification/g) || []).length,
      foreignAgentRejected: (log.match(/agent-id binding gate rejected/g) || []).length,
      replayRejected: (log.match(/job_replay_rejected/g) || []).length,
    };
    facts.reloadEvents = fs.existsSync(dir + "/reload-events.jsonl")
      ? fs.readFileSync(dir + "/reload-events.jsonl", "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];
    if (!name.includes("issuer") && fs.existsSync(dir + "/cert.pem")) {
      const certificate = new crypto.X509Certificate(fs.readFileSync(dir + "/cert.pem"));
      facts.certificate = {
        fingerprint256: certificate.fingerprint256,
        subjectAltName: certificate.subjectAltName,
        modifiedAt: fs.statSync(dir + "/cert.pem").mtimeMs,
      };
    }
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
  if (packageMode) fs.chownSync(root, roleUid, roleUid);
  if (packageMode) {
    const receiptPath = "/lab-input/agent-package/artifact.json";
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.candidateSha, process.env.TT_UX_CORE_COMMIT);
    if (process.env.TT_UX_MATERIAL_PROVIDER === "azure-key-vault") {
      assert.match(receipt.archive || "", /^tokentimer-agent-[A-Za-z0-9.+-]+\.tgz$/);
      const { extractVerified, verifyInstalled } = require("/repo/scripts/certops-agent-package");
      azurePackage = require("./azure-package-input.cjs").create({ archivePath: path.join("/lab-input/agent-package/artifacts", receipt.archive), archiveSha256: receipt.sha256,
        candidateSha: receipt.candidateSha, expectedCandidateSha: process.env.TT_UX_CORE_COMMIT, root: "/lab/packaged-agents", extractVerified, verifyInstalled });
      fs.mkdirSync("/lab/packaged-agents", { recursive: false, mode: 0o700 });
      fs.chownSync("/lab/packaged-agents", roleUid, roleUid);
      const roles = process.env.TT_UX_ISOLATED_ROLE === "issuer" ? ["issuer"] : process.env.TT_UX_ISOLATED_ROLE === "consumer" ? ["nginx", "haproxy"] : [];
      assert.ok(roles.length, "isolated Azure role required");
      for (const role of roles) roleBuilds.set(role, azurePackage.prepare(role));
    } else {
      acceptance = require("../package-acceptance.cjs").create({ root, build: "/lab/packaged-agent", receiptPath, artifactsRoot: "/lab-input/agent-package/artifacts" });
      build = acceptance.prepare();
    }
    // Administrative host preparation precedes all unprivileged processes.
    // The ACME subprocess intentionally does not inherit arbitrary CA env vars.
    const transportCa = privateCa?.transportCa || "/lab-input/pebble-ca.pem";
    for (let attempt = 0; !fs.existsSync(transportCa); attempt++) {
      assert.ok(attempt < 60, "Owned ACME transport CA was not delivered");
      await sleep(1000);
    }
    fs.copyFileSync(transportCa, "/usr/local/share/ca-certificates/tt-owned-acme.crt");
    run("update-ca-certificates", []);
    if (acceptance) run("setcap", ["cap_ipc_lock=+ep", "/usr/local/bin/vault"]);
  } else {
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
      capabilityForProvider(process.env.TT_UX_MATERIAL_PROVIDER || "vault-kv2"),
      "certificate-publication-v1",
      "deploy-from-store-v1",
    ]),
  );
  }
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
  if (!privateCa || process.env.TT_UX_ISOLATED_ROLE === "issuer")
    process.env.LAB_DNS_IP = (await dns.lookup(privateCa?.dnsService || "challtestsrv")).address;
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
  if (!privateCa) http
    .createServer((req, res) => forward(req, res, "challtestsrv", 8055))
    .listen(18055, "127.0.0.1");
  // Observe only request methods/paths from the product scanner. No bodies,
  // authentication headers or private material enter the lab evidence.
  http.createServer((req, res) => {
    scannerRequests.push({ method: req.method, path: req.url });
    if (scannerRequests.length > 500) scannerRequests.shift();
    forward(req, res, "vault", 8200);
  }).listen(18020, "0.0.0.0");
  // Public throwaway CA root only, retrieved on this isolated bridge.
  if (privateCa) fs.writeFileSync("/lab/issuer-root.pem", privateCa.loadOperatorRoot());
  else for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const pem = await new Promise((resolve, reject) =>
        https
          .get(
            "https://pebble:15000/roots/0",
            { ca: fs.readFileSync("/lab-input/pebble-ca.pem"), servername: "localhost", rejectUnauthorized: true },
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
    .listen(8085, process.env.TT_UX_ISOLATED_ROLE ? "127.0.0.1" : "0.0.0.0");
  http
    .createServer((req, res) => {
      if (req.url.startsWith("/api/") || req.url.startsWith("/auth/"))
        return forward(req, res, "api", 4000);
      if (req.url === "/env.js") {
        res.setHeader("Content-Type", "application/javascript");
        return res.end('window.__ENV__={API_URL:window.location.origin};');
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
  if (acceptance) await acceptance.close();
  process.exit(0);
});
