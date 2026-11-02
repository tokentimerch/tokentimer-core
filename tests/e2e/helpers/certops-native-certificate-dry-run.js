"use strict";
/** Real Linux signed certificate dry-run qualification, imported by the native
 * agent journey. Local CA-signed leaves, protected files and an actual TLS
 * listener are independent side-effect oracles. Positive controls execute the
 * production deploy path and an intentionally failing external-command adapter;
 * the latter proves sentinel sensitivity, not ACME or DNS-provider issuance. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), http = require("node:http"), https = require("node:https"), tls = require("node:tls"), { spawnSync } = require("node:child_process");
const scenarios = ["native-agent-certificate-deploy-dry-run", "native-agent-certificate-renew-dry-run", "native-agent-certificate-real-deploy-control", "native-agent-certificate-command-sentinel-control"];
const scope = "native-linux-signed-certificate-dry-run-with-local-command-controls";
const requiredSources = ["tests/e2e/helpers/certops-native-certificate-dry-run.js", "packages/agent/src/index.js", "apps/api/services/certops/jobs.js", "apps/api/services/certops/agentDispatch.js"];
const trueFields = ["deployDryRunComplete", "renewDryRunComplete", "authenticPlanEvidence", "deployedFilesUnchangedDuringDryRun", "custodyFilesUnchangedDuringDryRun", "servedLeafUnchangedDuringDryRun", "noCommandsOrGatewayCallsDuringDryRun", "realDeployChangedFileAndTrustedTls", "realValidateAndReloadObserved", "realRenewCommandReachedCaAndDnsSentinels", "renewControlFailedBeforeIssuance", "identityAndConfigRestored", "ownedResourcesCleaned"];
function verifyFacts(facts) {
  assert.deepEqual(Object.keys(facts).sort(), [...trueFields, "scope", "admission", "dryRunOperations", "deployPlanSteps", "renewPlanSteps", "validateCalls", "reloadCalls", "caSentinelCalls", "dnsSentinelCalls"].sort());
  assert.equal(facts.scope, scope); assert.equal(facts.admission, "production-service-explicit-mode");
  for (const field of trueFields) assert.equal(facts[field], true, field);
  for (const [field, expected] of Object.entries({ dryRunOperations: 2, deployPlanSteps: 3, renewPlanSteps: 6, validateCalls: 1, reloadCalls: 1, caSentinelCalls: 1, dnsSentinelCalls: 1 })) assert.equal(facts[field], expected, field);
  return true;
}
function snapshotTree(directory) {
  const result = [];
  function visit(current, relative) {
    const stat = fs.lstatSync(current); assert.equal(stat.isSymbolicLink(), false, "Owned dry-run fixture must not traverse symlinks");
    const entry = { path: relative, mode: stat.mode & 0o777, inode: stat.ino, type: stat.isDirectory() ? "directory" : "file" };
    if (stat.isFile()) entry.sha256 = crypto.createHash("sha256").update(fs.readFileSync(current)).digest("hex");
    else assert.equal(stat.isDirectory(), true);
    result.push(entry);
    if (stat.isDirectory()) for (const name of fs.readdirSync(current).sort()) visit(path.join(current, name), path.join(relative, name));
  }
  visit(directory, "."); return result;
}
async function qualifyNativeCertificateDryRun({ gate, fixture, prefix, configDir, root, stop, start, wait, row, prohibited }) {
  assert.equal(process.platform, "linux");
  const directory = fs.mkdtempSync(path.join(root, "certificate-dry-run-")), configFile = path.join(configDir, "config.json"), original = fs.readFileSync(configFile);
  const identity = ["credential", "signing-key-pin.json"].map(name => crypto.createHash("sha256").update(fs.readFileSync(path.join(configDir, name))).digest("hex"));
  const file = name => path.join(directory, name), domain = "dry-run.example.test", calls = { validate: 0, reload: 0, ca: 0, dns: 0 };
  let gateway, server, primary, restored = false, cleaned = false, leafB, baseline, initialFingerprint, stage = "certificate-fixture";
  const keyFile = file("active.key.pem"), certFile = file("active.cert.pem"), custodyDir = file("custody");
  const openssl = args => { const result = spawnSync("openssl", args, { stdio: "ignore", timeout: 20000 }); assert.equal(result.status, 0, "Owned public certificate fixture generation must succeed"); };
  const probe = () => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, servername: domain, ca: fs.readFileSync(file("ca.cert.pem")), rejectUnauthorized: true }, () => { const fingerprint = new crypto.X509Certificate(socket.getPeerCertificate().raw).fingerprint256; socket.end(); resolve(fingerprint); });
    socket.setTimeout(5000, () => socket.destroy(new Error("Owned TLS probe timed out"))); socket.once("error", reject);
  });
  async function create(operation, mode, payload) {
    // Generic public jobs intentionally do not accept a selectable execution
    // mode. Use the same production admission service as scheduler callers;
    // no row, result, dispatch, nonce, lease or evidence is manufactured.
    const job = await require("../../../apps/api/services/certops/jobs").createCertificateJob({ client: fixture.pool, workspaceId: fixture.workspaceId, requestedByUserId: fixture.userId, operation, source: "api", mode, subjectType: "domain", subjectId: domain, payload });
    assert.equal(job.mode, mode); return job.id;
  }
  async function finished(id, expected) {
    await wait(async () => ["dry_run_complete", "succeeded", "failed", "rejected", "blocked"].includes((await row(id)).status));
    const observed = await row(id); assert.equal(observed.status, expected, `Actual ${expected} native result required`); assert.equal(observed.attempt_count, 1);
    return (await fixture.pool.query("SELECT evidence_type,metadata->>'summary' AS summary,metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 ORDER BY id", [fixture.workspaceId, id])).rows;
  }
  function plan(evidence, operation, expectedSteps) {
    const rows = evidence.filter(item => item.evidence_type === "policy.checked" && item.summary.startsWith(`Dry run plan for ${operation} `)); assert.equal(rows.length, expectedSteps);
    const steps = [];
    for (let index = 0; index < rows.length; index++) {
      const metadata = Array.isArray(rows[index].metadata) ? Object.fromEntries(rows[index].metadata.map(item => [item.name, item.value])) : rows[index].metadata;
      assert.equal(metadata.dryRun, true); assert.equal(metadata.jobMode, "dry_run"); assert.equal(metadata.action, operation); steps.push(metadata.planStep);
    }
    assert.deepEqual(steps.sort((a, b) => a - b), Array.from({ length: expectedSteps }, (_, index) => index + 1));
    assert.equal(evidence.some(item => ["deployment.updated", "issuance.completed"].includes(item.evidence_type)), false);
  }
  async function unchanged() { assert.deepEqual(snapshotTree(directory), baseline); assert.equal(await probe(), initialFingerprint); assert.deepEqual(calls, { validate: 0, reload: 0, ca: 0, dns: 0 }); }
  async function close(listener) { if (!listener?.listening) return; listener.closeAllConnections?.(); await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve())); }
  try {
    fs.chmodSync(directory, 0o700); fs.mkdirSync(custodyDir, { mode: 0o700 });
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", file("ca.key.pem"), "-out", file("ca.cert.pem"), "-days", "2", "-subj", "/CN=Owned dry-run fixture CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile, "-out", file("leaf.csr.pem"), "-subj", `/CN=${domain}`]);
    fs.writeFileSync(file("leaf.ext"), `subjectAltName=DNS:${domain}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`, { mode: 0o600 });
    for (const [name, serial] of [["initial.cert.pem", "101"], ["replacement.cert.pem", "102"]]) openssl(["x509", "-req", "-in", file("leaf.csr.pem"), "-CA", file("ca.cert.pem"), "-CAkey", file("ca.key.pem"), "-set_serial", serial, "-out", file(name), "-days", "1", "-extfile", file("leaf.ext")]);
    for (const name of ["ca.key.pem", "active.key.pem"]) { fs.chmodSync(file(name), 0o600); prohibited.add(fs.readFileSync(file(name), "utf8").trim()); }
    fs.copyFileSync(file("initial.cert.pem"), certFile); fs.chmodSync(certFile, 0o644);
    leafB = fs.readFileSync(file("replacement.cert.pem"), "utf8");
    stage = "public-certificate-import";
    const imported = await fixture.request(`${prefix}/certificates`, "POST", { certificatePem: leafB, sourceRef: "Owned native dry-run fixture" }); assert.equal(imported.status, 201); const certificateId = String(imported.body.items[0].id);
    fs.copyFileSync(keyFile, path.join(custodyDir, `${certificateId}.key.pem`)); fs.chmodSync(path.join(custodyDir, `${certificateId}.key.pem`), 0o600);
    stage = "owned-tls-and-gateway";
    server = https.createServer({ key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) }, (_request, response) => response.end("Owned dry-run TLS fixture"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    gateway = http.createServer((request, response) => {
      const route = request.url;
      if (request.method !== "POST" || !["/validate", "/reload", "/ca/directory", "/dns/present"].includes(route)) { response.writeHead(404).end(); return; }
      try {
        if (route === "/validate") { assert.equal(new crypto.X509Certificate(fs.readFileSync(certFile)).checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyFile))), true); calls.validate++; }
        if (route === "/reload") { server.setSecureContext({ key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) }); calls.reload++; }
        if (route === "/ca/directory") calls.ca++;
        if (route === "/dns/present") calls.dns++;
        response.writeHead(204).end();
      } catch { response.writeHead(500).end(); }
    });
    await new Promise((resolve, reject) => { gateway.once("error", reject); gateway.listen(0, "127.0.0.1", resolve); });
    const endpoint = `http://127.0.0.1:${gateway.address().port}`, script = file("command-control.cjs");
    fs.writeFileSync(script, `"use strict";\n(async()=>{const base=process.argv[2],kind=process.argv[3];const routes=kind==="acme"?["/ca/directory","/dns/present"]:["/"+kind];for(const route of routes){const response=await fetch(base+route,{method:"POST",signal:AbortSignal.timeout(5000)});if(response.status!==204)process.exit(72);}if(kind==="acme")process.exit(73);})().catch(()=>{process.exitCode=74;});\n`, { mode: 0o600 });
    fs.writeFileSync(file("dns-credentials.json"), JSON.stringify({ baseUrl: endpoint }), { mode: 0o600 });
    stage = "agent-configuration";
    await stop(); const config = JSON.parse(original); config.execution.keysDir = custodyDir; config.policy.allowedPaths = [directory]; config.policy.allowedCaEndpoints = [endpoint + "/ca/directory"]; config.policy.allowedDnsZones = ["example.test"]; config.policy.allowedDnsProviders = ["pebble-challtestsrv"];
    config.policy.allowedCommands = Object.fromEntries(["validate", "reload", "acme"].map(kind => [`dry-run-${kind}`, { argv: [process.execPath, script, endpoint, kind] }]));
    config.declaredTargetSelectors = [domain]; config.declaredCommandProfileNames = Object.keys(config.policy.allowedCommands); config.dnsProviders = { "pebble-challtestsrv": { credentialsFile: file("dns-credentials.json") }, zoneProviderMap: { "example.test": "pebble-challtestsrv" } };
    fs.writeFileSync(configFile, JSON.stringify(config), { mode: 0o600 }); start();
    const payload = { certificateId, target: { type: "domain", reference: domain }, certPath: certFile, reloadService: "nginx", reloadCommandRefs: { validate: "dry-run-validate", reload: "dry-run-reload" } };
    const renew = { ...payload, commandRef: "dry-run-acme", acmeKind: "certbot", caEndpoint: endpoint + "/ca/directory", dnsZone: "example.test", dnsProvider: "pebble-challtestsrv", keyRotation: true };
    stage = "trusted-baseline";
    baseline = snapshotTree(directory); initialFingerprint = await probe(); assert.notEqual(initialFingerprint, new crypto.X509Certificate(leafB).fingerprint256);
    stage = "native-certificate-scenarios";
    await gate.scenario(scenarios[0], async () => { plan(await finished(await create("deploy", "dry_run", payload), "dry_run_complete"), "deploy", 3); await unchanged(); }, { oracle: "Actual signed native deploy plan completes dry_run_complete with three persisted steps; exact owned file/custody inventory, trusted served leaf and all side-effect counters remain unchanged" });
    await gate.scenario(scenarios[1], async () => { plan(await finished(await create("renew", "dry_run", renew), "dry_run_complete"), "renew", 6); await unchanged(); }, { oracle: "Actual signed native renewal plan completes dry_run_complete with six persisted steps; key rotation, external ACME/DNS commands, deployment and reload remain absent" });
    await gate.scenario(scenarios[2], async () => {
      const evidence = await finished(await create("deploy", "real", payload), "succeeded");
      assert.equal(new crypto.X509Certificate(fs.readFileSync(certFile)).fingerprint256, new crypto.X509Certificate(leafB).fingerprint256); assert.equal(await probe(), new crypto.X509Certificate(leafB).fingerprint256);
      assert.equal(evidence.some(item => item.evidence_type === "deployment.updated"), true); assert.deepEqual(calls, { validate: 1, reload: 1, ca: 0, dns: 0 });
    }, { oracle: "Positive control runs actual atomic certificate deployment and allowlisted validate/reload children, changes the real trusted TLS leaf and independently proves side-effect sensitivity" });
    await gate.scenario(scenarios[3], async () => {
      const deployed = fs.readFileSync(certFile), fingerprint = await probe();
      const evidence = await finished(await create("renew", "real", renew), "failed"); assert.deepEqual(calls, { validate: 1, reload: 1, ca: 1, dns: 1 });
      assert.equal(evidence.some(item => item.evidence_type === "validation.failed" && item.metadata?.step === "acme" && item.metadata?.exitCode === 73), true);
      assert.deepEqual(fs.readFileSync(certFile), deployed); assert.equal(await probe(), fingerprint);
    }, { oracle: "Real renewal invokes the allowlisted external-command adapter and independently observed CA/DNS HTTP sentinels, then deliberately exits before issuance; this is not ACME or DNS-provider qualification" });
  } catch (error) { gate.report.nativeCertificateDryRunDiagnostics = { stage, code: /^[A-Z0-9_]{1,64}$/.test(error?.code || "") ? error.code : "UNCLASSIFIED" }; primary = error; throw error; }
  finally {
    const failures = []; let drained = false;
    try { await stop(); drained = true; fs.writeFileSync(configFile, original, { mode: 0o600 }); assert.deepEqual(["credential", "signing-key-pin.json"].map(name => crypto.createHash("sha256").update(fs.readFileSync(path.join(configDir, name))).digest("hex")), identity); restored = true; } catch (error) { failures.push(error); }
    for (const listener of [gateway, server]) try { await close(listener); } catch (error) { failures.push(error); }
    if (drained) {
      try { assert.equal(path.dirname(path.resolve(directory)), path.resolve(root)); assert.ok(path.basename(directory).startsWith("certificate-dry-run-")); fs.rmSync(directory, { recursive: true, force: true }); assert.equal(fs.existsSync(directory), false); cleaned = true; } catch (error) { failures.push(error); }
      if (restored) try { start(); } catch (error) { failures.push(error); }
    }
    if (failures.length) throw new AggregateError(primary ? [primary, ...failures] : failures, "Native certificate dry-run qualification cleanup failed");
  }
  const facts = { scope, admission: "production-service-explicit-mode", dryRunOperations: 2, deployPlanSteps: 3, renewPlanSteps: 6, validateCalls: calls.validate, reloadCalls: calls.reload, caSentinelCalls: calls.ca, dnsSentinelCalls: calls.dns };
  for (const field of trueFields) facts[field] = field === "identityAndConfigRestored" ? restored : field === "ownedResourcesCleaned" ? cleaned : true;
  verifyFacts(facts); gate.report.nativeCertificateDryRun = facts;
  gate.report.fixtureSources ??= [];
  for (const source of requiredSources) gate.report.fixtureSources.push({ file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../../..", source))).digest("hex") });
}
module.exports = { scenarios, scope, trueFields, requiredSources, verifyFacts, snapshotTree, qualifyNativeCertificateDryRun };
