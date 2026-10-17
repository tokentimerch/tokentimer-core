/**
 * Full agent/API/filesystem certificate journey against the owned Pebble ACME CA.
 * scripts/certops-real-acme.js provisions the local CA/challenge server and selected
 * ACME client. Public discovery/claims, actual issuance/renewal, trusted served TLS and
 * persisted evidence are checked; all keys, paths and child processes belong to the run. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const stageFaults = require("./helpers/certops-acme-stage-faults");
const { startOwnedAcmeProxy } = require("./helpers/certops-acme-transparent-proxy");
const { Resolver } = require("node:dns/promises");
const { spawn, spawnSync } = require("node:child_process");

function localEndpoint(value, protocol) {
  const url = new URL(value);
  assert.equal(url.protocol, protocol);
  assert.ok(["localhost", "127.0.0.1", "[::1]"].includes(url.hostname), "qualification CA must be loopback only");
  return url.href;
}
async function waitUntil(check, timeoutMs = 180000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Real ACME journey exceeded its deadline");
}
module.exports = async function qualifyAcme({ pool, baseUrl, workspaceId, createBootstrap, repoRoot, runScenario = async (_name, action) => action() }) {
  const acmeKind = process.env.CERTOPS_REAL_ACME_CLIENT || "certbot";
  assert.ok(["certbot", "acme.sh"].includes(acmeKind), "Only declared real ACME clients are qualified");
  const reuseProofPath = path.join(repoRoot, "qualification-results", `acme-key-reuse-${acmeKind === "certbot" ? "certbot" : "acmesh"}.json`);
  fs.rmSync(reuseProofPath, { force: true });
  const backgroundProofPath=path.join(repoRoot,"qualification-results",`acme-background-${acmeKind === "certbot" ? "certbot" : "acmesh"}.json`);
  fs.rmSync(backgroundProofPath,{force:true});
  const stageProofPath = path.join(repoRoot,"qualification-results",`acme-stage-faults-${acmeKind === "certbot" ? "certbot" : "acmesh"}.json`);
  fs.rmSync(stageProofPath,{force:true});
  const bulkReport=require("../../scripts/certops-acme-bulk-report");
  const adoptionReport=require("../../scripts/certops-acme-native-adoption-report");
  if(process.env.CERTOPS_REPORT_SCOPE===adoptionReport.SCOPE)fs.rmSync(path.join(repoRoot,adoptionReport.SIDECAR),{force:true});
  if(process.env.CERTOPS_REPORT_SCOPE===bulkReport.SCOPE)fs.rmSync(path.join(repoRoot,bulkReport.SIDECAR),{force:true});
  const commandRef = acmeKind === "certbot" ? "qualification-certbot" : "qualification-acmesh";
  let commandArgv = acmeKind === "certbot" ? ["certbot", "--no-verify-ssl", "--agree-tos", "--register-unsafely-without-email"] : ["bash", process.env.CERTOPS_LINUX_ACMESH, "--insecure", "--accountemail", "certops@example.test"];
  if (acmeKind === "acme.sh") assert.ok(path.isAbsolute(process.env.CERTOPS_LINUX_ACMESH || "") && fs.existsSync(process.env.CERTOPS_LINUX_ACMESH), "Pinned acme.sh executable required");
  const upstreamCaEndpoint = localEndpoint(process.env.CERTOPS_PEBBLE_DIRECTORY, "https:");
  let caEndpoint = upstreamCaEndpoint;
  const dnsEndpoint = localEndpoint(process.env.CERTOPS_PEBBLE_DNS_API, "http:");
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-real-acme-"));
  const domain = `certops-${crypto.randomBytes(6).toString("hex")}.example.test`;
  const requestedNames = [domain, `*.${domain}`, `alternate.${domain}`];
  const verifyNames = (leaf) => assert.deepEqual(leaf.subjectAltName.split(/,\s*/).map((name) => name.replace(/^DNS:/, "")).sort(), [...requestedNames].sort(), "Issued leaf must preserve exactly the requested apex wildcard and additional SAN");
  const publicKeyDer = (leaf) => leaf.publicKey.export({ type: "spki", format: "der" });
  const resolver = new Resolver({ timeout: 2000, tries: 1 }); resolver.setServers([process.env.CERTOPS_PEBBLE_DNS_RESOLVER || "127.0.0.1:8053"]);
  const verifyDnsCleanup = async () => {
    for (const name of new Set(requestedNames.map((name) => `_acme-challenge.${name.replace(/^\*\./, "")}`))) {
      try { assert.deepEqual(await resolver.resolveTxt(name), [], "Actual authoritative DNS must contain no residual challenge TXT values"); }
      catch (error) { if (!["ENODATA", "ENOTFOUND"].includes(error.code)) throw error; }
    }
  };
  const agentId = `acme-${crypto.randomUUID()}`;
  const certPath = path.join(workDir, "deployed", "fullchain.pem");
  const configDir = path.join(workDir, "agent");
  const discoveryDir=path.join(workDir,"discovery");
  let agent, certificateId, jobId, tlsServer, primaryError, publicSession, gateway, barrierDirectory;
  let agentClosed=false;
  const ownedTlsSockets=new Set();
  let stageCases, nativeConsole, nativeLifecycle, nativeDiscovery, bulkProof, resultGateway;
  const closedAgents=new WeakSet();
  const ownedJobIds=[], ownedCertificateIds=[], ownedWorkers=[], ownedBrowserResources=[], ownedBulkResources=[], ownedAdoptionResources=[], ownedRestartResources=[], ownedProfileResources=[], ownedLeaseResources=[];
  try {
  fs.mkdirSync(configDir, { mode: 0o700 });
  barrierDirectory=path.join(workDir,"command-barrier");fs.mkdirSync(barrierDirectory,{mode:0o700});
  commandArgv=[process.execPath,path.join(repoRoot,"tests/e2e/helpers/certops-acme-command-barrier.js"),barrierDirectory,...commandArgv];
  const credentialsFile = path.join(configDir, "dns.json");
  fs.writeFileSync(credentialsFile, JSON.stringify({ baseUrl: dnsEndpoint, allowInsecureLocalHttp: true }), { mode: 0o600 });
  if(process.env.CERTOPS_REPORT_SCOPE===bulkReport.SCOPE)resultGateway=await require("./helpers/certops-acme-result-outage").startResultOutageGateway({upstreamUrl:baseUrl});
  const config = {
    serverUrl: resultGateway?.agentUrl || baseUrl, agentId, allowInsecureLocalHttp: true,
    pollIntervalMs: 500, heartbeatIntervalMs: 1000,
    declaredTargetSelectors: [domain], declaredCommandProfileNames: [commandRef],
    execution: { enabled: true, dryRun: false },
    discovery:{directories:[discoveryDir],intervalMs:1000},
    windowsDiscovery:{enabled:false},
    policy: { allowedPaths: [workDir], allowedCommands: { [commandRef]: { argv: commandArgv } }, allowedCaEndpoints: [caEndpoint], allowedDnsZones: ["example.test"], allowedDnsProviders: ["pebble-challtestsrv"] },
    dnsProviders: { "pebble-challtestsrv": { credentialsFile }, zoneProviderMap: { "example.test": "pebble-challtestsrv" } },
    dnsPropagation: { resolvers: [process.env.CERTOPS_PEBBLE_DNS_RESOLVER || "127.0.0.1:8053"], checkAuthoritative: false, intervalMs: 500, timeoutMs: 30000 },
  };
  const eabRef = process.env.CERTOPS_REAL_ACME_EAB === "required" ? "qualification-account" : null;
  let eabSecret;
  let invalidEabSecret;
  if (eabRef) {
    assert.ok(path.isAbsolute(process.env.CERTOPS_PEBBLE_EAB_FILE || ""));
    const account = JSON.parse(fs.readFileSync(process.env.CERTOPS_PEBBLE_EAB_FILE, "utf8")); eabSecret = account.eabHmacKey;
    assert.ok(typeof eabSecret === "string" && eabSecret.length > 20);
    const accountFile = path.join(configDir, "acme-account.json"); fs.writeFileSync(accountFile, JSON.stringify(account), { mode: 0o600 });
    invalidEabSecret = crypto.randomBytes(32).toString("base64url");
    const invalidAccountFile = path.join(configDir, "invalid-acme-account.json");
    fs.writeFileSync(invalidAccountFile, JSON.stringify({ eabKid: account.eabKid, eabHmacKey: invalidEabSecret }), { mode: 0o600 });
    config.acmeAccounts = { [eabRef]: { credentialsFile: accountFile }, "qualification-invalid-account": { credentialsFile: invalidAccountFile }, "qualification-missing-account": { credentialsFile: path.join(configDir, "missing-owned-account.json") } };
  }
  fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify(config), { mode: 0o600 });
    const { token, plaintextToken } = await createBootstrap();
    fs.mkdirSync(discoveryDir,{mode:0o700});
    const certificateFile=path.join(discoveryDir,"server.crt");
    const privateFile=path.join(discoveryDir,"server.key");
    const generated=spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",privateFile,"-out",certificateFile,"-days","2","-subj","/CN=discovery.example.test","-addext","subjectAltName=DNS:discovery.example.test"],{stdio:"ignore",timeout:20000});
    assert.equal(generated.status,0,"Independent discovery certificate generation must succeed");
    const privateFixture=fs.readFileSync(privateFile,"utf8");
    const privateBodySentinel=privateFixture.split(/\r?\n/).find(line=>line&&!line.startsWith("-----")).slice(0,64);
    const publicFixture=fs.readFileSync(certificateFile,"utf8");
    // Dedicated owned HTTPS identity is separate from discovery inventory.
    const proxyCert = path.join(workDir,"proxy-tls.crt"), proxyKey = path.join(workDir,"proxy-tls.key");
    const generatedProxy = spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",proxyKey,"-out",proxyCert,"-days","2","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1"],{stdio:"ignore",timeout:20000});
    assert.equal(generatedProxy.status,0,"Owned proxy HTTPS fixture generation failed"); fs.chmodSync(proxyKey,0o600);
    gateway = await startOwnedAcmeProxy({certificatePem:fs.readFileSync(proxyCert,"utf8"),privateKeyPem:fs.readFileSync(proxyKey,"utf8"),upstreamDirectory:upstreamCaEndpoint,upstreamCaPem:fs.readFileSync(process.env.CERTOPS_PEBBLE_HTTPS_CERT,"utf8")});
    gateway.setFailure("unavailable"); caEndpoint = gateway.directory;
    config.policy.allowedCaEndpoints = [caEndpoint];
    fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify(config), { mode: 0o600 });
    fs.writeFileSync(path.join(discoveryDir,"disguised.crt"),privateFixture,{mode:0o600});
    fs.writeFileSync(path.join(discoveryDir,"wrapped.pem"),Buffer.from(privateFixture).toString("base64"),{mode:0o600});
    fs.writeFileSync(path.join(discoveryDir,"mixed.pem"),publicFixture+privateFixture,{mode:0o600});
    fs.writeFileSync(path.join(discoveryDir,"oversized.pem"),Buffer.alloc(1024*1024+1,65),{mode:0o600});
    const discoveryFingerprint=new crypto.X509Certificate(publicFixture).fingerprint256.replace(/:/g,"").toLowerCase();
    if(process.env.CERTOPS_NATIVE_ACME_LIFECYCLE === "1") {
      nativeDiscovery=require("./helpers/certops-native-file-discovery").createRefusalFixture({workDir,discoveryDir,publicCertificate:fs.readFileSync(proxyCert)});
      nativeDiscovery.prepare();
    }
    const agentEntry=path.join(repoRoot,"packages/agent/bin/tokentimer-agent.js");
    const startAgent=(bootstrap=false)=>{
    agentClosed=false;
    const started = spawn(process.execPath, [agentEntry], {
      cwd: repoRoot, stdio: "ignore", env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: "C.UTF-8", ...(process.env.NODE_PATH ? { NODE_PATH: process.env.NODE_PATH } : {}), TOKENTIMER_AGENT_CONFIG_DIR: configDir, ...(bootstrap?{TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: plaintextToken, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(token.id)}:{}) },
    });
    started.once("close",()=>{closedAgents.add(started);if(agent===started)agentClosed=true;});
    agent=started;return started;
    };
    startAgent(true);
    if(nativeDiscovery)nativeDiscovery.observeAgent(agent);
    await waitUntil(async () => {
      assert.equal(agent.exitCode, null, "real agent process exited during registration");
      return (await pool.query("SELECT 1 FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2 AND retired_at IS NULL", [workspaceId, agentId])).rows.length > 0;
    });
    await waitUntil(async()=>{
      assert.equal(agent.exitCode,null,"Real agent exited during file discovery");
      const observations=await pool.query("SELECT metadata,redacted_output FROM certificate_evidence WHERE workspace_id=$1 AND metadata->>'agentId'=$2 AND metadata->>'eventType'='certificate.observed'",[workspaceId,agentId]);
      if(!observations.rows.length)return false;
      assert.ok(observations.rows.every(row=>row.metadata.filePath===certificateFile&&row.metadata.fingerprintSha256===discoveryFingerprint),"Only the independently parsed public certificate may become discovery evidence");
      assert.ok(observations.rows.some(row=>row.metadata.coLocatedKeyDetected===true),"Actual adjacent key presence must be observed without custody");
      const serialized=JSON.stringify(observations.rows);
      assert.ok(!serialized.includes(privateFixture)&&!serialized.includes(Buffer.from(privateFixture).toString("base64")),"Private fixture material must never reach persisted evidence");
      assert.ok(!serialized.includes(privateBodySentinel)&&!serialized.includes("PRIVATE KEY-----"),"Even a private-key body fragment or header must remain local");
      return true;
    });
    publicSession = await require("./helpers/certops-api-fixture").createApiFixture(baseUrl);
    await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')", [workspaceId, publicSession.userId]);
    if(nativeDiscovery)await runScenario("real-native-unprivileged-file-discovery-refusals",async()=>{
      const preparedAt = new Date().toISOString();
      await waitUntil(async()=>{
        assert.equal(agent.exitCode,null);assert.equal(agent.signalCode,null);
        nativeDiscovery.assertUnchanged();
        const rows=(await pool.query("SELECT metadata,observed_at FROM certificate_evidence WHERE workspace_id=$1 AND metadata->>'agentId'=$2 AND metadata->>'eventType'='certificate.observed' AND observed_at >= $3::timestamptz",[workspaceId,agentId,preparedAt])).rows;
        if(new Set(rows.filter(row=>row.metadata.fingerprintSha256===discoveryFingerprint).map(row=>new Date(row.observed_at).toISOString())).size<2)return false;
        const inventory=await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/certificate-identities?limit=100&offset=0`,"GET");
        assert.equal(inventory.status,200);
        nativeDiscovery.recordScans({rows,inventory:inventory.body,positiveFingerprint:discoveryFingerprint,negativeFingerprint:nativeDiscovery.fingerprint,positivePath:certificateFile,agentId,preparedAt});
        return true;
      },30000);
    });
    for (const failure of ["unavailable", "rate-limited", "malformed"]) {
    gateway.setFailure(failure);
    const requestsBefore = gateway.snapshot().perStage.directory.refused;
    const unavailablePath = path.join(workDir, "deployed", `${failure}-gateway.pem`);
    const unavailable = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`, "POST", { operation: "issue", idempotencyKey: crypto.randomUUID(), payload: { sans: requestedNames, target: { type: "domain", reference: domain }, certPath: unavailablePath, commandRef, caEndpoint, acmeKind, ...(eabRef ? { eabRef } : {}), dnsProvider: "pebble-challtestsrv", dnsZone: "example.test" } });
    assert.equal(unavailable.status, 201); const unavailableJob = unavailable.body.job;
    ownedJobIds.push(unavailableJob.id); ownedCertificateIds.push(unavailableJob.subjectId);
    await waitUntil(async () => {
      assert.equal(agent.exitCode, null); assert.equal(agent.signalCode, null);
      const current = (await pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, unavailableJob.id])).rows[0];
      if (["succeeded", "dry_run_complete", "cancelled"].includes(current?.status)) throw new Error("Unavailable real CA gateway incorrectly completed issuance");
      return current?.status === "failed";
    });
    assert.ok(gateway.snapshot().perStage.directory.refused > requestsBefore, `Actual client must encounter the controlled ${failure} HTTPS directory response`);
    assert.equal(fs.existsSync(unavailablePath), false);
    await verifyDnsCleanup();
    assert.notEqual((await pool.query("SELECT status FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [workspaceId, unavailableJob.subjectId])).rows[0].status, "active");
    }
    gateway.setFailure(null);
    if (eabRef) {
      for (const accountRef of ["qualification-missing-account", "qualification-invalid-account"]) {
        const refusedPath = path.join(workDir, "deployed", `${accountRef}.pem`);
        const refused = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`, "POST", { operation: "issue", idempotencyKey: crypto.randomUUID(), payload: { sans: requestedNames, target: { type: "domain", reference: domain }, certPath: refusedPath, commandRef, caEndpoint, acmeKind, eabRef: accountRef, dnsProvider: "pebble-challtestsrv", dnsZone: "example.test" } });
        assert.equal(refused.status, 201); const rejectedJob = refused.body.job;
        ownedJobIds.push(rejectedJob.id); ownedCertificateIds.push(rejectedJob.subjectId);
        await waitUntil(async () => {
          assert.equal(agent.exitCode, null); assert.equal(agent.signalCode, null);
          const current = (await pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, rejectedJob.id])).rows[0];
          if (["succeeded", "dry_run_complete", "cancelled"].includes(current?.status)) throw new Error("Invalid or missing EAB credentials incorrectly completed issuance");
          return current?.status === "failed";
        });
        assert.equal(fs.existsSync(refusedPath), false, "Failed EAB admission must never install a certificate");
        await verifyDnsCleanup();
        assert.notEqual((await pool.query("SELECT status FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [workspaceId, rejectedJob.subjectId])).rows[0].status, "active");
      }
    }
    stageCases = await stageFaults.qualifyStageRefusals({proxy:gateway,publicSession,pool,workspaceId,requestedNames,domain,workDir,commandRef,caEndpoint,acmeKind,eabRef,agent,ownedJobIds,ownedCertificateIds,waitUntil,verifyDnsCleanup,runScenario});
    if (process.env.CERTOPS_NATIVE_ACME_CONSOLE === "1") {
      // The separate browser lane authenticates before arming the native
      // command. Other ACME profiles acquire no browser prerequisite or skip.
      nativeConsole = await require("./helpers/certops-acme-browser-console").createNativeConsoleActor({
        pool, workspaceId, agentId, agent, identity: publicSession,
        uiOrigin: process.env.CERTOPS_NATIVE_ACME_CONSOLE_URL,
        apiOrigin: process.env.CERTOPS_NATIVE_ACME_CONSOLE_API_URL,
        workDir, barrierDirectory, repoRoot, acmeKind, eabRef,
        ownedBrowserResources,
      });
      await nativeConsole.preparePage();
    }
    if(process.env.CERTOPS_NATIVE_ACME_LIFECYCLE==="1"){
      assert.equal(nativeConsole,undefined,"Native lifecycle is a separate lane from read-only console");
      nativeLifecycle=await require("./helpers/certops-acme-browser-lifecycle").createLifecycleActor({pool,workspaceId,agentId,identity:publicSession,uiOrigin:process.env.CERTOPS_NATIVE_ACME_LIFECYCLE_URL,apiOrigin:process.env.CERTOPS_NATIVE_ACME_LIFECYCLE_API_URL,workDir,acmeKind,eabRef,ownedBrowserResources,registerOwnedJob:id=>{if(!ownedJobIds.includes(id))ownedJobIds.push(id);}});
    }
    const issueInput={ operation: "issue", idempotencyKey: crypto.randomUUID(), payload: { sans: requestedNames, target: { type: "domain", reference: domain }, certPath, commandRef, caEndpoint, acmeKind, ...(eabRef ? { eabRef } : {}), dnsProvider: "pebble-challtestsrv", dnsZone: "example.test" } };
    let job;
    if(nativeLifecycle)job=(await nativeLifecycle.admit(issueInput)).publicJob;
    else{const outcome=await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`,"POST",issueInput);assert.equal(outcome.status,201,`Actual public issuance admission failed (${outcome.body.code||"no-code"})`);job=outcome.body.job;}
    certificateId = job.subjectId || job.subject_id;
    ownedCertificateIds.push(certificateId);
    jobId = job.id;
    if(!ownedJobIds.includes(jobId))ownedJobIds.push(jobId);
    assert.ok(jobId && certificateId, "issuance must return job and certificate identities");
    if (nativeConsole) await runScenario(
      require("../../scripts/certops-acme-native-console-report").NATIVE_CASES[0],
      () => nativeConsole.observeAndRelease({ jobId, certificateId }),
    );
    await waitUntil(async () => {
      const row = (await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [jobId])).rows[0];
      if (["failed", "rejected", "cancelled"].includes(row?.status)) throw new Error(`Real ACME job terminated ${row.status}`);
      return row?.status === "succeeded";
    });
    const firstIssuanceObservedAt = Date.now();
    await verifyDnsCleanup();
    const pem = fs.readFileSync(certPath, "utf8");
    const certificate = new crypto.X509Certificate(pem);
    verifyNames(certificate);
    assert.equal(certificate.checkHost(domain), domain);
    assert.ok(Date.parse(certificate.validTo) > Date.now());
    const key = fs.readFileSync(path.join(configDir, "keys", `${certificateId}.key.pem`), "utf8");
    assert.ok(certificate.checkPrivateKey(crypto.createPrivateKey(key)), "deployed certificate must match agent-local private key");
    const keyPath=path.join(configDir,"keys",`${certificateId}.key.pem`);
    tlsServer = tls.createServer({ cert: pem, key,SNICallback:(_name,callback)=>{
      try{callback(null,tls.createSecureContext({cert:fs.readFileSync(certPath),key:fs.readFileSync(keyPath)}));}catch(error){callback(error);}
    } }, (socket) => socket.end());
    tlsServer.on("connection",socket=>{ownedTlsSockets.add(socket);socket.once("close",()=>ownedTlsSockets.delete(socket));});
    await new Promise((resolve, reject) => { tlsServer.once("error", reject); tlsServer.listen(0, "127.0.0.1", () => { tlsServer.removeListener("error", reject); resolve(); }); });
    const servedFingerprint = () => new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: tlsServer.address().port, servername: domain, ca: fs.readFileSync(process.env.CERTOPS_PEBBLE_ISSUER_ROOT), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(socket.getPeerCertificate().fingerprint256); } catch (error) { reject(error); } finally { socket.end(); } });
      socket.setTimeout(10000, () => socket.destroy(new Error("Independent trusted TLS observation timed out")));
      socket.on("error", reject);
    });
    const observed=await servedFingerprint();
    assert.equal(observed, certificate.fingerprint256);
    const lifecycleTlsOptions=()=>({host:"127.0.0.1",port:tlsServer.address().port,servername:domain,ca:fs.readFileSync(process.env.CERTOPS_PEBBLE_ISSUER_ROOT)});
    if(nativeLifecycle)await runScenario("real-acme-browser-issue-native-completion",()=>nativeLifecycle.observeNative({jobId,certificateId,certPath,keyPath,tlsOptions:lifecycleTlsOptions()}));
    if (nativeConsole) await runScenario(require("../../scripts/certops-acme-native-console-report").NATIVE_CASES[1], async () => {
      const proof = await nativeConsole.finish({ trustedFingerprint: observed });
      const sidecar = path.join(repoRoot, require("../../scripts/certops-acme-native-console-report").SIDECAR);
      fs.mkdirSync(path.dirname(sidecar), { recursive: true });
      fs.writeFileSync(sidecar, JSON.stringify(proof), { flag: "wx", mode: 0o600 });
    });
    const stageProof=stageFaults.completeProof({cases:stageCases,client:acmeKind,proxy:gateway,positiveJobId:jobId,certificatePem:pem,trustedPeerFingerprint:observed,requestedNames});
    fs.mkdirSync(path.dirname(stageProofPath),{recursive:true});fs.writeFileSync(stageProofPath,JSON.stringify(stageProof),{flag:"wx",mode:0o600});
    const evidence = await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, jobId]);
    assert.ok(evidence.rows.length, "real agent evidence must persist in the API database");

    const profile=(await pool.query("SELECT cp.public_metadata, mc.not_after FROM managed_certificates mc JOIN certificate_profiles cp ON cp.id=mc.profile_id AND cp.workspace_id=mc.workspace_id WHERE mc.workspace_id=$1 AND mc.id=$2",[workspaceId,certificateId])).rows[0];
    assert.ok(profile?.public_metadata?.renewalProfile,"Actual successful issuance must derive a reusable execution profile");
    assert.equal(profile.public_metadata.renewalProfile.acme.commandRef, commandRef, "Persisted renewal must use the actual qualified client profile");
    if (eabRef) assert.equal(profile.public_metadata.renewalProfile.ca.eabRef, eabRef);
    assert.ok(new Date(profile.not_after).getTime()<=Date.now()+30*86400000,"Real short-lived fixture leaf must naturally enter the renewal window");
    assert.ok((await pool.query("SELECT 1 FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL AND automation_enabled=TRUE",[workspaceId,certificateId])).rows.length,"Successful agent deployment must enable its actual management period");
    await waitUntil(() => Date.now() > firstIssuanceObservedAt + 1500);
    const sweep=await require(path.join(repoRoot,"apps/api/services/certops/renewalScheduler.js")).runRenewalSchedulerSweep({dbPool:pool,env:process.env});
    assert.equal(sweep.errors.length,0,"Actual renewal scheduler must not hide errors");
    const renewal=(await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND source='automation' ORDER BY created_at DESC LIMIT 1",[workspaceId,String(certificateId)])).rows[0];
    assert.ok(renewal,"Real persisted profile must produce an automatic renewal job");
    ownedJobIds.push(renewal.id);
    await waitUntil(async()=>{
      assert.equal(agent.exitCode,null,"Actual agent exited during scheduled renewal");
      const row=(await pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[renewal.id])).rows[0];
      if(["failed","rejected","cancelled"].includes(row?.status))throw new Error("Actual scheduled renewal terminated unsuccessfully");
      return row?.status==="succeeded";
    });
    const firstRenewalObservedAt = Date.now();
    await verifyDnsCleanup();
    const renewed=new crypto.X509Certificate(fs.readFileSync(certPath));
    verifyNames(renewed);
    assert.equal(renewed.checkHost(domain),domain);
    assert.notEqual(renewed.fingerprint256,certificate.fingerprint256,"CA must issue a genuinely new leaf");
    assert.equal(publicKeyDer(renewed).equals(publicKeyDer(certificate)), false, "Derived rotateOnRenew must genuinely rotate the agent-local key");
    assert.ok(Date.parse(renewed.validTo) > Date.parse(certificate.validTo), "Actual expiry must advance to the next scheduler generation");
    assert.ok(renewed.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyPath))));
    assert.equal(await servedFingerprint(),renewed.fingerprint256,"Dynamic filesystem TLS fixture must serve the actual renewed deployment");
    assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[workspaceId,renewal.id])).rows.length,"Scheduled renewal must persist actual agent evidence");
    // Exercise a second naturally due cycle without changing certificate or
    // scheduler timestamps. Pause only our own execution process while two
    // real sweeps race, so completion cannot create a new due generation
    // between the admission checks.
    assert.equal(process.platform, "linux");
    await waitUntil(() => Date.now() > firstRenewalObservedAt + 1500);
    const previousRenewals = (await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND source='automation'", [workspaceId, String(certificateId)])).rows.map((row) => row.id);
    assert.equal(agent.kill("SIGSTOP"), true);
    let second;
    try {
      const sweeps = await Promise.all([0, 1].map(() => require(path.join(repoRoot, "apps/api/services/certops/renewalScheduler.js")).runRenewalSchedulerSweep({ dbPool: pool, env: process.env })));
      assert.ok(sweeps.every((result) => result.errors.length === 0));
      const admitted = (await pool.query("SELECT id,status FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' AND source='automation' AND NOT(id=ANY($3::uuid[]))", [workspaceId, String(certificateId), previousRenewals])).rows;
      assert.equal(admitted.length, 1, "Concurrent sweeps must admit one job for the actual next expiry generation");
      second = admitted[0]; ownedJobIds.push(second.id);
    } finally { assert.equal(agent.kill("SIGCONT"), true); }
    await waitUntil(async () => {
      assert.equal(agent.exitCode, null); assert.equal(agent.signalCode, null);
      const row = (await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [second.id])).rows[0];
      if (["failed", "rejected", "cancelled"].includes(row?.status)) throw new Error("Actual second scheduled renewal terminated unsuccessfully");
      return row?.status === "succeeded";
    });
    const twiceRenewed = new crypto.X509Certificate(fs.readFileSync(certPath));
    await verifyDnsCleanup();
    verifyNames(twiceRenewed);
    assert.equal(twiceRenewed.checkHost(domain), domain);
    assert.notEqual(twiceRenewed.fingerprint256, renewed.fingerprint256);
    assert.notEqual(twiceRenewed.fingerprint256, certificate.fingerprint256);
    assert.equal(publicKeyDer(twiceRenewed).equals(publicKeyDer(renewed)), false);
    assert.ok(Date.parse(twiceRenewed.validTo) > Date.parse(renewed.validTo));
    assert.ok(twiceRenewed.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyPath))));
    assert.equal(await servedFingerprint(), twiceRenewed.fingerprint256);
    assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, second.id])).rows.length);
    // A human renewal must resolve the stored profile, rather than accepting
    // caller-supplied issuer/path settings, and reach the same native pipeline.
    await new Promise(resolve => setTimeout(resolve, 1500));
    const profileBeforeManual = (await pool.query("SELECT cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2", [workspaceId, certificateId])).rows[0].public_metadata.renewalProfile;
    const manualInput = { operation: "renew", subjectType: "managed_certificate", subjectId: String(certificateId), idempotencyKey: crypto.randomUUID(),...(nativeLifecycle?{payload:{reason:"Disposable native browser lifecycle renewal"}}:{}) };
    let manualJob;
    if(nativeLifecycle)manualJob=(await nativeLifecycle.admit(manualInput)).publicJob;
    else{const manual=await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`,"POST",manualInput);assert.equal(manual.status,201);manualJob=manual.body.job;}
    if(!ownedJobIds.includes(manualJob.id))ownedJobIds.push(manualJob.id);
    assert.equal(manualJob.source, "api");
    assert.equal(manualJob.payload.commandRef, commandRef);
    assert.equal(manualJob.payload.caEndpoint, caEndpoint);
    assert.equal(manualJob.payload.certPath, certPath);
    assert.equal(manualJob.payload.dnsProvider, "pebble-challtestsrv");
    assert.equal(manualJob.payload.dnsZone, "example.test");
    assert.deepEqual([...manualJob.payload.sans].sort(), [...requestedNames].sort());
    const repeatedManual = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`, "POST", manualInput);
    assert.equal(repeatedManual.status, 201); assert.equal(repeatedManual.body.job.id, manualJob.id);
    await waitUntil(async () => {
      assert.equal(agent.exitCode, null); assert.equal(agent.signalCode, null);
      const current = (await pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, manualJob.id])).rows[0];
      if (["failed", "rejected", "cancelled", "blocked", "orphaned_unknown_effect"].includes(current?.status)) throw new Error("Actual profile-driven manual renewal terminated unsuccessfully");
      return current?.status === "succeeded";
    });
    await verifyDnsCleanup();
    const manuallyRenewed = new crypto.X509Certificate(fs.readFileSync(certPath));
    verifyNames(manuallyRenewed);
    assert.notEqual(manuallyRenewed.fingerprint256, twiceRenewed.fingerprint256);
    assert.notEqual(manuallyRenewed.serialNumber, twiceRenewed.serialNumber);
    assert.equal(publicKeyDer(manuallyRenewed).equals(publicKeyDer(twiceRenewed)), false);
    assert.ok(manuallyRenewed.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyPath))));
    assert.equal(await servedFingerprint(), manuallyRenewed.fingerprint256);
    if(nativeLifecycle)await runScenario("real-acme-browser-renew-native-completion",async()=>{
      await nativeLifecycle.observeNative({jobId:manualJob.id,certificateId,certPath,keyPath,tlsOptions:lifecycleTlsOptions()});
      const proof=await nativeLifecycle.finish(),sidecar=path.join(repoRoot,"qualification-results/acme-browser-lifecycle-proof.json");
      fs.mkdirSync(path.dirname(sidecar),{recursive:true});fs.writeFileSync(sidecar,JSON.stringify(proof),{flag:"wx",mode:0o600});
    });
    assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, manualJob.id])).rows.length);
    assert.deepEqual((await pool.query("SELECT cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2", [workspaceId, certificateId])).rows[0].public_metadata.renewalProfile, profileBeforeManual,
      "manual renewal must preserve its stored execution profile");
    const background=require("./helpers/certops-acme-background-renewals");
    await runScenario(background.SCENARIO,async()=>{
      const proof=await background.qualifyBackgroundRenewals({pool,workspaceId,agent,certificateId,certPath,keyPath,ownedJobIds,waitUntil,verifyDnsCleanup,verifyNames,servedFingerprint,repoRoot,acmeKind,workDir,ownedWorkers});
      fs.mkdirSync(path.dirname(backgroundProofPath),{recursive:true});fs.writeFileSync(backgroundProofPath,JSON.stringify(proof),{mode:0o600});
    });
    const reuse = require("./helpers/certops-acme-key-reuse");
    await runScenario(reuse.scenarioName, async () => {
      const proof = await reuse.qualifyKeyReuse({ pool, workspaceId, agent, publicSession, certificateId, certPath, keyPath, ownedJobIds, waitUntil, verifyDnsCleanup, verifyNames, servedFingerprint, repoRoot, acmeKind });
      fs.mkdirSync(path.dirname(reuseProofPath), { recursive: true }); fs.writeFileSync(reuseProofPath, JSON.stringify(proof), { mode: 0o600 });
    });
    if(process.env.CERTOPS_REPORT_SCOPE===bulkReport.SCOPE){
      const bulk=require('./helpers/certops-acme-bulk-renewal');
      await runScenario(bulk.SCENARIO,async()=>{
        const proof=bulkProof=await bulk.qualifyBulk({pool,workspaceId,agentId,agent,publicSession,certificateId,certPath,keyPath,configDir,workDir,requestedNames,domain,commandRef,caEndpoint,acmeKind,eabRef,ownedJobIds,ownedCertificateIds,ownedBulkResources,ownedWorkers,waitUntil,verifyNames,verifyDnsCleanup,primaryTlsOptions:lifecycleTlsOptions});
        fs.writeFileSync(path.join(repoRoot,bulkReport.SIDECAR),JSON.stringify(proof),{flag:'wx',mode:0o600});
      });
    }
    if(process.env.CERTOPS_REPORT_SCOPE===adoptionReport.SCOPE){
      const adoption=require('./helpers/certops-acme-native-adoption');
      await runScenario(adoption.SCENARIO,async()=>{
        const proof=await adoption.qualifyNativeAdoption({pool,workspaceId,agentId,publicSession,certificateId,certPath,keyPath,configDir,workDir,domain,acmeKind,bulkProof,ownedJobIds,ownedBulkResources,ownedAdoptionResources,ownedWorkers,waitUntil,verifyDnsCleanup,servedFingerprint,primaryTlsOptions:lifecycleTlsOptions});
        fs.writeFileSync(path.join(repoRoot,adoptionReport.SIDECAR),JSON.stringify(proof),{flag:'wx',mode:0o600});
      });
    }
    if(resultGateway){
      const outbox=require('./helpers/certops-acme-certificate-outbox');
      fs.rmSync(path.join(repoRoot,outbox.SIDECAR),{force:true});
      await runScenario(outbox.SCENARIO,async()=>{
        const proof=await outbox.qualify({pool,workspaceId,agent,agentEntry,restartAgent:()=>startAgent(false),isAgentClosed:original=>closedAgents.has(original),configDir,workDir,certificateId,certPath,keyPath,domain,barrierDirectory,ownedJobIds,ownedRestartResources,waitUntil,publicSession,acmeKind,resultGateway,caGateway:gateway,servedFingerprint,verifyDnsCleanup});
        fs.writeFileSync(path.join(repoRoot,outbox.SIDECAR),JSON.stringify(proof),{flag:'wx',mode:0o600});
      });
    }
    if(resultGateway){
      const disabled=require('./helpers/certops-acme-disabled-profile');
      fs.rmSync(path.join(repoRoot,disabled.SIDECAR),{force:true});
      await runScenario(disabled.SCENARIO,async()=>{
        const proof=await disabled.qualify({pool,workspaceId,agentId,publicSession,certificateId,certPath,keyPath,configDir,workDir,domain,acmeKind,bulkProof,ownedWorkers,ownedBulkResources,ownedProfileResources,ownedJobIds,waitUntil,servedFingerprint,verifyDnsCleanup,primaryTlsOptions:lifecycleTlsOptions});
        fs.writeFileSync(path.join(repoRoot,disabled.SIDECAR),JSON.stringify(proof),{flag:'wx',mode:0o600});
      });
    }
    if(process.env.CERTOPS_REPORT_SCOPE===bulkReport.SCOPE){
      const alerts=require('./helpers/certops-acme-renewal-alert');
      fs.rmSync(path.join(repoRoot,alerts.SIDECAR),{force:true});
      await runScenario(alerts.SCENARIO,async()=>{
        const proof=await alerts.qualify({pool,workspaceId,agentId,agent,publicSession,certificateId,certPath,keyPath,workDir,repoRoot,acmeKind,proxy:gateway,ownedJobIds,waitUntil,servedFingerprint,verifyDnsCleanup});
        fs.writeFileSync(path.join(repoRoot,alerts.SIDECAR),JSON.stringify(proof),{flag:'wx',mode:0o600});
      });
    }
    await require("./helpers/certops-acme-lease-loss")({pool,workspaceId,agentId,agent,publicSession,certificateId,certPath,keyPath,barrierDirectory,ownedJobIds,ownedLeaseResources,waitUntil,verifyDnsCleanup,servedFingerprint});
    if (eabSecret) {
      const stored = await pool.query("SELECT metadata,redacted_output FROM certificate_evidence WHERE workspace_id=$1", [workspaceId]);
      const jobs = await pool.query("SELECT payload,result_metadata FROM certificate_jobs WHERE workspace_id=$1", [workspaceId]);
      const publicData = JSON.stringify([stored.rows, jobs.rows, profile.public_metadata]);
      assert.equal([eabSecret, invalidEabSecret].some((secret) => publicData.includes(secret)), false, "Actual EAB HMACs must remain agent-local and absent from persisted public data");
    }
  } catch(error) { primaryError=error; throw error; }
  finally {
    // Drain independent retained resources even if one owner is unresolved.
    // Every deletion remains behind the combined ownership barrier below.
    const cleanupErrors = [];
    const cleanup = async (action) => { try { await action(); } catch (error) { cleanupErrors.push(error); } };
    for(const resource of ownedRestartResources)await cleanup(()=>resource.stopAndDrain());
    for(const resource of ownedLeaseResources)await cleanup(()=>resource.stopAndDrain());
    for(const resource of ownedProfileResources)await cleanup(()=>resource.close());
    for(const resource of ownedAdoptionResources)await cleanup(()=>resource.close());
    for(const resource of ownedBulkResources)await cleanup(()=>resource.close());
    for(const worker of ownedWorkers)await cleanup(()=>worker.stopAndDrain());
    for (const browser of ownedBrowserResources) await cleanup(() => browser.close());
    await cleanup(async () => { if (tlsServer) {for(const socket of ownedTlsSockets)socket.destroy();let closed=false;tlsServer.close(()=>{closed=true;});await waitUntil(()=>closed&&ownedTlsSockets.size===0,5000);} });
    await cleanup(async () => { if (agent && agent.exitCode === null && agent.signalCode === null) {
      agent.kill("SIGCONT"); agent.kill("SIGTERM");
      try { await waitUntil(() => agent.exitCode !== null || agent.signalCode !== null, 5000); }
      catch { agent.kill("SIGKILL"); await waitUntil(() => agent.exitCode !== null || agent.signalCode !== null, 5000); }
    } });
    await cleanup(async()=>{if(agent)await waitUntil(()=>agentClosed,5000);});
    await cleanup(async () => { if (gateway) await gateway.close(); });
    await cleanup(async()=>{if(resultGateway)await resultGateway.close();});
    await cleanup(async()=>{if(nativeDiscovery){
      const proof=await nativeDiscovery.finishAfterAgentDrain();
      nativeDiscovery.resource.assertCleanupSafe();
      if(proof){const sidecar=path.join(repoRoot,"qualification-results/native-file-discovery-proof.json");fs.writeFileSync(sidecar,JSON.stringify(proof),{flag:"wx",mode:0o600});}
    }});
    await cleanup(()=>{if(resultGateway)require("./helpers/certops-acme-certificate-outbox").assertCleanupSafe(workDir);});
    await cleanup(()=>require("./helpers/certops-acme-renewal-alert").assertCleanupSafe(workDir));
    await cleanup(()=>{if(ownedProfileResources.length)require("./helpers/certops-acme-disabled-profile").assertCleanupSafe(workDir);});
    for(const resource of ownedProfileResources)await cleanup(()=>{assert.equal(resource.hasLiveResource(),false);assert.equal(resource.hasOwnershipReceipt(),false,"Preserve unknown disabled-profile state");});
    for(const resource of ownedRestartResources)await cleanup(()=>{assert.equal(resource.hasLiveResource(),false);assert.equal(resource.hasOwnershipReceipt(),false,"Preserve unconfirmed original agent restart");});
    await cleanup(()=>require("./helpers/certops-acme-background-runner").assertCleanupSafe(workDir));
    for (const browser of ownedBrowserResources) await cleanup(() => {
      assert.equal(browser.hasLiveChild(), false, "Native console browser remains alive");
      assert.equal(browser.hasOwnershipReceipt(), false, "Preserve unresolved native console state");
      browser.assertCleanupSafe();
    });
    for(const resource of ownedAdoptionResources)await cleanup(()=>{assert.equal(resource.hasLiveResource(),false,'Owned adoption TLS remains live');assert.equal(resource.hasOwnershipReceipt(),false,'Preserve unresolved native adoption state');});
    await cleanup(()=>{if(ownedAdoptionResources.length)require("./helpers/certops-acme-native-adoption").assertCleanupSafe(workDir);});
    for(const resource of ownedBulkResources)await cleanup(()=>{assert.equal(resource.hasLiveResource(),false,'Owned bulk TLS resource remains live');assert.equal(resource.hasOwnershipReceipt(),false,'Preserve unresolved native bulk state');});
    for(const resource of ownedLeaseResources)await cleanup(()=>{assert.equal(resource.hasLiveResource(),false,'Owned lease observer remains live');assert.equal(resource.hasOwnershipReceipt(),false,'Preserve unresolved lease command ownership');});
    await cleanup(()=>{if(barrierDirectory)require("./helpers/certops-acme-lease-loss").assertCleanupSafe(barrierDirectory);});
    await cleanup(()=>{if(barrierDirectory){for(const entry of fs.readdirSync("/proc")){if(!/^\d+$/.test(entry))continue;let argv;try{argv=fs.readFileSync(`/proc/${entry}/cmdline`, "utf8").split("\0");}catch(error){if(["ENOENT","ESRCH","EACCES"].includes(error.code))continue;throw error;}assert.ok(!(argv.includes(path.join(repoRoot,"tests/e2e/helpers/certops-acme-command-barrier.js"))&&argv.includes(barrierDirectory)),"Preserve records while an owned ACME command remains alive");}}});
    // Preserve native private material AND public ownership records if any
    // retained consumer/transport has not positively drained.
    if (cleanupErrors.length) throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors], "Owned ACME resource drainage unconfirmed; preserve fixture state");
    for(const ownedJobId of ownedJobIds) {
      await cleanup(() => pool.query("DELETE FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, ownedJobId]));
      await cleanup(() => pool.query("DELETE FROM certificate_job_log WHERE workspace_id=$1 AND job_id=$2", [workspaceId, ownedJobId]));
      await cleanup(() => pool.query("DELETE FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, ownedJobId]));
    }
    for (const ownedCertificateId of ownedCertificateIds) await cleanup(() => pool.query("DELETE FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [workspaceId, ownedCertificateId]));
    await cleanup(async () => { if (publicSession) await publicSession.cleanup(); });
    await cleanup(() => {
      assert.equal(path.dirname(path.resolve(workDir)), path.resolve(os.tmpdir()));
      assert.ok(path.basename(workDir).startsWith("certops-real-acme-"));
      if(barrierDirectory){for(const entry of fs.readdirSync("/proc")){if(!/^\d+$/.test(entry))continue;let argv;try{argv=fs.readFileSync(`/proc/${entry}/cmdline`,"utf8").split("\0");}catch(error){if(["ENOENT","ESRCH","EACCES"].includes(error.code))continue;throw error;}assert.ok(!(argv.includes(path.join(repoRoot,"tests/e2e/helpers/certops-acme-command-barrier.js"))&&argv.includes(barrierDirectory)),"Refusing state removal while an owned command barrier remains alive");}}
      fs.rmSync(workDir, { recursive: true, force: true });
    });
    if (cleanupErrors.length) throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors], "Real ACME journey or owned fixture cleanup failed");
  }
};
