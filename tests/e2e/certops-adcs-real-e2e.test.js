"use strict";
/* Installed SYSTEM-agent AD CS qualification on an owned disposable forest.
 * Invoked by protected enterprise AD CS workflows; public API jobs drive real
 * CA/CNG/IIS operations, with independent native/TLS oracles and finally-owned
 * service/key/site cleanup. The elapsed-pending selector is a separate suite,
 * not an abbreviated success report for the comprehensive baseline. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const net = require("node:net");
const { spawnSync } = require("node:child_process");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { applyRestrictivePermissions } = require("../../packages/agent/src/platform");
const { hostBinaryName } = require("../../packages/agent/scripts/build-windows-service-host");
const safetyCases = require("../../infra/certops-adcs/safety-cases.json");
function nativeCommandEnvironment(file, additions = {}) {
  const env = { ...process.env, ...additions };
  if (path.basename(file).toLowerCase() === "powershell.exe") for (const name of Object.keys(env)) if (name.toLowerCase() === "psmodulepath") delete env[name];
  return env;
}
function command(file, args) {
  const result = spawnSync(file, args, { encoding: "utf8", timeout: 180000, env: nativeCommandEnvironment(file) });
  assert.ifError(result.error); assert.equal(result.status, 0, `${file} failed with status ${result.status}`);
  return result.stdout.trim();
}
function ps(script) { return command("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; ${script}`]); }
async function until(check, timeout = 180000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise((resolve) => setTimeout(resolve, 500)); }
  throw new Error("Domain-backed AD CS journey exceeded its deadline");
}
function tlsAuthority(authority) {
  const certificate=new crypto.X509Certificate(Buffer.from(authority.certificateB64,"base64")).toString();
  return process.env.CERTOPS_ADCS_HIERARCHY === "subordinate" ? [certificate,new crypto.X509Certificate(Buffer.from(process.env.CERTOPS_ADCS_HIERARCHY_ROOT_CERT,"base64")).toString()] : certificate;
}
async function freePort() { return new Promise((resolve, reject) => { const server = net.createServer(); server.on("error", reject); server.listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); }); }); }

test("Domain-backed AD CS real API agent CNG and IIS", { timeout: process.env.CERTOPS_ADCS_PENDING_ELAPSED === "1" ? 4800000 : 3600000 }, async () => {
  assert.equal(process.platform, "win32", "requires disposable Windows domain member");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(ps("(Get-CimInstance Win32_ComputerSystem).Domain"), "lab.certops.test");
  const requestedVersion=process.env.CERTOPS_WINDOWS_VERSION || "2022";
  const osBuild=ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber");
  assert.equal(ps("(Get-CimInstance Win32_OperatingSystem).ProductType"),"3","Qualification requires a Windows Server member, not a desktop sharing the same build number");
  assert.equal(osBuild,{"2019":"17763","2022":"20348","2025":"26100"}[requestedVersion],"Actual guest must match selected Windows Server qualification version");
  assert.equal(ps("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"), "True");
  assert.notEqual(spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status, 0, "refuse pre-existing agent service");
  const url = new URL(process.env.CERTOPS_ADCS_API_URL);
  assert.equal(url.protocol, "https:"); assert.equal(url.hostname, "10.64.0.6");
  const hierarchy=process.env.CERTOPS_ADCS_HIERARCHY === "subordinate";
  const elapsedPending=process.env.CERTOPS_ADCS_PENDING_ELAPSED === "1";
  const issuerSwitch=process.env.CERTOPS_ADCS_ISSUER_SWITCH === "1";
  const issuerSwitchJourney=require("./helpers/certops-native-issuer-reassignment");
  if(issuerSwitch){assert.equal(hierarchy,false);assert.equal(elapsedPending,false);assert.equal(process.env.CERTOPS_ADCS_DESTINATION_CA_CONFIG,"tt-ca-switch.lab.certops.test\\TTQualificationDestination");assert.notEqual(process.env.CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT,"1");assert.ok(!process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT);}
  const browserJourney=require("./helpers/certops-adcs-browser-journey");
  if(!elapsedPending && !issuerSwitch)assert.equal(process.env.CERTOPS_ADCS_BROWSER,"1","Comprehensive native AD CS suites require their browser journey");
  if(elapsedPending){assert.equal(hierarchy,false);assert.equal(requestedVersion,"2022");assert.equal(ps("(Get-UICulture).Name"),"en-US");assert.notEqual(process.env.CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT,"1");assert.ok(!process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT);}
  const cancelledLateApprovalJourney=require("./helpers/certops-adcs-cancelled-late-approval"),ownedLateApprovalGuards=[];
  const pendingCaJourney=require("./helpers/certops-adcs-pending-ca-renewal");
  const pendingNewKeyJourney=require("./helpers/certops-adcs-pending-ca-key-change");
  const excludedHierarchyScenarios=new Set([...pendingCaJourney.REQUIRED_SCENARIOS,...pendingNewKeyJourney.REQUIRED_SCENARIOS,"adcs-real-ca-same-key-renewal-preserves-confirmed-pin","adcs-real-ca-key-change-refuses-installation","adcs-real-ca-revalidation-recovers-confirmed-new-key"]);
  const gate = createHostGate({ suite: issuerSwitch ? issuerSwitchJourney.SUITE : elapsedPending ? "enterprise-adcs-elapsed-pending-real" : hierarchy ? "enterprise-adcs-hierarchy-real" : "enterprise-adcs-real", strict: true, reportPath: process.env.CERTOPS_ADCS_REPORT, requiredCapabilities: ["windows", "elevated", "domain", "api", "qualifiedBuild",...(!elapsedPending && !issuerSwitch ? ["browserRuntime","dashboard"] : [])], probeCapabilities: async () => ({ ...(!elapsedPending && !issuerSwitch ? { browserRuntime: {available:(()=>{try{const browserRuntime=JSON.parse(fs.readFileSync("C:\\ttqualification\\browser-runtime.json","utf8"));if(browserRuntime.candidateSha!==process.env.GITHUB_SHA || browserRuntime.playwrightVersion!==require("../../package.json").devDependencies.playwright || browserRuntime.browserCache!=="C:\\ttqualification\\browser-cache")return false;process.env.PLAYWRIGHT_BROWSERS_PATH=browserRuntime.browserCache;return fs.existsSync(require("playwright").chromium.executablePath());}catch{return false;}})()},dashboard:{available:await (async()=>{try{const response=await fetch(new URL("/login",url),{signal:AbortSignal.timeout(10000)});return response.ok&&(await response.text()).includes('id="root"');}catch{return false;}})()} } : {}), windows: { available: true, evidence: { release: requestedVersion, build: osBuild, uiCulture: ps("(Get-UICulture).Name") } }, elevated: { available: true }, domain: { available: true }, api: { available: (await fetch(new URL("/health",url),{signal:AbortSignal.timeout(10000)})).ok }, qualifiedBuild: { available: require("../../packages/agent/src/capabilities/qualified-capabilities.generated").qualified?.includes("adcs-enroll-v1") || false } }) });
  if(hierarchy){const selectedScenario=gate.scenario;gate.scenario=(id,run)=>excludedHierarchyScenarios.has(id) ? Promise.resolve() : selectedScenario(id,run);}
  await gate.preflight();
  gate.report.fixtureSource={file:"tests/e2e/certops-adcs-real-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")};
  if(issuerSwitch)gate.report.fixtureSource={file:issuerSwitchJourney.SOURCE,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../..",issuerSwitchJourney.SOURCE))).digest("hex")};
  gate.report.artifactQualification=process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  if(hierarchy){const selected=require("../../scripts/certops-adcs-hierarchy-profile");selected.profile(requestedVersion,process.env.CERTOPS_WINDOWS_LANGUAGE||"en-US");gate.report.fixtureSources??=[];for(const file of selected.REQUIRED_SOURCES)gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../..",file))).digest("hex")});}
  const runtime=JSON.parse(fs.readFileSync("C:\\ttqualification\\runtime.json","utf8"));
  assert.equal(runtime.candidateSha,process.env.GITHUB_SHA);assert.equal(runtime.buildMode,"qualification-only-not-release");assert.equal(runtime.nodeVersion,process.version);
  for(const field of ["nodeArchiveSha256","goArchiveSha256","sourceArchiveSha256","qualifiedModuleSha256"])assert.match(runtime[field],/^[a-f0-9]{64}$/i);
  assert.equal(runtime.qualifiedModuleSha256.toLowerCase(),crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../packages/agent/src/capabilities/qualified-capabilities.generated.js"))).digest("hex"));
  gate.report.buildProvenance={buildMode:runtime.buildMode,nodeVersion:runtime.nodeVersion,goVersion:runtime.goVersion,nodeArchiveSha256:runtime.nodeArchiveSha256,goArchiveSha256:runtime.goArchiveSha256,sourceArchiveSha256:runtime.sourceArchiveSha256,qualifiedModuleSha256:runtime.qualifiedModuleSha256};
  if(process.env.CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT === "1" || process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT){gate.report.qualificationStatus="not-qualified";gate.report.experimental=true;gate.report.workflowPurpose="native-fault-boundary-experiment";}
  gate.report.nativeCertificates=[];
  gate.report.pendingContinuationQualification=[];
  const fixture = await createApiFixture(url.href);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-domain-adcs-"));
  // Protect this newly created root before any private campaign receipt exists.
  applyRestrictivePermissions(workDir, { kind: "directory" });
  let originalConfigurationIdentity;
  const chainCacheSnapshot=path.join(workDir,"chain-cache-before.xml");
  ps(`$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config');try{$exists=$key -and @($key.GetValueNames()) -contains 'ChainCacheResyncFiletime';$state=@{exists=[bool]$exists};if($exists){$state.kind=$key.GetValueKind('ChainCacheResyncFiletime').ToString();$state.value=$key.GetValue('ChainCacheResyncFiletime')};$state|Export-Clixml -LiteralPath '${chainCacheSnapshot.replace(/'/g,"''")}'}finally{if($key){$key.Dispose()}}`);
  const configDir = path.join(workDir, "agent"); fs.mkdirSync(configDir);
  const caConfig = "tt-ca.lab.certops.test\\TTQualificationRoot";
  const cases = [{ id: "rsa2048", template: "TTQualificationRSAShort", algorithm: "rsa", size: 2048 }, { id: "rsa3072", template: "TTQualificationRSA3072", algorithm: "rsa", size: 3072 }, { id: "rsa4096", template: "TTQualificationRSA4096", algorithm: "rsa", size: 4096 }, { id: "ec256", template: "TTQualificationEC256", algorithm: "ecdsa", size: 256 }, { id: "ec384", template: "TTQualificationEC384", algorithm: "ecdsa", size: 384 }, { id: "ec256schema3", template: "TTQualificationEC256Schema3", algorithm: "ecdsa", size: 256 }, { id: "ec384schema3", template: "TTQualificationEC384Schema3", algorithm: "ecdsa", size: 384 }];
  if(elapsedPending)cases.splice(1);
  for (const item of cases) item.schema = item.id.endsWith("schema3") ? 3 : item.algorithm === "rsa" ? 2 : 4;
  const issuedFixtures = [];
  const webHostingJourney=require("./helpers/certops-adcs-webhosting-renewal");
  const ownedStoreCertificates=[];
  const ownedBackgroundStoreCertificates=[];
  const ownedCapacityStoreCertificates=[];
  const ownedIssuerSwitchStoreCertificates=[];
  const ownedTlsProbes=[];
  const ownedApiFixtures=[];
  const ownedForeignRequests=[];
  const ownedTemplateAttributeRestorations=[];
  const httpIntermediateCrlJourney=require("./helpers/certops-adcs-http-intermediate-crl");
  const httpLeafCrlJourney=require("./helpers/certops-adcs-http-leaf-crl");
  const ocspJourney=require("./helpers/certops-adcs-ocsp");
  const resultOutboxJourney=require("./helpers/certops-adcs-result-outbox"),ownedResultResources=[];
  const ownedHttpCrlResources=[];
  const requiredTemplateAttributesJourney=require("./helpers/certops-adcs-template-required-attributes");
  const publicForeignSpkiJourney=require("./helpers/certops-adcs-public-foreign-spki");
  const capacityJourney=require("./helpers/certops-adcs-capacity");
  const registerCapacityStoreCertificate=value=>webHostingJourney.registerCapacityStoreCertificate(ownedCapacityStoreCertificates,value);
  let webHostingServiceDrain;
  const run = crypto.randomBytes(5).toString("hex");
  for (const item of cases) item.domain = `certops-adcs-${run}-${item.id}.example.test`;
  const webHostingDomain=`certops-adcs-${run}-webhosting.example.test`;
  const faultDomain=`certops-adcs-${run}-fault.example.test`;
  const journalDomain=`certops-adcs-${run}-journal.example.test`;
  const transportDomain=`certops-adcs-${run}-transport.example.test`;
  const pendingCases = ["approve", "deny", "expire", "cancel"].map(action => ({ action, domain: `certops-adcs-${run}-${action}.example.test` }));
  const deniedCases=[{id:"enroll-permission",template:"TTQualificationNoEnroll",hresult:"0x80094012"},{id:"unpublished",template:"TTQualificationUnpublished",hresult:"0x80094800"}].map(item=>({...item,domain:`certops-adcs-${run}-${item.id.replace(/-/g,"")}.example.test`}));
  const safetyEnrollments=[...safetyCases.keyConstraintCases,...safetyCases.caFlagCases].map(item=>({...item,domain:`certops-adcs-${run}-${item.id.replace(/-/g,"")}.example.test`}));
  const agentId = `domain-adcs-${crypto.randomUUID()}`;
  const ownedSites = []; const ownedNativeBindings=[]; const ownedThumbprints = new Set();
  const ownedCertificateIds = [];
  const ownedEnrollmentIds = [];
  const unacceptedCleanup=require("./helpers/certops-adcs-unaccepted-cleanup"),ownedUnacceptedEnrollments=[];
  const registerOwnedUnacceptedEnrollment=value=>unacceptedCleanup.register(ownedUnacceptedEnrollments,value,run);
  const ownedBrowserResources=[];
  const ownedBrowserPreflightJobIds=[];
  const pendingRecoveryFixtures = {};
  const ownedCaServiceFaults = new Set();
  const ownedFirewallRules=[];
  const ownedPhaseObservers=[];
  let caSafetyFaultActive = false;
  let renewalFixture;
  let serviceOwned = false;
  let agentRowId;
  const api = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  async function jobFinished(id) { return until(async () => { const row = (await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1 AND workspace_id=$2", [id, fixture.workspaceId])).rows[0]; if (["failed", "rejected", "cancelled"].includes(row?.status)) throw new Error(`Native AD CS job terminated ${row.status}`); return row?.status === "succeeded"; }); }
  const preflightCache=new Map();
  let primaryPreflightCount=0;
  const preflightCohorts=require("./helpers/certops-adcs-preflight-cohorts").createNativePreflightCohorts({baseUrl:url.href,configDir,workDir,caConfig,until,ps,report:gate.report});
  async function preflight(template) {
    if(preflightCache.has(template)) return preflightCache.get(template);
    assert.ok(++primaryPreflightCount<=18,"Primary workspace native preflight budget exceeded");
    const created = await fixture.request(`${api}/issuers`, "POST", { kind: "adcs", name: `${template}-${run}` }); assert.equal(created.status, 201);
    const issuerId = created.body.issuer.id;
    const dispatched = await fixture.request(`${api}/issuers/${issuerId}/preflight`, "POST", { agentId: agentRowId, caConfig, template }); assert.equal(dispatched.status, 201);
    await jobFinished(dispatched.body.job.id);
    const row = await until(async () => (await fixture.pool.query("SELECT last_preflight FROM certificate_issuers WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, issuerId])).rows[0]?.last_preflight);
    const value={ issuerId, result: row };preflightCache.set(template,value);return value;
  }
  function caSafety(action, item) {
    return command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.resolve(__dirname,"../../infra/certops-adcs/ca-safety-flags.ps1"), "-Action", action, "-RunId", run, ...(action === "apply" ? ["-CaseId", item.id] : []), ...(item ? ["-CommonName", item.domain] : [])]);
  }
  async function requireNativeRefusal(item, issuerId, errorCode) {
    assert.equal(caSafety("request-count", item), "0", "Owned safety subject must have no prior CA request");
    const suffix=crypto.randomBytes(3).toString("hex");const site=`TTADCS-${run}-${item.id}-${suffix}`; const port=await freePort(); const directory=path.join(workDir,`${item.id}-${suffix}`);fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),item.id);ownedSites.push(site);
    ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${item.domain}' -Ssl | Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${item.domain}' -PropertyName sslFlags -Value 1`);
    const certificateId=crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:item.algorithm || "rsa",keySize:item.size || 2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
    const outcome=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.jobId])).rows[0];if(row?.status === "succeeded")throw new Error("Unsafe native enrollment incorrectly succeeded");return ["failed","rejected"].includes(row?.status) ? row : null;});
    assert.equal(outcome.result_metadata.enrollmentResult.state,"refused");assert.equal(outcome.result_metadata.enrollmentResult.errorCode,errorCode);
    assert.equal(caSafety("request-count", item),"0","Safety refusal must precede actual native CA submission");
    const container=require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(created.body.enrollmentId);assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container),"Safety refusal must precede owned CNG key generation");
    assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${item.domain}').Count`),"0");
    return {enrollmentId:created.body.enrollmentId,jobId:created.body.jobId};
  }
  try {
    await gate.scenario("adcs-real-installed-native-language",async()=>{
      const language=process.env.CERTOPS_WINDOWS_LANGUAGE || "en-US";
      assert.ok(["en-US","de-DE","fr-FR"].includes(language));
      assert.equal(ps("(Get-UICulture).Name"),language);
      assert.equal(ps("(Get-WinSystemLocale).Name"),language);
      assert.equal(ps(`Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\MUI\\UILanguages\\${language}'`),"True");
      assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
      gate.report.qualificationEnvironment={osFamily:"windows",osVersion:{"17763":"2019","20348":"2022","26100":"2025"}[osBuild],nativeLanguage:ps("(Get-UICulture).Name"),identity:"LocalSystem",measurement:"native"};
      gate.report.languageQualification={language,osBuild,installedDisplayResources:true,nativeIdentity:"LocalSystem",caLanguageVerifiedByProvisioner:true};
    });
    await gate.scenario("adcs-real-agent-registration-system", async () => {
      const bootstrap = await fixture.request(`${api}/agent-bootstrap-tokens`, "POST", { name: `domain-${run}`, expiresAt: new Date(Date.now() + 3600000).toISOString() }); assert.equal(bootstrap.status, 201);
      fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify({ serverUrl: url.href, caBundlePath: process.env.NODE_EXTRA_CA_CERTS, agentId, heartbeatIntervalMs: 5000, pollIntervalMs: 2000, windowsDiscovery: {enabled:true,intervalMs:5000,stores:["My", "WebHosting"]}, declaredTargetSelectors: [...cases, ...pendingCases, ...deniedCases, ...safetyEnrollments].map((item) => item.domain).concat(capacityJourney.domains(run)).concat(issuerSwitch ? [issuerSwitchJourney.domain(run)] : []).concat([webHostingDomain, transportDomain, `certops-adcs-${run}-uncertain.example.test`, `certops-adcs-${run}-operatorambiguity.example.test`]).concat(process.env.CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT === "1" ? [faultDomain] : []).concat(process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT ? [journalDomain] : []), execution: { enabled: true, dryRun: false }, policy: { allowedPaths: [workDir], allowedCommands: {}, allowedCaEndpoints: [], allowedDnsZones: [], allowedDnsProviders: [] }, adcs: { enrollmentRules: [...new Set([...cases.map((item) => item.template), "TTQualificationPending", "TTQualificationPendingOlder", ...deniedCases.map(item=>item.template), ...safetyCases.templateCases.map(item=>item.name), ...safetyEnrollments.map(item=>item.template), "WebServer"])].map((template) => ({ caConfig, template, dnsScopes:["example.test"],keyAlgorithms:["rsa","ecdsa"],operatorAttested: false })) } }));
      if(issuerSwitch){const file=path.join(configDir,"config.json");const settings=JSON.parse(fs.readFileSync(file,"utf8"));settings.adcs.enrollmentRules.push({caConfig:process.env.CERTOPS_ADCS_DESTINATION_CA_CONFIG,template:"TTQualificationRSAShort",dnsScopes:["example.test"],keyAlgorithms:["rsa"],operatorAttested:false});fs.writeFileSync(file,JSON.stringify(settings));}
      applyRestrictivePermissions(configDir, { kind: "dir" }); applyRestrictivePermissions(path.join(configDir, "config.json"));
      const originalConfigStat=fs.lstatSync(path.join(configDir,"config.json"),{bigint:true});assert.ok(originalConfigStat.isFile()&&!originalConfigStat.isSymbolicLink()&&originalConfigStat.dev>0n&&originalConfigStat.ino>0n);originalConfigurationIdentity=`${originalConfigStat.dev}:${originalConfigStat.ino}`;
      const root = path.resolve(__dirname, "../..");
      const host = path.join(root, "packages/agent/bin", hostBinaryName("amd64")); assert.ok(fs.existsSync(host));
      command("sc.exe", ["create", "TokenTimerAgent", "type=", "own", "start=", "demand", "obj=", "LocalSystem", "binPath=", `"${host}" "${process.execPath}" "${path.join(root, "packages/agent/bin/tokentimer-agent.js")}"`]); serviceOwned = true;
      command("reg.exe", ["add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent", "/v", "Environment", "/t", "REG_MULTI_SZ", "/d", `TOKENTIMER_AGENT_CONFIG_DIR=${configDir}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=${bootstrap.body.plaintextToken}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID=${bootstrap.body.token.id}\\0NODE_EXTRA_CA_CERTS=${process.env.NODE_EXTRA_CA_CERTS}\\0PATH=${process.env.PATH}`, "/f"]);
      command("sc.exe", ["start", "TokenTimerAgent"]);
      agentRowId = await until(async () => (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agentId])).rows[0]?.id);
      assert.equal(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\"; $p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($s.ProcessId)\"; (Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid"), "S-1-5-18");
      assert.doesNotMatch(command("reg.exe", ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent", "/v", "Environment"]), /TOKENTIMER_AGENT_BOOTSTRAP_TOKEN/);
    });
    if(issuerSwitch){
      await issuerSwitchJourney.qualifyNativeIssuerReassignment({ownedTlsProbes,gate,fixture,api,agentRowId,caConfig,destinationCaConfig:process.env.CERTOPS_ADCS_DESTINATION_CA_CONFIG,command,ps,until,jobFinished,configDir,workDir,run,tlsAuthority,ownedEnrollmentIds,ownedCertificateIds,ownedSites,ownedThumbprints,registerOwnedStoreCertificate:value=>webHostingJourney.registerIssuerSwitchStoreCertificate(ownedIssuerSwitchStoreCertificates,value),reservePrimaryPreflights:count=>{assert.equal(count,4);assert.ok(primaryPreflightCount+count<=18);primaryPreflightCount+=count;}});
      return;
    }
    for (const item of cases) await gate.scenario(`adcs-real-${item.id}-issued-cng-iis`, async () => {
      const { issuerId, result } = await preflight(item.template);
      assert.equal(result.templateCheck.verdict, "safe"); assert.equal(result.caCheck.verdict, "safe");
      assert.equal(result.templateCheck.schemaVersion, item.schema);
      const authority = result.caCertificates[0]; assert.ok(authority.keySha256);
      assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: authority.keySha256, caConfig, template: item.template })).status, 200);
      const site = `TTADCS-${run}-${item.id}`; const port = await freePort();
      const directory = path.join(workDir, item.id); fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, "index.html"), item.id);
      ownedSites.push(site);
      ps(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g, "''")}' -IPAddress '*' -Port ${port} -HostHeader '${item.domain}' -Ssl | Out-Null; Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${item.domain}' -PropertyName sslFlags -Value 1`);
      const certificateId = crypto.randomUUID();
      ownedCertificateIds.push(certificateId);
      const enrollment = await fixture.request(`${api}/enrollments`, "POST", { issuerId, certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: item.domain, store: "My", binding: { site, port, sniHost: item.domain } }, authorizedDnsNames: [item.domain], keyAlgorithm: item.algorithm, keySize: item.size }); assert.equal(enrollment.status, 201);
      ownedEnrollmentIds.push(enrollment.body.enrollmentId);
      await jobFinished(enrollment.body.jobId);
      const state = (await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, enrollment.body.enrollmentId])).rows[0]; assert.equal(state.state, "installed");
      const peer = await new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: item.domain, ca: tlsAuthority(authority) }, () => { resolve(socket.getPeerCertificate()); socket.end(); }); socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out"))); socket.on("error", reject); });
      const observed = new crypto.X509Certificate(peer.raw); assert.equal(observed.checkHost(item.domain), item.domain);
      assert.equal(observed.publicKey.asymmetricKeyType,item.algorithm === "rsa" ? "rsa" : "ec");
      if(item.algorithm === "rsa")assert.equal(observed.publicKey.asymmetricKeyDetails.modulusLength,item.size);
      else assert.equal(observed.publicKey.asymmetricKeyDetails.namedCurve,item.size === 256 ? "prime256v1" : "secp384r1");
      const thumbprint = crypto.createHash("sha1").update(peer.raw).digest("hex").toUpperCase(); ownedThumbprints.add(thumbprint);
      gate.report.nativeCertificates.push({scenario:`adcs-real-${item.id}-issued-cng-iis`,fingerprintSha256:observed.fingerprint256.replace(/:/g,"").toLowerCase(),keyAlgorithm:item.algorithm,keySize:item.size,template:item.template,templateSchema:result.templateCheck.schemaVersion,requestId:String(state.request_id),notAfter:new Date(observed.validTo).toISOString(),caKeySha256:authority.keySha256});
      assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}'; if (-not $c.HasPrivateKey) { throw 'Missing private key' }; $k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); if (-not $k) {$k=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)}; try { if ($k.Key.KeyName -ne '${require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(enrollment.body.enrollmentId)}') {throw 'Issued leaf uses a foreign native key'}; if ($k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None) {throw 'Exportable key'}; 'nonexportable-cng' } finally {$k.Dispose()}`), "nonexportable-cng");
      assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, enrollment.body.jobId])).rows.length);
      const nativeRequest=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/owned-issued-request.ps1"),"-CommonName",item.domain,"-FingerprintSha256",observed.fingerprint256.replace(/:/g,"").toLowerCase()]));assert.equal(nativeRequest.disposition,20);assert.equal(nativeRequest.fingerprintSha256,observed.fingerprint256.replace(/:/g,"").toLowerCase());assert.equal(nativeRequest.serialNumber.replace(/^0+/,"").toLowerCase(),observed.serialNumber.replace(/^0+/,"").toLowerCase());assert.equal(nativeRequest.subjectRequestCount,1);assert.ok(Number(nativeRequest.requestId)>0);if(state.request_id!=null)assert.equal(String(state.request_id),String(nativeRequest.requestId));
      gate.report.nativeCertificates[gate.report.nativeCertificates.length-1].requestId=String(nativeRequest.requestId);gate.report.nativeCertificates[gate.report.nativeCertificates.length-1].requestIdSource="native-CA-exact-leaf-fingerprint";
      issuedFixtures.push({item,issuerId,authority,site,port,certificateId,enrollmentId:enrollment.body.enrollmentId,observed,thumbprint,requestId:nativeRequest.requestId});
      if(item.id === "rsa2048") renewalFixture={item,issuerId,authority,site,port,certificateId,enrollmentId:enrollment.body.enrollmentId,observed,thumbprint,foreignRequestId:nativeRequest.requestId};
    });
    if(elapsedPending){
      await require("./helpers/certops-adcs-pending-elapsed").qualifyPendingElapsed({gate,fixture,api,agentRowId,renewalFixture,configDir,run,preflight,command,ps,until,jobFinished,ownedEnrollmentIds,tlsAuthority,caConfig});
    }else{
    await gate.scenario("adcs-real-localized-native-discovery-binding-identity",async()=>{
      const observations=await require("../../packages/agent/src/discovery/windows").collectWindowsDiscoveryObservations({stores:["My"]});
      const language=ps("(Get-UICulture).Name");assert.equal(language,gate.report.qualificationEnvironment.nativeLanguage);
      const identities=[];
      for(const issued of issuedFixtures){
        const fingerprint=issued.observed.fingerprint256.replace(/:/g,"").toLowerCase();
        const binding=observations.filter(row=>row.locationKind==="iis_binding"&&row.siteName===issued.site&&row.port===issued.port&&row.sniHost===issued.item.domain);
        assert.equal(binding.length,1,"Actual native discovery must resolve the exact owned SNI site/port/host");
        assert.equal(binding[0].fingerprintSha256,fingerprint);assert.equal(binding[0].storeLocation,"LocalMachine");assert.equal(binding[0].storeName,"My");assert.equal(binding[0].keyPresent,true);assert.equal(binding[0].thumbprint.toLowerCase(),issued.thumbprint.toLowerCase());assert.ok(binding[0].subjectAltNames.includes(issued.item.domain));
        const stores=observations.filter(row=>row.locationKind==="windows_store"&&row.fingerprintSha256===fingerprint&&row.storeName==="My");assert.equal(stores.length,1);assert.equal(stores[0].keyPresent,true);
        identities.push({fingerprintSha256:fingerprint,store:"LocalMachine/My",siteName:issued.site,port:issued.port,sniHost:issued.item.domain,keyPresent:true});
      }
      gate.report.localizedDiscovery={nativeLanguage:language,measurement:"native",fixtureIdentities:identities,publicDerFingerprintComparedToTrustedTls:true,localizedConsoleLabelsRequired:false};
    },{evidenceLevel:"real-host",oracle:"actual production Windows store/HTTP.sys/IIS discovery on measured installed native language, exact seven owned SNI coordinates and protected-key locality compared to independently trusted TLS DER"});
    await require("./helpers/certops-adcs-iis-locale").qualifyIisLocale({gate,issuedFixtures,ps,command,workDir,run,tlsAuthority,ownedNativeBindings});
    await require("./helpers/certops-adcs-algorithm-boundaries").qualifyAlgorithmBoundaries({gate,fixture,api,agentRowId,issuedFixtures,configDir,preflight,requireNativeRefusal,command,ps,tlsAuthority,caConfig});
    await require("./helpers/certops-adcs-positive-renewals").qualifyPositiveRenewals({gate,fixture,api,agentRowId,issuedFixtures,ownedEnrollmentIds,ownedThumbprints,jobFinished,ps,command,tlsAuthority});
    {
      // Separate store/site identity leaves the existing My qualification fixtures intact.
      const source=issuedFixtures.find(row=>row.item.id==="rsa2048");
      const site=`TTAdcsWebHosting${run}`,port=await freePort(),certificateId=crypto.randomUUID();
      const directory=path.join(workDir,"webhosting");fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),"WebHosting qualification");
      ownedSites.push(site);ownedCertificateIds.push(certificateId);
      ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Isolated WebHosting site already exists'};New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${webHostingDomain}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${webHostingDomain}' -PropertyName sslFlags -Value 1`);
      await webHostingJourney.qualifyWebHostingRenewal({gate,fixture,api,agentRowId,configDir,isolated:{domain:webHostingDomain,site,port,certificateId,issuerId:source.issuerId,authority:source.authority},ownedEnrollmentIds,ownedStoreCertificates,jobFinished,until,ps,command,tlsAuthority});
    }
    gate.report.nativeAdcsCapacity=await capacityJourney.qualifyCapacity({approvalActor:require("./helpers/certops-adcs-browser-job-approval").createBrowserJobApprovalActor({gate,fixture,configDir,command,workDir,ownedBrowserResources}),cancelActor:require("./helpers/certops-adcs-browser-cancel").createBrowserCancelActor({gate,fixture,api,configDir,command,ps,until,ownedEnrollmentIds,tlsAuthority,agentRowId,workDir,ownedBrowserResources}),gate,fixture,api,baseUrl:url.href,caConfig,agentRowId,configDir,workDir,run,command,ps,until,jobFinished,ownedApiFixtures,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,tlsAuthority,reservePrimaryPreflights:count=>{assert.equal(count,2);assert.ok(primaryPreflightCount+count<=18,"Native capacity preflights exceed original primary budget");primaryPreflightCount+=count;},registerOwnedStoreCertificate:({domain,certificateId})=>registerCapacityStoreCertificate({domain,certificateId})});
    await require("./helpers/certops-adcs-native-reconcile").qualifyNativeReconciliation({gate,fixture,api,configDir,workDir,run,issuedFixtures,ps,command,tlsAuthority});
    await require("./helpers/certops-adcs-retrieve-boundaries").qualifyRetrieveBoundaries({gate,configDir,workDir,run,issuedFixtures,ps,command});
    await require("./helpers/certops-adcs-validity-boundaries").qualifyValidityBoundaries({gate,fixture,api,agentRowId,renewalFixture,configDir,preflight,until,ps,command,ownedEnrollmentIds,tlsAuthority,caConfig});
    await require("./helpers/certops-adcs-local-rules").qualifyLocalRules({gate,fixture,api,agentRowId,renewalFixture,configDir,run,preflight,command,ps,until,ownedEnrollmentIds,tlsAuthority,workDir,ownedResultResources,ownedTlsProbes,ownedSites,ownedThumbprints,ownedCertificateIds,freePort});
    await require("./helpers/certops-adcs-issued-cancellation").qualifyIssuedCancellation({gate,fixture,api,agentRowId,renewalFixture,configDir,preflight,command,ps,until,jobFinished,ownedEnrollmentIds,tlsAuthority,caConfig});
    if(hierarchy){
      await gate.scenario("adcs-hierarchy-offline-root-and-public-crl",async()=>{
        const state=ps(`$credential=[PSCredential]::new('tt-root\\ttqualification',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force));Invoke-Command -ComputerName '10.64.0.7' -Credential $credential -ScriptBlock {if($env:COMPUTERNAME -ne 'tt-root' -or (Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'Unexpected root identity'};$service=Get-Service CertSvc;if($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled'){throw 'Root signing service must remain offline'};'offline-standalone-root'}`);
        assert.equal(state,"offline-standalone-root");
        const rootResponse=await fetch("http://10.64.0.7/pki/root.cer",{signal:AbortSignal.timeout(10000)});assert.equal(rootResponse.status,200);
        const root=new crypto.X509Certificate(Buffer.from(await rootResponse.arrayBuffer()));const expected=new crypto.X509Certificate(Buffer.from(process.env.CERTOPS_ADCS_HIERARCHY_ROOT_CERT,"base64"));assert.equal(root.fingerprint256,expected.fingerprint256);assert.equal(root.subject,"CN=TTQualificationOfflineRoot");assert.equal(root.issuer,root.subject);
        const crlResponse=await fetch("http://10.64.0.7/pki/TTQualificationOfflineRoot.crl",{signal:AbortSignal.timeout(10000)});assert.equal(crlResponse.status,200);const crl=Buffer.from(await crlResponse.arrayBuffer());assert.ok(crl.length>100 && crl.length<65536);
        gate.report.hierarchyQualification={rootSigningService:"stopped-and-disabled-native-observation",rootDomainJoined:false,rootFingerprintSha256:root.fingerprint256.replace(/:/g,"").toLowerCase(),publicCrlAvailable:true,publicCrlSha256:crypto.createHash("sha256").update(crl).digest("hex")};
      });
      await gate.scenario("adcs-hierarchy-issued-three-certificate-chain",async()=>{
        assert.equal(gate.report.nativeCertificates.length,cases.length);
        for(const certificate of gate.report.nativeCertificates){
          const thumbprint=ps(`$c=@(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object {([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-','').ToLowerInvariant() -eq '${certificate.fingerprintSha256}'});if($c.Count -ne 1){throw 'Owned leaf missing'};$chain=[Security.Cryptography.X509Certificates.X509Chain]::new();try{$chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online;$chain.ChainPolicy.RevocationFlag=[Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot;if(-not $chain.Build($c[0]) -or $chain.ChainElements.Count -ne 3){throw 'Native three-certificate chain failed'};if($chain.ChainElements[1].Certificate.Subject -ne 'CN=TTQualificationRoot' -or $chain.ChainElements[2].Certificate.Subject -ne 'CN=TTQualificationOfflineRoot'){throw 'Unexpected native hierarchy'};$chain.ChainElements[2].Certificate.Thumbprint}finally{$chain.Dispose()}`);
          const expected=new crypto.X509Certificate(Buffer.from(process.env.CERTOPS_ADCS_HIERARCHY_ROOT_CERT,"base64"));assert.equal(thumbprint.toUpperCase(),crypto.createHash("sha1").update(expected.raw).digest("hex").toUpperCase());
        }
        gate.report.hierarchyQualification.nativeChainLength=3;gate.report.hierarchyQualification.nativeAlgorithmsVerified=5;gate.report.hierarchyQualification.nativeTemplateProfilesVerified=cases.length;gate.report.hierarchyQualification.installedAgentIdentity="LocalSystem";
      });
    }
    await gate.scenario("adcs-real-manual-renewal-replaces-iis-certificate", async()=>{
      assert.ok(renewalFixture);
      const {item,issuerId,authority,site,port,certificateId,observed,thumbprint}=renewalFixture;
      // Use the existing public enrollment service with the same managed identity and live binding.
      // This is a new CA enrollment, not a claim of a CMC signed-renewal protocol.
      const response=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});
      assert.equal(response.status,201); ownedEnrollmentIds.push(response.body.enrollmentId);
      assert.notEqual(response.body.enrollmentId,renewalFixture.enrollmentId);
      await jobFinished(response.body.jobId);
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});
      const renewed=new crypto.X509Certificate(raw); assert.equal(renewed.checkHost(item.domain),item.domain);
      assert.notEqual(renewed.fingerprint256,observed.fingerprint256); assert.notEqual(renewed.serialNumber,observed.serialNumber);
      assert.notDeepEqual(renewed.publicKey.export({type:"spki",format:"der"}),observed.publicKey.export({type:"spki",format:"der"}));
      const newThumbprint=crypto.createHash("sha1").update(raw).digest("hex").toUpperCase();ownedThumbprints.add(newThumbprint);assert.notEqual(newThumbprint,thumbprint);
      assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${newThumbprint}'; $k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); try {if($k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Renewed key exportable'}; 'nonexportable-cng'} finally {$k.Dispose()}`),"nonexportable-cng");
      assert.equal((await fixture.pool.query("SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,response.body.enrollmentId])).rows[0].state,"installed");
      assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,response.body.jobId])).rows.length);
      renewalFixture.observed=renewed; renewalFixture.thumbprint=newThumbprint;
    });
    await gate.scenario("adcs-real-profile-automatic-service-renewal", async()=>{
      const {item,issuerId,authority,site,port,certificateId,observed}=renewalFixture;
      const target={type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}};
      const profile=await fixture.request(`${api}/profiles`,"POST",{name:`Native renewal ${run}`,issuerId,target,keyAlgorithm:"rsa",keySize:2048,renewBeforeDays:30});assert.equal(profile.status,201);
      const profileRow=(await fixture.pool.query("SELECT public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,profile.body.id])).rows[0];
      // Automatic dispatch requires fresh real native preflight evidence created after confirmation.
      assert.ok(++primaryPreflightCount<=18);const check=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template:item.template});assert.equal(check.status,201);await jobFinished(check.body.job.id);
      const renewal=await require("../../apps/api/services/certops/renewalScheduler").createAutomaticAdcsRenewal({dbPool:fixture.pool,certificate:{id:certificateId,workspace_id:fixture.workspaceId,profile_id:profile.body.id,profile_issuer_id:issuerId,profile_public_metadata:profileRow.public_metadata,not_after:new Date(observed.validTo),common_name:item.domain},mode:"real",env:process.env,auditWriter:require("../../apps/api/services/audit").writeAudit});
      assert.equal(renewal.created,true);assert.ok(renewal.job.id);
      const enrollment=(await fixture.pool.query("SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2",[fixture.workspaceId,renewal.job.id])).rows[0];assert.ok(enrollment);ownedEnrollmentIds.push(enrollment.id);
      await jobFinished(renewal.job.id);
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});
      const leaf=new crypto.X509Certificate(raw);assert.equal(leaf.checkHost(item.domain),item.domain);assert.notEqual(leaf.fingerprint256,observed.fingerprint256);ownedThumbprints.add(crypto.createHash("sha1").update(raw).digest("hex").toUpperCase());
      assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,renewal.job.id])).rows.length);
      renewalFixture.profileId=profile.body.id; renewalFixture.observed=leaf;
    });
    await gate.scenario("adcs-real-scheduler-selects-short-lived-observed-certificate",async()=>{
      const {item,site,port,profileId,observed,authority}=renewalFixture;
      assert.ok(Date.parse(observed.validTo)>Date.now());
      assert.ok(Date.parse(observed.validTo)<=Date.now()+7*86400000,"Actual CA template must issue a short-lived certificate without rewriting database expiry");
      const fingerprint=observed.fingerprint256.replace(/:/g,"").toLowerCase();
      const source=await until(async()=> (await fixture.pool.query("SELECT mc.id,mc.not_after FROM managed_certificates mc JOIN certificate_instances ci ON ci.workspace_id=mc.workspace_id AND ci.managed_certificate_id=mc.id JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id WHERE mc.workspace_id=$1 AND ci.observed_fingerprint_sha256=$2 AND ct.windows_site=$3 AND mc.source='agent_windows' ORDER BY ci.observed_at DESC LIMIT 1",[fixture.workspaceId,fingerprint,site])).rows[0]);
      assert.equal(new Date(source.not_after).getTime(),Date.parse(observed.validTo));
      const managed=await fixture.request(`${api}/sources/${source.id}/replace-management`,"POST",{renewalProfileId:profileId,automationEnabled:true});assert.equal(managed.status,201);
      const scheduler=require("../../apps/api/services/certops/renewalScheduler");
      const before=await fixture.pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew'",[fixture.workspaceId,String(source.id)]);assert.equal(before.rows.length,0);
      const sweep=await scheduler.runRenewalSchedulerSweep({dbPool:fixture.pool,env:{...process.env,CERTOPS_ENABLED:"true"}});assert.equal(sweep.lockAcquired,true);assert.ok(sweep.created>=1);assert.deepEqual(sweep.errors,[]);
      const job=await until(async()=> (await fixture.pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='renew' ORDER BY created_at DESC LIMIT 1",[fixture.workspaceId,String(source.id)])).rows[0]);
      const enrollment=(await fixture.pool.query("SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2",[fixture.workspaceId,job.id])).rows[0];assert.ok(enrollment);ownedEnrollmentIds.push(enrollment.id);
      await jobFinished(job.id);
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});
      const leaf=new crypto.X509Certificate(raw);assert.equal(leaf.checkHost(item.domain),item.domain);assert.notEqual(leaf.fingerprint256,observed.fingerprint256);ownedThumbprints.add(crypto.createHash("sha1").update(raw).digest("hex").toUpperCase());
      assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,job.id])).rows.length);
      gate.report.schedulerQualification={eligibilityClock:"actual-database-now",validityFixture:"actual-six-day-CA-template",observation:"native-agent-IIS",profileAuthority:"public-replace-management"};
      renewalFixture.observed=leaf;
      renewalFixture.currentEnrollmentId=enrollment.id;
    });
    await require("./helpers/certops-adcs-two-renewals").qualifyTwoRenewals({gate,fixture,renewalFixture,configDir,ps,command,until,jobFinished,ownedEnrollmentIds,ownedThumbprints,tlsAuthority});
    await require("./helpers/certops-adcs-background-renewals").qualifyBackgroundRenewals({gate,fixture,renewalFixture,configDir,ps,command,until,jobFinished,ownedEnrollmentIds,tlsAuthority,workDir,ownedPhaseObservers,registerOwnedStoreCertificate:value=>webHostingJourney.registerBackgroundStoreCertificate(ownedBackgroundStoreCertificates,value)});
    gate.report.nativeLiveEnrollAcl=await require("./helpers/certops-adcs-live-enroll-acl").qualifyLiveEnrollAcl({gate,fixture,api,agentRowId,renewalFixture,configDir,workDir,run,command,ps,until,jobFinished,ownedEnrollmentIds,ownedStoreReceipt:ownedBackgroundStoreCertificates[0],tlsAuthority});
    gate.report.nativeHttpOnlyLeafCrl=await httpLeafCrlJourney.qualifyHttpOnlyLeafCrl({gate,fixture,api,agentRowId,renewalFixture,configDir,workDir,run,command,ps,until,jobFinished,ownedEnrollmentIds,ownedStoreReceipt:ownedBackgroundStoreCertificates[0],tlsAuthority,registerOwnership:resource=>ownedHttpCrlResources.push(resource)});
    gate.report.nativeOcspResponder=await ocspJourney.qualifyOcsp({gate,fixture,api,agentRowId,renewalFixture,configDir,workDir,run,command,ps,until,jobFinished,ownedEnrollmentIds,ownedStoreReceipt:ownedBackgroundStoreCertificates[0],tlsAuthority,registerOwnership:resource=>ownedHttpCrlResources.push(resource)});
    await gate.scenario(resultOutboxJourney.SCENARIO,async()=>{gate.report[resultOutboxJourney.FIELD]=await resultOutboxJourney.qualifyResultOutbox({gate,fixture,api,agentRowId,renewalFixture,configDir,workDir,run,command,ps,until,ownedEnrollmentIds,ownedStoreReceipt:ownedBackgroundStoreCertificates[0],ownedResultResources,configurationIdentity:originalConfigurationIdentity,tlsAuthority});},{evidenceLevel:"real-host"});
    if(hierarchy)gate.report.nativeHttpIntermediateCrl=await httpIntermediateCrlJourney.qualifyHttpIntermediateCrl({gate,workDir,run,renewalFixture,command,ps,tlsAuthority,registerOwnership:resource=>ownedHttpCrlResources.push(resource)});
    for (const item of pendingCases) await gate.scenario(`adcs-real-pending-${item.action}-continuation`, async () => {
      const { issuerId, result } = await preflight("TTQualificationPending");
      assert.equal(result.templateCheck.verdict, "safe"); assert.equal(result.caCheck.verdict, "safe");
      const authority = result.caCertificates[0];
      assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: authority.keySha256, caConfig, template: "TTQualificationPending" })).status, 200);
      const site = `TTADCS-${run}-${item.action}`; const port = await freePort();
      const directory = path.join(workDir, item.action); fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, "index.html"), item.action); ownedSites.push(site);
      ps(`Import-Module WebAdministration; New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${item.domain}' -Ssl | Out-Null; Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${item.domain}' -PropertyName sslFlags -Value 1`);
      const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId);
      const created = await fixture.request(`${api}/enrollments`, "POST", { issuerId, certificateId, agentId: agentRowId, target: { type: "windows-iis", reference: item.domain, store: "My", binding: { site, port, sniHost: item.domain } }, authorizedDnsNames: [item.domain], keyAlgorithm: "rsa", keySize: 2048 }); assert.equal(created.status,201);
      const enrollmentId = created.body.enrollmentId; ownedEnrollmentIds.push(enrollmentId);
      const pending = await until(async()=> { const row=(await fixture.pool.query("SELECT state,request_id,next_poll_at FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,enrollmentId])).rows[0]; return row?.state === "pending_issuance" && row.request_id ? row : null; });
      assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[created.body.jobId])).rows[0].status,"awaiting_issuer");
      if (["approve","deny"].includes(item.action)) command("powershell.exe", ["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(pending.request_id),"-Action",item.action,"-CommonName",item.domain]);
      if (item.action === "cancel") assert.equal((await fixture.request(`${api}/enrollments/${enrollmentId}/cancel`,"POST",{})).status,204);
      // Advance only supported scheduler eligibility; CA and signed agent execution use their actual clocks.
      const eligibility = item.action === "expire" ? new Date(Date.now()+15*86400000) : new Date(new Date(pending.next_poll_at).getTime()+1000);
      gate.report.pendingContinuationQualification.push({action:item.action,eligibilityClock:"supported-scheduler-now-input",eligibilityTime:eligibility.toISOString(),hostAndCaClocks:"actual",databaseExpiryRewritten:false});
      const dispatched = await require("../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:eligibility});
      const continuation = dispatched.find(row=>row.enrollmentId===enrollmentId); assert.ok(continuation);
      const expectedState = {approve:"installed",deny:"denied",expire:"expired",cancel:"cancelled"}[item.action];
      await until(async()=> { const row=(await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,enrollmentId])).rows[0]; assert.equal(String(row.request_id),String(pending.request_id)); return row.state === expectedState; });
      if(["expire","cancel"].includes(item.action)) await jobFinished(continuation.jobId);
      if(item.action === "approve") {
        await jobFinished(continuation.jobId);
        const raw = await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});
        assert.equal(new crypto.X509Certificate(raw).checkHost(item.domain),item.domain); ownedThumbprints.add(crypto.createHash("sha1").update(raw).digest("hex").toUpperCase());
        assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,continuation.jobId])).rows.length);
      } else {
        const container = require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(enrollmentId);
        assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container),"Denied request retained its native CNG key");
        assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${item.domain}').Count`),"0");
      }
      if (["expire", "cancel"].includes(item.action)) pendingRecoveryFixtures[item.action] = {item,site,port,certificateId,issuerId,authority,created:created.body,pending,continuation};
    });
    await require("./helpers/certops-adcs-cmc-boundaries").qualifyNativeCmcBoundaries({gate,configDir,workDir,pendingRecoveryFixtures});
    await require("./helpers/certops-adcs-recovery").qualifyRecovery({gate,fixture,api,caConfig,agentRowId,configDir,serviceOwned,run,ps,command,until,jobFinished,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,workDir,tlsAuthority,pendingRecoveryFixtures});
    await cancelledLateApprovalJourney.qualifyCancelledLateApproval({gate,fixture,api,configDir,pendingRecoveryFixtures,ownedEnrollmentIds,ownedLateApprovalGuards,ps,command,until,tlsAuthority});
    gate.report.nativeSameCertificateLateApproval=await require("./helpers/certops-adcs-same-certificate-late-approval").qualifySameCertificateLateApproval({gate,fixture,api,agentRowId,configDir,workDir,pendingRecoveryFixtures,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,ownedLateApprovalGuards,ps,command,until,jobFinished,tlsAuthority});
    await require("./helpers/certops-adcs-ca-outage").qualifyCaOutage({gate,fixture,api,agentRowId,configDir,run,ps,command,until,jobFinished,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,pendingRecoveryFixtures,tlsAuthority,ownedCaServiceFaults});
    await require("./helpers/certops-adcs-submission-boundaries").qualifySubmissionBoundaries({gate,fixture,api,agentRowId,configDir,workDir,run,preflight,ps,command,until,jobFinished,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,ownedFirewallRules,pendingRecoveryFixtures,tlsAuthority});
    await require("./helpers/certops-adcs-issued-san-boundary").qualifyIssuedSanBoundary({gate,fixture,api,agentRowId,configDir,run,pendingRecoveryFixtures,command,ps,until,tlsAuthority,ownedCertificateIds,ownedEnrollmentIds,registerOwnedUnacceptedEnrollment});
    await require("./helpers/certops-adcs-issued-revocation").qualifyIssuedRevocation({gate,fixture,api,agentRowId,configDir,run,pendingRecoveryFixtures,command,ps,until,tlsAuthority,ownedCertificateIds,ownedEnrollmentIds,registerOwnedUnacceptedEnrollment,invalidateOwnedRevocationCache:()=>{assert.ok(fs.existsSync(chainCacheSnapshot),"Original owned revocation-cache snapshot must exist");command("certutil.exe",["-urlcache","CRL","delete"]);command("certutil.exe",["-setreg","chain\\ChainCacheResyncFiletime","@now"]);}});
    await gate.scenario("adcs-real-pending-profile-edit-preserves-frozen-contract",async()=>{
      const {item,site,port,certificateId,observed}=renewalFixture;
      const {issuerId,result}=await preflight("TTQualificationPending");const authority=result.caCertificates[0];
      assert.equal(result.templateCheck.verdict,"safe");assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:authority.keySha256,caConfig,template:"TTQualificationPending"})).status,200);
      const target={type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}};
      const profile=await fixture.request(`${api}/profiles`,"POST",{name:`Pending immutable contract ${run}`,issuerId,target,keyAlgorithm:"rsa",keySize:2048,renewBeforeDays:30});assert.equal(profile.status,201);
      assert.ok(++primaryPreflightCount<=18);const check=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template:"TTQualificationPending"});assert.equal(check.status,201);await jobFinished(check.body.job.id);
      const profileRow=(await fixture.pool.query("SELECT public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,profile.body.id])).rows[0];
      const renewal=await require("../../apps/api/services/certops/renewalScheduler").createAutomaticAdcsRenewal({dbPool:fixture.pool,certificate:{id:certificateId,workspace_id:fixture.workspaceId,profile_id:profile.body.id,profile_issuer_id:issuerId,profile_public_metadata:profileRow.public_metadata,not_after:new Date(observed.validTo),common_name:item.domain},mode:"real",env:process.env,auditWriter:require("../../apps/api/services/audit").writeAudit});assert.equal(renewal.created,true);
      const ownedPending=(await fixture.pool.query("SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2",[fixture.workspaceId,renewal.job.id])).rows[0];assert.ok(ownedPending);ownedEnrollmentIds.push(ownedPending.id);
      const pending=await until(async()=>{const row=(await fixture.pool.query("SELECT id,state,request_id,next_poll_at,snapshot_bytes,snapshot_sha256,deploy_target FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2",[fixture.workspaceId,renewal.job.id])).rows[0];return row?.state === "pending_issuance" && row.request_id ? row : null;});
      const snapshot=JSON.parse(Buffer.from(pending.snapshot_bytes).toString("utf8"));assert.equal(snapshot.keySize,2048);assert.equal(snapshot.template,"TTQualificationPending");assert.equal(snapshot.issuerId,issuerId);assert.deepEqual(pending.deploy_target,target);
      const edited=await fixture.request(`${api}/profiles/${profile.body.id}`,"PATCH",{issuerId:renewalFixture.issuerId,renewalProfile:{keySize:4096}});assert.equal(edited.status,200);assert.equal(edited.body.issuerId,renewalFixture.issuerId);assert.equal(edited.body.renewalProfile.keySize,4096);
      const retarget=await fixture.request(`${api}/profiles/${profile.body.id}`,"PATCH",{renewalProfile:{target:{...target,reference:"retarget.certops.test"}}});assert.equal(retarget.status,422);assert.equal(retarget.body.code,"CERTOPS_PROFILE_FIELD_IMMUTABLE");
      command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(pending.request_id),"-Action","approve","-CommonName",item.domain]);
      const continuation=(await require("../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(new Date(pending.next_poll_at).getTime()+1000)})).find(row=>row.enrollmentId===pending.id);assert.ok(continuation);await jobFinished(continuation.jobId);
      const after=(await fixture.pool.query("SELECT state,request_id,snapshot_sha256,deploy_target FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,pending.id])).rows[0];assert.equal(after.state,"installed");assert.equal(String(after.request_id),String(pending.request_id));assert.equal(after.snapshot_sha256,pending.snapshot_sha256);assert.deepEqual(after.deploy_target,target);
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Pending snapshot TLS oracle timed out")));socket.on("error",reject);});const leaf=new crypto.X509Certificate(raw);assert.equal(leaf.checkHost(item.domain),item.domain);assert.equal(leaf.publicKey.asymmetricKeyDetails.modulusLength,2048);assert.notEqual(leaf.fingerprint256,observed.fingerprint256);ownedThumbprints.add(crypto.createHash("sha1").update(raw).digest("hex").toUpperCase());
      const installedThumbprint=crypto.createHash("sha1").update(raw).digest("hex").toUpperCase();const expectedContainer=require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(pending.id);
      assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${installedThumbprint}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{if($k.Key.KeyName -ne '${expectedContainer}' -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Pending profile edit changed owned key custody'};'same-nonexportable-cng'}finally{$k.Dispose()}`),"same-nonexportable-cng");
      assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,continuation.jobId])).rows.length);
      renewalFixture.observed=leaf;renewalFixture.currentEnrollmentId=pending.id;
      gate.report.pendingProfileQualification={initiation:"profile-driven-renewal-service",profileIssuerChanged:true,profileKeySizeChanged:4096,actualIssuedKeySize:2048,frozenSnapshotPreserved:true,originalCaRequestPreserved:true,targetEditRefused:true,pollEligibilityClock:"supported-scheduler-now-input"};
    });
    if(process.env.CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT === "1"){
      // Experimental fault timing is deliberately outside the release qualification scenario set.
      const experiment={schemaVersion:1,scope:"enterprise-adcs-response-loss-experimental",qualificationStatus:"not-qualified",candidateSha:process.env.GITHUB_SHA,fixtureSource:gate.report.fixtureSource,qualificationEnvironment:gate.report.qualificationEnvironment,status:"running"};
      const experimentPath=path.join(workDir,"response-loss-experimental.json");
      let controller;
      try{
        const {issuerId,result}=await preflight("TTQualificationPending");assert.equal(result.templateCheck.verdict,"safe");
        assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:result.caCertificates[0].keySha256,caConfig,template:"TTQualificationPending"})).status,200);
        const site=`TTADCS-${run}-fault`;const port=await freePort();const directory=path.join(workDir,"fault");fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),"fault");ownedSites.push(site);
        ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${faultDomain}' -Ssl | Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${faultDomain}' -PropertyName sslFlags -Value 1`);
        controller=require("./helpers/certops-adcs-response-loss")({commonName:faultDomain,ownedDirectory:workDir});ownedPhaseObservers.push(controller);
        await controller.ready;
        const certificateId=crypto.randomUUID();ownedCertificateIds.push(certificateId);
        const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:faultDomain,store:"My",binding:{site,port,sniHost:faultDomain}},authorizedDnsNames:[faultDomain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
        experiment.fault=await controller.result;
        await until(async()=> (await fixture.pool.query("SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0]?.state === "submission_uncertain");
        const originalContainer=require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(created.body.enrollmentId);
        assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(originalContainer),"Uncertain submission must retain its exact native CNG key");
        command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(experiment.fault.requestId),"-Action","approve","-CommonName",faultDomain]);
        assert.ok(renewalFixture.foreignRequestId);assert.notEqual(String(renewalFixture.foreignRequestId),String(experiment.fault.requestId));
        assert.equal((await fixture.request(`${api}/enrollments/${created.body.enrollmentId}/reconcile`,"POST",{requestId:renewalFixture.foreignRequestId})).status,204);
        const scheduler=require("../../apps/api/services/certops/certificateEnrollments");
        const foreignDispatch=(await scheduler.scheduleDueEnrollments({client:fixture.pool})).find(row=>row.enrollmentId===created.body.enrollmentId);assert.ok(foreignDispatch);
        await until(async()=>{const row=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,foreignDispatch.jobId])).rows[0];if(row.status === "succeeded")throw new Error("Foreign CA RequestId incorrectly installed another enrollment's material");return row.status === "failed";});
        assert.equal((await fixture.pool.query("SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0].state,"submission_uncertain");
        assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${faultDomain}').Count`),"0");
        assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(originalContainer),"Foreign reconciliation candidate must preserve the owned key");
        experiment.foreignRequestRefused=true;
        assert.equal((await fixture.request(`${api}/enrollments/${created.body.enrollmentId}/reconcile`,"POST",{requestId:experiment.fault.requestId})).status,204);
        const scheduled=await require("../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool});const continuation=scheduled.find(row=>row.enrollmentId===created.body.enrollmentId);assert.ok(continuation);await jobFinished(continuation.jobId);
        const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:faultDomain,ca:new crypto.X509Certificate(Buffer.from(result.caCertificates[0].certificateB64,"base64")).toString()},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});assert.equal(new crypto.X509Certificate(raw).checkHost(faultDomain),faultDomain);const recoveredThumbprint=crypto.createHash("sha1").update(raw).digest("hex").toUpperCase();ownedThumbprints.add(recoveredThumbprint);
        assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${recoveredThumbprint}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{if($k.Key.KeyName -ne '${originalContainer}' -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Recovery replaced or exposed original owned key'};'same-nonexportable-cng'}finally{$k.Dispose()}`),"same-nonexportable-cng");experiment.recoveredOwnedKey=true;
        experiment.status="passed";
      }catch(error){experiment.status="failed";throw error;}
      finally{try{await controller?.stopAndDrain();}catch(error){experiment.status="failed";throw error;}finally{fs.writeFileSync(experimentPath,JSON.stringify(experiment));fs.copyFileSync(experimentPath,process.env.CERTOPS_ADCS_RESPONSE_LOSS_REPORT || "C:\\ttqualification\\response-loss-experimental.json");}}
    }
    for(const item of deniedCases)await gate.scenario(`adcs-real-template-${item.id}-denied`,async()=>{
      const {issuerId,result}=await preflight(item.template);assert.equal(result.templateCheck.verdict,"safe");
      assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:result.caCertificates[0].keySha256,caConfig,template:item.template})).status,200);
      const site=`TTADCS-${run}-${item.id}`;const port=await freePort();const directory=path.join(workDir,item.id);fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),item.id);ownedSites.push(site);
      ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${item.domain}' -Ssl | Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${item.domain}' -PropertyName sslFlags -Value 1`);
      const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId:crypto.randomUUID(),agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
      const outcome=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.jobId])).rows[0];if(row.status === "succeeded")throw new Error("Native CA issued a certificate despite template denial fixture");return row.status === "failed" ? row : null;});
      assert.equal(outcome.result_metadata.enrollmentResult.state,"denied");assert.equal(outcome.result_metadata.enrollmentResult.caHresult.toLowerCase(),item.hresult);
      assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${item.domain}').Count`),"0");
      const container=require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(created.body.enrollmentId);assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));
      assert.equal((await fixture.pool.query("SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0].state,"denied");
    });
    for (const unsafeCase of [...safetyCases.templateCases,{name:"WebServer",reason:"schema_version_1"}]) await gate.scenario(`adcs-real-unsafe-${unsafeCase.name}-confirmation-refused`, async () => {
      const template=unsafeCase.name;
      const { result, confirm } = await preflightCohorts.preflight(template); assert.equal(result.templateCheck.verdict, "unsafe");
      assert.ok(result.templateCheck.reasons.includes(unsafeCase.reason),"Actual native template facts must identify the specific unsafe rule");
      const response = await confirm({ caKeySha256: result.caCertificates[0]?.keySha256 || "0".repeat(64), caConfig, template }); assert.equal(response.status, 400);
    });
    await require("./helpers/certops-adcs-template-mutations").qualifyTemplateMutations({gate,fixture,api,agentRowId,renewalFixture,preflightCohorts,run,command,ps,until,ownedEnrollmentIds,tlsAuthority});
    await requiredTemplateAttributesJourney.qualifyRequiredTemplateAttributes({gate,fixture,api,caConfig,agentRowId,renewalFixture,preflightCohorts,run,command,ps,until,configDir,ownedEnrollmentIds,ownedTemplateAttributeRestorations,tlsAuthority,serviceOwned});
    for(const item of safetyEnrollments.filter(item=>item.algorithm&&!require("./helpers/certops-adcs-algorithm-boundaries").CASES.some(selected=>selected.id===item.id)))await gate.scenario(`adcs-real-template-key-${item.id}-refused`,async()=>{
      const {issuerId,result}=await preflight(item.template);assert.equal(result.templateCheck.verdict,"safe");assert.equal(result.templateCheck.schemaVersion,item.schema);
      assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:result.caCertificates[0].keySha256,caConfig,template:item.template})).status,200);
      await requireNativeRefusal(item,issuerId,"ADCS_TEMPLATE_UNSAFE");
    });
    for(const descriptor of safetyEnrollments.filter(item=>!item.algorithm))await gate.scenario(`adcs-real-ca-flags-${descriptor.id}-refused`,async()=>{
      // CA flags affect every template. Reuse the already confirmed, genuinely
      // issued RSA issuer; retain each independent fault, subject and attestation.
      assert.equal(renewalFixture.item.template,"TTQualificationRSAShort");
      const item={...descriptor,template:renewalFixture.item.template};
      const issuerId=renewalFixture.issuerId;
      const result=(await fixture.pool.query("SELECT last_preflight FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0].last_preflight;
      assert.equal(result.caConfig,caConfig);assert.equal(result.template,item.template);assert.equal(result.templateCheck.verdict,"safe");assert.equal(result.caCheck.verdict,"safe");assert.ok(result.caCertificates.some(certificate=>certificate.keySha256===renewalFixture.authority.keySha256));
      const originalConfig=fs.readFileSync(path.join(configDir,"config.json"));
      try{
        preflightCache.clear();caSafetyFaultActive=true;const flags=JSON.parse(caSafety("apply",item));assert.equal(flags.editFlags & 0x40000,item.editFlagsSet);assert.equal((flags.interfaceFlags & 0x200)===0,item.interfaceFlagsClear===0x200);
        for(const operatorAttested of [false,true]){
          const configured=JSON.parse(originalConfig);const rule=configured.adcs.enrollmentRules.find(rule=>rule.caConfig===caConfig&&rule.template===item.template);assert.ok(rule);rule.operatorAttested=operatorAttested;fs.writeFileSync(path.join(configDir,"config.json"),JSON.stringify(configured));
          command("sc.exe",["stop","TokenTimerAgent"]);await until(async()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000);command("sc.exe",["start","TokenTimerAgent"]);await until(async()=>ps("(Get-Service TokenTimerAgent).Status")==="Running",30000);
          const unsafe=await preflightCohorts.preflight(item.template);assert.equal(unsafe.result.caCheck.verdict,"unsafe");assert.equal(unsafe.result.caCheck.operatorAttested,false,"Known unsafe flags must never be waived by local operator attestation");assert.deepEqual([...unsafe.result.caCheck.reasons].sort(),[...item.reasons].sort());
          assert.equal((await unsafe.confirm({caKeySha256:result.caCertificates[0].keySha256,caConfig,template:item.template})).status,400);
          await requireNativeRefusal(item,issuerId,"ADCS_CA_CONFIG_UNSAFE");
          gate.report.caSafetyQualification ||= [];gate.report.caSafetyQualification.push({caseId:item.id,operatorAttestationConfigured:operatorAttested,verdict:"unsafe",reasons:item.reasons,nativeRequestCount:0,keyGenerated:false});
        }
      }finally{
        const restoreErrors=[];try{fs.writeFileSync(path.join(configDir,"config.json"),originalConfig);}catch(error){restoreErrors.push(error);}
        try{assert.equal(caSafety("restore"),"CERTOPS_CA_SAFETY=restored-original-flags");caSafetyFaultActive=false;preflightCache.clear();}catch(error){restoreErrors.push(error);}
        if(restoreErrors.length)throw new AggregateError(restoreErrors,"Owned native CA fault or agent configuration restoration failed");
      }
    });
    await gate.scenario("adcs-real-ca-same-key-renewal-preserves-confirmed-pin",async()=>{
      const {item,issuerId,site,port,certificateId,authority,observed}=renewalFixture;
      let issuer;
      await pendingCaJourney.qualifyPendingCaRenewal({gate,fixture,api,agentRowId,configDir,run,caConfig,pendingRecoveryFixtures,ownedCapacityStoreCertificates,ownedEnrollmentIds,command,ps,until,jobFinished,tlsAuthority,renewCaAndObserve:async()=>{
        assert.equal(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/ca-rekey.ps1"),"-Mode","reuse-key"]),"CERTOPS_CA_RENEWAL=reused-key-certificate-recorded");
        preflightCache.clear();assert.ok(++primaryPreflightCount<=18);const check=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template:item.template});assert.equal(check.status,201);await jobFinished(check.body.job.id);
        issuer=await until(async()=>{const row=(await fixture.pool.query("SELECT last_preflight,last_preflight_job_id,revalidation_required FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0];return row?.last_preflight_job_id===check.body.job.id?row:null;},30000);
        assert.equal(issuer.revalidation_required,false);assert.ok(issuer.last_preflight.caCertificates.length>=2);assert.ok(issuer.last_preflight.caCertificates.every(certificate=>certificate.keySha256===authority.keySha256),"Actual CA certificate renewal must retain the public key pin");
        return issuer.last_preflight;
      }});
      const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);await jobFinished(created.body.jobId);
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Same-key CA renewal TLS oracle timed out")));socket.on("error",reject);});const leaf=new crypto.X509Certificate(raw);assert.equal(leaf.checkHost(item.domain),item.domain);assert.notEqual(leaf.fingerprint256,observed.fingerprint256);ownedThumbprints.add(crypto.createHash("sha1").update(raw).digest("hex").toUpperCase());
      renewalFixture.observed=leaf;renewalFixture.currentEnrollmentId=created.body.enrollmentId;
      gate.report.sameKeyCaRenewalQualification={caKeySha256:authority.keySha256,caCertificateCount:issuer.last_preflight.caCertificates.length,reconfirmationRequired:false,newCertificateFingerprintSha256:leaf.fingerprint256.replace(/:/g,"").toLowerCase()};
    });
    await gate.scenario("adcs-real-ca-revocation-native-chain-refusal",async()=>{
      const {item,observed,currentEnrollmentId}=renewalFixture;
      const row=(await fixture.pool.query("SELECT request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,currentEnrollmentId])).rows[0];assert.ok(row.request_id);
      const thumbprint=crypto.createHash("sha1").update(observed.raw).digest("hex").toUpperCase();
      command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(row.request_id),"-Action","revoke","-CommonName",item.domain]);
      // This VM is disposable and contains only this forest's qualification identities.
      command("certutil.exe",["-urlcache","CRL","delete"]);command("certutil.exe",["-setreg","chain\\ChainCacheResyncFiletime","@now"]);
      await until(async()=>ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$chain=[Security.Cryptography.X509Certificates.X509Chain]::new();try{$chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online;$chain.ChainPolicy.RevocationFlag=[Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot;$chain.ChainPolicy.UrlRetrievalTimeout=[TimeSpan]::FromSeconds(10);$valid=$chain.Build($c);if(-not $valid -and @($chain.ChainStatus|Where-Object {$_.Status -band [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked}).Count -gt 0){'revoked'}}finally{$chain.Dispose()}`)==="revoked",60000);
      gate.report.revocationQualification={oracle:"native-X509Chain-online-CRL",reason:"keyCompromise",scope:"owned-issued-leaf",applicationRevocationRequested:false};
    });
    if(!hierarchy)await pendingNewKeyJourney.qualifyPendingCaKeyChange({gate,fixture,api,agentRowId,configDir,run,caConfig,pendingRecoveryFixtures,ownedCapacityStoreCertificates,ownedEnrollmentIds,command,ps,until,jobFinished,tlsAuthority,reservePrimaryPreflights:count=>{assert.equal(count,1);assert.ok(primaryPreflightCount+count<=18,"Pending new-key recovery exceeds reviewed primary budget");primaryPreflightCount+=count;},rekeyAndObserve:()=>{
      assert.equal(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/ca-rekey.ps1")]),"CERTOPS_CA_REKEY=new-certificate-recorded");
    }});
    await gate.scenario("adcs-real-ca-key-change-refuses-installation",async()=>{
      const {item,issuerId,site,port,certificateId,authority,observed}=renewalFixture;

      const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
      const rejected=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.jobId])).rows[0];if(row.status === "succeeded")throw new Error("Unconfirmed CA key was accepted");return row.status === "failed" ? row : null;});
      assert.equal(rejected.result_metadata.enrollmentResult.errorCode,"ADCS_CA_KEY_CHANGED");
      assert.equal((await fixture.pool.query("SELECT revalidation_required FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0].revalidation_required,true);
      const fingerprint=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().fingerprint256);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});assert.equal(fingerprint,observed.fingerprint256,"Rejected CA material must not replace live IIS TLS");
      const again=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(again.body.code,"CERTOPS_ISSUER_REVALIDATION_REQUIRED");assert.notEqual(again.status,201);
    });
    await gate.scenario("adcs-real-ca-revalidation-recovers-confirmed-new-key",async()=>{
      const {item,issuerId,site,port,certificateId,authority,observed}=renewalFixture;
      command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/domain-verify.ps1")]);
      preflightCache.clear();assert.ok(++primaryPreflightCount<=18);const check=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template:item.template});assert.equal(check.status,201);await jobFinished(check.body.job.id);
      const preflightResult=(await fixture.pool.query("SELECT last_preflight FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0].last_preflight;
      assert.equal(preflightResult.templateCheck.verdict,"safe");assert.equal(preflightResult.caCheck.verdict,"safe");
      preflightCache.set(item.template,{issuerId,result:preflightResult});
      const newAuthority=preflightResult.caCertificates.find(candidate=>candidate.keySha256!==authority.keySha256);assert.ok(newAuthority,"Fresh native preflight must observe the new CA public key");
      assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:newAuthority.keySha256,caConfig,template:item.template})).status,200);
      assert.equal((await fixture.pool.query("SELECT revalidation_required FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0].revalidation_required,false);
      const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);await jobFinished(created.body.jobId);
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(newAuthority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});
      const leaf=new crypto.X509Certificate(raw);assert.equal(leaf.checkHost(item.domain),item.domain);assert.notEqual(leaf.fingerprint256,observed.fingerprint256);ownedThumbprints.add(crypto.createHash("sha1").update(raw).digest("hex").toUpperCase());
      assert.ok((await fixture.pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,created.body.jobId])).rows.length);
      gate.report.caRotationQualification={oldCaKeySha256:authority.keySha256,newCaKeySha256:newAuthority.keySha256,operatorConfirmation:"public-confirm-after-native-preflight",newCertificateFingerprintSha256:leaf.fingerprint256.replace(/:/g,"").toLowerCase(),oldPinRefused:true};
      renewalFixture.observed=leaf;renewalFixture.authority=newAuthority;renewalFixture.currentEnrollmentId=created.body.enrollmentId;
    });
    await require("./helpers/certops-adcs-validation-expiry").qualifyValidationExpiry({gate,fixture,api,agentRowId,renewalFixture,configDir,workDir,run,command,ps,until,ownedEnrollmentIds,ownedFirewallRules,tlsAuthority});
    await gate.scenario("adcs-real-crl-outage-defers-then-recovers-owned-key",async()=>{
      const {item,issuerId,site,port,certificateId,authority,observed}=renewalFixture;
      const fault=require("./helpers/certops-adcs-crl-fault").createCrlFault({gate,workDir,run,observed,authority,command,ps,ownedFirewallRules});
      let enrollmentId;let pending;let container;let primaryFaultError;let originalJobId;let deferredIdentity;
      const deferredIdentityContract=require("./helpers/certops-adcs-deferred-identity");
      const readDeferredJournal=()=>require("../../packages/agent/src/issuers/adcs-enrollment").readEnrollmentJournal(configDir,enrollmentId);
      const observeIssued=journal=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/owned-issued-request.ps1"),"-CommonName",item.domain,"-FingerprintSha256",new crypto.X509Certificate(journal.artifacts.leafPem).fingerprint256.replace(/:/g,"").toLowerCase()]));
      const binding={site,port,sniHost:item.domain};
      try{
        await fault.install();
        const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);enrollmentId=created.body.enrollmentId;originalJobId=created.body.jobId;ownedEnrollmentIds.push(enrollmentId);ownedBackgroundStoreCertificates[0].enrollmentIds.push(enrollmentId);
        pending=await until(async()=>{const row=(await fixture.pool.query("SELECT state,request_id,next_poll_at,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,enrollmentId])).rows[0];return deferredIdentityContract.isDeferredPollReady(row) ? row : null;});
        const deferredJournal=readDeferredJournal();deferredIdentity=deferredIdentityContract.observe({row:pending,journal:deferredJournal,nativeRequest:observeIssued(deferredJournal),jobId:originalJobId,state:"validation_deferred"});
        const current=await require("../../packages/agent/src/windows-iis").queryCurrentBinding({binding});assert.equal(current.thumbprint.toUpperCase(),crypto.createHash("sha1").update(observed.raw).digest("hex").toUpperCase(),"Deferred revocation validation must leave outgoing IIS material intact");
        container=require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(enrollmentId);assert.equal(ps(`[Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`),"True");
      }catch(error){primaryFaultError=error;throw error;}finally{await fault.close(primaryFaultError);}
      const continuation=(await require("../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(new Date(pending.next_poll_at).getTime()+1000)})).find(row=>row.enrollmentId===enrollmentId);assert.ok(continuation);await jobFinished(continuation.jobId);
      const recoveredRow=(await fixture.pool.query("SELECT state,request_id,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,enrollmentId])).rows[0];const recoveredJournal=readDeferredJournal();deferredIdentityContract.verifyRecovery(deferredIdentity,deferredIdentityContract.observe({row:recoveredRow,journal:recoveredJournal,nativeRequest:observeIssued(recoveredJournal),jobId:continuation.jobId,state:"installed"}));
      const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("CRL recovery TLS oracle timed out")));socket.on("error",reject);});const leaf=new crypto.X509Certificate(raw);assert.equal(leaf.checkHost(item.domain),item.domain);assert.notEqual(leaf.fingerprint256,observed.fingerprint256);const thumbprint=crypto.createHash("sha1").update(raw).digest("hex").toUpperCase();ownedThumbprints.add(thumbprint);
      assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{if($k.Key.KeyName -ne '${container}' -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Deferred validation changed key custody'};'same-nonexportable-cng'}finally{$k.Dispose()}`),"same-nonexportable-cng");
      renewalFixture.observed=leaf;renewalFixture.thumbprint=thumbprint;renewalFixture.currentEnrollmentId=enrollmentId;ownedBackgroundStoreCertificates[0].thumbprints.push(thumbprint);
      const deferredSource="tests/e2e/helpers/certops-adcs-deferred-identity.js";gate.report.fixtureSources??=[];if(!gate.report.fixtureSources.some(value=>value.file===deferredSource))gate.report.fixtureSources.push({file:deferredSource,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../..",deferredSource))).digest("hex")});
      gate.report.crlOutageQualification={fault:"owned-chain-helper-LDAP-outbound-block",realNetworkUnavailabilityObserved:true,actualChainHelperRevocationUnknown:true,caLdapAvailableForPreflight:true,chainHelperSha256:fault.programSha256,chainCacheValueRestored:fault.cacheRestored,actualLeafCdp:"LDAP-without-HTTP-fallback",CARequestPreserved:true,cngKeyPreserved:true,pollEligibilityClock:"supported-scheduler-now-input",nativeAndCaClocks:"actual"};
    });
    await gate.scenario("adcs-real-stopped-site-tls-failure-restores-outgoing-binding",async()=>{
      const {item,issuerId,site,port,certificateId,authority,observed}=renewalFixture;
      const expectedThumbprint=crypto.createHash("sha1").update(observed.raw).digest("hex").toUpperCase();
      const binding={site,port,sniHost:item.domain};
      const iis=require("../../packages/agent/src/windows-iis");
      ps(`Import-Module WebAdministration;Stop-Website -Name '${site}'`);
      try{
        await until(async()=>new Promise(resolve=>{const socket=net.createConnection({host:"127.0.0.1",port},()=>{socket.destroy();resolve(false);});socket.setTimeout(2000,()=>{socket.destroy();resolve(false);});socket.once("error",()=>{socket.destroy();resolve(true);});}),30000);
        assert.equal((await iis.queryCurrentBinding({binding})).thumbprint.toUpperCase(),expectedThumbprint,"Fault must preserve the outgoing binding before dispatch");
        const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
        const outcome=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.jobId])).rows[0];if(row.status === "succeeded")throw new Error("Unavailable owned IIS endpoint incorrectly qualified TLS deployment");return row.status === "failed" ? row : null;});
        assert.equal(outcome.result_metadata.enrollmentResult.state,"install_failed");
        const after=await iis.queryCurrentBinding({binding});assert.equal(after.ok,true);assert.equal(after.thumbprint.toUpperCase(),expectedThumbprint,"Real post-bind TLS failure must restore outgoing HTTP.sys certificate");
        const container=require("../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(created.body.enrollmentId);assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container),"Accepted install-failure material must retain its CNG key for deliberate recovery");
        gate.report.installFailureQualification={fault:"owned-site-stopped",rollback:"actual-http-sys-outgoing-thumbprint",acceptedKeyRetained:true,automaticInstallFailedRetry:false};
      }finally{ps(`Import-Module WebAdministration;Start-Website -Name '${site}'`);}
      const fingerprint=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{resolve(socket.getPeerCertificate().fingerprint256);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Restored IIS TLS oracle timed out")));socket.on("error",reject);});assert.equal(fingerprint,observed.fingerprint256,"Restarted fixture must serve the original independently verified certificate");
    });
    await gate.scenario("adcs-real-service-restart-preserves-registration", async () => {
      command("sc.exe", ["stop", "TokenTimerAgent"]); await until(async () => ps("(Get-Service TokenTimerAgent).Status") === "Stopped", 30000);
      const restartMarker=(await fixture.pool.query("SELECT now() AS marker")).rows[0].marker;
      command("sc.exe", ["start", "TokenTimerAgent"]);
      await until(async () => ps("(Get-Service TokenTimerAgent).Status") === "Running", 30000);
      await until(async()=> (await fixture.pool.query("SELECT last_seen_at>$3 AS resumed FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",[fixture.workspaceId,agentId,restartMarker])).rows[0]?.resumed,30000);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agentId])).rows[0].n, 1);
    });
    await require("./helpers/certops-adcs-uncertain-abandon").qualifyUncertainAbandon({gate,fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedFirewallRules,ownedPhaseObservers,serviceOwned,abandonActor:require("./helpers/certops-adcs-browser-abandon").createBrowserAbandonActor({gate,fixture,workDir,command,ownedBrowserResources,beforeAbandon:enrollmentId=>require("./helpers/certops-adcs-browser-admin-boundary").qualifyAdminRoleBoundary({gate,fixture,baseUrl:url.href,workDir,configDir,command,ps,renewalFixture,tlsAuthority,ownedApiFixtures,ownedBrowserResources},enrollmentId)})});
    await require("./helpers/certops-adcs-uncertain-operator-unique").qualifyOperatorCreatedUnique({gate,fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedFirewallRules,ownedPhaseObservers,ownedTlsProbes,serviceOwned,renewalFixture,tlsAuthority,ownedThumbprints});
    await require("./helpers/certops-adcs-uncertain-operator-ambiguity").qualifyOperatorCreatedAmbiguity({gate,fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedFirewallRules,ownedPhaseObservers,serviceOwned,renewalFixture,tlsAuthority,ownedThumbprints,foreignReconcileActor:publicForeignSpkiJourney.createForeignReconcileActor({ownedForeignRequests}),reconcileActor:require("./helpers/certops-adcs-browser-reconcile").createBrowserReconcileActor({gate,fixture,workDir,command,ownedBrowserResources})});
    if(["accepted-before-bind","bound-before-complete"].includes(process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT))await require("./helpers/certops-adcs-accepted-install-recovery").qualifyObservedInstallRecovery({fixture,api,agentRowId,configDir,workDir,renewalFixture,ps,command,until,jobFinished,tlsAuthority,ownedEnrollmentIds,ownedThumbprints,ownedPhaseObservers,serviceOwned},process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT);
    else await require("./helpers/certops-adcs-journal-phase-experiment")({fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,tlsAuthority,gate,serviceOwned});
    await browserJourney.qualifyAdcsBrowserJourney({ownedTlsProbes,gate,fixture,api,agentRowId,configDir,workDir,run,renewalFixture,until,jobFinished,ps,command,tlsAuthority,ownedEnrollmentIds,ownedThumbprints,ownedBrowserResources,ownedBrowserPreflightJobIds});
    }
  } finally {
    await gate.scenario("adcs-real-owned-cleanup", async () => {
      // This must precede SCM/site/key/API cleanup on every error path.
      resultOutboxJourney.assertCleanupSafe(workDir);
      require("./helpers/certops-adcs-local-rules").assertCleanupSafe(workDir);
      httpLeafCrlJourney.assertCleanupSafe(workDir);
      ocspJourney.assertCleanupSafe(workDir);
      httpIntermediateCrlJourney.assertNoHttpCrlGuard(workDir);
      for(const resource of ownedHttpCrlResources)resource.assertCleanupSafe();
      require("./helpers/certops-adcs-same-certificate-late-approval").assertCleanupSafe(workDir);
      cancelledLateApprovalJourney.assertCleanupSafe(ownedLateApprovalGuards);
      publicForeignSpkiJourney.assertCleanupSafe(ownedForeignRequests);
      requiredTemplateAttributesJourney.assertCleanupSafe(ownedTemplateAttributeRestorations);
      const nativeCleanupGuard=require("./helpers/certops-adcs-native-cleanup-guard").createNativeCleanupGuard();
      const assertPendingCaResolved=()=>{assert.ok(!ownedBackgroundStoreCertificates.some(receipt=>receipt.ocspPendingVerification===true),"Preserve native state while Microsoft OCSP recovery remains unresolved");assert.ok(!ownedBackgroundStoreCertificates.some(receipt=>receipt.httpLeafCrlPendingVerification===true),"Preserve native state while HTTP leaf CRL recovery remains unresolved");assert.ok(!ownedBackgroundStoreCertificates.some(receipt=>receipt.machineAclPendingVerification===true),"Preserve native state while live machine Enroll ACL recovery remains unresolved");assert.ok(!ownedBackgroundStoreCertificates.some(receipt=>receipt.workerPendingVerification===true),"Preserve native and durable ownership while background renewal remains unresolved");assert.ok(!ownedCapacityStoreCertificates.some(receipt=>receipt.pendingCaRenewalUnresolved===true),"Preserve native and durable ownership while pending CA renewal remains unresolved");};
      const errors = []; const clean = async (action) => { try { await action(); } catch (error) { errors.push(error); } };
      const cleanNative=action=>clean(()=>nativeCleanupGuard.run(()=>{assertPendingCaResolved();return action();}));
      for(const probes of ownedTlsProbes)await clean(()=>probes.drain());
      assert.ok(ownedTlsProbes.every(probes=>probes.isDrained()),"Preserve native fixtures while owned TLS probe close is unproven");
      for(const observer of ownedPhaseObservers)await clean(()=>observer.stopAndDrain());
      assert.equal(ownedPhaseObservers.some(observer=>observer.hasLiveChild()),false,"Preserve native fixtures while an owned fault observer remains alive");
      for(const resource of ownedBrowserResources)await clean(()=>resource.close());
      await clean(()=>preflightCohorts.close());
      await clean(async()=>{const measured=Number((await fixture.pool.query("SELECT count(*) AS count FROM certificate_jobs WHERE workspace_id=$1 AND operation='adcs-preflight'",[fixture.workspaceId])).rows[0].count);assert.ok(primaryPreflightCount<=18);if(!elapsedPending && !issuerSwitch){assert.equal(ownedBrowserPreflightJobIds.length,2);assert.equal(new Set(ownedBrowserPreflightJobIds).size,2);for(const id of ownedBrowserPreflightJobIds)assert.match(id,/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);const browserJobs=(await fixture.pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND operation='adcs-preflight' AND id=ANY($2::uuid[])",[fixture.workspaceId,ownedBrowserPreflightJobIds])).rows;assert.equal(browserJobs.length,2);gate.report.browserNativePreflightDispatch={count:2,jobIds:[...ownedBrowserPreflightJobIds]};}else assert.equal(ownedBrowserPreflightJobIds.length,0);assert.equal(measured,primaryPreflightCount+ownedBrowserPreflightJobIds.length,"Every actual primary and browser preflight dispatch must be accounted for");assert.ok(measured<=(elapsedPending?18:20));gate.report.primaryNativePreflightDispatchCount=measured;});
      if(caSafetyFaultActive)await clean(async()=>{assert.equal(caSafety("restore"),"CERTOPS_CA_SAFETY=restored-original-flags");caSafetyFaultActive=false;});
      if(ownedStoreCertificates.length||ownedCapacityStoreCertificates.length||ownedIssuerSwitchStoreCertificates.length||ownedBackgroundStoreCertificates.length||ownedUnacceptedEnrollments.length)await clean(()=>{webHostingServiceDrain=webHostingJourney.captureServiceDrain(ps,{configDir,expectedServicePath:`"${path.join(path.resolve(__dirname,"../.."),"packages/agent/bin",hostBinaryName("amd64"))}" "${process.execPath}" "${path.join(path.resolve(__dirname,"../.."),"packages/agent/bin/tokentimer-agent.js")}"`});});
      if (serviceOwned) { await clean(async () => { const result=spawnSync("sc.exe",["stop","TokenTimerAgent"]); if (result.status !== 0 && ps("(Get-Service TokenTimerAgent).Status") !== "Stopped") throw new Error("Could not stop owned service"); await until(async()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000); }); await clean(async()=>{command("sc.exe",["delete","TokenTimerAgent"]);await until(async()=>spawnSync("sc.exe",["query","TokenTimerAgent"]).status!==0,30000);}); }
      await clean(async()=>{
        const rows=(await fixture.pool.query("SELECT id,operation,status,error_code,result_metadata->'enrollmentResult'->>'state' AS enrollment_state,result_metadata->'enrollmentResult'->>'errorCode' AS enrollment_error,result_metadata->'enrollmentResult'->>'caHresult' AS ca_hresult FROM certificate_jobs WHERE workspace_id=$1 ORDER BY created_at,id",[fixture.workspaceId])).rows;
        const publicCode=value=>typeof value === "string" && /^[A-Z][A-Z0-9_]{0,95}$/.test(value) ? value : null;
        gate.report.ownedJobOutcomes=rows.map(row=>({id:row.id,operation:row.operation,status:row.status,errorCode:publicCode(row.error_code),enrollmentState:typeof row.enrollment_state === "string" && /^[a-z_]{1,40}$/.test(row.enrollment_state) ? row.enrollment_state : null,enrollmentError:publicCode(row.enrollment_error),caHresult:/^0x[0-9a-f]{8}$/i.test(row.ca_hresult || "") ? row.ca_hresult : null}));
      });
      for (const faultRun of ownedCaServiceFaults) await clean(async()=>{const restored=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../infra/certops-adcs/ca-service-outage.ps1"),"-Action","restore","-RunId",faultRun]));assert.equal(restored.status,"Running");assert.equal(restored.snapshotPresent,false);ownedCaServiceFaults.delete(faultRun);});
      await cleanNative(()=>unacceptedCleanup.cleanup({receipts:ownedUnacceptedEnrollments,fixture,ps,drain:webHostingServiceDrain}));
      for(const ownedBinding of ownedNativeBindings)await clean(async()=>{assertPendingCaResolved();assert.equal(ownedBinding.runId,run);assert.match(ownedBinding.selector,/^ipport=127\.0\.0\.1:\d{1,5}$/);assert.match(ownedBinding.appId,/^\{[a-f0-9-]{36}\}$/i);assert.match(ownedBinding.thumbprint,/^[a-f0-9]{40}$/i);ps(`$output=& netsh.exe http show sslcert ${ownedBinding.selector};if($LASTEXITCODE -eq 0){$text=($output -join ' ').ToLowerInvariant();if(-not $text.Contains('${ownedBinding.appId.toLowerCase()}') -or -not $text.Contains('${ownedBinding.thumbprint.toLowerCase()}')){throw 'Refusing foreign native shadow replacement'};& netsh.exe http delete sslcert ${ownedBinding.selector}|Out-Null;if($LASTEXITCODE -ne 0){throw 'Owned native shadow cleanup failed'}};& netsh.exe http show sslcert ${ownedBinding.selector}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Owned native shadow remains'}`);});
      for (const site of ownedSites) await clean(async()=>{assertPendingCaResolved();return ps(`Import-Module WebAdministration; if (Test-Path 'IIS:\\Sites\\${site}') {Remove-Website -Name '${site}'}`);});
      for(const rule of ownedFirewallRules)await clean(async()=>ps(`$r=Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue;if($r){if($r.DisplayName -ne '${rule}'){throw 'Refusing foreign replacement firewall rule'};Remove-NetFirewallRule -Name '${rule}'}`));
      await clean(async()=>ps(`$state=Import-Clixml -LiteralPath '${chainCacheSnapshot.replace(/'/g,"''")}';$key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config');try{if($state.exists){$kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],$state.kind);$key.SetValue('ChainCacheResyncFiletime',$state.value,$kind)}else{$key.DeleteValue('ChainCacheResyncFiletime',$false)}}finally{$key.Dispose()}`));
      await cleanNative(()=>webHostingJourney.cleanupWebHosting({receipts:ownedStoreCertificates,configDir,ps,drain:webHostingServiceDrain}));
      await cleanNative(()=>webHostingJourney.cleanupCapacity({receipts:ownedCapacityStoreCertificates,configDir,ps,drain:webHostingServiceDrain}));
      await cleanNative(()=>webHostingJourney.cleanupIssuerSwitch({receipts:ownedIssuerSwitchStoreCertificates,configDir,ps,drain:webHostingServiceDrain}));
      await cleanNative(async()=>{const rows=(await fixture.pool.query("SELECT e.id,e.workspace_id,e.certificate_id,e.state,ARRAY(SELECT j.id FROM certificate_jobs j WHERE j.workspace_id=e.workspace_id AND j.enrollment_id=e.id) AS job_ids FROM certificate_enrollments e WHERE e.workspace_id=$1 AND e.id=ANY($2::uuid[])",[fixture.workspaceId,ownedEnrollmentIds])).rows;webHostingJourney.refreshBackgroundEnrollmentOwnership(ownedBackgroundStoreCertificates,ownedEnrollmentIds,containerName=>require("../../packages/agent/src/windows-cert-store").readIssuedContainerRecord({stateDir:configDir,containerName}),{workspaceId:fixture.workspaceId,rows,readJournal:id=>require("../../packages/agent/src/issuers/adcs-enrollment").readEnrollmentJournal(configDir,id)});});
      await cleanNative(()=>webHostingJourney.cleanupBackground({receipts:ownedBackgroundStoreCertificates,configDir,ps,drain:webHostingServiceDrain}));
      for (const thumbprint of ownedThumbprints) await cleanNative(async()=>{nativeCleanupGuard.assertStateRemovable();unacceptedCleanup.assertComplete(ownedUnacceptedEnrollments);return ps(`if (Test-Path 'Cert:\\LocalMachine\\My\\${thumbprint}') {Remove-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}' -DeleteKey}`);});
      for(const item of [...cases,...pendingCases,...deniedCases,...safetyEnrollments,{domain:faultDomain},{domain:journalDomain},{domain:transportDomain}])await cleanNative(async()=>{nativeCleanupGuard.assertStateRemovable();unacceptedCleanup.assertComplete(ownedUnacceptedEnrollments);return ps(`Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${item.domain}' | Remove-Item -DeleteKey`);});
      for(const id of ownedCertificateIds)await cleanNative(async()=>{
        assert.ok(!ownedUnacceptedEnrollments.some(receipt=>receipt.certificateId===id&&!receipt.cleanupCompleted),"Preserve unresolved unaccepted certificate ownership");
        assert.ok(![...ownedStoreCertificates,...ownedCapacityStoreCertificates,...ownedIssuerSwitchStoreCertificates,...ownedBackgroundStoreCertificates].some(receipt=>receipt.certificateId===id&&!receipt.cleanupCompleted),"Preserve native certificate identity while store ownership cleanup remains unresolved");
        const prefix=`tokentimer-${id}-`;
        const containers=command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).split(/\r?\n/).map(line=>line.trim()).filter(line=>line.startsWith(prefix)&&/^[a-f0-9]{8}$/.test(line.slice(prefix.length)));
        for(const containerName of containers)assert.equal((await require("../../packages/agent/src/windows-cert-store").removeAbandonedKeyContainer({containerName})).ok,true);
      });
      for(const id of ownedEnrollmentIds)await cleanNative(async()=>{
        assert.ok(!ownedUnacceptedEnrollments.some(receipt=>receipt.enrollmentIds.includes(id)&&!receipt.cleanupCompleted),"Preserve unresolved unaccepted enrollment custody");
        assert.ok(![...ownedStoreCertificates,...ownedCapacityStoreCertificates,...ownedIssuerSwitchStoreCertificates,...ownedBackgroundStoreCertificates].some(receipt=>receipt.enrollmentIds.includes(id)&&!receipt.cleanupCompleted),"Preserve WebHosting key while public store cleanup remains unresolved");
        const store=require("../../packages/agent/src/windows-cert-store");
        const containerName=store.buildEnrollmentContainerName(id);
        assert.equal((await store.removeAbandonedKeyContainer({containerName,allowAlreadyAbsent:true})).ok,true);
        assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(containerName),"Owned enrollment CNG container remains");
        for(const receipt of [...ownedStoreCertificates,...ownedCapacityStoreCertificates,...ownedIssuerSwitchStoreCertificates,...ownedBackgroundStoreCertificates])if(receipt.enrollmentIds.includes(id)){receipt.removedEnrollmentIds??=[];receipt.removedEnrollmentIds.push(id);}
      });
      webHostingJourney.confirmRegisteredKeyCleanup([...ownedStoreCertificates,...ownedCapacityStoreCertificates,...ownedIssuerSwitchStoreCertificates,...ownedBackgroundStoreCertificates]);
      const assertNativeStateReleased=()=>{assertPendingCaResolved();nativeCleanupGuard.assertStateRemovable();unacceptedCleanup.assertComplete(ownedUnacceptedEnrollments);webHostingJourney.assertRegisteredCleanupComplete([...ownedStoreCertificates,...ownedCapacityStoreCertificates,...ownedIssuerSwitchStoreCertificates,...ownedBackgroundStoreCertificates]);};await clean(()=>{assertNativeStateReleased();return fixture.cleanup();});for(const ownedFixture of ownedApiFixtures)await clean(()=>{assertNativeStateReleased();return ownedFixture.cleanup();}); await clean(async()=>{assert.equal(preflightCohorts.hasLiveChildren(),false,"Cannot remove state while owned native preflight agents remain alive");assert.equal(ownedPhaseObservers.some(observer=>observer.hasLiveChild()),false,"Cannot remove state while an owned native phase observer remains alive");assert.equal(ownedBrowserResources.some(resource=>resource.hasLiveChild()||resource.hasOwnershipReceipt()),false,"Cannot remove state while owned Chromium or browser trust receipt remains");nativeCleanupGuard.assertStateRemovable();unacceptedCleanup.assertComplete(ownedUnacceptedEnrollments);webHostingJourney.assertRegisteredCleanupComplete([...ownedStoreCertificates,...ownedCapacityStoreCertificates,...ownedIssuerSwitchStoreCertificates,...ownedBackgroundStoreCertificates]);assertPendingCaResolved();fs.rmSync(workDir,{recursive:true,force:true});});
      if(errors.length)throw new AggregateError(errors,"Domain AD CS owned cleanup failed");
    });
    await gate.finish({cleanup:{status:"passed"},requiredScenarios:issuerSwitch ? issuerSwitchJourney.NATIVE_REQUIRED_SCENARIOS : elapsedPending ? ["adcs-real-installed-native-language","adcs-real-agent-registration-system","adcs-real-rsa2048-issued-cng-iis","adcs-elapsed-pending-one-hour-terminal-cleanup","adcs-real-owned-cleanup"] : ["adcs-real-installed-native-language","adcs-real-agent-registration-system",...cases.map(item=>`adcs-real-${item.id}-issued-cng-iis`),...cases.filter(item=>item.id!=="rsa2048").map(item=>`adcs-real-${item.id}-renewed-cng-iis`),"adcs-real-manual-renewal-replaces-iis-certificate","adcs-real-profile-automatic-service-renewal","adcs-real-scheduler-selects-short-lived-observed-certificate",...require("./helpers/certops-adcs-two-renewals").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-background-renewals").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-live-enroll-acl").REQUIRED_SCENARIOS,...httpLeafCrlJourney.REQUIRED_SCENARIOS,...ocspJourney.REQUIRED_SCENARIOS,resultOutboxJourney.SCENARIO,...webHostingJourney.REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-browser-abandon").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-browser-admin-boundary").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-browser-reconcile").REQUIRED_SCENARIOS,...capacityJourney.REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-browser-cancel").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-browser-job-approval").REQUIRED_SCENARIOS,...browserJourney.REQUIRED_SCENARIOS,require("./helpers/certops-adcs-native-reconcile").foreignScenario,...require("./helpers/certops-adcs-local-rules").pairCases.map(id=>`adcs-real-local-rule-${id}-refused`),require("./helpers/certops-adcs-local-rules").survivorScenario,...pendingCases.map(item=>`adcs-real-pending-${item.action}-continuation`),"adcs-real-late-approval-remains-expired",...cancelledLateApprovalJourney.REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-same-certificate-late-approval").REQUIRED_SCENARIOS,"adcs-real-pending-restart-single-continuation","adcs-real-pending-abandon-refused","adcs-real-installation-failure-audited-retry","adcs-real-pending-ca-service-outage-recovers-same-request","adcs-real-native-cmc-signed-response-boundaries","adcs-real-native-retrieve-unknown-request-remains-uncertain","adcs-real-native-retrieve-foreign-requester-remains-uncertain","adcs-real-late-approved-older-leaf-refused","adcs-real-minimum-remaining-validity-refused",...["missing-constraints","dns-dot-boundary","key-algorithm","cross-product","extra-san"].map(id=>`adcs-real-local-rule-${id}-refused`),"adcs-real-local-rule-tightening-preserves-pending-retrieval","adcs-real-cancel-ca-issued-unaccepted-key","adcs-real-localized-native-discovery-binding-identity","adcs-real-initial-certreq-rpc-unreachable-retries-same-csr-key","adcs-real-issued-template-mismatch-refuses-installation",...require("./helpers/certops-adcs-issued-san-boundary").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-issued-revocation").REQUIRED_SCENARIOS,...deniedCases.map(item=>`adcs-real-template-${item.id}-denied`),...safetyCases.templateCases.map(item=>`adcs-real-unsafe-${item.name}-confirmation-refused`),"adcs-real-unsafe-WebServer-confirmation-refused",...["schema-one","application-policy-absent","subject-client-auth","schema-three-algorithm-absent","eku-absent","subject-any-purpose","subject-enrollment-agent","subject-smartcard","subject-pkinit","application-policy-any-purpose","application-policy-client-mixed","minimum-key-absent","template-oid-absent","schema-out-of-range"].map(id=>`adcs-real-mutated-template-${id}-native-refused`),...requiredTemplateAttributesJourney.REQUIRED_SCENARIOS,...safetyCases.keyConstraintCases.map(item=>`adcs-real-template-key-${item.id}-refused`),...safetyCases.caFlagCases.map(item=>`adcs-real-ca-flags-${item.id}-refused`),"adcs-real-elapsed-validation-deadline-frees-unaccepted-key","adcs-real-crl-outage-defers-then-recovers-owned-key","adcs-real-stopped-site-tls-failure-restores-outgoing-binding",...pendingCaJourney.REQUIRED_SCENARIOS,...pendingNewKeyJourney.REQUIRED_SCENARIOS,"adcs-real-ca-same-key-renewal-preserves-confirmed-pin","adcs-real-ca-revocation-native-chain-refusal","adcs-real-ca-key-change-refuses-installation","adcs-real-ca-revalidation-recovers-confirmed-new-key","adcs-real-service-restart-preserves-registration",...require("./helpers/certops-adcs-uncertain-operator-unique").REQUIRED_SCENARIOS,...require("./helpers/certops-adcs-uncertain-operator-ambiguity").REQUIRED_SCENARIOS,...publicForeignSpkiJourney.REQUIRED_SCENARIOS,"adcs-real-uncertain-zero-request-owned-termination","adcs-real-uncertain-zero-request-acknowledged-recovery","adcs-real-uncertain-zero-request-public-abandon-cleans-key","adcs-real-owned-cleanup","adcs-real-pending-profile-edit-preserves-frozen-contract",...(hierarchy ? ["adcs-hierarchy-offline-root-and-public-crl","adcs-hierarchy-issued-three-certificate-chain",httpIntermediateCrlJourney.SCENARIO] : [])].filter(id=>!hierarchy || !excludedHierarchyScenarios.has(id))});
    if(gate.report.experimental!==true && gate.report.qualificationStatus!=="not-qualified" && !issuerSwitch && !elapsedPending && !hierarchy && requestedVersion==="2022" && (process.env.CERTOPS_WINDOWS_LANGUAGE||"en-US")==="en-US"){
      const browserEnrollment=require("./helpers/certops-adcs-browser-enrollment");
      browserEnrollment.writeReport("C:\\ttqualification\\browser-enrollment-native.json",browserEnrollment.createNativeReport(gate.report));
      const nativeAbandon=require("../../scripts/certops-adcs-uncertain-abandon-native");
      browserEnrollment.writeReport("C:\\ttqualification\\uncertain-abandon-native.json",nativeAbandon.createNativeReport(gate.report));
    }
  }
});
