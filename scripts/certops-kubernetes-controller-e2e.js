"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const os=require("node:os");
const path=require("node:path");
const crypto=require("node:crypto");
const tls=require("node:tls");
const {spawn,spawnSync}=require("node:child_process");
const {createApiFixture}=require("../tests/e2e/helpers/certops-api-fixture");
const {createHostGate}=require("../packages/agent/scripts/host-gate");
function run(binary,args,input){
  const result=spawnSync(binary,args,{input,encoding:"utf8",timeout:180000,maxBuffer:1024*1024});
  if(result.error||result.status!==0)throw new Error("Disposable controller fixture operation failed");
  return result.stdout;
}
function kube(args,input){return run("kubectl",["--context",process.env.CERTOPS_KUBE_CONTEXT,...args],input);}
async function eventually(check){
  const until=Date.now()+180000;
  while(Date.now()<until){const result=await check();if(result)return result;await new Promise(resolve=>setTimeout(resolve,1000));}
  throw new Error("Actual controller journey exceeded deadline");
}
async function stopChild(child){
  if(!child?.pid||child.exitCode!==null||child.signalCode!==null)return;
  const exited=new Promise(resolve=>child.once("exit",resolve));
  child.kill("SIGCONT");child.kill("SIGTERM");
  let timeout;
  await Promise.race([exited,new Promise(resolve=>{timeout=setTimeout(resolve,5000);})]);clearTimeout(timeout);
  if(child.exitCode===null&&child.signalCode===null){
    child.kill("SIGKILL");
    await Promise.race([exited,new Promise(resolve=>{timeout=setTimeout(resolve,5000);})]);clearTimeout(timeout);
    assert.ok(child.exitCode!==null||child.signalCode!==null,"Owned child must terminate during cleanup");
  }
}
async function main(){
  assert.equal(process.platform,"linux");
  assert.equal(process.env.GITHUB_ACTIONS,"true","Only disposable hosted Linux may expose the private kind fixture bridge");
  assert.match(process.env.CERTOPS_KUBE_CONTEXT||"",/^kind-certops-qualification-[a-z0-9-]+$/);
  const api=new URL(process.env.CERTOPS_CSR_API_URL);
  assert.ok(["127.0.0.1","localhost"].includes(api.hostname));
  const fixture=await createApiFixture(api.href);
  const namespace="controller-"+crypto.randomBytes(8).toString("hex");
  const clusterId="qualification-"+crypto.randomBytes(6).toString("hex");
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-controller-"));
  let bridge,forward,forwardPort,owned=false,ready=false,primary;
  const gate=createHostGate({suite:"kubernetes-controller-api",evidenceLevel:"e2e",requiredCapabilities:["api","kind","openssl"],probeCapabilities:async()=>({api:{available:(await fetch(api)).ok},kind:{available:JSON.parse(kube(["get","nodes","-o","json"])).items.length>0},openssl:{available:spawnSync("openssl",["version"]).status===0}})});
  gate.report.fixtureSource={file:"scripts/certops-kubernetes-controller-e2e.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")};
  gate.report.artifactQualification="workflow-checkout-source";
  try{
    assert.equal(await gate.preflight(),true);ready=true;
    const existing=JSON.parse(kube(["get","namespaces","-o","json"]));
    assert.ok(!existing.items.some(item=>item.metadata.name===namespace));
    owned=true;kube(["create","namespace",namespace]);
    const publicCa=path.join(directory,"bridge.crt");
    const privateCa=path.join(directory,"bridge.key");
    const bridgeDns=`controlplane.${namespace}.svc`;
    run("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",privateCa,"-out",publicCa,"-days","2","-subj",`/CN=${bridgeDns}`,"-addext",`subjectAltName=DNS:${bridgeDns}`]);
    bridge=spawn(process.execPath,[path.join(__dirname,"certops-kube-api-bridge.js"),api.href,publicCa,privateCa],{stdio:["ignore","pipe","ignore"]});
    const bridgePort=await new Promise((resolve,reject)=>{
      let buffered="";const timeout=setTimeout(()=>reject(new Error("Private bridge readiness missing")),15000);
      bridge.once("error",()=>{clearTimeout(timeout);reject(new Error("Private bridge failed to start"));});
      bridge.once("exit",()=>{clearTimeout(timeout);reject(new Error("Private bridge exited before ready"));});
      bridge.stdout.on("data",chunk=>{buffered+=chunk.toString();if(buffered.length>256){clearTimeout(timeout);reject(new Error("Invalid bridge readiness"));return;}if(buffered.includes("\n")){try{const value=JSON.parse(buffered.trim());assert.ok(Number.isInteger(value.port)&&value.port>0&&value.port<65536);clearTimeout(timeout);resolve(value.port);}catch(error){clearTimeout(timeout);reject(error);}}});
    });
    const gateway=run("docker",["network","inspect","kind","--format","{{(index .IPAM.Config 0).Gateway}}"] ).trim();
    assert.match(gateway,/^\d+\.\d+\.\d+\.\d+$/);
    const token=await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`,"POST",{name:"Scoped disposable controller",scopes:["certops:observations:write","certops:provision:execute","certops:events:write","certops:evidence:write"],controllerClusterId:clusterId});
    assert.equal(token.status,201);
    kube(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"List",items:[
      {apiVersion:"cert-manager.io/v1",kind:"Issuer",metadata:{name:"fixture",namespace},spec:{selfSigned:{}}},
      {apiVersion:"v1",kind:"Service",metadata:{name:"controlplane",namespace},spec:{ports:[{name:"https",port:8443,targetPort:bridgePort}]}},
      {apiVersion:"discovery.k8s.io/v1",kind:"EndpointSlice",metadata:{name:"controlplane",namespace,labels:{"kubernetes.io/service-name":"controlplane"}},addressType:"IPv4",ports:[{name:"https",protocol:"TCP",port:bridgePort}],endpoints:[{addresses:[gateway]}]},
      {apiVersion:"v1",kind:"Secret",metadata:{name:"controller-credential",namespace},type:"Opaque",data:{token:Buffer.from(token.body.plaintextToken).toString("base64")}},
      {apiVersion:"v1",kind:"ConfigMap",metadata:{name:"controller-ca",namespace},data:{"ca.crt":fs.readFileSync(publicCa,"utf8")}},
      {apiVersion:"v1",kind:"ServiceAccount",metadata:{name:"controller",namespace}},
      {apiVersion:"rbac.authorization.k8s.io/v1",kind:"Role",metadata:{name:"controller",namespace},rules:[{apiGroups:["cert-manager.io"],resources:["certificates"],verbs:["get","list","watch","create","patch"]},{apiGroups:["cert-manager.io"],resources:["certificaterequests"],verbs:["get","list","watch"]},{apiGroups:[""],resources:["secrets"],resourceNames:["journey-tls"],verbs:["get"]}]},
      {apiVersion:"rbac.authorization.k8s.io/v1",kind:"RoleBinding",metadata:{name:"controller",namespace},subjects:[{kind:"ServiceAccount",name:"controller",namespace}],roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"Role",name:"controller"}},
      {apiVersion:"apps/v1",kind:"Deployment",metadata:{name:"controller",namespace},spec:{replicas:1,selector:{matchLabels:{app:"controller"}},template:{metadata:{labels:{app:"controller"}},spec:{serviceAccountName:"controller",securityContext:{fsGroup:1001},containers:[{name:"controller",image:"certops-controller:qualification",imagePullPolicy:"Never",env:[{name:"TOKENTIMER_API_URL",value:`https://${bridgeDns}:8443`},{name:"TOKENTIMER_API_TOKEN_FILE",value:"/credential/token"},{name:"TOKENTIMER_WORKSPACE_ID",value:fixture.workspaceId},{name:"TOKENTIMER_CLUSTER_ID",value:clusterId},{name:"CERTOPS_WATCH_NAMESPACES",value:namespace},{name:"CERTOPS_CONTROLLER_MODE",value:"provision"},{name:"CERTOPS_SECRET_FALLBACK_ENABLED",value:"true"},{name:"CERTOPS_RECONCILE_INTERVAL",value:"1s"},{name:"NODE_EXTRA_CA_CERTS",value:"/ca/ca.crt"}],securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},readinessProbe:{httpGet:{path:"/readyz",port:8080},initialDelaySeconds:2,periodSeconds:2},volumeMounts:[{name:"credential",mountPath:"/credential",readOnly:true},{name:"ca",mountPath:"/ca",readOnly:true}]}],volumes:[{name:"credential",secret:{secretName:"controller-credential",defaultMode:0o440}},{name:"ca",configMap:{name:"controller-ca"}}]}}}}
    ]}));
    kube(["rollout","status","deployment/controller","-n",namespace,"--timeout=180s"]);
    const desired={schemaVersion:1,clusterId,namespace,certificateName:"journey",secretName:"journey-tls",issuerRef:{group:"cert-manager.io",kind:"Issuer",name:"fixture"},dnsNames:["journey.certops.invalid"]};
    const prefix=`/api/v1/workspaces/${fixture.workspaceId}/certops`;
    let intent,leaf,publicLeafPem;
    await gate.scenario("controller-public-api-provision",async()=>{
      const key=crypto.randomUUID();
      intent=await fixture.request(`${prefix}/provision-intents`,"POST",desired,{"Idempotency-Key":key});assert.equal(intent.status,201);
      const replay=await fixture.request(`${prefix}/provision-intents`,"POST",desired,{"Idempotency-Key":key});assert.equal(replay.status,200);assert.equal(replay.body.job.id,intent.body.job.id);
      await eventually(async()=>{const job=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,intent.body.job.id])).rows[0];if(["failed","cancelled","rejected"].includes(job?.status))throw new Error("Real controller provisioning failed");return job?.status==="succeeded";});
      kube(["wait","--for=condition=Ready","certificate/journey","-n",namespace,"--timeout=180s"]);
      publicLeafPem=Buffer.from(kube(["get","secret","journey-tls","-n",namespace,"-o","jsonpath={.data.tls\\.crt}"]),"base64");
      leaf=new crypto.X509Certificate(publicLeafPem);assert.equal(leaf.checkHost("journey.certops.invalid"),"journey.certops.invalid");
    },{oracle:"Actual public intent, authenticated cluster-bound command, production controller mutation and independent cert-manager issued public leaf"});
    await gate.scenario("controller-public-observation",async()=>{
      const fingerprint=leaf.fingerprint256.replace(/:/g,"").toLowerCase();
      await eventually(async()=>{const rows=await fixture.pool.query("SELECT 1 FROM certificate_instances WHERE workspace_id=$1 AND observed_fingerprint_sha256=$2",[fixture.workspaceId,fingerprint]);return rows.rows.length>0;});
      assert.equal((await fixture.pool.query("SELECT COUNT(*)::int AS count FROM certops_agents WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].count,0,"Controller inventory must not register an agent");
    },{oracle:"Real list/watch and bounded public Secret fallback persist actual CA fingerprint without agent registration"});
    await gate.scenario("controller-served-tls-leaf",async()=>{
      // Only the destination pod consumes tls.key from its local mounted
      // Secret. The harness reads public bytes and performs a TLS handshake.
      const endpointCode="const fs=require('node:fs'),https=require('node:https'),tls=require('node:tls');const material=()=>({cert:fs.readFileSync('/tls/tls.crt'),key:fs.readFileSync('/tls/tls.key')});https.createServer({...material(),SNICallback:(_name,callback)=>{try{callback(null,tls.createSecureContext(material()));}catch(error){callback(error);}}},(_req,res)=>res.end('qualification')).listen(8443,'0.0.0.0');";
      kube(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"Pod",metadata:{name:"tls-destination",namespace},spec:{automountServiceAccountToken:false,securityContext:{fsGroup:1001},containers:[{name:"endpoint",image:"certops-controller:qualification",imagePullPolicy:"Never",command:["node","-e",endpointCode],securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},readinessProbe:{tcpSocket:{port:8443},periodSeconds:2},volumeMounts:[{name:"tls",mountPath:"/tls",readOnly:true}]}],volumes:[{name:"tls",secret:{secretName:"journey-tls",defaultMode:0o440}}]}}));
      kube(["wait","--for=condition=Ready","pod/tls-destination","-n",namespace,"--timeout=120s"]);
      forward=spawn("kubectl",["--context",process.env.CERTOPS_KUBE_CONTEXT,"port-forward","pod/tls-destination","-n",namespace,"0:8443","--address","127.0.0.1"],{stdio:["ignore","pipe","ignore"]});
      const port=await new Promise((resolve,reject)=>{let text="";const timeout=setTimeout(()=>reject(new Error("TLS destination forwarding missing")),20000);forward.once("error",()=>{clearTimeout(timeout);reject(new Error("TLS forwarding failed"));});forward.once("exit",()=>{clearTimeout(timeout);reject(new Error("TLS forwarding exited"));});forward.stdout.on("data",chunk=>{text+=chunk.toString();if(text.length>1024){clearTimeout(timeout);reject(new Error("Invalid forwarding receipt"));return;}const match=/Forwarding from 127\.0\.0\.1:(\d+)/.exec(text);if(match){clearTimeout(timeout);resolve(Number(match[1]));}});});
      forwardPort=port;
      const served=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:"journey.certops.invalid",ca:publicLeafPem,rejectUnauthorized:true},()=>{resolve(socket.getPeerCertificate().fingerprint256);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("TLS observation timed out")));socket.on("error",reject);});
      assert.equal(served,leaf.fingerprint256);
    },{oracle:"Real destination pod serves locally mounted Secret; trusted TLS peer fingerprint equals independently read public leaf without exporting its private key"});
    await gate.scenario("controller-public-pause-gate",async()=>{
      const last=(await fixture.pool.query("SELECT MAX(observed_at) AS observed_at FROM certificate_instances WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].observed_at;
      assert.equal((await fixture.request(`${prefix}/settings`,"PUT",{certOpsPaused:true})).status,200);
      const refused=await fixture.request(`${prefix}/provision-intents`,"POST",{...desired,certificateName:"paused-refusal",secretName:"paused-refusal-tls"},{"Idempotency-Key":crypto.randomUUID()});assert.equal(refused.status,409);
      assert.ok(!JSON.parse(kube(["get","certificates","-n",namespace,"-o","json"])).items.some(item=>item.metadata.name==="paused-refusal"));
      kube(["annotate","certificate/journey","-n",namespace,`qualification-paused-observation=${crypto.randomUUID()}`]);
      await eventually(async()=>{const current=(await fixture.pool.query("SELECT MAX(observed_at) AS observed_at FROM certificate_instances WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].observed_at;return current&&new Date(current).getTime()>new Date(last).getTime();});
      assert.equal((await fixture.request(`${prefix}/settings`,"PUT",{certOpsPaused:false})).status,200);
    },{oracle:"Actual public pause gate refuses new intent without resource creation, while a real watch update advances passive observations"});
    await gate.scenario("controller-api-outage-recovery",async()=>{
      const before=JSON.parse(kube(["get","certificate","journey","-n",namespace,"-o","json"]));
      assert.equal(bridge.kill("SIGSTOP"),true,"Actual owned API bridge must stop transport");
      try{
        const changed={...desired,dnsNames:[...desired.dnsNames,"updated.certops.invalid"]};
        const update=await fixture.request(`${prefix}/provision-intents`,"POST",changed,{"Idempotency-Key":crypto.randomUUID()});assert.equal(update.status,201);
        const during=JSON.parse(kube(["get","certificate","journey","-n",namespace,"-o","json"]));assert.deepEqual(during.spec,before.spec,"API outage must leave the actual destination unchanged");
        assert.equal(bridge.kill("SIGCONT"),true);
        await eventually(async()=>{const job=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,update.body.job.id])).rows[0];if(["failed","cancelled","rejected"].includes(job?.status))throw new Error("Actual resumed controller update failed");return job?.status==="succeeded";});
        const updated=await eventually(async()=>{const pem=Buffer.from(kube(["get","secret","journey-tls","-n",namespace,"-o","jsonpath={.data.tls\\.crt}"]),"base64");const certificate=new crypto.X509Certificate(pem);return certificate.checkHost("updated.certops.invalid")?certificate:false;});
        assert.notEqual(updated.fingerprint256,leaf.fingerprint256);
        await eventually(()=>new Promise(resolve=>{const socket=tls.connect({host:"127.0.0.1",port:forwardPort,servername:"updated.certops.invalid",ca:updated.toString(),rejectUnauthorized:true},()=>{resolve(socket.authorized===true&&socket.getPeerCertificate().fingerprint256===updated.fingerprint256);socket.end();});socket.setTimeout(10000,()=>socket.destroy());socket.on("error",()=>resolve(false));socket.on("close",()=>resolve(false));}));
        await eventually(async()=>Boolean((await fixture.pool.query("SELECT 1 FROM certificate_instances WHERE workspace_id=$1 AND observed_fingerprint_sha256=$2",[fixture.workspaceId,updated.fingerprint256.replace(/:/g,"").toLowerCase()])).rows.length));
        assert.ok((await fixture.pool.query("SELECT 1 FROM certops_slot_observations WHERE workspace_id=$1 AND fingerprint_sha256=$2",[fixture.workspaceId,leaf.fingerprint256.replace(/:/g,"").toLowerCase()])).rows.length,"Earlier public observation history must survive the resumed update");
        assert.equal(JSON.parse(kube(["get","certificate","journey","-n",namespace,"-o","json"])).metadata.uid,before.metadata.uid);
      }finally{if(bridge.exitCode===null)bridge.kill("SIGCONT");}
    },{oracle:"Actual suspended private API transport preserves destination, then production command retry/watch records a genuinely reissued public leaf and retained history"});
    await gate.scenario("controller-production-restart",async()=>{
      const before=JSON.parse(kube(["get","certificate","journey","-n",namespace,"-o","json"]));
      const jobCount=(await fixture.pool.query("SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].count;
      const last=(await fixture.pool.query("SELECT MAX(observed_at) AS observed_at FROM certificate_instances WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].observed_at;
      kube(["rollout","restart","deployment/controller","-n",namespace]);kube(["rollout","status","deployment/controller","-n",namespace,"--timeout=180s"]);
      const after=JSON.parse(kube(["get","certificate","journey","-n",namespace,"-o","json"]));assert.equal(after.metadata.uid,before.metadata.uid);
      assert.equal((await fixture.pool.query("SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].count,jobCount);
      kube(["annotate","certificate/journey","-n",namespace,`qualification-restart-observation=${crypto.randomUUID()}`]);
      await eventually(async()=>{const current=(await fixture.pool.query("SELECT MAX(observed_at) AS observed_at FROM certificate_instances WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].observed_at;return current&&new Date(current).getTime()>new Date(last).getTime();});
    },{oracle:"Real production pod restart resynchronizes without replacing the owned Certificate or duplicating the completed job"});
  }catch(error){primary=error;throw error;}
  finally{
    const cleanup=async()=>{
      const errors=[];
      for(const action of [()=>stopChild(forward),async()=>{if(owned)kube(["delete","namespace",namespace,"--wait=true","--timeout=120s"]);},()=>stopChild(bridge),fixture.cleanup,async()=>fs.rmSync(directory,{recursive:true,force:true})]){try{await action();}catch(error){errors.push(error);}}
      if(errors.length)throw new AggregateError(errors,"Owned controller fixture cleanup failed");
    };
    try{if(ready){await gate.scenario("controller-api-fixture-cleanup",cleanup,{oracle:"Owned namespace, bridge, credentials and API identities removed"});await gate.finish({requiredScenarios:["controller-public-api-provision","controller-public-observation","controller-served-tls-leaf","controller-public-pause-gate","controller-api-outage-recovery","controller-production-restart","controller-api-fixture-cleanup"]});}else await cleanup();}
    catch(error){if(primary)throw new AggregateError([primary,error],"Controller journey and finalization failed");throw error;}
  }
}
if(require.main===module)main().catch(()=>{console.error("Controller API E2E failed; inspect sanitized report");process.exitCode=1;});
module.exports={main};
