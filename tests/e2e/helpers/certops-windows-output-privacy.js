"use strict";
/* Installed SCM child-output privacy proof, used by windows-real-journey.js.
 * The owned wrapper emits only synthetic secrets before the genuine ACME
 * client. Actual successful certificate/TLS outcomes remain the parent oracle;
 * this helper verifies intentional output withholding, not live forwarding of
 * child console lines. Reports contain only bounded public counts/booleans. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),http=require("node:http");
async function prepareOutputPrivacy(workDir,program,args,upstreamUrl){
 const startedAt=new Date().toISOString();
 const upstreamOrigin=new URL(upstreamUrl);assert.equal(upstreamOrigin.protocol,"http:");assert.equal(upstreamOrigin.hostname,"127.0.0.1");assert.equal(upstreamOrigin.pathname,"/");assert.equal(upstreamOrigin.search,"");assert.equal(upstreamOrigin.hash,"");assert.equal(upstreamOrigin.username,"");assert.equal(upstreamOrigin.password,"");const upstreamPort=Number(upstreamOrigin.port);assert.ok(Number.isInteger(upstreamPort)&&upstreamPort>=1&&upstreamPort<=65535);
 const directory=path.join(workDir,"native-output-receipts");fs.mkdirSync(directory);
 require("../../../packages/agent/src/platform").applyRestrictivePermissions(directory,{kind:"directory"});
 const recipe={runId:crypto.randomBytes(16).toString("hex"),receiptDirectory:directory,bearer:`ttagent_${crypto.randomBytes(32).toString("hex")}`,password:crypto.randomBytes(32).toString("hex"),pemPayload:crypto.randomBytes(48).toString("base64")};
 const recipePath=path.join(workDir,"native-output-recipe.json");fs.writeFileSync(recipePath,JSON.stringify(recipe),{flag:"wx",mode:0o600});
 require("../../../packages/agent/src/platform").applyRestrictivePermissions(recipePath,{kind:"file"});
 const transport={inspectedUploads:0,secretsObserved:false,oversizedUpload:false};
 const pendingUpstream=new Set(),heldResults=new Set(),pendingResultBodies=new Set();let resultBarrier=null;
 const server=http.createServer((request,response)=>{
  const agentPath=/^\/api\/v1\/certops\/agent\/(?:register|heartbeat|jobs\/(?:claim|results|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\/(?:lease|logs)))$/;
  if(request.method!=="POST"||!agentPath.test(request.url)){response.statusCode=404;response.end();return;}
  const headers={"content-type":"application/json"};if(typeof request.headers.authorization==="string"&&request.headers.authorization.length<=4096)headers.authorization=request.headers.authorization;
  // The dedicated stopped/offline lane may hold only its original claim's
  // actual result before ANY upstream request exists. No bytes are rewritten,
  // no successful API response is manufactured and held results are discarded
  // after captured native drainage rather than replayed into terminal history.
  if(resultBarrier&&request.url==='/api/v1/certops/agent/jobs/results'){
   const armed=resultBarrier;pendingResultBodies.add(response);response.once('close',()=>pendingResultBodies.delete(response));
   const chunks=[];let size=0,oversized=false;
   request.on('data',chunk=>{size+=chunk.length;if(size<=1048576)chunks.push(chunk);else{oversized=true;transport.oversizedUpload=true;}});
   request.on('end',()=>{
    if(response.destroyed)return;
    if(oversized){response.statusCode=413;response.end();return;}
    const bytes=Buffer.concat(chunks),body=bytes.toString('utf8');transport.inspectedUploads++;
    for(const secret of [recipe.bearer,recipe.password,recipe.pemPayload,'-----BEGIN PRIVATE KEY-----'])if(body.includes(secret))transport.secretsObserved=true;
    let envelope;try{envelope=JSON.parse(body);}catch{}
    if(envelope?.messageType==='result'&&envelope.body?.jobId===armed.jobId&&envelope.body?.claimId===armed.claimId){
     armed.actualHeldRequests++;heldResults.add(response);response.once('close',()=>heldResults.delete(response));return;
    }
    pendingResultBodies.delete(response);
    const upstream=http.request({hostname:'127.0.0.1',port:upstreamPort,path:request.url,method:'POST',headers,agent:false},incoming=>{response.writeHead(incoming.statusCode,{'content-type':'application/json'});incoming.pipe(response);});
    pendingUpstream.add(upstream);upstream.once('close',()=>pendingUpstream.delete(upstream));upstream.setTimeout(60000,()=>upstream.destroy());
    upstream.on('error',()=>{if(!response.headersSent&&!response.destroyed){response.statusCode=502;response.end();}else response.destroy();});upstream.end(bytes);
   });return;
  }
  const upstream=http.request({hostname:"127.0.0.1",port:upstreamPort,path:request.url,method:"POST",headers,agent:false},incoming=>{response.writeHead(incoming.statusCode,{"content-type":"application/json"});incoming.pipe(response);});
  pendingUpstream.add(upstream);upstream.once("close",()=>pendingUpstream.delete(upstream));upstream.setTimeout(60000,()=>upstream.destroy());
  upstream.on("error",()=>{if(!response.headersSent&&!response.destroyed){response.statusCode=502;response.end();}else response.destroy();});
  if(/\/api\/v1\/certops\/agent\//.test(request.url)&&/(?:logs|evidence|result)/.test(request.url)){
   const chunks=[];let size=0;request.on("data",chunk=>{size+=chunk.length;if(size<=1048576)chunks.push(chunk);else transport.oversizedUpload=true;});
   request.on("end",()=>{transport.inspectedUploads++;const body=Buffer.concat(chunks).toString("utf8");for(const secret of [recipe.bearer,recipe.password,recipe.pemPayload,"-----BEGIN PRIVATE KEY-----"])if(body.includes(secret))transport.secretsObserved=true;});
  }
  request.pipe(upstream);
 });
 await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
 return {recipe,directory,transport,startedAt,agentUrl:`http://127.0.0.1:${server.address().port}`,
 armResultBarrier(jobId,claimId){assert.equal(resultBarrier,null);for(const value of [jobId,claimId])assert.match(value,/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);resultBarrier={jobId,claimId,actualHeldRequests:0};},
 resultBarrierObservation(){return resultBarrier?{...resultBarrier,heldConnections:heldResults.size}:null;},
 async discardHeldResults(){for(const response of new Set([...heldResults,...pendingResultBodies]))response.destroy();const deadline=performance.now()+5000;while((heldResults.size||pendingResultBodies.size)&&performance.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));assert.equal(heldResults.size+pendingResultBodies.size,0,'Owned held result responses remain');resultBarrier=null;},
 close:()=>new Promise((resolve,reject)=>{for(const response of new Set([...heldResults,...pendingResultBodies]))response.destroy();for(const request of pendingUpstream)request.destroy();server.closeAllConnections();server.close(error=>error?reject(error):resolve());}),argv:[process.execPath,path.join(__dirname,"certops-windows-output-child.js"),recipePath,program,...args]};
}
async function verifyOutputPrivacy({pool,workspaceId,jobId,configDir,proof,waitUntil,ps,keyProfile}){
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST,"1");
 const osBuild=ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber");assert.equal(ps("(Get-CimInstance Win32_OperatingSystem).ProductType"),"3");const version={"20348":"2022","26100":"2025"}[osBuild];assert.ok(version);
 const file="tests/e2e/helpers/certops-windows-output-privacy.js",{createHostGate}=require("../../../packages/agent/scripts/host-gate");
 const gate=createHostGate({suite:"windows-native-child-output-privacy",strict:true,evidenceLevel:"e2e",reportPath:null,fixtureSource:{file,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},requiredCapabilities:["windows","scm","api","nativeAcme"],probeCapabilities:()=>({windows:{available:process.platform==="win32"},scm:{available:ps("[bool](Get-CimClass Win32_Service)")==="True"},api:{available:true},nativeAcme:{available:true}})});
 assert.ok(Number.isFinite(Date.parse(proof.startedAt))&&Date.parse(proof.startedAt)<=Date.now());gate.report.startedAt=proof.startedAt;
 gate.report.qualificationEnvironment={osFamily:"windows",osVersion:version,build:osBuild,identity:"LocalSystem",measurement:"native",keyProfile:process.env.CERTOPS_WINDOWS_KEY_PROFILE||"rsa-2048",keyAlgorithm:keyProfile.keyAlgorithm,keySize:keyProfile.keySize};
 await gate.preflight();
 await gate.scenario("windows-native-child-output-withheld",async()=>{
 const receipts=fs.readdirSync(proof.directory).filter(file=>/^[0-9]+-[a-f0-9-]+\.json$/.test(file)).map(file=>JSON.parse(fs.readFileSync(path.join(proof.directory,file),"utf8")));
 assert.ok(receipts.length>0&&receipts.length<=32);for(const receipt of receipts){assert.equal(receipt.runId,proof.recipe.runId);assert.equal(receipt.platform,"win32");assert.equal(receipt.nativeSid,"S-1-5-18");assert.equal(receipt.stdoutEmitted,true);assert.equal(receipt.stderrEmitted,true);}
 assert.ok(receipts.some(receipt=>receipt.delegatedExit===0&&receipt.delegatedSignal===null),"A real successful delegated ACME invocation must complete");
 assert.ok(proof.transport.inspectedUploads>0);assert.equal(proof.transport.secretsObserved,false);assert.equal(proof.transport.oversizedUpload,false);
 const logs=await waitUntil(async()=>{const rows=(await pool.query("SELECT message,fields,redaction_count FROM certops_agent_job_log WHERE workspace_id=$1 AND job_id=$2 ORDER BY seq",[workspaceId,jobId])).rows;return rows.some(row=>/ACME order succeeded/.test(row.message))?rows:null;});
 const evidence=(await pool.query("SELECT metadata,redacted_output FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[workspaceId,jobId])).rows;assert.ok(evidence.length);
 const result=(await pool.query("SELECT status,result_metadata,error_message FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[workspaceId,jobId])).rows[0];assert.equal(result.status,"succeeded");
 const persisted=JSON.stringify({logs,evidence,result}),localLogs=[];
 for(const name of fs.readdirSync(configDir).filter(name=>/^host\.log(?:\.[0-9]+)?$/.test(name)))localLogs.push(fs.readFileSync(path.join(configDir,name),"utf8"));
 assert.ok(localLogs.length>0);
 for(const value of [proof.recipe.bearer,proof.recipe.password,proof.recipe.pemPayload,"-----BEGIN PRIVATE KEY-----"]){assert.equal(persisted.includes(value),false,"Native child material reached persisted API evidence/log/result");assert.equal(localLogs.some(log=>log.includes(value)),false,"Native child material reached the SCM host console");}
 // Source identity and public observations are handed to the parent report;
 // recipe values, raw console output and native receipt contents stay local.
 const sources=["tests/e2e/helpers/certops-windows-output-child.js","tests/e2e/helpers/certops-windows-output-privacy.js","tests/e2e/windows-real-journey.js"].map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../..",file))).digest("hex")}));
 Object.assign(gate.report,{fixtureSources:sources,actualNativeIdentity:"LocalSystem",actualStdoutAndStderrEmission:true,actualDelegatedSuccess:true,actualAcmeSuccessLogObserved:true,childOutputPolicy:"captured-and-withheld-not-live-forwarded",actualHttpUploadsSecretFree:true,httpUploadCount:proof.transport.inspectedUploads,persistedLogsEvidenceResultsSecretFree:true,scmConsoleSecretFree:true,receiptCount:receipts.length,jobLogCount:logs.length,evidenceCount:evidence.length,nativeCertificateOutcome:"parent-independent-CNG-IIS-trusted-TLS"});
 },{evidenceLevel:"e2e",oracle:"actual installed SYSTEM child emission and delegated ACME success, transparent real HTTP inspection, persisted logs/evidence/results and native SCM console absence; parent independent CNG/IIS/TLS"});
 await gate.finish({requiredScenarios:["windows-native-child-output-withheld"]});return gate.report;
}
function verifyPrivacyReport(report,{expectedSha=process.env.GITHUB_SHA}={}){
 assert.equal(report.schemaVersion,1);assert.equal(report.suite,"windows-native-child-output-privacy");assert.equal(report.status,"passed");assert.equal(report.strict,true);assert.deepEqual(report.requiredScenarios,["windows-native-child-output-withheld"]);assert.equal(report.scenarios.length,1);assert.equal(report.scenarios[0].id,"windows-native-child-output-withheld");assert.equal(report.scenarios[0].status,"passed");assert.match(report.candidateSha,/^[a-f0-9]{40}$/i);if(expectedSha)assert.equal(report.candidateSha,expectedSha);
 assert.ok(Number.isFinite(Date.parse(report.startedAt))&&Number.isFinite(Date.parse(report.finishedAt))&&Date.parse(report.finishedAt)>=Date.parse(report.startedAt));
 const environment=report.qualificationEnvironment;assert.equal(environment.osFamily,"windows");assert.ok(["2022","2025"].includes(environment.osVersion));assert.equal(environment.identity,"LocalSystem");assert.equal(environment.measurement,"native");assert.equal(environment.build,{"2022":"20348","2025":"26100"}[environment.osVersion]);
 const keyProfiles={"rsa-2048":["rsa",2048],"rsa-3072":["rsa",3072],"rsa-4096":["rsa",4096],"ec-p256":["ecdsa",256],"ec-p384":["ecdsa",384]};assert.deepEqual([environment.keyAlgorithm,environment.keySize],keyProfiles[environment.keyProfile]);
 assert.equal(report.actualNativeIdentity,"LocalSystem");assert.equal(report.childOutputPolicy,"captured-and-withheld-not-live-forwarded");assert.equal(report.nativeCertificateOutcome,"parent-independent-CNG-IIS-trusted-TLS");
 for(const field of ["actualStdoutAndStderrEmission","actualDelegatedSuccess","actualAcmeSuccessLogObserved","actualHttpUploadsSecretFree","persistedLogsEvidenceResultsSecretFree","scmConsoleSecretFree"])assert.equal(report[field],true);
 assert.ok(report.receiptCount<=32);
 for(const field of ["receiptCount","jobLogCount","evidenceCount","httpUploadCount"])assert.ok(Number.isInteger(report[field])&&report[field]>0&&report[field]<=10000);
 for(const file of ["tests/e2e/helpers/certops-windows-output-child.js","tests/e2e/helpers/certops-windows-output-privacy.js","tests/e2e/windows-real-journey.js"]){const actual=report.fixtureSources.filter(source=>source.file===file);assert.equal(actual.length,1);assert.equal(actual[0].sha256,crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../..",file))).digest("hex"));}
 return true;
}
module.exports={prepareOutputPrivacy,verifyOutputPrivacy,verifyPrivacyReport};
