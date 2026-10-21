"use strict";
/* Portable supporting checks for the qualification launcher and transparent
 * upload observer. Real benign child processes/loopback sockets prove argv,
 * environment, exit and detection behavior; these tests do not install SCM,
 * create certificates or qualify Windows certificate execution. */
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),http=require("node:http"),{spawnSync}=require("node:child_process");
const {prepareOutputPrivacy,verifyPrivacyReport}=require("../e2e/helpers/certops-windows-output-privacy");
test("real output child preserves executable argv environment and nonzero exit without publishing raw sentinels",async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-output-child-"));let proof;
 try{
  proof=await prepareOutputPrivacy(directory,process.execPath,["-e","process.stdout.write('actual-delegate:'+process.env.QUALIFICATION_BENIGN+':'+process.argv[1]);process.exitCode=17","argument with spaces"],"http://127.0.0.1:1");
  const child=spawnSync(proof.argv[0],proof.argv.slice(1),{encoding:"utf8",timeout:30000,env:{...process.env,QUALIFICATION_BENIGN:"present"}});assert.ifError(child.error);assert.equal(child.status,17);
  assert.equal(child.stdout.includes("actual-delegate:present:argument with spaces"),true);for(const value of [proof.recipe.bearer,proof.recipe.password,proof.recipe.pemPayload]){assert.equal(child.stdout.includes(value),true);assert.equal(child.stderr.includes(value),true);}
  const files=fs.readdirSync(proof.directory);assert.equal(files.length,1);const receipt=JSON.parse(fs.readFileSync(path.join(proof.directory,files[0]),"utf8"));assert.equal(receipt.stdoutEmitted,true);assert.equal(receipt.stderrEmitted,true);assert.equal(receipt.delegatedExit,17);assert.equal(JSON.stringify(receipt).includes(proof.recipe.password),false);
 }finally{if(proof)await proof.close();fs.rmSync(directory,{recursive:true,force:true});}
});
test("owned observer forwards real upload unchanged while detecting synthetic secret exposure",async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-output-proxy-"));let proof,received;
 const upstream=http.createServer((request,response)=>{const chunks=[];request.on("data",chunk=>chunks.push(chunk));request.on("end",()=>{received=Buffer.concat(chunks).toString("utf8");response.end("accepted");});});await new Promise(resolve=>upstream.listen(0,"127.0.0.1",resolve));
 try{
  proof=await prepareOutputPrivacy(directory,process.execPath,[],`http://127.0.0.1:${upstream.address().port}`);const body=JSON.stringify({message:proof.recipe.bearer});
  const response=await fetch(`${proof.agentUrl}/api/v1/certops/agent/jobs/00000000-0000-4000-8000-000000000001/logs`,{method:"POST",body});assert.equal(await response.text(),"accepted");assert.equal(received===body,true);assert.equal(proof.transport.inspectedUploads,1);assert.equal(proof.transport.secretsObserved,true);assert.equal((await fetch(`${proof.agentUrl}/foreign`)).status,404);
 }finally{if(proof)await proof.close();upstream.closeAllConnections();await new Promise(resolve=>upstream.close(resolve));fs.rmSync(directory,{recursive:true,force:true});}
});
test("observer refuses absolute, traversing, encoded or foreign paths and drains an unfinished upload on close",async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-output-fences-"));let proof,received=0;
 const upstream=http.createServer(request=>{received++;request.resume();});await new Promise(resolve=>upstream.listen(0,"127.0.0.1",resolve));
 const send=(port,target)=>new Promise((resolve,reject)=>{const request=http.request({hostname:"127.0.0.1",port,path:target,method:"POST"},response=>{response.resume();response.once("end",()=>resolve(response.statusCode));});request.once("error",reject);request.end("{}");});
 try{
  proof=await prepareOutputPrivacy(directory,process.execPath,[],`http://127.0.0.1:${upstream.address().port}`);const port=Number(new URL(proof.agentUrl).port);
  for(const target of ["http://example.invalid/api/v1/certops/agent/register","//example.invalid/api/v1/certops/agent/register","/api/v1/certops/agent/jobs/../register","/api/v1/certops/agent/register?x=1","/api/v1/certops/agent/register#x","/api/v1/certops/agent/%72egister","/api/v1/certops/agent/jobs/------------------------------------/logs","/foreign"])assert.equal(await send(port,target),404);
  assert.equal(received,0);const outstanding=send(port,"/api/v1/certops/agent/jobs/results").catch(()=>null);
  while(received===0)await new Promise(resolve=>setImmediate(resolve));
  let timer;try{await Promise.race([proof.close(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error("Owned observer cleanup did not drain")),5000);})]);}finally{clearTimeout(timer);}proof=null;await outstanding;
 }finally{if(proof)await proof.close();upstream.closeAllConnections();await new Promise(resolve=>upstream.close(resolve));fs.rmSync(directory,{recursive:true,force:true});}
});

test("privacy proof requires actual emission, withholding, HTTP persistence and both producer hashes",()=>{
 const crypto=require("node:crypto");const sourceFiles=["tests/e2e/helpers/certops-windows-output-child.js","tests/e2e/helpers/certops-windows-output-privacy.js","tests/e2e/windows-real-journey.js"];
 const report={startedAt:new Date(Date.now()-1000).toISOString(),finishedAt:new Date().toISOString(),schemaVersion:1,suite:"windows-native-child-output-privacy",status:"passed",strict:true,requiredScenarios:["windows-native-child-output-withheld"],scenarios:[{id:"windows-native-child-output-withheld",status:"passed"}],candidateSha:process.env.GITHUB_SHA||"a".repeat(40),qualificationEnvironment:{osFamily:"windows",osVersion:"2022",build:"20348",identity:"LocalSystem",measurement:"native",keyProfile:"rsa-2048",keyAlgorithm:"rsa",keySize:2048},actualNativeIdentity:"LocalSystem",actualStdoutAndStderrEmission:true,actualDelegatedSuccess:true,actualAcmeSuccessLogObserved:true,actualHttpUploadsSecretFree:true,persistedLogsEvidenceResultsSecretFree:true,scmConsoleSecretFree:true,childOutputPolicy:"captured-and-withheld-not-live-forwarded",nativeCertificateOutcome:"parent-independent-CNG-IIS-trusted-TLS",receiptCount:1,jobLogCount:2,evidenceCount:3,httpUploadCount:4,fixtureSources:sourceFiles.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../..",file))).digest("hex")}))};
 assert.equal(verifyPrivacyReport(report),true);assert.throws(()=>verifyPrivacyReport(report,{expectedSha:"f".repeat(40)}));
 for(const change of [{actualStdoutAndStderrEmission:false},{actualDelegatedSuccess:false},{actualHttpUploadsSecretFree:false},{scmConsoleSecretFree:false},{httpUploadCount:0},{receiptCount:33},{fixtureSources:[]},{childOutputPolicy:"live-console-lines"},{qualificationEnvironment:{...report.qualificationEnvironment,build:"26100"}}])assert.throws(()=>verifyPrivacyReport({...report,...change}));
});
