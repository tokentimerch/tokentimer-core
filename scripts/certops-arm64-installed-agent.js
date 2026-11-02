"use strict";
/** Standalone real API bootstrap for the bounded installed ARM64 lane.
 * Secrets stay in memory; only the host gate's bounded public proof is saved.
 * A native/cleanup failure preserves database and local ownership evidence. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),net=require("node:net"),{spawn}=require("node:child_process");
function freePort(){return new Promise((resolve,reject)=>{const s=net.createServer();s.once("error",reject);s.listen(0,"127.0.0.1",()=>{const p=s.address().port;s.close(error=>error?reject(error):resolve(p));});});}
function finalizeReport(file,succeeded,expectedCandidate=process.env.GITHUB_SHA){
 if(!fs.existsSync(file))return;
 const stat=fs.lstatSync(file);assert.equal(stat.isSymbolicLink(),false);assert.ok(stat.isFile()&&stat.size<=2097152);
 const report=JSON.parse(fs.readFileSync(file,"utf8"));assert.equal(report.suite,require("./certops-arm64-installed-proof").suite);assert.equal(report.candidateSha,expectedCandidate);
 if(!succeeded){report.status="failed";report.cleanup={status:"failed",summary:"Outer API or owned workspace cleanup incomplete"};report.finishedAt=new Date().toISOString();fs.writeFileSync(file,JSON.stringify(report));}
 return report;
}
async function main(){
 assert.equal(process.platform,"win32");assert.equal(process.arch,"arm64");assert.equal(process.env.CERTOPS_ARM64_AGENT_REQUIRED,"1");assert.equal(process.env.DB_HOST,"127.0.0.1");assert.equal(process.env.DB_PORT,"55432");assert.equal(process.env.DB_NAME,"certops_arm64_qualification");
 process.env.CERTOPS_CSR_DISPOSABLE_STACK="1";
 // Admission and the actual API child must share the same real encryption
 // keys; their values never appear in source, argv, reports or artifacts.
 process.env.CERTOPS_SIGNING_ENCRYPTION_KEY=crypto.randomBytes(32).toString("hex");process.env.CERTOPS_REGISTRATION_ENCRYPTION_KEY=crypto.randomBytes(32).toString("hex");
 const port=await freePort(),baseUrl=`http://127.0.0.1:${port}`,api=spawn(process.execPath,["index.js"],{cwd:path.resolve(__dirname,"../apps/api"),stdio:["ignore","pipe","pipe"],windowsHide:true,env:{...process.env,NODE_ENV:"test",PORT:String(port),HOST:"127.0.0.1",CERTOPS_ENABLED:"true",SESSION_SECRET:crypto.randomBytes(32).toString("hex"),DISABLE_ADMIN_BOOTSTRAP:"true",ENABLE_METRICS:"false"}});
 api.stdout.resume();api.stderr.resume();let closed=false;const close=new Promise(resolve=>api.once("close",()=>{closed=true;resolve();}));api.on("error",()=>{});
 let fixture,complete=false,primary;const errors=[];
 try{
  const deadline=performance.now()+60000;let healthy=false;while(performance.now()<deadline){assert.equal(closed,false,"Owned API exited before readiness");try{healthy=(await fetch(`${baseUrl}/health`,{signal:AbortSignal.timeout(1000)})).status===200;}catch{}if(healthy)break;await new Promise(resolve=>setTimeout(resolve,250));}assert.equal(healthy,true,"Actual API health prerequisite failed");
  fixture=await require("../tests/e2e/helpers/certops-api-fixture").createApiFixture(baseUrl);
  await require("../tests/e2e/helpers/certops-arm64-installed-journey").qualify({fixture,baseUrl});complete=true;
 }catch(error){primary=error;}
 finally{
  if(fixture){if(complete){try{await fixture.cleanup();}catch(error){errors.push(error);}}else await fixture.pool.end().catch(error=>errors.push(error));}
  if(!closed)api.kill("SIGTERM");await Promise.race([close,new Promise(resolve=>setTimeout(resolve,10000))]);if(!closed){api.kill("SIGKILL");await Promise.race([close,new Promise(resolve=>setTimeout(resolve,5000))]);}if(!closed)errors.push(new Error("Owned API child did not drain"));
  try{finalizeReport(path.resolve(__dirname,"../qualification-results/windows-arm64-installed-agent.json"),complete&&!primary&&!errors.length);}catch(error){errors.push(error);}
 }
 if(primary||errors.length)throw new AggregateError([...(primary?[primary]:[]),...errors],"Installed ARM64 qualification or API cleanup failed");
}
if(require.main===module)main().catch(()=>{console.error("Actual ARM64 installed-agent lane failed; raw private diagnostics retained on disposable runner");process.exitCode=1;});
module.exports={main,finalizeReport};
