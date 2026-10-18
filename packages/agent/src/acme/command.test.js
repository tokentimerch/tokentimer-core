/**
 * Regression coverage for the production ACME runner's output bounds and owned-tree abort.
 * Native child-process cases measure real termination; platform-specific cases keep
 * their declared prerequisites. These checks do not stand in for the full ACME journey. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),cp=require("node:child_process");
const {execWithoutShell}=require("./command");
// Windows starts PowerShell and compiles the Job Object wrapper before the
// fixture child can report readiness. Hosted runners need a cold-start budget;
// the command deadline and actual process-tree termination assertions stay active.
const windows=process.platform==="win32";
const commandBudget=windows?20000:5000,readyBudget=windows?30000:8000;
const testBudget=windows?45000:15000;
async function boundedDrain(running, proof){
 let finished=false;running.then(()=>{finished=true;});await Promise.resolve();
 if(!finished&&proof){for(const pid of [proof.child,proof.parent])try{process.kill(pid,"SIGKILL");}catch(error){if(error.code!=="ESRCH")throw error;}}
 let timer;try{await Promise.race([running,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error("Owned test command did not drain")),5000);})]);}finally{clearTimeout(timer);}
}
async function until(check){const deadline=Date.now()+readyBudget;while(Date.now()<deadline){if(check())return;await new Promise(resolve=>setTimeout(resolve,20));}throw new Error("Owned ACME command termination deadline exceeded");}
test("aborted ACME execution never invokes an external command",async()=>{const ac=new AbortController();ac.abort();let called=false;const result=await execWithoutShell(()=>{called=true;},["never"],1000,{},ac.signal);assert.equal(called,false);assert.ok(result.execError);});
test("real ACME command cancellation terminates its owned child process tree",{timeout:testBudget},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-abort-")),receipt=path.join(directory,"processes.json"),ac=new AbortController();let proof;
 const script="const cp=require('child_process'),fs=require('fs');const child=cp.spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[1],JSON.stringify({parent:process.pid,child:child.pid}));setInterval(()=>{},1000);";
 const running=execWithoutShell(cp.execFile,[process.execPath,"-e",script,receipt],windows?commandBudget:10000,{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},ac.signal);
 try{await until(()=>fs.existsSync(receipt));proof=JSON.parse(fs.readFileSync(receipt));process.kill(proof.parent,0);process.kill(proof.child,0);ac.abort(new Error("Real qualification lease loss"));const result=await running;assert.ok(result.execError);for(const pid of [proof.parent,proof.child])await until(()=>{try{process.kill(pid,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});}
 finally{ac.abort();await boundedDrain(running,proof);fs.rmSync(directory,{recursive:true});}
});

for(const mode of ["abort","timeout"])test(`owned command ${mode} drains a leader that exits before its TERM-resistant child holding stdout`,{timeout:testBudget},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-drain-")),receipt=path.join(directory,"ready.json"),ac=new AbortController();let proof;
 const stubborn="process.on('SIGTERM',()=>{});require('fs').writeFileSync(process.argv[1],JSON.stringify({parent:process.ppid,child:process.pid}));setInterval(()=>{},1000);";
 const leader="process.on('SIGTERM',()=>process.exit(0));require('child_process').spawn(process.execPath,['-e',process.argv[1],process.argv[2]],{stdio:['ignore','inherit','inherit']});setInterval(()=>{},1000);";
 const began=Date.now(),running=execWithoutShell(cp.execFile,[process.execPath,"-e",leader,stubborn,receipt],mode==="timeout"?(windows?commandBudget:1200):(windows?commandBudget:10000),{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},ac.signal);
 try{await until(()=>fs.existsSync(receipt));proof=JSON.parse(fs.readFileSync(receipt));if(mode==="abort")ac.abort();const result=await running;assert.ok(result.execError,"Cancellation or timeout cannot become success when the leader exits zero");assert.ok(Date.now()-began<(windows?35000:7000),"Whole tree drain must remain bounded");for(const pid of [proof.parent,proof.child])await until(()=>{try{process.kill(pid,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});}
 finally{ac.abort();await running;fs.rmSync(directory,{recursive:true});}
});

for(const code of [0,17])test(`native command preserves bounded stdout stderr and actual exit ${code}`,{timeout:testBudget},async()=>{
 const result=await execWithoutShell(cp.execFile,[process.execPath,"-e",`process.stdout.write('public-output');process.stderr.write('public-diagnostic');process.exitCode=${code};`],commandBudget,{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot});assert.equal(result.exitCode,code,`Native fixture failed: ${result.execError?.message}; ${result.stderr}`);assert.equal(String(result.stdout),"public-output");assert.equal(String(result.stderr),"public-diagnostic");assert.equal(Boolean(result.execError),code!==0);
});
test("native excessive-output command fails bounded and terminates its actual process",{timeout:testBudget},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-output-")),receipt=path.join(directory,"pid"),ac=new AbortController();let proof;
 const script="require('fs').writeFileSync(process.argv[1],String(process.pid));const chunk=Buffer.alloc(65536,65);setInterval(()=>{for(let i=0;i<8;i++)process.stdout.write(chunk);},1);";
 const running=execWithoutShell(cp.execFile,[process.execPath,"-e",script,receipt],commandBudget,{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},ac.signal);
 try{await until(()=>fs.existsSync(receipt));const pid=Number(fs.readFileSync(receipt,"utf8"));proof={parent:pid,child:pid};const result=await running;assert.ok(result.execError);assert.ok(Buffer.byteLength(result.stdout)+Buffer.byteLength(result.stderr)<=10*1024*1024);await until(()=>{try{process.kill(pid,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});}
 finally{ac.abort();await boundedDrain(running,proof);fs.rmSync(directory,{recursive:true});}
});

for (const mode of ["abort", "timeout"]) test('exited launcher cannot orphan an inherited-pipe child before '+mode, {timeout:testBudget}, async () => {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-orphan-")),receipt=path.join(directory,"ready.json"),ac=new AbortController();let proof;
  const descendant="process.on('SIGTERM',()=>{});process.send('ready');setInterval(()=>{},1000);";
  const launcher="const cp=require('child_process'),fs=require('fs');const child=cp.spawn(process.execPath,['-e',process.argv[1]],{stdio:['ignore','inherit','inherit','ipc']});child.once('message',()=>{fs.writeFileSync(process.argv[2],JSON.stringify({parent:process.pid,child:child.pid}));process.exit(0);});";
  const running=execWithoutShell(cp.execFile,[process.execPath,"-e",launcher,descendant,receipt],mode==="timeout"?(windows?commandBudget:4000):(windows?commandBudget:10000),{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},ac.signal);
  try {
    await until(()=>fs.existsSync(receipt));proof=JSON.parse(fs.readFileSync(receipt));
    await until(()=>{try{process.kill(proof.parent,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});
    if(mode==="abort")ac.abort();
    await running;
    await until(()=>{try{process.kill(proof.child,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});
  } finally {ac.abort();await boundedDrain(running,proof);fs.rmSync(directory,{recursive:true});}
});

test("native command preserves quoted and empty arguments", {timeout:testBudget}, async () => {
  const args=["", "café/测试", "space value", 'embedded"quote', "trailing space \\"];
  const result=await execWithoutShell(cp.execFile,[process.execPath,"-e","process.stdout.write(JSON.stringify(process.argv.slice(1)))",...args],commandBudget,{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot});
  assert.equal(result.exitCode,0);assert.deepEqual(JSON.parse(result.stdout),args);
});
