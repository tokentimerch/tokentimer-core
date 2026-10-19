/**
 * Regression coverage for the production ACME runner's output bounds and owned-tree abort.
 * Native child-process cases measure real termination; platform-specific cases keep
 * their declared prerequisites. These checks do not stand in for the full ACME journey. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),cp=require("node:child_process");
const {execWithoutShell}=require("./command");
const {buildMinimalSubprocessEnv}=require("../exec-env");
// Exercise the shipped allowlist, including Windows profile/temp variables.
// Omitting them creates a different host than the production ACME adapter.
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

test("native command uses the production environment without inherited agent secrets",{timeout:testBudget},async()=>{
 const env=buildMinimalSubprocessEnv({...process.env,TOKENTIMER_AGENT_BOOTSTRAP_TOKEN:"private-bootstrap-needle",UNRELATED_SECRET:"private-unrelated-needle"});
 const script="process.stdout.write(JSON.stringify({bootstrap:process.env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN||null,unrelated:process.env.UNRELATED_SECRET||null,profile:process.env.USERPROFILE||null,temp:process.env.TEMP||null}))";
 const result=await execWithoutShell(cp.execFile,[process.execPath,"-e",script],commandBudget,env);
 assert.equal(result.exitCode,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),{bootstrap:null,unrelated:null,profile:env.USERPROFILE||null,temp:env.TEMP||null});assert.doesNotMatch(result.stdout+result.stderr,/private-bootstrap-needle|private-unrelated-needle/);
});
test("real ACME command cancellation terminates its owned child process tree",{timeout:testBudget},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-abort-")),receipt=path.join(directory,"processes.json"),ac=new AbortController();let proof;
 const script="const cp=require('child_process'),fs=require('fs');const child=cp.spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[1],JSON.stringify({parent:process.pid,child:child.pid}));setInterval(()=>{},1000);";
 const running=execWithoutShell(cp.execFile,[process.execPath,"-e",script,receipt],windows?commandBudget:10000,buildMinimalSubprocessEnv(),ac.signal);
 try{await until(()=>fs.existsSync(receipt));proof=JSON.parse(fs.readFileSync(receipt));process.kill(proof.parent,0);process.kill(proof.child,0);ac.abort(new Error("Real qualification lease loss"));const result=await running;assert.ok(result.execError);for(const pid of [proof.parent,proof.child])await until(()=>{try{process.kill(pid,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});}
 finally{ac.abort();await boundedDrain(running,proof);fs.rmSync(directory,{recursive:true});}
});

for(const mode of ["abort","timeout"])test(`owned command ${mode} drains a leader that exits before its TERM-resistant child holding stdout`,{timeout:testBudget},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-drain-")),receipt=path.join(directory,"ready.json"),ac=new AbortController();let proof;
 const stubborn="process.on('SIGTERM',()=>{});require('fs').writeFileSync(process.argv[1],JSON.stringify({parent:process.ppid,child:process.pid}));setInterval(()=>{},1000);";
 const leader="process.on('SIGTERM',()=>process.exit(0));require('child_process').spawn(process.execPath,['-e',process.argv[1],process.argv[2]],{stdio:['ignore','inherit','inherit']});setInterval(()=>{},1000);";
 const began=Date.now(),running=execWithoutShell(cp.execFile,[process.execPath,"-e",leader,stubborn,receipt],mode==="timeout"?(windows?commandBudget:1200):(windows?commandBudget:10000),buildMinimalSubprocessEnv(),ac.signal);
 try{await until(()=>fs.existsSync(receipt));proof=JSON.parse(fs.readFileSync(receipt));if(mode==="abort")ac.abort();const result=await running;assert.ok(result.execError,"Cancellation or timeout cannot become success when the leader exits zero");assert.match(result.execError.message,mode==="timeout"?/timed out/:/cancelled/);assert.ok(Date.now()-began<(windows?35000:7000),"Whole tree drain must remain bounded");for(const pid of [proof.parent,proof.child])await until(()=>{try{process.kill(pid,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});}
 finally{ac.abort();await running;fs.rmSync(directory,{recursive:true});}
});

for(const code of [0,17])test(`native command preserves bounded stdout stderr and actual exit ${code}`,{timeout:testBudget},async()=>{
 const result=await execWithoutShell(cp.execFile,[process.execPath,"-e",`process.stdout.write('public-output');process.stderr.write('public-diagnostic');process.exitCode=${code};`],commandBudget,buildMinimalSubprocessEnv());assert.equal(result.exitCode,code,`Native fixture failed: ${result.execError?.message}; ${result.stderr}`);assert.equal(String(result.stdout),"public-output");assert.equal(String(result.stderr),"public-diagnostic");assert.equal(Boolean(result.execError),code!==0);
});
test("native excessive-output command fails bounded and terminates its actual process",{timeout:testBudget},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-output-")),receipt=path.join(directory,"pid"),ac=new AbortController();let proof;
 const script="require('fs').writeFileSync(process.argv[1],String(process.pid));const chunk=Buffer.alloc(65536,65);setInterval(()=>{for(let i=0;i<8;i++)process.stdout.write(chunk);},1);";
 const running=execWithoutShell(cp.execFile,[process.execPath,"-e",script,receipt],commandBudget,buildMinimalSubprocessEnv(),ac.signal);
 try{await until(()=>fs.existsSync(receipt));const pid=Number(fs.readFileSync(receipt,"utf8"));proof={parent:pid,child:pid};const result=await running;assert.ok(result.execError);assert.match(result.execError.message,/output exceeded its bound/);assert.ok(Buffer.byteLength(result.stdout)+Buffer.byteLength(result.stderr)<=10*1024*1024);await until(()=>{try{process.kill(pid,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});}
 finally{ac.abort();await boundedDrain(running,proof);fs.rmSync(directory,{recursive:true});}
});

for (const mode of ["abort", "timeout"]) test('exited launcher cannot orphan an inherited-pipe child before '+mode, {timeout:testBudget}, async () => {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-orphan-")),receipt=path.join(directory,"ready.json"),ac=new AbortController();let proof;
  const descendant="process.on('SIGTERM',()=>{});process.send('ready');setInterval(()=>{},1000);";
  const launcher="const cp=require('child_process'),fs=require('fs');const child=cp.spawn(process.execPath,['-e',process.argv[1]],{stdio:['ignore','inherit','inherit','ipc']});child.once('message',()=>{fs.writeFileSync(process.argv[2],JSON.stringify({parent:process.pid,child:child.pid}));process.exit(0);});";
  const running=execWithoutShell(cp.execFile,[process.execPath,"-e",launcher,descendant,receipt],mode==="timeout"?(windows?commandBudget:4000):(windows?commandBudget:10000),buildMinimalSubprocessEnv(),ac.signal);
  try {
    await until(()=>fs.existsSync(receipt));proof=JSON.parse(fs.readFileSync(receipt));
    await until(()=>{try{process.kill(proof.parent,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});
    if(mode==="abort")ac.abort();
    await running;
    await until(()=>{try{process.kill(proof.child,0);return false;}catch(error){if(error.code==="ESRCH")return true;throw error;}});
  } finally {ac.abort();await boundedDrain(running,proof);fs.rmSync(directory,{recursive:true});}
});

test("native command preserves quoted and empty arguments", {timeout:testBudget}, async () => {
  if (windows) {
    const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-acme-handles-")),driver=path.join(directory,"noninheritable.ps1"),noAutoload=path.join(directory,"no-autoload.ps1"),probe=path.join(directory,"bootstrap.ps1"),receipt=path.join(directory,"stage.txt");
    // Correct startup must not depend on discovering every installed host module.
    fs.writeFileSync(noAutoload,"$PSModuleAutoLoadingPreference='None'\n& $env:CERTOPS_COMMAND_WRAPPER\nexit $LASTEXITCODE\n");
    // A test-only copy records fixed startup phases without mixing diagnostics
    // into client output or changing the production wrapper's inputs.
    let source=fs.readFileSync(path.join(__dirname,"windows-command.ps1"),"utf8").replace(/^([ \t]*\$stage='([a-z-]+)')\r?$/gm,(_line,assignment,stage)=>assignment+`\n  [IO.File]::WriteAllText($env:CERTOPS_STARTUP_RECEIPT,'${stage}')`);
    for(const [anchor,stage] of [["IntPtr job=CreateJobObject","create-job"],["Check(CreateProcess(","create-process"],["Check(AssignProcessToJobObject(","assign-job"],["Check(ResumeThread(","resume-client"],["Check(WaitForSingleObject(","wait-client"]]) {
      assert.ok(source.includes(anchor),`Native startup probe anchor missing: ${anchor}`);
      source=source.replace(anchor,`System.IO.File.WriteAllText(Environment.GetEnvironmentVariable("CERTOPS_STARTUP_RECEIPT"),"${stage}"); ${anchor}`);
    }
    fs.writeFileSync(probe,source);
    function startupPhase(){try{const value=fs.readFileSync(receipt,"utf8");return ["read-request","load-utility","parse-request","compile-owner","execute-client","create-job","create-process","assign-job","resume-client","wait-client"].includes(value)?value:"unknown";}catch{return "script-not-started";}}
    // Model service hosts that do not mark their redirected handles inheritable.
    // Compile the production owner first so this isolates CreateProcess handle
    // inheritance from the separate CodeDOM compiler process.
    fs.writeFileSync(driver,`$ErrorActionPreference='Stop'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HandleFixture {
 [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int kind);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
}
'@
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CERTOPS_COMMAND_WRAPPER,[ref]$null,[ref]$null)
$compile=$ast.Find({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type'},$true)
. ([scriptblock]::Create($compile.Extent.Text))
foreach($kind in @(-10,-11,-12)) {
 if(-not [HandleFixture]::SetHandleInformation([HandleFixture]::GetStdHandle($kind),1,0)){throw 'Could not set fixture handle inheritance'}
}
& $env:CERTOPS_COMMAND_WRAPPER
exit $LASTEXITCODE
`);
    try { for(const script of [probe,noAutoload,driver]) {
    fs.rmSync(receipt,{force:true});
    // Keep stdin open after a complete frame. A ReadToEnd wrapper deadlocks here.
    await new Promise((resolve,reject)=>{
      const wrapper=cp.spawn(path.join(process.env.SystemRoot,"System32/WindowsPowerShell/v1.0/powershell.exe"),
        ["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",script],
        {windowsHide:true,env:{...buildMinimalSubprocessEnv(),CERTOPS_COMMAND_WRAPPER:path.join(__dirname,"windows-command.ps1"),CERTOPS_STARTUP_RECEIPT:receipt},stdio:["pipe","pipe","pipe"]});
      let output="",diagnostic="";
      const timer=setTimeout(()=>{const phase=startupPhase();cp.spawnSync("taskkill.exe",["/PID",String(wrapper.pid),"/T","/F"],{windowsHide:true,stdio:"ignore",timeout:5000});wrapper.kill();reject(new Error(`Windows wrapper did not finish the framed request (phase ${phase})`));},commandBudget);
      wrapper.stdout.on("data",chunk=>{output+=chunk;});wrapper.stderr.on("data",chunk=>{diagnostic+=chunk;});
      wrapper.stdin.on("error",()=>{});
      wrapper.once("error",error=>{clearTimeout(timer);reject(error);});
      wrapper.once("close",code=>{clearTimeout(timer);wrapper.stdin.destroy();try{assert.equal(code,0,diagnostic);assert.equal(output,"framed");resolve();}catch(error){reject(error);}});
      wrapper.stdin.write(JSON.stringify({executable:process.execPath,arguments:["-e","process.stdout.write('framed')"]})+"\n");
    });
    }
    const refused=await execWithoutShell(cp.execFile,[path.join(directory,"missing-client.exe"),"private-argument-needle"],commandBudget,buildMinimalSubprocessEnv());
    assert.ok(refused.execError);assert.match(refused.stderr,/failed at execute-client \(code [0-9]+\)/);assert.doesNotMatch(refused.stderr,/private-argument-needle|missing-client/);
    } finally {fs.rmSync(directory,{recursive:true,force:true});}
  }
  const args=["", "café/测试", "space value", 'embedded"quote', "trailing space \\"];
  const result=await execWithoutShell(cp.execFile,[process.execPath,"-e","process.stdout.write(JSON.stringify(process.argv.slice(1)))",...args],commandBudget,buildMinimalSubprocessEnv());
  assert.equal(result.exitCode,0);assert.deepEqual(JSON.parse(result.stdout),args);
});
