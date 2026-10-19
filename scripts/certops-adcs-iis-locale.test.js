"use strict";
// Run the exact two native absence probes in real PowerShell. A child Node
// process supplies netsh's native exit status without touching HTTP.sys.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
const source=require("../tests/e2e/helpers/certops-adcs-iis-locale").qualifyIisLocale.toString();
const probes=[...source.matchAll(/ps\(`(& netsh\.exe http show sslcert [^`]+)`\)/g)].map(match=>match[1].replace('${selector}',"ipport=127.0.0.1:443"));
assert.equal(probes.length,2,"Both pre-mutation and post-cleanup absence probes must be exercised");
for(const [index,probe] of probes.entries())test(`IIS shadow absence probe ${index+1} accepts native absence and rejects an existing binding`,()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"iis-absence-")),shim=path.join(directory,"native-status.cjs");
 try{
  fs.writeFileSync(shim,"process.exit(Number(process.env.CERTOPS_TEST_NETSH_STATUS));\n");
  const run=(script,status)=>spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';Set-Alias netsh.exe $env:CERTOPS_TEST_NATIVE_NODE;${script}`],{encoding:"utf8",windowsHide:true,timeout:15000,env:{...process.env,NODE_OPTIONS:`--require ${JSON.stringify(shim)}`,CERTOPS_TEST_NATIVE_NODE:process.execPath,CERTOPS_TEST_NETSH_STATUS:String(status)}});
  const absent=run(probe,1);assert.ifError(absent.error);assert.equal(absent.status,0,absent.stderr);
  const present=run(probe,0);assert.ifError(present.error);assert.notEqual(present.status,0);assert.match(present.stderr,/Refusing existing concrete-IP shadow binding|Owned concrete-IP shadow remains/);
  // Reproduce the original native-status leak rather than asserting text alone.
  const original=run(probe.replace(/;exit 0$/,""),1);assert.ifError(original.error);assert.equal(original.status,1,"Unchecked expected native failure must reproduce the PowerShell exit leak");
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
