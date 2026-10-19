"use strict";
// Run the exact guarded native absence probes in real PowerShell. A child Node
// process supplies netsh's native exit status without touching HTTP.sys.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
const source=require("../tests/e2e/helpers/certops-adcs-iis-locale").qualifyIisLocale.toString();
const probes=[...source.matchAll(/ps\(`(& netsh\.exe http show sslcert [^`]+)`\)/g)].map(match=>match[1].replace('${selector}',"ipport=127.0.0.1:443"));
assert.equal(probes.length,2,"Both pre-mutation and post-cleanup absence probes must be exercised");
for(const file of ["tests/e2e/helpers/certops-adcs-journal-phase-experiment.js","tests/e2e/helpers/certops-adcs-response-loss-experiment.js"]){
 const text=fs.readFileSync(path.join(__dirname,"..",file),"utf8");
 const found=[...text.matchAll(/ps\(`(Import-Module WebAdministration;if\(Test-Path[^`]+Foreign (?:fault|fixture) endpoint[^`]+)`\)/g)];assert.equal(found.length,1);
 probes.push(found[0][1].replace(/\$\{site\}/g,"TTOwnedFixture").replace(/\$\{domain\}/g,"owned.example.test").replace(/\$\{port\}/g,"443"));
}
const producer=fs.readFileSync(path.join(__dirname,"../tests/e2e/certops-adcs-real-e2e.test.js"),"utf8");
const parentProbe=producer.match(/ps\(`(\$output=& netsh\.exe http show sslcert [^`]+Owned native shadow remains[^`]+)`\)/)[1]
 .replace(/\$\{ownedBinding\.selector\}/g,"ipport=127.0.0.1:443")
 .replace(/\$\{ownedBinding\.appId\.toLowerCase\(\)\}/g,"{11111111-1111-4111-8111-111111111111}")
 .replace(/\$\{ownedBinding\.thumbprint\.toLowerCase\(\)\}/g,"a".repeat(40));
probes.push(parentProbe);
for(const [index,probe] of probes.entries())test(`IIS shadow absence probe ${index+1} accepts native absence and rejects an existing binding`,()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"iis-absence-")),shim=path.join(directory,"native-status.cjs");
 try{
  fs.writeFileSync(shim,"process.exit(Number(process.env.CERTOPS_TEST_NETSH_STATUS));\n");
  const run=(script,status)=>spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';function Import-Module {};function Test-Path { $false };Set-Alias netsh.exe $env:CERTOPS_TEST_NATIVE_NODE;${script}`],{encoding:"utf8",windowsHide:true,timeout:15000,env:{...process.env,NODE_OPTIONS:`--require ${JSON.stringify(shim)}`,CERTOPS_TEST_NATIVE_NODE:process.execPath,CERTOPS_TEST_NETSH_STATUS:String(status)}});
  const absent=run(probe,1);assert.ifError(absent.error);assert.equal(absent.status,0,absent.stderr);
  const present=run(probe,0);assert.ifError(present.error);assert.notEqual(present.status,0);assert.match(present.stderr,/Refusing existing concrete-IP shadow binding|Owned concrete-IP shadow remains|Foreign fault endpoint|Foreign fixture endpoint|Refusing foreign native shadow replacement/);
  // Reproduce the original native-status leak rather than asserting text alone.
  const original=run(probe.replace(/;exit 0$/,""),1);assert.ifError(original.error);assert.equal(original.status,1,"Unchecked expected native failure must reproduce the PowerShell exit leak");
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test("parent shadow cleanup deletes only exact owned binding and verifies absence",()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"iis-parent-cleanup-")),shim=path.join(directory,"native-shadow.cjs"),state=path.join(directory,"state.json");
 try{
  fs.writeFileSync(shim,`const fs=require("node:fs"),file=process.env.CERTOPS_TEST_SHADOW_STATE,s=JSON.parse(fs.readFileSync(file));s.calls++;fs.writeFileSync(file,JSON.stringify(s));if(s.calls===1){console.log((s.mode==="foreign"?"{foreign}":"{11111111-1111-4111-8111-111111111111}")+" "+"a".repeat(40));process.exit(0)}if(s.calls===2)process.exit(s.mode==="delete-fails"?5:0);process.exit(s.mode==="still-present"?0:1);`);
  for(const mode of ["owned","foreign","delete-fails","still-present"]){
   fs.writeFileSync(state,JSON.stringify({mode,calls:0}));
   const result=spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';Set-Alias netsh.exe $env:CERTOPS_TEST_NATIVE_NODE;${parentProbe}`],{encoding:"utf8",windowsHide:true,timeout:15000,env:{...process.env,NODE_OPTIONS:`--require ${JSON.stringify(shim)}`,CERTOPS_TEST_NATIVE_NODE:process.execPath,CERTOPS_TEST_SHADOW_STATE:state}});
   assert.ifError(result.error);assert.equal(result.status===0,mode==="owned",result.stderr);
   assert.equal(JSON.parse(fs.readFileSync(state)).calls,mode==="foreign"?1:mode==="delete-fails"?2:3);
  }
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
