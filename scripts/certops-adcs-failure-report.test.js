"use strict";
// Exercise the producer's real sanitizer and command boundary with adversarial
// subprocess output; no Windows host or certificate operation is simulated as qualified.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
function producer(result){
  const source=fs.readFileSync(path.resolve(__dirname,"../tests/e2e/certops-adcs-real-e2e.test.js"),"utf8");
  const start=source.indexOf("function nativeCommandEnvironment("),end=source.indexOf("function ps(script)",start);
  return vm.runInNewContext(source.slice(start,end)+";({command,boundedFailureMetadata,boundedJobErrorCode})",{path,spawnSync:()=>result,process:{env:{}}});
}
const plain=value=>JSON.parse(JSON.stringify(value));
test("native failure retains only approved executable, exit and PowerShell category",()=>{
  const api=producer({status:1,stdout:"PRIVATE_KEY_AND_TOKEN",stderr:`private argument
 FullyQualifiedErrorId : NamedParameterNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand
secret`});
  let failure;try{api.command("C:/Windows/System32/powershell.exe",["-Command","SECRET_BOOTSTRAP_TOKEN"]);}catch(error){failure=error;}
  const report={scenarios:[{id:"adcs-real-rsa2048-issued-cng-iis",status:"failed"}]};
  const bounded=plain(api.boundedFailureMetadata(failure,report));
  assert.equal(bounded.errorCode,"CERTOPS_NATIVE_COMMAND_FAILED");
  assert.deepEqual(bounded.command,{executable:"powershell.exe",exitStatus:1,powerShellCode:"NamedParameterNotFound"});
  assert.equal(bounded.scenario,report.scenarios[0].id);
  assert.doesNotMatch(JSON.stringify(bounded)+String(failure),/PRIVATE_KEY|TOKEN|private argument|secret|Windows/i);
});
test("untrusted error fields and arbitrary FQID strings never enter reports",()=>{
  const api=producer({status:null,error:{message:"SECRET",path:"SECRET",spawnargs:["SECRET"]},stderr:"FullyQualifiedErrorId : SECRET_TOKEN"});
  let failure;try{api.command("SECRET.exe",["SECRET"]);}catch(error){failure=error;}
  const bounded=plain(api.boundedFailureMetadata(failure,{scenarios:[]}));
  assert.deepEqual(bounded.command,{executable:"other",exitStatus:null});assert.doesNotMatch(JSON.stringify(bounded),/SECRET/);
  const supplied={constructor:{name:"SECRET"},code:"SECRET",message:"SECRET",stack:"SECRET",qualificationCommand:{executable:"SECRET",exitStatus:"SECRET",powerShellCode:"SECRET"}};
  assert.deepEqual(plain(api.boundedFailureMetadata(supplied,{})),{errorClass:"Error",command:{executable:"other",exitStatus:null}});
});
test("helper assertion location keeps only the repository file name and line",()=>{
  const api=producer({status:0,stdout:"ok"});
  const stack="AssertionError: SECRET\n at verifyDecision (C:/private/SECRET/tests/e2e/helpers/certops-adcs-browser-job-approval.js:118:12)\n at C:/private/SECRET/tests/e2e/certops-adcs-real-e2e.test.js:303:41";
  const bounded=plain(api.boundedFailureMetadata({constructor:{name:"AssertionError"},message:"SECRET",stack},{scenarios:[]}));
  assert.equal(bounded.helperFrame,"certops-adcs-browser-job-approval.js:118");assert.equal(bounded.sourceLine,303);
  assert.doesNotMatch(JSON.stringify(bounded),/SECRET|private/);
  const outside=plain(api.boundedFailureMetadata({constructor:{name:"Error"},stack:"Error\n at C:/x/tests/e2e/helpers/../../evil.js:9:1"},{scenarios:[]}));
  assert.equal(outside.helperFrame,undefined);
});
test("cleanup failure metadata preserves the original failure separately and strips stack paths",()=>{
  const api=producer({status:0,stdout:"ok"});
  const report={scenarios:[{id:"adcs-real-rsa2048-issued-cng-iis",status:"failed"}]};
  report.originalFailure=api.boundedFailureMetadata({constructor:{name:"Error"},code:"ADCS_CERTIFICATE_INVALID",stack:"Error SECRET\n at C:/private/SECRET/tests/e2e/certops-adcs-real-e2e.test.js:227:17"},report);
  report.cleanupFailure=api.boundedFailureMetadata({constructor:{name:"AssertionError"},message:"SECRET"},report,"cleanup");
  assert.equal(report.originalFailure.errorCode,"ADCS_CERTIFICATE_INVALID");assert.equal(report.originalFailure.sourceLine,227);
  assert.equal(report.cleanupFailure.scenario,"adcs-real-owned-cleanup");assert.equal(report.cleanupFailure.errorClass,"AssertionError");
  assert.doesNotMatch(JSON.stringify(report),/SECRET|private|stack/);
});

test("aggregate cleanup exposes bounded sanitized command causes without recursive payloads",()=>{
  const api=producer({status:1,stderr:"FullyQualifiedErrorId : PathNotFound"});let native;
  try{api.command("powershell.exe",["SECRET"]);}catch(error){native=error;}
  const nested={constructor:{name:"AggregateError"},message:"SECRET",errors:[native]};
  const metadata=plain(api.boundedFailureMetadata({constructor:{name:"AggregateError"},errors:[native,nested,native,native,native]},null,"cleanup"));
  assert.equal(metadata.causes.length,4);assert.equal(metadata.causes[0].command.powerShellCode,"PathNotFound");
  assert.equal(metadata.causes[1].causes,undefined);assert.doesNotMatch(JSON.stringify(metadata),/SECRET|stderr|argv/);
});

test("enrollment error takes priority over generic agent failure without exposing result payload",()=>{
  const api=producer({status:0,stdout:"ok"});
  assert.equal(api.boundedJobErrorCode({enrollment_error_code:"ADCS_CERTIFICATE_INVALID",error_code:"AGENT_RESULT_FAILED"}),"ADCS_CERTIFICATE_INVALID");
  assert.equal(api.boundedJobErrorCode({enrollment_error_code:"SECRET",error_code:"CERTOPS_NATIVE_COMMAND_FAILED"}),"CERTOPS_NATIVE_COMMAND_FAILED");
  assert.equal(api.boundedJobErrorCode({enrollment_error_code:{token:"SECRET"},error_code:"AGENT_RESULT_FAILED"}),undefined);
  const bounded=api.boundedFailureMetadata({code:api.boundedJobErrorCode({enrollment_error_code:"ADCS_CERTIFICATE_INVALID",error_code:"AGENT_RESULT_FAILED"})},{});
  assert.equal(bounded.errorCode,"ADCS_CERTIFICATE_INVALID");assert.doesNotMatch(JSON.stringify(bounded),/SECRET|AGENT_RESULT_FAILED|result_metadata/);
});
