/**
 * Regression coverage: AD CS validation deadline retains its default actual 24-hour window.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {newValidationDeadline,validateValidationTimeoutSeconds}=require("./adcs-validation-deadline");
test("AD CS validation deadline retains its default actual 24-hour window",()=>{
  const before=Date.now(),deadline=Date.parse(newValidationDeadline({}));
  assert.ok(deadline>=before+86400000&&deadline<=Date.now()+86400000);
});
test("AD CS operator can shorten the actual validation deadline to five minutes",()=>{
  const before=Date.now(),deadline=Date.parse(newValidationDeadline({adcsValidationTimeoutSeconds:300}));
  assert.ok(deadline>=before+300000&&deadline<=Date.now()+300000);
});
test("AD CS validation timeout cannot be disabled coerced or extended beyond 24 hours",()=>{
  for(const value of [null,0,299,86401,"300",300.1,Infinity,NaN]){assert.throws(()=>validateValidationTimeoutSeconds(value),/300 to 86400/);assert.throws(()=>newValidationDeadline({adcsValidationTimeoutSeconds:value}),/300 to 86400/);}
  assert.equal(validateValidationTimeoutSeconds(86400),86400);
});
test("real config loader and execution context carry the local deadline without enrollment rules",()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),"adcs-deadline-config-"));
  const {loadAgentConfig,ensureConfigDir}=require("../config");
  const {buildExecutionContext}=require("../index");
  const previous=process.env.TOKENTIMER_AGENT_SERVER_URL;delete process.env.TOKENTIMER_AGENT_SERVER_URL;
  try{
    ensureConfigDir(directory);
    const write=adcs=>fs.writeFileSync(path.join(directory,"config.json"),JSON.stringify({serverUrl:"https://control.example.test",adcs}));
    write({validationTimeoutSeconds:300});const loaded=loadAgentConfig({configDir:directory});assert.equal(loaded.adcs.validationTimeoutSeconds,300);assert.deepEqual(loaded.adcs.enrollmentRules,[]);
    const context=buildExecutionContext({config:{...loaded,execution:{enabled:true,dryRun:true,keysDir:path.join(directory,"keys"),replayStorePath:path.join(directory,"replay.json"),outboxDir:path.join(directory,"outbox"),clockDriftToleranceMs:30000}}});
    const before=Date.now(),deadline=Date.parse(newValidationDeadline(context));assert.ok(deadline>=before+300000&&deadline<=Date.now()+300000);
    for(const invalid of [null,"300",299,86401]){write({validationTimeoutSeconds:invalid});assert.throws(()=>loadAgentConfig({configDir:directory}),/300 to 86400/);}
  }finally{if(previous===undefined)delete process.env.TOKENTIMER_AGENT_SERVER_URL;else process.env.TOKENTIMER_AGENT_SERVER_URL=previous;fs.rmSync(directory,{recursive:true,force:true});}
});
