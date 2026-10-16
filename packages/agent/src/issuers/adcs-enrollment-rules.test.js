/**
 * Regression coverage: whole local enrollment rule applies dot-boundary DNS coverage to every SAN and key together.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const {normalizeRuleConstraints,matchWholeEnrollmentRule}=require("./adcs-enrollment-rules");
const pair={caConfig:"ca.example.com\\Example CA",template:"Web"};
const requested={authorizedDnsNames:["app.example.com","*.sub.example.com"],keyAlgorithm:"rsa"};
const permitted={...pair,dnsScopes:["example.com"],keyAlgorithms:["rsa"]};
test("whole local enrollment rule applies dot-boundary DNS coverage to every SAN and key together",()=>{
  assert.equal(matchWholeEnrollmentRule([permitted],pair.caConfig,pair.template,requested),permitted);
  for(const name of ["evilexample.com","example.com.evil.test","app.other.test","bad\n.example.com","*.bad_underscore.example.com"])
    assert.equal(matchWholeEnrollmentRule([permitted],pair.caConfig,pair.template,{...requested,authorizedDnsNames:["app.example.com",name]}),null);
  assert.equal(matchWholeEnrollmentRule([permitted],pair.caConfig,pair.template,{...requested,keyAlgorithm:"ecdsa"}),null);
  assert.equal(matchWholeEnrollmentRule([permitted],pair.caConfig,pair.template,{...requested,extraDnsNames:["outside.test"]}),null);
});
test("DNS and key permissions from different rules cannot form an unintended cross product",()=>{
  const rules=[{...permitted,keyAlgorithms:["ecdsa"]},{...permitted,dnsScopes:["outside.test"]}];
  assert.equal(matchWholeEnrollmentRule(rules,pair.caConfig,pair.template,requested),null);
  rules.push(permitted);assert.equal(matchWholeEnrollmentRule(rules,pair.caConfig,pair.template,requested),permitted);
});
test("pair-only rules remain readable for preflight but never authorize enrollment",()=>{
  assert.equal(matchWholeEnrollmentRule([pair],pair.caConfig,pair.template),pair);
  assert.equal(matchWholeEnrollmentRule([pair],pair.caConfig,pair.template,requested),null);
  for(const field of ["dnsScopes","keyAlgorithms"]){const rule={...permitted};delete rule[field];assert.equal(matchWholeEnrollmentRule([rule],pair.caConfig,pair.template,requested),null);}
});
test("malformed explicit constraints fail closed even for readonly native preflight",()=>{
  for(const fields of [{dnsScopes:null},{dnsScopes:[]},{dnsScopes:["*.example.com"]},{dnsScopes:["example.com;evil"]},{dnsScopes:["EXAMPLE.COM","example.com"]},{dnsScopes:Array(33).fill("example.com")},{keyAlgorithms:"rsa"},{keyAlgorithms:[]},{keyAlgorithms:["RSA"]},{keyAlgorithms:["rsa","rsa"]}]){
    const rule={...permitted,...fields};assert.throws(()=>normalizeRuleConstraints(rule));assert.equal(matchWholeEnrollmentRule([rule],pair.caConfig,pair.template),null);assert.equal(matchWholeEnrollmentRule([rule],pair.caConfig,pair.template,requested),null);
  }
  assert.deepEqual(normalizeRuleConstraints({...permitted,dnsScopes:["EXAMPLE.COM"]}),{dnsScopes:["example.com"],keyAlgorithms:["rsa"]});
});
