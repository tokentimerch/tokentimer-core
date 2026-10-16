"use strict";
/** Offline exact-pair/proof checks. Native installed-agent refusal remains host gated. */
const {test}=require("node:test"),assert=require("node:assert/strict");
const helper=require("../tests/e2e/helpers/certops-adcs-local-rules");
const {matchWholeEnrollmentRule}=require("../packages/agent/src/issuers/adcs-enrollment-rules");
const allowed={caConfig:"tt-ca.lab.certops.test\\TTQualificationRoot",template:"TTQualificationRSAShort",dnsScopes:["owned.example.test"],keyAlgorithms:["rsa"]};
const request={authorizedDnsNames:["owned.example.test"],extraDnsNames:[],keyAlgorithm:"rsa"};
test("each native pair fixture changes exactly its intended CA or template dimension",()=>{
 assert.ok(matchWholeEnrollmentRule([allowed],allowed.caConfig,allowed.template,request));
 for(const name of helper.pairCases){const rules=helper.pairRules(name,allowed);assert.equal(rules.length,1);assert.equal(matchWholeEnrollmentRule(rules,allowed.caConfig,allowed.template,request),null);assert.deepEqual(rules[0].dnsScopes,allowed.dnsScopes);assert.deepEqual(rules[0].keyAlgorithms,allowed.keyAlgorithms);
 const [host,authority]=rules[0].caConfig.split("\\"),[originalHost,originalAuthority]=allowed.caConfig.split("\\");
 assert.equal(host===originalHost,name!=="ca-host-mismatch");assert.equal(authority===originalAuthority,name!=="ca-authority-mismatch");assert.equal(rules[0].template===allowed.template,name!=="template-pair-mismatch");}
});
test("pair proof needs exactly all three native cases and every custody/restoration fact",()=>{
 const proof=helper.pairCases.map(caseId=>({caseId,...Object.fromEntries(helper.pairFlags.map(field=>[field,true]))}));assert.equal(helper.verifyPairProof(proof),true);
 for(const field of helper.pairFlags)for(const invalid of [false,1,null,"true"]){const changed=structuredClone(proof);changed[0][field]=invalid;assert.throws(()=>helper.verifyPairProof(changed));}
 for(const field of helper.pairFlags){const changed=structuredClone(proof);delete changed[0][field];assert.throws(()=>helper.verifyPairProof(changed));}
 for(const changed of [proof.slice(1),[proof[0],proof[0],proof[2]],proof.map(row=>({...row,rawNativeKey:"private"}))])assert.throws(()=>helper.verifyPairProof(changed));
});
