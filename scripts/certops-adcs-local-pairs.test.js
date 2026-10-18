"use strict";
/** Offline exact-pair/proof checks. Native installed-agent refusal remains host gated. */
const {test}=require("node:test"),assert=require("node:assert/strict");
const helper=require("../tests/e2e/helpers/certops-adcs-local-rules");
const {matchWholeEnrollmentRule}=require("../packages/agent/src/issuers/adcs-enrollment-rules");
const allowed={caConfig:"tt-ca.lab.certops.test\\TTQualificationRoot",template:"TTQualificationRSAShort",dnsScopes:["owned.example.test"],keyAlgorithms:["rsa"]};
const request={authorizedDnsNames:["owned.example.test"],extraDnsNames:[],keyAlgorithm:"rsa"};
test("each native pair fixture changes exactly its intended CA or template dimension",()=>{
 assert.ok(matchWholeEnrollmentRule([allowed],allowed.caConfig,allowed.template,request));
 for(const name of helper.pairCases.filter(name=>name!=="empty-allowlist")){const rules=helper.pairRules(name,allowed);assert.equal(rules.length,1);assert.equal(matchWholeEnrollmentRule(rules,allowed.caConfig,allowed.template,request),null);assert.deepEqual(rules[0].dnsScopes,allowed.dnsScopes);assert.deepEqual(rules[0].keyAlgorithms,allowed.keyAlgorithms);
 const [host,authority]=rules[0].caConfig.split("\\"),[originalHost,originalAuthority]=allowed.caConfig.split("\\");
 assert.equal(host===originalHost,name!=="ca-host-mismatch");assert.equal(authority===originalAuthority,name!=="ca-authority-mismatch");assert.equal(rules[0].template===allowed.template,name!=="template-pair-mismatch");}
});
test("pair proof needs exactly every native allowlist boundary and every custody/restoration fact",()=>{
 const proof=helper.pairCases.map(caseId=>({caseId,...Object.fromEntries(helper.pairFlags.map(field=>[field,true]))}));assert.equal(helper.verifyPairProof(proof),true);
 for(const field of helper.pairFlags)for(const invalid of [false,1,null,"true"]){const changed=structuredClone(proof);changed[0][field]=invalid;assert.throws(()=>helper.verifyPairProof(changed));}
 for(const field of helper.pairFlags){const changed=structuredClone(proof);delete changed[0][field];assert.throws(()=>helper.verifyPairProof(changed));}
 for(const changed of [proof.slice(1),[proof[0],proof[0],proof[2]],proof.map(row=>({...row,rawNativeKey:"private"}))])assert.throws(()=>helper.verifyPairProof(changed));
});

test("empty local allowlist refuses the previously permitted pair and cannot be omitted from native proof",()=>{
 assert.deepEqual(helper.pairRules("empty-allowlist",allowed),[]);
 assert.equal(matchWholeEnrollmentRule([],allowed.caConfig,allowed.template,request),null);
 const proof=helper.pairCases.map(caseId=>({caseId,...Object.fromEntries(helper.pairFlags.map(field=>[field,true]))}));
 assert.throws(()=>helper.verifyPairProof(proof.filter(row=>row.caseId!=="empty-allowlist")));
 const contract=require("../docs/certops/qualification-suites.json"),matrix=require("../docs/certops/release-qualification-matrix.json");
 for(const suite of ["enterprise-adcs-real","enterprise-adcs-hierarchy-real"]){
  assert.ok(contract.suites[suite].includes("adcs-real-local-rule-empty-allowlist-refused"));
  for(const slot of matrix.slots.filter(row=>row.suite===suite))for(const file of helper.REQUIRED_SOURCES)assert.ok(slot.requiredSources.includes(file),file);
 }
});

function survivorProof(){return {"scope":"native-pending-key-policy-refusal-then-public-cancellation","store":"WebHosting","recovery":"public-cancel-then-terminal-cleanup","firstError":"Local policy refusal could not free the protected enrollment key; retry required","enrollmentId":"11111111-1111-1111-1111-111111111111","requestId":"17","failedJobId":"22222222-2222-2222-2222-222222222222","cleanupJobId":"33333333-3333-3333-3333-333333333333","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","csrSpkiSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","caRequestCounts":[7,7,7],"automaticRetryQualified":false,"schedulerDefaultClockQualified":false,"actualOwnedPendingRequest":true,"actualOwnedCaLeafSameCsrSpki":true,"exactWebHostingAssociationAndProtectedKey":true,"nativeSurvivorReferenceObserved":true,"signedCleanupRefusedWhileReferenced":true,"pendingJournalAndKeyPreserved":true,"noAdditionalCaRequest":true,"exactPublicAssociationOnlyRemoved":true,"publicCancellationAcknowledged":true,"signedTerminalCleanupCompleted":true,"predecessorCustodyIisTlsPreserved":true,"configurationCredentialRestored":true,"ownedCaLeafRevoked":true,"ownershipGuardReleased":true};}
test("native pending-key survivor proof cannot skip guards, invent retries or lose public identity",()=>{
 assert.equal(helper.verifySurvivorProof(survivorProof()),true);
 for(const flag of helper.survivorFlags)for(const wrong of [false,1,null,"true"]){assert.throws(()=>helper.verifySurvivorProof({...survivorProof(),[flag]:wrong}));}
 for(const change of [{automaticRetryQualified:true},{schedulerDefaultClockQualified:true},{store:"My"},{recovery:"automatic-retry"},{caRequestCounts:[7,7,8]},{firstError:"ignored"},{requestId:"0"},{privateKey:"withheld"}])assert.throws(()=>helper.verifySurvivorProof({...survivorProof(),...change}));
});
