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
 const contract=require("../docs/certops/qualification-suites.json"),matrix=require("../docs/certops/qualification-suites.json");
 for(const suite of ["enterprise-adcs-real","enterprise-adcs-hierarchy-real"]){
  assert.ok(contract.suites[suite].includes("adcs-real-local-rule-empty-allowlist-refused"));
  for(const slot of matrix.slots.filter(row=>row.suite===suite))for(const file of helper.REQUIRED_SOURCES)assert.ok(slot.requiredSources.includes(file),file);
 }
});

function survivorProof(){return {"scope":"native-pending-key-policy-change-retrieval-install-and-survivor-protection","store":"WebHosting","recovery":"signed-retrieval-and-isolated-iis-installation","enrollmentId":"11111111-1111-1111-1111-111111111111","requestId":"17","continuationJobId":"22222222-2222-2222-2222-222222222222","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","csrSpkiSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","caRequestCounts":[7,7,7],"actualOwnedPendingRequest":true,"actualOwnedCaLeafSameCsrSpki":true,"exactWebHostingAssociationAndProtectedKey":true,"nativeSurvivorReferenceObserved":true,"signedRetrievalInstalled":true,"frozenEnrollmentIdentityPreserved":true,"originalKeyUsableAfterReconciliation":true,"installedKeyProtectedFromCleanup":true,"installedReferenceSurvivesSecondaryRemoval":true,"noAdditionalCaRequest":true,"exactPublicAssociationOnlyRemoved":true,"predecessorCustodyIisTlsPreserved":true,"configurationCredentialRestored":true,"ownedCaLeafRevoked":true,"ownershipGuardReleased":true};}
test("native pending-key survivor proof cannot skip guards, invent retries or lose public identity",()=>{
 assert.equal(helper.verifySurvivorProof(survivorProof()),true);
 for(const flag of helper.survivorFlags)for(const wrong of [false,1,null,"true"]){assert.throws(()=>helper.verifySurvivorProof({...survivorProof(),[flag]:wrong}));}
 for(const change of [{automaticRetryQualified:true},{schedulerDefaultClockQualified:true},{store:"My"},{recovery:"automatic-retry"},{caRequestCounts:[7,7,8]},{firstError:"ignored"},{requestId:"0"},{privateKey:"withheld"}])assert.throws(()=>helper.verifySurvivorProof({...survivorProof(),...change}));
});

test("pending policy proof requires actual retrieval, usable original key and an unchanged request count",()=>{
 const proof={enrollmentId:"11111111-1111-1111-1111-111111111111",continuationJobId:"22222222-2222-2222-2222-222222222222",requestId:"17",snapshotSha256:"a".repeat(64),caRequestCounts:[7,7],...Object.fromEntries(helper.tighteningFlags.map(flag=>[flag,true]))};
 assert.equal(helper.verifyTighteningProof(proof),true);
 for(const field of Object.keys(proof)){const missing={...proof};delete missing[field];assert.throws(()=>helper.verifyTighteningProof(missing));}
 for(const flag of helper.tighteningFlags)for(const value of [false,1,null,"true"])assert.throws(()=>helper.verifyTighteningProof({...proof,[flag]:value}));
 for(const patch of [{caRequestCounts:[7,8]},{requestId:"4294967296"},{actualSignedContinuationRefused:true},{exactUnacceptedKeyFreed:true}])assert.throws(()=>helper.verifyTighteningProof({...proof,...patch}));
});

test("old destructive pending proofs and missing installed-key protection cannot qualify",()=>{
 for(const patch of [{firstError:"Local policy refusal could not free the protected enrollment key; retry required"},{signedRetrievalInstalled:false},{originalKeyUsableAfterReconciliation:false},{installedKeyProtectedFromCleanup:false},{installedReferenceSurvivesSecondaryRemoval:false}])assert.throws(()=>helper.verifySurvivorProof({...survivorProof(),...patch}));
 const contract=require("../docs/certops/qualification-suites.json");for(const suite of ["enterprise-adcs-real","enterprise-adcs-hierarchy-real"]){assert.ok(contract.suites[suite].includes(helper.tighteningScenario));assert.ok(contract.suites[suite].includes(helper.survivorScenario));assert.ok(!contract.suites[suite].includes("adcs-real-local-rule-tightening-frees-pending-key"));assert.ok(!contract.suites[suite].includes("adcs-real-pending-key-survivor-protects-local-policy-cleanup"));}
});

test("survivor setup uses trigger-created management without readding an open source",async()=>{
 const certificateId="11111111-1111-4111-8111-111111111111",periodId="22222222-2222-4222-8222-222222222222",ownedCertificateIds=[],calls=[];
 const fixture={workspaceId:"workspace",pool:{query:async(sql,values)=>{
  calls.push(sql);
  if(sql.startsWith("INSERT")){assert.equal(values[0],"workspace");assert.equal(values[6],"agent");assert.match(sql,/'provisioning','agent_issuance'/);return {rows:[{id:certificateId}]};}
  assert.deepEqual(values,["workspace",certificateId]);assert.match(sql,/certops_is_initial_provisioning/);assert.match(sql,/ended_at IS NULL/);return {rows:[{id:periodId,eligible:true}]};
 }},request:async()=>{throw new Error("New source must not call readd");}};
 assert.equal(await helper.provisionSurvivorSource({fixture,agentRowId:"agent",domain:"owned.example.test",site:"owned",port:443,ownedCertificateIds}),certificateId);
 assert.equal(calls.length,2);assert.deepEqual(ownedCertificateIds,[certificateId]);
 fixture.pool.query=async(sql)=>({rows:sql.startsWith("INSERT")?[{id:certificateId}]:[{id:periodId,eligible:false}]});
 await assert.rejects(()=>helper.provisionSurvivorSource({fixture,agentRowId:"agent",domain:"owned.example.test",site:"owned",port:443,ownedCertificateIds:[]}),/eligible/);
});

test("survivor initial enrollment must be claimed by its installed agent for its managed source",()=>{
 const expected={certificateId:"certificate",agentRowId:"agent"};
 const job={subject_type:"managed_certificate",subject_id:"certificate",assigned_agent_id:"agent",claim_id:"claim",status:"awaiting_issuer"};
 helper.assertSurvivorInitialClaim(job,expected);
 for(const patch of [{claim_id:null},{subject_id:"other"},{assigned_agent_id:"other"},{status:"queued"},{subject_type:"other"}])assert.throws(()=>helper.assertSurvivorInitialClaim({...job,...patch},expected));
 assert.throws(()=>helper.assertSurvivorInitialClaim(undefined,expected));
});
