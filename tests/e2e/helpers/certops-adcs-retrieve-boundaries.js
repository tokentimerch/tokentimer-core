"use strict";
/* Native retrieval of real unknown/foreign request IDs under the installed identity, with no
 * accepted foreign certificate, new key or outgoing TLS change. Called only by the protected
 * disposable-forest AD CS harness; native qualification requires that workflow to execute.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {createAdcsIssuer,assertIssuanceOutcome,resolveAdcsCmcHelperPath,readEnrollmentJournal}=require("../../../packages/agent/src/issuers");
async function qualifyRetrieveBoundaries({gate,configDir,workDir,run,issuedFixtures,ps,command}){
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
  gate.report.fixtureSources??=[];for(const file of ["tests/e2e/helpers/certops-adcs-retrieve-boundaries.js","infra/certops-adcs/foreign-request.ps1"])gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../..",file))).digest("hex")});
  const original=issuedFixtures.find(value=>value.item.id==="rsa2048");assert.ok(original);
  const root=path.resolve(__dirname,"../../.."),directory=path.join(workDir,"retrieve-boundaries");fs.mkdirSync(directory);
  const journal=readEnrollmentJournal(configDir,original.enrollmentId);assert.equal(journal.kind,"valid");
  const assertUnchanged=()=>assert.deepEqual(readEnrollmentJournal(configDir,original.enrollmentId).journal,journal.journal);
  const ownershipToken=crypto.randomUUID();
  const foreignScript=path.join(root,"infra/certops-adcs/foreign-request.ps1");
  const foreign=(action,requestId)=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",foreignScript,"-Action",action,"-RunId",run,"-OwnershipToken",ownershipToken,...(requestId?["-RequestId",String(requestId)]:[])]));
  let foreignStarted=false,foreignId,primaryError;const failures=[];
  try{
    const caCertPath=path.join(directory,"public-ca.cer");fs.writeFileSync(caCertPath,Buffer.from(original.authority.certificateB64,"base64"));
    const helper=resolveAdcsCmcHelperPath();assert.equal(helper.error,undefined);
    const issuer=createAdcsIssuer({caConfig:"tt-ca.lab.certops.test\\TTQualificationRoot",template:original.item.template,caKeySha256:original.authority.keySha256,caCertPath,helperPath:helper.path,scratchDir:directory,jobId:`retrieve-${run}-${crypto.randomUUID()}`,enrollmentId:original.enrollmentId,timeoutMs:30000});
    const checkpoint=()=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-ca-checkpoint.ps1"),"-RunId",run]));
    await gate.scenario("adcs-real-native-retrieve-unknown-request-remains-uncertain",async()=>{
      const before=checkpoint();assert.ok(before.highestRequestId<4294967295,"Native CA head proves the chosen uint32 request ID does not exist");
      const outcome=assertIssuanceOutcome(await issuer.retrieve(4294967295));assert.equal(outcome.outcome,"uncertain");assert.equal(outcome.caHresult,"0x80094004");assert.equal(outcome.certificatePem,undefined);assert.deepEqual(checkpoint(),before);assertUnchanged();
      gate.report.nativeUnknownRetrieve={requestId:"4294967295",observedHighestRequestId:before.highestRequestId,nativeIdentity:"LocalSystem",outcome:"uncertain",caHresult:outcome.caHresult,noCertificateReturned:true,noCaRequestAllocated:true};
    },{evidenceLevel:"real-host",oracle:"actual SYSTEM certreq/CMC retrieval beyond independently measured native CA head returns numeric property-empty HRESULT with no certificate or CA mutation"});
    await gate.scenario("adcs-real-native-retrieve-foreign-requester-remains-uncertain",async()=>{
      const before=checkpoint();foreignStarted=true;const actual=foreign("create");foreignId=actual.requestId;assert.equal(actual.requester.toLowerCase(),"ttqual\\tt-lab-admin");assert.equal(actual.disposition,20);assert.ok(foreignId>before.highestRequestId);
      const publicLeaf=new crypto.X509Certificate(Buffer.from(actual.certificateB64,"base64"));assert.equal(publicLeaf.checkHost(`certops-adcs-${run}-foreign.example.test`),`certops-adcs-${run}-foreign.example.test`);assert.equal(publicLeaf.verify(new crypto.X509Certificate(Buffer.from(original.authority.certificateB64,"base64")).publicKey),true);
      const issued=checkpoint();assert.equal(issued.nativeTotalRequestCount,before.nativeTotalRequestCount+1);assert.equal(issued.nativeRequesterCount,before.nativeRequesterCount,"Officer request must not be counted as the SYSTEM machine requester");
      const outcome=assertIssuanceOutcome(await issuer.retrieve(foreignId));assert.equal(outcome.outcome,"uncertain");assert.equal(outcome.caHresult,"0x80070005");assert.equal(outcome.certificatePem,undefined);assert.deepEqual(checkpoint(),issued);assertUnchanged();
      const thumbprint=publicLeaf.fingerprint.replace(/:/g,"");assert.equal(ps(`$foundCertificates=@();foreach($store in @('My','WebHosting')){$storePath='Cert:\\LocalMachine\\'+$store;if(Test-Path -LiteralPath $storePath){$foundCertificates+=@(Get-ChildItem -LiteralPath $storePath|Where-Object Thumbprint -eq '${thumbprint}')}};$foundCertificates.Count`),"0");
      gate.report.nativeForeignRetrieve={requestId:String(foreignId),actualRequester:actual.requester,nativeIdentity:"LocalSystem",foreignCaSignedLeaf:true,outcome:"uncertain",caHresult:outcome.caHresult,noCertificateReturned:true,noAdditionalCaRequestAllocated:true};
    },{evidenceLevel:"real-host",oracle:"actual officer-authenticated nonexportable CSR submission creates a genuine different-requester CA row; original machine-identity native retrieval refuses access numerically without importing or returning its certificate"});
  }catch(error){primaryError=error;}
  finally{
    if(foreignStarted)try{const cleanup=foreign("revoke",foreignId);assert.ok(cleanup.revoked || (!foreignId&&cleanup.absent));}catch(error){failures.push(error);}
    try{assert.equal(path.dirname(directory),workDir);assert.ok(!fs.lstatSync(directory).isSymbolicLink());fs.rmSync(directory,{recursive:true});}catch(error){failures.push(error);}
  }
  if(failures.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...failures],"Native retrieve boundary fixture or owned cleanup failed");if(primaryError)throw primaryError;
}
module.exports={qualifyRetrieveBoundaries};
