"use strict";
/** Supporting contract checks only: never installs a service or starts PG. */
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path");
const h=require("./certops-arm64-installed-proof"),lock=require("./certops-arm64-postgres-lock.json");
function proof(){return{scope:h.SCOPE,architecture:"arm64",productType:1,build:"26200",certificateDryRunTarget:"file-path",postgresArchitecture:"x64",postgresExecution:"windows11-x64-emulation",postgresVersion:lock.version,postgresArchiveSha256:lock.sha256,candidateArchiveSha256:"a".repeat(64),hostSha256:"b".repeat(64),certificateFingerprint:"c".repeat(64),jobIds:["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"],claimIds:["33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"],agentRowId:"55555555-5555-5555-5555-555555555555",issuanceQualified:false,iisQualified:false,serverQualified:false,publicCertificateAdmissionQualified:false,serviceCreatedDryRun:true,...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};}
test("installed ARM64 proof distinguishes native agent, emulated PG, certificate plan and discovery",()=>{
 assert.equal(h.verifyProof(proof()),true);
 for(const key of Object.keys(proof())){const missing=proof();delete missing[key];assert.throws(()=>h.verifyProof(missing),key);const invalid=proof();invalid[key]=typeof invalid[key]==="boolean"?!invalid[key]:"invalid";assert.throws(()=>h.verifyProof(invalid),key);}
 for(const patch of [{postgresArchitecture:"arm64"},{postgresExecution:"native"},{certificateDryRunTarget:"windows-iis"},{productType:3},{architecture:"x64"},{jobIds:[proof().jobIds[0],proof().jobIds[0]]},{claimIds:[proof().claimIds[0],proof().claimIds[0]]},{rawCustody:"private"}])assert.throws(()=>h.verifyProof({...proof(),...patch}));
});
test("EDB dependency has an actual reviewed fixed official download identity",()=>{
 assert.equal(lock.version,"17.11");assert.equal(lock.build,"17.11-5");assert.equal(lock.architecture,"x64");
 assert.equal(lock.url,"https://get.enterprisedb.com/postgresql/postgresql-17.11-5-windows-x64-binaries.zip");assert.equal(lock.sourceUrl,"https://sbp.enterprisedb.com/getfile.jsp?fileid=1260616");
 assert.equal(lock.bytes,381531864);assert.match(lock.sha256,/^[a-f0-9]{64}$/);assert.equal(fs.lstatSync(path.join(__dirname,"certops-arm64-postgres-lock.json")).isSymbolicLink(),false);
});

test("installed ARM64 source preserves true scope, original installer and conservative cleanup",()=>{
 const h=require("../tests/e2e/helpers/certops-arm64-installed-journey"),source=fs.readFileSync(path.resolve(__dirname,"../tests/e2e/helpers/certops-arm64-installed-journey.js"),"utf8");
 for(const file of h.sourceFiles)assert.ok(fs.statSync(path.resolve(__dirname,"..",file)).isFile(),file);
 for(const token of ['assert.deepEqual(fs.readFileSync(installer),installerBytes)','verifyPeArchitecture(candidateHost,0xaa64)','mode:"dry_run"','e.claim_id=j.claim_id',"e.metadata->>'storeName'='My'",'readState(),original','afterRestart','mutationUnresolved,false','drained();fs.rmSync(canonical','Foreign native custody replacement preserved','survivors.ok,true','survivors.shared,false','survivors.complete,true','Uncaptured owned process preserves native roots'])assert.ok(source.includes(token),token);
 assert.doesNotMatch(source,/installerBytes\.replace|filterQualifiedCapabilities\s*=|writeEnrollmentJournal|UPDATE certificate_jobs|ownedThumbprints/);
 const pg=fs.readFileSync(path.join(__dirname,"certops-arm64-postgres.js"),"utf8");assert.ok(pg.indexOf('rootIdentity=identity(root)')<pg.indexOf('await download(archive)'));assert.ok(pg.includes('Unknown native startup preserves PostgreSQL root'));assert.ok(pg.includes('assertDrainAbsent({processes:captured},all)'));
});
test("PostgreSQL preparation cleanup binds original root and marker before any native startup",()=>{
 fs.mkdirSync(path.resolve(__dirname,"../.build"),{recursive:true});
 const crypto=require("node:crypto"),pg=require("./certops-arm64-postgres"),parent=path.resolve(__dirname,"../.build"),base=fs.mkdtempSync(path.join(parent,"arm64-pg-contract-")),nonce=crypto.randomBytes(16).toString("hex"),root=path.join(base,`certops-arm64-pg-${nonce}`),oldTemp=process.env.RUNNER_TEMP,oldSeal=process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256,oldReceiptSeal=process.env.CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256;
 fs.mkdirSync(root);fs.writeFileSync(path.join(root,".owner"),nonce,{flag:"wx"});
 try{
  process.env.RUNNER_TEMP=base;
  const r={schemaVersion:1,phase:"preparing",nonce,root,rootIdentity:pg.identity(root),markerIdentity:pg.identity(path.join(root,".owner")),archiveSha256:lock.sha256,bin:path.join(root,"extract","pgsql","bin"),data:path.join(root,"data"),port:55432},file=path.join(root,"ownership.json");
  fs.writeFileSync(file,JSON.stringify(r),{flag:"wx"});process.env.CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256=crypto.createHash("sha256").update(JSON.stringify(pg.identity(file))).digest("hex");
  process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256=crypto.createHash("sha256").update(JSON.stringify([r.root,r.nonce,r.rootIdentity,r.markerIdentity])).digest("hex");
  assert.equal(pg.validateReceipt(r,file),true);
  const originalBytes=fs.readFileSync(file),backup=file+".original";fs.renameSync(file,backup);fs.writeFileSync(file,originalBytes,{flag:"wx"});
  assert.throws(()=>pg.validateReceipt(r,file),/Original PostgreSQL receipt file identity/);fs.unlinkSync(file);fs.renameSync(backup,file);assert.equal(pg.validateReceipt(r,file),true);
  assert.throws(()=>pg.validateReceipt({...r,rootIdentity:{...r.rootIdentity,ino:"0"}},file));
  assert.throws(()=>pg.validateReceipt({...r,markerIdentity:{...r.markerIdentity,ino:"0"}},file));
  assert.throws(()=>pg.validateReceipt({...r,data:path.join(base,"foreign")},file));
  process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256="0".repeat(64);assert.throws(()=>pg.validateReceipt(r,file),/Original independently recorded/);
 }finally{
  if(oldTemp===undefined)delete process.env.RUNNER_TEMP;else process.env.RUNNER_TEMP=oldTemp;if(oldSeal===undefined)delete process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256;else process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256=oldSeal;
  if(oldReceiptSeal===undefined)delete process.env.CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256;else process.env.CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256=oldReceiptSeal;
  fs.rmSync(base,{recursive:true});
 }
});

test("post-native API or database cleanup failure invalidates the public report",()=>{
 const dir=fs.mkdtempSync(path.join(require("node:os").tmpdir(),"arm64-finalize-")),file=path.join(dir,"report.json"),{artifact,candidateSha}=require("./test-support/arm64-installed-artifact.cjs"),{finalizeReport}=require("./certops-arm64-installed-agent");
 try{fs.writeFileSync(file,JSON.stringify(artifact().report));assert.equal(h.verifyRuntimeReport(finalizeReport(file,true,candidateSha)),true);const failed=finalizeReport(file,false,candidateSha);assert.equal(failed.status,"failed");assert.equal(failed.cleanup.status,"failed");assert.throws(()=>h.verifyRuntimeReport(failed));assert.equal(JSON.parse(fs.readFileSync(file)).status,"failed");}finally{fs.rmSync(dir,{recursive:true});}
});
