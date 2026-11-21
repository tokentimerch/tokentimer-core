"use strict";

const assert=require("node:assert/strict"),os=require("node:os"),crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path");
const {Client,Pool}=require("pg");
const {migrations}=require("../../apps/api/migrations/migrate");
const {persistAgentDiscoveryEvidenceBatch}=require("../../apps/api/services/certops/agentObservations");
const {bindAuthenticatedCredential}=require("../../apps/api/services/certops/agentCredentialFence");
const {listCertificateIdentities}=require("../../apps/api/services/certops/certificateIdentity");
const {runWindowsDiscoveryScan}=require("../../packages/agent/src/index");

const connection={host:process.env.DB_HOST||"localhost",port:Number(process.env.DB_PORT||5432),user:process.env.DB_USER||"tokentimer",password:process.env.DB_PASSWORD||"password"};
const database=`certops_iis_proof_e2e_${process.pid}_${Date.now()}`;
const pem=fs.readFileSync(path.join(__dirname,"../fixtures/certops-public-observation.txt"),"utf8"),cert=new crypto.X509Certificate(pem);
const fingerprint=cert.fingerprint256.replaceAll(":","").toLowerCase(),thumbprint=crypto.createHash("sha1").update(cert.raw).digest("hex").toUpperCase();

describe("IIS topology attestation from agent to location projection",function(){
  this.timeout(120000);let db,agent,workspaceId;
  before(async()=>{
    const admin=new Client({...connection,database:process.env.DB_NAME||"tokentimer"});await admin.connect();await admin.query(`CREATE DATABASE ${database}`);await admin.end();
    db=new Pool({...connection,database});for(const migration of migrations)await db.query(migration.sql);
    const email=`iis-proof-${crypto.randomUUID()}@example.test`;
    const owner=(await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES($1,$2,'IIS proof','x','local') RETURNING id",[email,email])).rows[0].id;
    workspaceId=crypto.randomUUID();await db.query("INSERT INTO workspaces(id,name,plan,created_by,certops_managed_identity_limit) VALUES($1,'IIS proof','oss',$2,4)",[workspaceId,owner]);
    const agentId=`iis-proof-${crypto.randomUUID()}`;
    const agentRow=(await db.query("INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash) VALUES($1,$2,'test','1.0.0',$3,$4) RETURNING id",[workspaceId,agentId,`ttagent_${crypto.randomBytes(8).toString("hex")}`,crypto.createHash("sha256").update(agentId).digest("hex")])).rows[0];
    agent=bindAuthenticatedCredential({id:agentRow.id,workspaceId,agentId,hostname:os.hostname()},agentId);
  });
  after(async()=>{if(db)await db.end();const admin=new Client({...connection,database:process.env.DB_NAME||"tokentimer"});await admin.connect();await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);await admin.end()});
  it("folds an old HTTP.sys location only while the newer IIS capture is attested",async()=>{
    let sequence=0;
    const send=async evidenceItems=>persistAgentDiscoveryEvidenceBatch({dbPool:db,agent,envelope:{sequence:++sequence},evidenceItems});
    const metadata={locationKind:"http_sys",locationSlot:"0:0:0:0:0:0:0:1:18450",targetHost:os.hostname(),port:"18450",boundAddress:"0:0:0:0:0:0:0:1",storeLocation:"LocalMachine",storeName:"My",thumbprint,keyPresent:true,certificatePem:pem};
    await send([{evidenceId:crypto.randomUUID(),eventType:"certificate.observed",fingerprintSha256:fingerprint,observedAt:new Date(Date.now()-10000).toISOString(),metadata:Object.entries(metadata).map(([name,value])=>({name,value}))}]);
    const observation={locationKind:"iis_binding",locationSlot:"Default Web Site:18450@0:0:0:0:0:0:0:1",targetHost:os.hostname(),siteName:"Default Web Site",port:18450,boundAddress:"0:0:0:0:0:0:0:1",storeLocation:"LocalMachine",storeName:"My",thumbprint,keyPresent:true,fingerprintSha256:fingerprint};
    const snapshot={iis:[{site:observation.siteName,address:"::1",port:18450,hostname:"",flags:0}],http:[{keyedBy:"ipport",ipPort:"[::1]:18450",thumbprint,storeName:"My"}],certificates:[{thumbprint,fingerprintSha256:fingerprint,hasPrivateKey:true}]};
    // The protocol client assigns evidence IDs before sending the batch.
    const client={reportEvidence:async body=>send(body.evidenceItems.map(item=>({...item,evidenceId:crypto.randomUUID()})))};
    await runWindowsDiscoveryScan({client,collect:async()=>[observation],readIisProofSnapshot:async()=>snapshot});
    const persisted=(await db.query("SELECT public_metadata FROM certificate_instances WHERE workspace_id=$1 AND location_kind='iis_binding'",[workspaceId])).rows[0].public_metadata;
    assert.equal(persisted.iisTopologyProof,"v1");
    let result=await listCertificateIdentities({client:db,workspaceId,includeDetails:true});
    let identity=result.items.find(item=>item.fingerprintSha256===fingerprint);assert.ok(identity);
    assert.equal(identity.locations.length,1);assert.equal(identity.locations[0].locationKind,"iis_binding");
    assert.equal(identity.locations[0].previousObservationCount,1);assert.equal(identity.locations[0].previousObservations[0].locationKind,"http_sys");
    await new Promise(resolve=>setTimeout(resolve,10));
    await runWindowsDiscoveryScan({client,collect:async()=>[observation],readIisProofSnapshot:async()=>{throw Error("snapshot unavailable")},log:()=>{}});
    const unproved=(await db.query("SELECT public_metadata FROM certificate_instances WHERE workspace_id=$1 AND location_kind='iis_binding'",[workspaceId])).rows[0].public_metadata;
    assert.equal(unproved.iisTopologyProof,undefined);
    result=await listCertificateIdentities({client:db,workspaceId,includeDetails:true});identity=result.items.find(item=>item.fingerprintSha256===fingerprint);
    assert.deepEqual(identity.locations.map(item=>item.locationKind).sort(),["http_sys","iis_binding"]);
  });
});
