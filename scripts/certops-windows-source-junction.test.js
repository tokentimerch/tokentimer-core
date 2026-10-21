"use strict";
/** Synthetic verifier and owned regular-file controls; no junction/native mutation. */
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os");
const h=require("../tests/e2e/helpers/certops-windows-source-junction");
const fixture=()=>({scope:h.SCOPE,reparseTag:2684354563,otherReparseVariantsQualified:false,...Object.fromEntries(h.FLAGS.map(k=>[k,true]))});
test("junction native proof refuses other tags, absent custody, fake cleanup and broader promotion",()=>{
 h.verifyProof(fixture());for(const key of Object.keys(fixture())){const p=fixture();delete p[key];assert.throws(()=>h.verifyProof(p));}
 for(const patch of [{reparseTag:2684354572},{otherReparseVariantsQualified:true},{rawTarget:"private-path"},...h.FLAGS.map(k=>({[k]:false}))])assert.throws(()=>h.verifyProof({...fixture(),...patch}));
});
test("held and removed receipts bind exact original link and target and cannot interchange",()=>{
 const context={token:"a".repeat(32),linkId:"12:34",targetId:"12:35"},ready={schemaVersion:1,...context,reparseTag:2684354563,exactTarget:true,originalHandlesHeld:true},removed={schemaVersion:1,...context,originalJunctionRemoved:true,targetHandleClosed:true};
 h.verifyReceipt(ready,context);h.verifyReceipt(removed,context,true);
 assert.throws(()=>h.verifyReceipt(ready,context,true));assert.throws(()=>h.verifyReceipt(removed,context));
 for(const patch of [{token:"b".repeat(32)},{linkId:"12:99"},{targetId:"12:99"},{exactTarget:false},{originalHandlesHeld:false},{reparseTag:0}])assert.throws(()=>h.verifyReceipt({...ready,...patch},context));
});
test("actual reporter refuses missing, foreign-scope and partial native source-junction receipts",()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),"source-junction-proof-")),dir=path.join(root,"qualification-results");fs.mkdirSync(dir);const file=path.join(dir,"windows-source-junction-rsa-2048.json"),reporter=require("./certops-stack-reporter"),scope="real-agent-windows-acme-iis/rsa-2048",name="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
 try{assert.equal(reporter.sourceJunctionProof("real-agent-windows-stop-offline/rsa-2048",name,root),undefined);assert.throws(()=>reporter.sourceJunctionProof(scope,name,root));fs.writeFileSync(file,JSON.stringify(fixture()));assert.deepEqual(reporter.sourceJunctionProof(scope,name,root),fixture());fs.writeFileSync(file,JSON.stringify({...fixture(),originalJunctionRemovedByHandle:false}));assert.throws(()=>reporter.sourceJunctionProof(scope,name,root));}finally{fs.rmSync(root,{recursive:true,force:true});}
});
