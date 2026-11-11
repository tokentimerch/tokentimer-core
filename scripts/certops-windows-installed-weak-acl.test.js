"use strict";
/** Synthetic public proofs and private-file parser controls; no DACL/SCM changes. */
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const h=require("../tests/e2e/helpers/certops-windows-installed-weak-acl");
const fixture=()=>({scope:h.SCOPE,untrustedSid:"S-1-1-0",readMask:1,startupFailureCount:1,inFlightMutationQualified:false,...Object.fromEntries(h.FLAGS.map(k=>[k,true]))});
test("installed weak ACL proof requires exact Everyone ReadData refusal and repaired custody",()=>{
  h.verifyProof(fixture());
  for(const key of Object.keys(fixture())){const p=fixture();delete p[key];assert.throws(()=>h.verifyProof(p));}
  for(const patch of [{untrustedSid:"S-1-5-32-545"},{readMask:2},{inFlightMutationQualified:true},{startupFailureCount:0},{rawCredential:"secret"},...h.FLAGS.map(k=>({[k]:false}))])assert.throws(()=>h.verifyProof({...fixture(),...patch}));
});
test("reporter admits only completed real full journey bounded owned sidecar",()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"installed-weak-acl-proof-"));
  fs.mkdirSync(path.join(root,"qualification-results"));const file=path.join(root,"qualification-results/windows-installed-weak-acl-rsa-2048.json");
  const reporter=require("./certops-stack-reporter");const name="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try{assert.equal(reporter.installedWeakAclProof("real-agent-windows-stop-offline/rsa-2048",name,root),undefined);assert.throws(()=>reporter.installedWeakAclProof("real-agent-windows-acme-iis/rsa-2048",name,root));fs.writeFileSync(file,JSON.stringify(fixture()));assert.deepEqual(reporter.installedWeakAclProof("real-agent-windows-acme-iis/rsa-2048",name,root),fixture());fs.writeFileSync(file,JSON.stringify({...fixture(),noAuthenticatedHeartbeatDuringRefusal:false}));assert.throws(()=>reporter.installedWeakAclProof("real-agent-windows-acme-iis/rsa-2048",name,root));}finally{fs.rmSync(root,{recursive:true,force:true});}
});
