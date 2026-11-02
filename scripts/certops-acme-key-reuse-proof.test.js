"use strict";
/** Bounded public proof controls only; these do not claim ACME execution. */
const test = require("node:test"), assert = require("node:assert/strict");
const { verifyProof, fields, scope } = require("../tests/e2e/helpers/certops-acme-key-reuse");
const paths = require("../tests/e2e/helpers/certops-acme-key-reuse");
const fixture = client => ({ scope, client, materialPaths:{scope:paths.MATERIAL_PATH_SCOPE,observedGenerations:3,spaceAndUnicodeInEveryPath:true,...Object.fromEntries(paths.MATERIAL_PATH_FLAGS.map(flag=>[flag,true])),...Object.fromEntries(paths.MATERIAL_PATH_LIMITS.map(flag=>[flag,false]))}, ...Object.fromEntries(fields.map(field => [field, true])), fingerprints: ["1", "2", "3"].map(v => v.repeat(64)), serials: ["01", "02", "03"], spkiFingerprint: "4".repeat(64), jobIds: ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"], sourceProfileId: "33333333-3333-3333-3333-333333333333", sourceProfileFingerprint: "5".repeat(64) });
test("both real CSR client variants require all exact reuse facts", () => {
  for (const client of ["certbot", "acme.sh"]) {
    const proof = fixture(client); assert.equal(verifyProof(proof), true);
    for (const field of fields) {
      for (const value of [false, null, 1, "true"]) assert.throws(() => verifyProof({ ...proof, [field]: value }));
      const missing = { ...proof }; delete missing[field]; assert.throws(() => verifyProof(missing));
    }
    assert.throws(() => verifyProof({ ...proof, privateKey: "private" }));
  }
});
test("rotating, duplicated and unsupported public identities cannot qualify reuse", () => {
  const proof = fixture("certbot");
  for (const field of ["scope", "client", "spkiFingerprint", "sourceProfileId", "sourceProfileFingerprint"]) {
    const missing = { ...proof }; delete missing[field]; assert.throws(() => verifyProof(missing));
    for (const value of [null, false, "unsupported"]) assert.throws(() => verifyProof({ ...proof, [field]: value }));
  }
  for (const field of ["jobIds", "serials", "fingerprints"]) {
    assert.throws(() => verifyProof({ ...proof, [field]: [] }));
    assert.throws(() => verifyProof({ ...proof, [field]: proof[field].map(() => proof[field][0]) }));
    assert.throws(() => verifyProof({ ...proof, [field]: [...proof[field], proof[field][0]] }));
    assert.throws(() => verifyProof({ ...proof, [field]: proof[field].map(() => "invalid") }));
  }
});

test("material-path evidence is exact and never promotes executable or platform paths", () => {
  const original = fixture("certbot");
  for (const key of Object.keys(original.materialPaths)) {
    for (const wrong of [undefined,null,typeof original.materialPaths[key] === "boolean" ? 1 : true]) {
      const proof = structuredClone(original); proof.materialPaths[key] = wrong;
      assert.throws(()=>verifyProof(proof));
    }
  }
  for (const flag of paths.MATERIAL_PATH_FLAGS) {
    const proof = structuredClone(original); proof.materialPaths[flag] = false; assert.throws(()=>verifyProof(proof));
  }
  for (const flag of paths.MATERIAL_PATH_LIMITS) {
    const proof = structuredClone(original); proof.materialPaths[flag] = true; assert.throws(()=>verifyProof(proof));
  }
  const proof=structuredClone(original);proof.materialPaths.rawPath="private";assert.throws(()=>verifyProof(proof));
});

test("native material-path observer rejects alias, foreign custody and changed directory identity", () => {
  const fs=require("node:fs"), vm=require("node:vm"), path=require("node:path"), filename=path.join(__dirname,"../tests/e2e/helpers/certops-acme-key-reuse.js");
  const root="/tmp/owned acme ü-123", configDir=root+"/agent", certPath=root+"/deployed/leaf.pem", keyPath=configDir+"/keys/key.pem";
  const observeFixture=()=>{
    let broken;
    const files=new Set([certPath,keyPath,configDir+"/config.json"]);
    const fakeFs={lstatSync(file){return {isDirectory:()=>!files.has(file),isFile:()=>files.has(file),isSymbolicLink:()=>broken?.alias===file,ino:broken?.replace===file?2n:1n,dev:1n,uid:broken?.foreign===file?2n:1n,nlink:1n,size:1n,mode:0o600n};},realpathSync:file=>file,readdirSync:()=>["state"]};
    const module={exports:{}};
    vm.runInNewContext(fs.readFileSync(filename,"utf8"),{module,exports:module.exports,require:name=>name==="node:fs"?fakeFs:name==="node:path"?path.posix:require(name),process:{getuid:()=>1},Buffer},{filename});
    const observer=module.exports.materialPathObserver({workDir:root,configDir,certPath,keyPath,acmeKind:"certbot",workDirIdentity:fakeFs.lstatSync(root)});
    return {observer,setBroken:value=>{broken=value;}};
  };
  const positive=observeFixture();for(let i=0;i<3;i++)positive.observer.observe();assert.equal(positive.observer.proof().observedGenerations,3);
  for(const broken of [{alias:configDir},{replace:configDir},{replace:root},{foreign:keyPath}]) {
    const value=observeFixture();value.observer.observe();value.setBroken(broken);assert.throws(()=>value.observer.observe());
  }
});
