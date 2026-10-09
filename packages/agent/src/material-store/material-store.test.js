"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { createVaultStore, writeProtectedJson, protectDirectory, validateBundle } = require("./index");
const { applyRestrictivePermissions } = require("../platform");
const { computeCertificateFingerprint, parseDnsSans } = require("../verify");
const { publicationSession, withMaterialLock } = require("./lifecycle");

function fixture(t, address) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-vault-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const tokenFile = path.join(directory, "token");
  fs.writeFileSync(tokenFile, "isolated-vault-fixture-only", { mode: 0o600 });
  applyRestrictivePermissions(tokenFile);
  const cert = fs.readFileSync(path.join(__dirname, "../verify/fixtures/leaf.crt.pem"), "utf8");
  const key = fs.readFileSync(path.join(__dirname, "../verify/fixtures/leaf.key.pem"), "utf8");
  const x509 = new crypto.X509Certificate(cert);
  const intent = { workspaceId: crypto.randomUUID(), groupId: crypto.randomUUID(), materialVersionId: crypto.randomUUID(), materialStoreRef: "customer" };
  const bundle = { schemaVersion: 1, workspaceId: intent.workspaceId, groupId: intent.groupId,
    materialVersionId: intent.materialVersionId, certificatePem: cert, privateKeyPem: key,
    fingerprintSha256: computeCertificateFingerprint(cert), sans: parseDnsSans(x509.subjectAltName) };
  const scope = { workspaceId: intent.workspaceId, prefix: `${intent.workspaceId}/${intent.groupId}`,
    sans: bundle.sans, keyAlgorithm: x509.publicKey.asymmetricKeyType };
  const stores = { customer: { address, mount: "secret", tokenFile, timeoutMs: 500,
    groups: { [intent.groupId]: scope } } };
  return { intent, bundle, scope, stores, directory };
}

test("publication uses CAS=0, reconciles lost response, and fetch pins version", async (t) => {
  let stored;
  let posts = 0;
  let gets = 0;
  const server = http.createServer((req, res) => {
    if (req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        posts++;
        const parsed = JSON.parse(body);
        assert.equal(parsed.options.cas, 0);
        if (stored) { res.writeHead(400).end("secret response must never escape"); return; }
        stored = parsed.data;
        // Simulate successful Vault commit followed by a lost response.
        req.socket.destroy();
      });
    } else {
      gets++;
      assert.equal(new URL(req.url, "http://fixture").searchParams.get("version"), "1");
      res.end(JSON.stringify({ data: { data: stored, metadata: { version: 1, deletion_time: "", destroyed: false } } }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const f = fixture(t, `http://127.0.0.1:${server.address().port}`);
  const client = createVaultStore(f.stores, f.intent, { fixtureLoopbackHttp: true });
  const receipt = await client.publish(f.bundle);
  assert.equal(receipt.providerVersion, 1);
  assert.equal(JSON.stringify(receipt).includes("PRIVATE KEY"), false);
  assert.deepEqual(await client.publish(f.bundle), receipt);
  assert.equal((await client.fetch(1)).fingerprintSha256, f.bundle.fingerprintSha256);
  await assert.rejects(client.fetch(undefined), { code: "material_provider_version_invalid" });
  assert.equal(posts, 2);
  assert.equal(gets, 3);
});

test("local authority rejects cross-customer, arbitrary aliases and HTTP", (t) => {
  const f = fixture(t, "http://127.0.0.1:58200");
  assert.throws(() => createVaultStore(f.stores, f.intent), { code: "material_store_config_invalid" });
  assert.throws(() => createVaultStore(f.stores, { ...f.intent, workspaceId: crypto.randomUUID() }, { fixtureLoopbackHttp: true }), { code: "material_scope_denied" });
  assert.throws(() => createVaultStore(f.stores, { ...f.intent, materialStoreRef: "https://attacker" }), { code: "material_intent_invalid" });
  assert.throws(() => validateBundle({ ...f.bundle, privateKeyPem: "bad" }, f.intent, f.scope), { code: "material_bundle_invalid" });
  assert.throws(() => validateBundle({ ...f.bundle, sans: ["*.unapproved.test"] }, f.intent, f.scope), { code: "material_bundle_invalid" });
  assert.throws(() => validateBundle({ ...f.bundle, unknownSecret: "canary" }, f.intent, f.scope), { code: "material_bundle_invalid" });
  const file = path.join(f.directory, "protected", "bundle.json");
  protectDirectory(path.dirname(file));
  writeProtectedJson(file, f.bundle);
  assert.equal(fs.readFileSync(file, "utf8").includes("PRIVATE KEY"), true);
});

test("real isolated Vault KV v2: pinned publication and idempotent CAS", { skip: process.env.TT_WILDCARD_VAULT_REAL !== "1" }, async (t) => {
  const f = fixture(t, "http://127.0.0.1:58200");
  f.stores.customer.timeoutMs = 5000;
  const client = createVaultStore(f.stores, f.intent, { fixtureLoopbackHttp: true });
  const first = await client.publish(f.bundle);
  assert.deepEqual(await client.publish(f.bundle), first);
  assert.deepEqual(await client.fetch(1), f.bundle);
  await assert.rejects(client.fetch(2), { code: "material_version_unavailable" });
});

test("CAS conflict never adopts unrelated existing bytes or returns Vault errors", async (t) => {
  const server=http.createServer((req,res)=>{res.writeHead(req.method==="POST"?400:404).end("customer-secret-canary");});
  await new Promise(r=>server.listen(0,"127.0.0.1",r));t.after(()=>new Promise(r=>server.close(r)));
  const f=fixture(t,`http://127.0.0.1:${server.address().port}`);
  await assert.rejects(createVaultStore(f.stores,f.intent,{fixtureLoopbackHttp:true}).publish(f.bundle),e=>e.code==="material_cas_conflict"&&!e.message.includes("canary"));
});

test("real Vault ACL separates issuer, consumer, scanner and customer prefixes", { skip: process.env.TT_WILDCARD_VAULT_REAL !== "1" }, async (t) => {
  const f=fixture(t,"http://127.0.0.1:58200");f.stores.customer.timeoutMs=5000;
  const root="isolated-vault-fixture-only",base="http://127.0.0.1:58200/v1";
  async function api(url,token,method="GET",body) {
    return fetch(base+url,{method,headers:{"X-Vault-Token":token,"Content-Type":"application/json"},...(body?{body:JSON.stringify(body)}:{})});
  }
  async function token(role,capabilities) {
    const name=`wildcard-${role}-${crypto.randomUUID()}`;
    const created=await api(`/sys/policies/acl/${name}`,root,"PUT",{policy:`path "secret/data/${f.scope.prefix}/bundles/*" { capabilities = ${JSON.stringify(capabilities)} }`});
    assert.equal(created.status,204);
    const issued=await api("/auth/token/create",root,"POST",{policies:[name],no_default_policy:true,ttl:"2m"});assert.equal(issued.status,200);
    const secret=(await issued.json()).auth.client_token;
    t.after(async()=>{await api("/auth/token/revoke",root,"POST",{token:secret});await api(`/sys/policies/acl/${name}`,root,"DELETE");});
    return secret;
  }
  const issuer=await token("issuer",["create","read"]);
  const consumer=await token("consumer",["read"]);
  const scanner=await token("scanner",["deny"]);
  fs.writeFileSync(f.stores.customer.tokenFile,issuer);
  const store=createVaultStore(f.stores,f.intent,{fixtureLoopbackHttp:true});
  await store.publish(f.bundle);await store.publish(f.bundle);
  fs.writeFileSync(f.stores.customer.tokenFile,consumer);
  assert.deepEqual(await store.fetch(1),f.bundle);
  const object=`/secret/data/${f.scope.prefix}/bundles/${f.intent.materialVersionId}`;
  assert.equal((await api(object,consumer,"POST",{options:{cas:1},data:{}})).status,403);
  assert.equal((await api(`/secret/data/${crypto.randomUUID()}/other/bundles/${f.intent.materialVersionId}`,consumer)).status,403);
  assert.equal((await api(object,scanner)).status,403);
});

test("checkpoint without validated material exposes uncertainty and never permits a new order", async (t) => {
  const server=http.createServer((req,res)=>{assert.equal(req.method,"GET");res.writeHead(404).end();});
  await new Promise(r=>server.listen(0,"127.0.0.1",r));t.after(()=>new Promise(r=>server.close(r)));
  const f=fixture(t,`http://127.0.0.1:${server.address().port}`);
  Object.assign(f.scope,{issuerAgentId:"issuer",issuanceProfileRef:"profile",profileRevision:1,caEndpoint:"https://ca.test/dir",dnsProvider:"test",dnsZone:"example.com"});
  const job={workspaceId:f.intent.workspaceId,agentId:"issuer",jobId:crypto.randomUUID(),publication:{...f.intent,type:"vault-kv2",issuanceProfileRef:"profile",profileRevision:1},sans:f.bundle.sans,keyAlgorithm:f.scope.keyAlgorithm,caEndpoint:f.scope.caEndpoint,dnsProvider:f.scope.dnsProvider,dnsZone:f.scope.dnsZone};
  const session=()=>publicationSession({job,stores:f.stores,stateDir:f.directory,keysDir:path.join(f.directory,"custom-custody"),fixtureLoopbackHttp:true});
  assert.equal(await session().recover(async()=>{}),null);session().start();
  await assert.rejects(session().recover(async()=>{}),{code:"material_issuance_uncertain"});
});

test("local binding lock excludes concurrent deployment and releases after failure", async (t) => {
  const f=fixture(t,"https://vault.test");const locks=path.join(f.directory,"locks");
  await withMaterialLock(locks,"binding",async()=>{
    await assert.rejects(withMaterialLock(locks,"binding",async()=>{}),{code:"material_binding_locked"});
  });
  await assert.rejects(withMaterialLock(locks,"binding",async()=>{throw new Error("fixture");}),/fixture/);
  assert.equal(await withMaterialLock(locks,"binding",async()=>"released"),"released");
});

test("custom issuer custody survives lost responses and recovery; next CSR reuses the promoted key", async (t) => {
  let stored, loseReadback = true, posts = 0;
  const server=http.createServer((req,res)=>{
    if(req.method==="POST") {
      let body="";req.on("data",chunk=>{body+=chunk;});req.on("end",()=>{
        posts++;
        if(stored) {res.writeHead(400).end();return;}
        stored=JSON.parse(body).data;req.socket.destroy();
      });
    } else if(loseReadback) {req.socket.destroy();}
    else res.end(JSON.stringify({data:{data:stored,metadata:{version:1,deletion_time:"",destroyed:false}}}));
  });
  await new Promise(r=>server.listen(0,"127.0.0.1",r));t.after(()=>new Promise(r=>server.close(r)));
  const f=fixture(t,`http://127.0.0.1:${server.address().port}`);
  Object.assign(f.scope,{issuerAgentId:"issuer",issuanceProfileRef:"profile",profileRevision:1,caEndpoint:"https://ca.test/dir",dnsProvider:"test",dnsZone:"example.com"});
  const job={workspaceId:f.intent.workspaceId,agentId:"issuer",jobId:crypto.randomUUID(),certificateId:crypto.randomUUID(),
    publication:{...f.intent,type:"vault-kv2",issuanceProfileRef:"profile",profileRevision:1},sans:f.bundle.sans,
    keyAlgorithm:f.scope.keyAlgorithm,caEndpoint:f.scope.caEndpoint,dnsProvider:f.scope.dnsProvider,dnsZone:f.scope.dnsZone};
  const keysDir=path.join(f.directory,"issuer-custody-custom");
  const canonical=path.join(keysDir,`${job.certificateId}.key.pem`);
  const {writeProtectedFile,readProtectedFile}=require("./index");
  const {generateCsr}=require("../keys");
  const oldKey=crypto.generateKeyPairSync("rsa",{modulusLength:2048}).privateKey.export({type:"pkcs8",format:"pem"});
  writeProtectedFile(canonical,oldKey);
  // A control-plane-looking path is never consulted for local custody.
  job.keysDir=path.join(f.directory,"unauthorized");
  const session=()=>publicationSession({job,stores:f.stores,stateDir:f.directory,keysDir,fixtureLoopbackHttp:true});
  session().stage(f.bundle.certificatePem,f.bundle.privateKeyPem,f.bundle.fingerprintSha256,true);
  await assert.rejects(session().recover(async()=>{}),{code:"material_publication_uncertain"});
  assert.equal(readProtectedFile(canonical),oldKey);
  loseReadback=false;
  const recovered=await session().recover(async()=>{});
  assert.equal(recovered.keyRotated,true);assert.equal(posts,2);
  assert.equal(readProtectedFile(canonical),f.bundle.privateKeyPem);
  assert.equal(fs.existsSync(path.join(f.directory,"keys")),false);
  assert.equal(fs.existsSync(job.keysDir),false);
  const csr=generateCsr({keyPath:canonical,subject:{commonName:"example.com"},altNames:f.bundle.sans});
  assert.equal(csr.publicKeyPem,crypto.createPublicKey(f.bundle.privateKeyPem).export({type:"spki",format:"pem"}));
  assert.notEqual(csr.publicKeyPem,crypto.createPublicKey(oldKey).export({type:"spki",format:"pem"}));
  assert.equal((await session().recover(async()=>{})).keyRotated,true,"durable rotation outcome survives repeated recovery");
  session().stage(f.bundle.certificatePem,f.bundle.privateKeyPem,f.bundle.fingerprintSha256,false);
  assert.equal((await session().recover(async()=>{})).keyRotated,false,"reuse does not report rotation");
  await assert.rejects(session().recover(async()=>{throw Object.assign(new Error("lease"),{code:"material_lease_unavailable"});}),{code:"material_lease_unavailable"});
  writeProtectedFile(canonical,oldKey);
  let leaseChecks=0;
  await assert.rejects(session().recover(async()=>{if(++leaseChecks===2)throw Object.assign(new Error("lease"),{code:"material_lease_unavailable"});}),{code:"material_lease_unavailable"});
  assert.equal(readProtectedFile(canonical),oldKey,"lease loss after Vault reconciliation prevents promotion");
});

test("bounded transport times out a stalled Vault body without exposing contents", async (t) => {
  const server=http.createServer((req,res)=>{res.writeHead(200);res.write('{"sensitive":"canary"');});
  await new Promise(r=>server.listen(0,"127.0.0.1",r));t.after(()=>{server.closeAllConnections();server.close();});
  const f=fixture(t,`http://127.0.0.1:${server.address().port}`);f.stores.customer.timeoutMs=100;
  await assert.rejects(createVaultStore(f.stores,f.intent,{fixtureLoopbackHttp:true}).fetch(1),e=>e.code==="material_store_unavailable"&&!e.message.includes("canary"));
});
