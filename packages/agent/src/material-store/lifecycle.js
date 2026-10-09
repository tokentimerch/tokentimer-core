"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const { createVaultStore, readProtectedFile, writeProtectedFile, writeProtectedJson, protectDirectory, failure, UUID, sameSans, validateBundle } = require("./index");
const { applyRestrictivePermissions } = require("../platform");
const { deployCertificateAndKey } = require("../deploy");
const { canonicalizeJobPayload } = require("../signing");

// Locks are never stolen on elapsed time: DNS/ACME/device operations can still
// be active after an arbitrary TTL. A crashed process requires reconciliation.
async function withMaterialLock(directory, key, task) {
  protectDirectory(directory);
  const lock = path.join(directory, `${crypto.createHash("sha256").update(key).digest("hex")}.lock`);
  let fd;
  try { fd = fs.openSync(lock, "wx", 0o600); }
  catch { throw failure("material_binding_locked"); }
  try {
    applyRestrictivePermissions(lock);
    fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }));
    fs.fsyncSync(fd);
    return await task();
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(lock);
  }
}

function intentFromJob(job) {
  const destination = job.publication || job.materialDeployment;
  if (!destination) throw failure("material_intent_invalid");
  return { ...destination, workspaceId: job.workspaceId };
}

function publicationSession({ job, stores, stateDir, keysDir, fixtureLoopbackHttp = false }) {
  // Both directories are authoritative customer-local execution configuration.
  // Never resolve custody paths from control-plane payload fields.
  if (typeof keysDir !== "string" || !path.isAbsolute(keysDir)) throw failure("material_local_path_invalid");
  const intent = intentFromJob(job);
  const store = createVaultStore(stores, intent, { fixtureLoopbackHttp });
  const scope = store.scope;
  if (scope.issuerAgentId !== job.agentId || scope.issuanceProfileRef !== intent.issuanceProfileRef ||
    scope.profileRevision !== intent.profileRevision || scope.caEndpoint !== job.caEndpoint ||
    scope.dnsProvider !== job.dnsProvider || scope.dnsZone !== job.dnsZone ||
    !sameSans(scope.sans, job.sans) || scope.keyAlgorithm !== (job.keyAlgorithm === "ecdsa" ? "ec" : job.keyAlgorithm)) throw failure("material_issuer_policy_denied");
  const directory = path.join(stateDir, "material-artifacts", intent.workspaceId, intent.groupId, intent.materialVersionId);
  const bundleFile = path.join(directory, "bundle.json");
  const checkpointFile = path.join(directory, "checkpoint.json");
  protectDirectory(directory);
  let keyRotated = null;
  if (fs.existsSync(checkpointFile)) {
    const saved = JSON.parse(readProtectedFile(checkpointFile, 16384));
    if (saved.jobId !== job.jobId || saved.materialVersionId !== intent.materialVersionId || saved.groupId !== intent.groupId) throw failure("material_staging_invalid");
    if (typeof saved.keyRotated === "boolean") keyRotated = saved.keyRotated;
  }

  function checkpoint(phase) {
    // Metadata journal and key-bearing artifacts are deliberately separate.
    writeProtectedJson(checkpointFile, { schemaVersion: 1, jobId: job.jobId,
      groupId: intent.groupId, materialVersionId: intent.materialVersionId, phase, keyRotated });
  }
  async function publish(bundle, checkLease) {
    validateBundle(bundle, intent, scope);
    writeProtectedJson(bundleFile, bundle);
    checkpoint("validated_staging");
    await checkLease();
    const receipt = await store.publish(bundle);
    checkpoint("published");
    await checkLease();
    // Keep the issuer's local reuse key consistent after rotation and after
    // recovery. This protected customer-side copy never enters job metadata.
    if (/^[A-Za-z0-9_.:-]{1,128}$/.test(job.certificateId || "")) {
      writeProtectedFile(path.join(keysDir,`${job.certificateId}.key.pem`),bundle.privateKeyPem);
    }
    return { status: "succeeded", keyRotated, errorMessage: null,
      publicationReceipt: receipt, publicationCertificatePem: bundle.certificatePem };
  }
  function stage(certificatePem, privateKeyPem, fingerprintSha256, rotated = null) {
    const bundle = { schemaVersion: 1, workspaceId: intent.workspaceId, groupId: intent.groupId,
      materialVersionId: intent.materialVersionId, certificatePem, privateKeyPem, fingerprintSha256, sans: scope.sans };
    validateBundle(bundle, intent, scope);
    keyRotated = typeof rotated === "boolean" ? rotated : null;
    writeProtectedJson(bundleFile, bundle);
    checkpoint("validated_staging");
  }
  async function recover(checkLease) {
    if (fs.existsSync(bundleFile)) {
      let bundle;
      try { bundle = JSON.parse(readProtectedFile(bundleFile)); }
      catch { throw failure("material_staging_invalid"); }
      return publish(bundle, checkLease);
    }
    // Deterministic remote reconciliation happens even when local artifacts
    // were lost. A new order is forbidden if an attempt had already started.
    await checkLease();
    try {
      const bundle = await store.fetch(1);
      return publish(bundle, checkLease);
    } catch (error) {
      if (error.code !== "material_version_unavailable") throw error;
    }
    if (fs.existsSync(checkpointFile)) throw failure("material_issuance_uncertain");
    return null;
  }
  return { directory, store, recover, publish, stage,
    start: () => checkpoint("issuance_started"),
    makeBundle: (certificatePem, privateKeyPem, fingerprintSha256) => ({ schemaVersion: 1,
      workspaceId: intent.workspaceId, groupId: intent.groupId, materialVersionId: intent.materialVersionId,
      certificatePem, privateKeyPem, fingerprintSha256, sans: scope.sans }) };
}

function probeListener(probe, fingerprintSha256, verificationPolicy) {
  if (!probe || typeof probe.dialAddress !== "string" || !Number.isInteger(probe.port) || probe.port < 1 || probe.port > 65535 ||
    typeof probe.sni !== "string" || !/^[a-z0-9.-]{1,253}$/i.test(probe.sni)) throw failure("material_probe_config_invalid");
  let ca;
  try { ca = probe.trustCaFile ? fs.readFileSync(probe.trustCaFile) : undefined; }
  catch { throw failure("material_probe_config_invalid"); }
  return new Promise((resolve) => {
    let socket;
    let settled = false;
    const timer = setTimeout(() => finish({ servedVerified: false, trustValidated: false }), 10000);
    function finish(value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      resolve(value);
    }
    socket = tls.connect({ host: probe.dialAddress, port: probe.port, servername: probe.sni,
      ca, rejectUnauthorized: verificationPolicy === "trust" }, () => {
      const raw = socket.getPeerCertificate()?.raw;
      const actual = raw ? crypto.createHash("sha256").update(raw).digest("hex") : null;
      finish({ servedVerified: actual === fingerprintSha256,
        trustValidated: verificationPolicy === "trust" && socket.authorized && actual === fingerprintSha256,
        observedFingerprintSha256: actual });
    });
    socket.on("error", () => finish({ servedVerified: false, trustValidated: false }));
  });
}

function resolveBindingPolicy(job, bindings, policyEngine) {
  const intent = intentFromJob(job);
  const binding = Object.hasOwn(bindings || {}, intent.bindingId) ? bindings[intent.bindingId] : null;
  if (!UUID.test(intent.bindingId) || !Number.isSafeInteger(intent.generation) || intent.generation < 1 ||
    !binding || binding.workspaceId !== intent.workspaceId || binding.groupId !== intent.groupId ||
    binding.agentId !== job.agentId || binding.materialStoreRef !== intent.materialStoreRef ||
    binding.deploymentProfileRef !== intent.deploymentProfileRef || binding.profileRevision !== intent.profileRevision ||
    binding.authorizationRevision !== intent.authorizationRevision || binding.verificationPolicy !== intent.verificationPolicy ||
    binding.target?.type !== "endpoint" || !Array.isArray(binding.probes) || binding.probes.length < 1 || binding.probes.length > 16 ||
    typeof binding.target.certPath !== "string" || typeof binding.target.keyPath !== "string") throw failure("material_binding_policy_denied");
  // Destination/reload/probes all come from approved local configuration.
  for (const file of [binding.target.certPath, binding.target.keyPath, binding.target.chainPath].filter(Boolean)) {
    if (!policyEngine.checkPath(file).allowed) throw failure("material_destination_denied");
  }
  return { intent,binding };
}

async function executePinnedDeployment({ job, stores, bindings, stateDir, policyEngine, checkLease, reload, recoveryOnly = false, fixtureLoopbackHttp = false }) {
  const { intent,binding } = resolveBindingPolicy(job,bindings,policyEngine);
  const store = createVaultStore(stores, intent, { fixtureLoopbackHttp });
  const locks = path.join(stateDir, "material-locks");
  const record = path.join(stateDir, "material-bindings", `${intent.bindingId}.json`);
  const hash = crypto.createHash("sha256").update(canonicalizeJobPayload(intent)).digest("hex");
  return withMaterialLock(locks, `binding:${intent.workspaceId}:${intent.bindingId}`, async () => {
    let previous = null;
    if (fs.existsSync(record)) {
      try { previous = JSON.parse(readProtectedFile(record, 16384)); }
      catch { throw failure("material_binding_state_invalid"); }
      if (previous.generation > intent.generation || (previous.generation === intent.generation && previous.intentHash !== hash)) throw failure("material_stale_generation");
      if (previous.uncertain) throw failure("material_binding_uncertain");
    }
    if (recoveryOnly && !previous) throw failure("material_binding_uncertain");
    await checkLease();
    const bundle = await store.fetch(intent.providerVersion);
    const facts = validateBundle(bundle, intent, store.scope);
    if (intent.verificationOnly === true) {
      const receipt={schemaVersion:1,workspaceId:intent.workspaceId,groupId:intent.groupId,bindingId:intent.bindingId,
        materialVersionId:intent.materialVersionId,generation:intent.generation,fetched:true,installed:false,bound:false,
        servedVerified:false,trustValidated:false,...facts,observedAt:new Date().toISOString()};
      try {
        const installed=new crypto.X509Certificate(fs.readFileSync(binding.target.certPath));
        const key=crypto.createPrivateKey(readProtectedFile(binding.target.keyPath));
        receipt.installed=installed.checkPrivateKey(key) && crypto.createHash("sha256").update(installed.raw).digest("hex")===facts.fingerprintSha256;
        if (receipt.installed) {
          const probes=[];for(const p of binding.probes)probes.push(await probeListener(p,facts.fingerprintSha256,binding.verificationPolicy));
          receipt.servedVerified=probes.every(p=>p.servedVerified);receipt.trustValidated=probes.every(p=>p.trustValidated);
          receipt.bound=receipt.servedVerified;
        }
      } catch { /* Public failure code below; never return local file errors. */ }
      await checkLease();
      receipt.observedAt=new Date().toISOString();
      writeProtectedJson(record,{generation:intent.generation,intentHash:hash,intent,uncertain:false,receipt});
      const verified=receipt.servedVerified && (binding.verificationPolicy!=="trust" || receipt.trustValidated);
      return {status:verified?"succeeded":"failed",deploymentReceipt:receipt,errorMessage:verified?null:"material_drift_detected"};
    }
    const stageDir = path.join(stateDir, "material-consumer-staging", intent.bindingId);
    protectDirectory(stageDir);
    const privateKeyPath = path.join(stageDir, "key.pem");
    // A crash before the uncertain marker may leave only protected staging.
    // The binding lock and marker check above prove no live writer owns it.
    if (fs.existsSync(privateKeyPath)) { readProtectedFile(privateKeyPath); fs.unlinkSync(privateKeyPath); }
    const fd = fs.openSync(privateKeyPath, "wx", 0o600);
    try {
      applyRestrictivePermissions(privateKeyPath);
      fs.writeFileSync(fd, bundle.privateKeyPem);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    let mutated = false;
    const receipt = { schemaVersion: 1, workspaceId: intent.workspaceId, groupId: intent.groupId,
      bindingId: intent.bindingId, materialVersionId: intent.materialVersionId, generation: intent.generation,
      fetched: true, installed: false, bound: false, servedVerified: false, trustValidated: false,
      fingerprintSha256: facts.fingerprintSha256, validTo: facts.validTo,
      observedAt: new Date().toISOString() };
    try {
      await checkLease();
      writeProtectedJson(record, { generation: intent.generation, intentHash: hash, intent, uncertain: true });
      mutated = true;
      const blocks = bundle.certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      const deployed = await deployCertificateAndKey({ target: binding.target,
        certificatePem: binding.target.chainPath ? `${blocks[0]}\n` : bundle.certificatePem,
        chainPem: binding.target.chainPath ? `${blocks.slice(1).join("\n")}\n` : undefined,
        privateKeyPath, retainPrivateKeyStaging: true, checkPath: (file) => policyEngine.checkPath(file) });
      if (!deployed.deployed && !(deployed.skipped && deployed.reason === "idempotent")) throw failure("material_install_failed");
      receipt.installed = true;
      await checkLease();
      if (typeof reload !== "function" || !(await reload(binding.reloadService, binding.reloadCommandRefs))) throw failure("material_reload_failed");
      receipt.bound = true;
      const probes = [];
      for (const probe of binding.probes) probes.push(await probeListener(probe, facts.fingerprintSha256, binding.verificationPolicy));
      receipt.servedVerified = probes.every((probe) => probe.servedVerified);
      receipt.trustValidated = probes.every((probe) => probe.trustValidated);
      receipt.observedAt = new Date().toISOString();
      if (!receipt.servedVerified || (binding.verificationPolicy === "trust" && !receipt.trustValidated)) throw failure("material_service_verification_failed");
      await checkLease();
      writeProtectedJson(record, { generation: intent.generation, intentHash: hash, intent, uncertain: false, receipt });
      return { status: "succeeded", deploymentReceipt: receipt, errorMessage: null };
    } catch (error) {
      // Do not infer compensation or device state after lease/reload/probe failure.
      return { status: mutated ? "orphaned_unknown_effect" : "failed", deploymentReceipt: receipt,
        errorMessage: /^material_[a-z_]+$/.test(error.code || "") ? error.code : "material_deployment_failed" };
    } finally { fs.rmSync(privateKeyPath, { force: true }); }
  });
}

// Explicit customer-side reconciliation only: no install/reload and no server
// current-state promotion. Prove the installed pair AND every configured TLS
// listener before clearing an uncertain local marker. The subsequent signed
// retry still needs a live claim and the original approved generation.
async function reconcilePinnedDeployment({ job,bindings,stateDir,policyEngine }) {
  const { intent,binding }=resolveBindingPolicy(job,bindings,policyEngine);
  return withMaterialLock(path.join(stateDir,"material-locks"),`binding:${intent.workspaceId}:${intent.bindingId}`,async()=>{
    const record=path.join(stateDir,"material-bindings",`${intent.bindingId}.json`);
    const previous=JSON.parse(readProtectedFile(record,16384));
    const intentHash=crypto.createHash("sha256").update(canonicalizeJobPayload(intent)).digest("hex");
    if(previous.generation!==intent.generation || previous.intentHash!==intentHash)throw failure("material_stale_generation");
    const cert=new crypto.X509Certificate(fs.readFileSync(binding.target.certPath));
    const key=crypto.createPrivateKey(readProtectedFile(binding.target.keyPath));
    if(!cert.checkPrivateKey(key) || crypto.createHash("sha256").update(cert.raw).digest("hex")!==intent.fingerprintSha256)throw failure("material_reconciliation_mismatch");
    for(const p of binding.probes){const proof=await probeListener(p,intent.fingerprintSha256,binding.verificationPolicy);if(!proof.servedVerified || binding.verificationPolicy==="trust"&&!proof.trustValidated)throw failure("material_reconciliation_mismatch");}
    writeProtectedJson(record,{...previous,uncertain:false,reconciledAt:new Date().toISOString()});
    return { reconciled:true,bindingId:intent.bindingId,generation:intent.generation,fingerprintSha256:intent.fingerprintSha256 };
  });
}

module.exports = { withMaterialLock, publicationSession, resolveBindingPolicy, executePinnedDeployment, reconcilePinnedDeployment, probeListener };
