"use strict";
/** Native fixture running inside the candidate controller image. Kubernetes
 * mounted ServiceAccount credentials and real authorization enforce each fault;
 * no client, HTTP error, observer clock, or watch event is substituted. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { publish } = require("./certops-kubernetes-compaction-incluster");
function status(error) {
  return [error?.statusCode, error?.status, error?.code, error?.body?.code, error?.response?.statusCode].map(Number).find(code => code === 403 || code === 404);
}
async function until(check, timeout = 90000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 250)); }
  throw new Error("Native RBAC recovery handshake deadline exceeded");
}
function command(name) {
  try { return JSON.parse(fs.readFileSync(`/tmp/${name}.json`, "utf8")); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
}
async function main() {
  const { createInClusterCertManagerClient } = require("/app/apps/k8s-controller/src/cert-manager-client");
  const { createCertManagerObserver } = require("/app/apps/k8s-controller/src/cert-manager-observer");
  const { createCertificateProvisioner } = require("/app/apps/k8s-controller/src/certificate-provisioner");
  const desired = JSON.parse(process.env.CERTOPS_TEST_COMMAND);
  const client = createInClusterCertManagerClient({ provisionEnabled: true });
  const observations = [];
  let observer, deniedWatch, watchStatus, certificateRestarts = 0;
  try {
    await client.start();
    // RBAC propagation is asynchronous. First prove the get-only grant took
    // effect, so a later provisioning403 cannot be an initial get refusal.
    const certificate = await until(async () => {
      try { const value = await client.getCertificate({ namespace: desired.namespace, name: "owned" }); return value.body || value; }
      catch (error) { if (status(error) === 403) return false; throw error; }
    });
    const listStatus = await until(async () => {
      try { await client.list({ resource: "Certificate", namespace: desired.namespace }); return false; }
      catch (error) { assert.equal(status(error), 403); return status(error); }
    });
    // Both asynchronous completion errors and initial HTTP refusal must carry a
    // genuine403 from the mounted-credential Kubernetes transport.
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Native watch403 missing")), 20000);
      const denied = error => {
        clearTimeout(timer);
        if (status(error) !== 403) { reject(new Error("Watch failed without native403")); return; }
        watchStatus = status(error); resolve();
      };
      client.watch({ resource: "Certificate", namespace: desired.namespace, onEvent: (phase, value) => { if (phase === "ERROR") denied(value); }, onError: denied }).then(handle => { deniedWatch = handle; }, denied);
    });
    deniedWatch?.close(); deniedWatch = null;
    let createReached = false;
    const provisioner = createCertificateProvisioner({ client, workspaceId: desired.workspaceId, clusterId: desired.clusterId, watchNamespaces: [desired.namespace], authorizeMutation: () => { createReached = true; return Promise.resolve(); } });
    let createStatus;
    await assert.rejects(provisioner.reconcile(desired), error => { createStatus = status(error); return createStatus === 403; });
    assert.equal(createReached, true, "Native denial must reach the create side effect after the allowed get404");
    await assert.rejects(client.getCertificate({ namespace: desired.namespace, name: desired.certificateName }), error => status(error) === 404);
    observer = createCertManagerObserver({ client, workspaceId: desired.workspaceId, clusterId: desired.clusterId, watchNamespaces: [desired.namespace], observationHandler: value => { observations.push(value); return Promise.resolve(); }, logger: { warn(message, metadata) { if (message === "cert-manager-watch-restarting" && metadata.resource === "Certificate") certificateRestarts++; } } });
    await observer.start();
    assert.equal(observer.isReady(), false);
    assert.equal(observations.length, 0);
    publish("/tmp/denied.json", { listStatus, watchStatus, createStatus, certificateUid: certificate.metadata.uid });
    const missed = await until(() => command("missed"));
    assert.equal(observer.isReady(), false);
    assert.equal(observations.some(value => value.resourceVersion === missed.resourceVersion), false);
    publish("/tmp/missed-confirmed.json", { resourceVersion: missed.resourceVersion, notReady: true });
    // Do not restart/recreate this observer: its unmodified production retry
    // must recover after the host restores only this namespace's Role.
    await until(() => observer.isReady() && observations.some(value => value.certificateUid === certificate.metadata.uid && value.resourceVersion === missed.resourceVersion));
    const recoveredGeneration = certificateRestarts;
    publish("/tmp/recovered.json", { resourceVersion: missed.resourceVersion, ready: observer.isReady() });
    const watched = await until(() => command("watched"));
    await until(() => observations.some(value => value.certificateUid === certificate.metadata.uid && value.resourceVersion === watched.resourceVersion));
    // An observation after a relist/reconnect cannot stand in for the required
    // live-watch event: the real observer logs every resynchronization trigger.
    assert.equal(certificateRestarts, recoveredGeneration);
    const created = await provisioner.reconcile(desired);
    assert.equal(created.operation, "created");
    assert.equal((await provisioner.reconcile(desired)).operation, "unchanged");
    console.log(JSON.stringify({ listStatus, watchStatus, createStatus, certificateUid: certificate.metadata.uid, missedResourceVersion: missed.resourceVersion, watchedResourceVersion: watched.resourceVersion, createdCertificateUid: created.resource.metadata.uid, sameObserverRecovered: observer.isReady(), productionWatchObserved: true, recoveryIdempotent: true }));
  } finally {
    deniedWatch?.close();
    if (observer) await observer.close(); else await client.close();
  }
}
if (require.main === module) main().catch(() => { console.error("Native RBAC journey failed; no qualifying proof emitted"); process.exitCode = 1; });
module.exports = { status };
