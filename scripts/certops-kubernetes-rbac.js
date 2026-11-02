"use strict";
/** Namespace-owned native RBAC denial and production observer/provisioner recovery.
 * The existing disposable cluster producer supplies its retained namespace UID
 * and owner token. This fixture creates no cluster-scoped permissions/resources. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const SCENARIO = "controller-native-rbac-startup-recovery";
const SCOPE = "native-kubernetes-mounted-serviceaccount-rbac-startup-denial-recovery";
const OWNER_LABEL = "qualification.tokentimer.io/owner";
const FLAGS = ["namespaceOwnershipVerified", "deniedCertificateAbsent", "sameObserverRecovered", "productionWatchObserved", "recoveryIdempotent", "publicIssuedLeafVerified", "noClusterLevelMutation"];
const REQUIRED_SOURCES = ["scripts/certops-kubernetes-host.js", "scripts/certops-kubernetes-rbac.js", "scripts/certops-kubernetes-rbac-incluster.js", "scripts/certops-kubernetes-compaction-incluster.js", "apps/k8s-controller/src/cert-manager-client.js", "apps/k8s-controller/src/cert-manager-observer.js", "apps/k8s-controller/src/certificate-provisioner.js", "apps/k8s-controller/src/tls-crt-secret-reader.js", "apps/k8s-controller/src/public-certificate-parser.js", "packages/agent/scripts/host-gate.js"];
function verifyNamespace(value, { namespace, uid, owner }) {
  assert.match(namespace, /^certops-[a-f0-9]{16}$/);
  assert.match(owner, /^[a-f0-9]{32}$/);
  assert.equal(value?.metadata?.name, namespace);
  assert.equal(value?.metadata?.labels?.[OWNER_LABEL], owner);
  assert.equal(value?.metadata?.deletionTimestamp, undefined);
  assert.match(value.metadata.uid, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
  if (uid !== undefined) assert.equal(value.metadata.uid, uid);
  return value.metadata.uid;
}
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ["schemaVersion", "scope", "listStatus", "watchStatus", "createStatus", "certificateUid", "createdCertificateUid", "missedResourceVersion", "watchedResourceVersion", ...FLAGS].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.scope, SCOPE);
  for (const name of ["listStatus", "watchStatus", "createStatus"]) assert.equal(value[name], 403);
  for (const name of ["certificateUid", "createdCertificateUid"]) assert.match(value[name], /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
  assert.notEqual(value.certificateUid, value.createdCertificateUid);
  for (const name of ["missedResourceVersion", "watchedResourceVersion"]) assert.match(value[name], /^[1-9][0-9]{0,19}$/);
  assert.ok(BigInt(value.watchedResourceVersion) > BigInt(value.missedResourceVersion));
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
async function until(check) {
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 500)); }
  throw new Error("Owned namespace RBAC handshake deadline exceeded");
}
async function qualifyNativeRbac({ kubectl, namespace, namespaceUid, namespaceOwner, command, gate }) {
  assert.equal(process.env.CERTOPS_KUBE_HOST_TESTS, "1");
  assert.match(process.env.CERTOPS_KUBE_CONTEXT || "", /^kind-certops-qualification-[a-z0-9-]+$/);
  assert.equal(command.namespace, namespace);
  const owned = () => verifyNamespace(JSON.parse(kubectl(["get", "namespace", namespace, "-o", "json"])), { namespace, uid: namespaceUid, owner: namespaceOwner });
  owned();
  // Even recovery permissions remain namespaced and never grant Secret access.
  const readRules = [{ apiGroups: ["cert-manager.io"], resources: ["certificates"], verbs: ["get"] }];
  const restoredRules = [{ apiGroups: ["cert-manager.io"], resources: ["certificates"], verbs: ["get", "list", "watch", "create", "patch"] }, { apiGroups: ["cert-manager.io"], resources: ["certificaterequests"], verbs: ["get", "list", "watch"] }];
  const material = name => fs.readFileSync(path.join(__dirname, name), "utf8");
  const desired = { ...command, certificateName: "rbac-created", secretName: "rbac-created-tls", managedCertificateId: crypto.randomUUID(), jobId: crypto.randomUUID() };
  const baseline = JSON.parse(kubectl(["get", "certificate", "owned", "-n", namespace, "-o", "json"]));
  const pod = { apiVersion: "v1", kind: "Pod", metadata: { name: "rbac-fixture", namespace }, spec: { restartPolicy: "Never", activeDeadlineSeconds: 420, serviceAccountName: "rbac-fixture", containers: [{ name: "client", image: "certops-controller:qualification", imagePullPolicy: "Never", command: ["node", "/qualification/fixture.js"], env: [{ name: "CERTOPS_TEST_COMMAND", value: JSON.stringify(desired) }], securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } }, volumeMounts: [{ name: "fixture", mountPath: "/qualification", readOnly: true }] }], volumes: [{ name: "fixture", configMap: { name: "rbac-fixture" } }] } };
  owned(); kubectl(["apply", "-f", "-"], JSON.stringify({ apiVersion: "v1", kind: "List", items: [
    { apiVersion: "v1", kind: "ServiceAccount", metadata: { name: "rbac-fixture", namespace } },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", metadata: { name: "rbac-fixture", namespace }, rules: readRules },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: { name: "rbac-fixture", namespace }, subjects: [{ kind: "ServiceAccount", name: "rbac-fixture", namespace }], roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: "rbac-fixture" } },
    { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "rbac-fixture", namespace }, data: { "fixture.js": material("certops-kubernetes-rbac-incluster.js"), "certops-kubernetes-compaction-incluster.js": material("certops-kubernetes-compaction-incluster.js") } }, pod,
  ] }));
  kubectl(["wait", "--for=condition=Ready", "pod/rbac-fixture", "-n", namespace, "--timeout=120s"]);
  const read = name => JSON.parse(kubectl(["exec", "rbac-fixture", "-n", namespace, "--", "node", "-e", "const fs=require('node:fs'),p=process.argv[1];process.stdout.write(fs.existsSync(p)?fs.readFileSync(p,'utf8'):'null');", `/tmp/${name}.json`]));
  const write = (name, value) => { owned(); kubectl(["exec", "rbac-fixture", "-n", namespace, "--", "node", "-e", "const fs=require('node:fs'),p=process.argv[1];if(fs.existsSync(p))throw Error('Existing handshake');fs.writeFileSync(p+'.tmp',process.argv[2],{flag:'wx'});fs.renameSync(p+'.tmp',p);", `/tmp/${name}.json`, JSON.stringify(value)]); };
  const denied = await until(() => read("denied"));
  for (const field of ["listStatus", "watchStatus", "createStatus"]) assert.equal(denied[field], 403);
  assert.equal(denied.certificateUid, baseline.metadata.uid);
  assert.equal(kubectl(["get", "certificate", desired.certificateName, "-n", namespace, "--ignore-not-found", "-o", "name"]).trim(), "");
  const mutate = phase => { owned(); return JSON.parse(kubectl(["patch", "certificate", "owned", "-n", namespace, "--type=merge", "-p", JSON.stringify({ metadata: { annotations: { "qualification-rbac": phase } } }), "-o", "json"])); };
  const missed = mutate("while-denied"); write("missed", { resourceVersion: missed.metadata.resourceVersion });
  const confirmed = await until(() => read("missed-confirmed")); assert.equal(confirmed.notReady, true); assert.equal(confirmed.resourceVersion, missed.metadata.resourceVersion);
  owned(); kubectl(["patch", "role", "rbac-fixture", "-n", namespace, "--type=merge", "-p", JSON.stringify({ rules: restoredRules })]);
  const recovered = await until(() => read("recovered")); assert.equal(recovered.ready, true); assert.equal(recovered.resourceVersion, missed.metadata.resourceVersion);
  const watched = mutate("after-restored-watch"); write("watched", { resourceVersion: watched.metadata.resourceVersion });
  kubectl(["wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/rbac-fixture", "-n", namespace, "--timeout=120s"]);
  const result = JSON.parse(kubectl(["logs", "rbac-fixture", "-n", namespace]));
  assert.equal(result.certificateUid, baseline.metadata.uid); assert.equal(result.missedResourceVersion, missed.metadata.resourceVersion); assert.equal(result.watchedResourceVersion, watched.metadata.resourceVersion);
  assert.equal(JSON.parse(kubectl(["get", "certificate", "owned", "-n", namespace, "-o", "json"])).metadata.uid, baseline.metadata.uid);
  kubectl(["wait", "--for=condition=Ready", `certificate/${desired.certificateName}`, "-n", namespace, "--timeout=180s"]);
  const created = JSON.parse(kubectl(["get", "certificate", desired.certificateName, "-n", namespace, "-o", "json"])); assert.equal(created.metadata.uid, result.createdCertificateUid);
  const pem = Buffer.from(kubectl(["get", "secret", desired.secretName, "-n", namespace, "-o", "jsonpath={.data.tls\\.crt}"]), "base64");
  const leaf = new crypto.X509Certificate(pem); for (const name of desired.dnsNames) assert.equal(leaf.checkHost(name), name);
  owned();
  const proof = { schemaVersion: 1, scope: SCOPE, ...result, namespaceOwnershipVerified: true, deniedCertificateAbsent: true, publicIssuedLeafVerified: true, noClusterLevelMutation: true };
  verifyProof(proof); gate.report.nativeKubernetesRbacStartupRecovery = proof;
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) if (!gate.report.fixtureSources.some(row => row.file === file)) gate.report.fixtureSources.push({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "..", file))).digest("hex") });
}
module.exports = { SCENARIO, SCOPE, OWNER_LABEL, FLAGS, REQUIRED_SOURCES, verifyNamespace, verifyProof, qualifyNativeRbac };
