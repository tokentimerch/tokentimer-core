/**
 * Qualification: disposable native controller and watch recovery
 *
 * Run trusted-main manual certops-kubernetes-qualification.yml on Ubuntu 24.04, one
 * owned kind cluster, pinned cert-manager and candidate production controller image.
 * Match official SHA256-checked kubectl 1.35.0 to pinned server 1.35.0; never target a
 * customer cluster. Native host cases require real issuance, ownership/namespaces,
 * idempotence, independent public parsing, in-cluster list/watch/patch and actual HTTP
 * 403 create/patch refusals with unchanged existing resources and absent refused
 * resources. The companion controller E2E uses migrated API/Postgres and real admin
 * admission, scoped machine tokens, actual cert-manager issuance and persisted
 * fingerprints; no agent registration may exist. Only the consuming destination reads
 * its key. Secret fallback gets only named destination Secrets, never mutation/deletion
 * rights. Pause blocks new resources while observation continues. Suspend only the
 * retained private TLS bridge during an API outage; changed intent must leave
 * destination unchanged until recovery/reissue, then served TLS and history must
 * advance. Restart the production deployment without changing Certificate UID or
 * completed-job count. Bridge requests stay unchanged and path-restricted, trust via
 * NODE_EXTRA_CA_CERTS, with no delivery TLS bypass/body logging. Drain
 * bridge/port-forward, delete only random namespaces and owned accounts/private
 * material; always destroy cluster and Compose volumes. Publish sanitized results, not
 * tokens, DB files, keys or pod logs. The loopback Status/410 control proves
 * transport/relist behavior only. Native compaction additionally pins the single owned
 * control-plane Docker container ID, node name and ownership labels, records a real list
 * cursor in a production-image read-only pod, advances revision with eight owned
 * annotations, compacts via etcdctl, then restarts only the verified running
 * kube-apiserver and requires changed container ID and restored readiness. Actual
 * numeric HTTP 410 must trigger production relist and subsequent same-UID update with
 * measured cursor; cache hits/timeouts are failures. Keep helper hashes/closed public
 * facts. External issuers, HTTP-01 and full renewal timing require their separate native
 * lanes.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
// Qualify production controller adapters against one disposable kind cluster;
// each scenario owns only its random namespace and emits strict public evidence.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const { createCertificateProvisioner } = require("../apps/k8s-controller/src/certificate-provisioner");
function rawKubectl(args, input) {
  const result = spawnSync("kubectl", ["--context", process.env.CERTOPS_KUBE_CONTEXT, ...args], { input, encoding: "utf8", timeout: 180000, maxBuffer: 4*1024*1024 });
  if (result.error || result.status !== 0) { const error = new Error("Disposable cluster operation failed"); error.statusCode = /NotFound/.test(result.stderr || "") ? 404 : result.status; throw error; }
  return result.stdout;
}
async function main() {
  const rbac = require("./certops-kubernetes-rbac");
  const namespace = "certops-"+crypto.randomBytes(8).toString("hex");
  const namespaceOwner = crypto.randomBytes(16).toString("hex");
  let namespaceUid, owned = false;
  const kubectl = (args, input) => {
    if (owned) rbac.verifyNamespace(JSON.parse(rawKubectl(["get", "namespace", namespace, "-o", "json"])), { namespace, uid: namespaceUid, owner: namespaceOwner });
    return rawKubectl(args, input);
  };
  if (!/^kind-certops-qualification-[a-z0-9-]+$/.test(process.env.CERTOPS_KUBE_CONTEXT || "")) throw new Error("Dedicated disposable kind context required");
  const gate = createHostGate({suite:"kubernetes-host", requiredCapabilities:["cluster","optIn"], probeCapabilities:async()=>({cluster:{available:JSON.parse(kubectl(["get","nodes","-o","json"])).items.length>0},optIn:{available:process.env.CERTOPS_KUBE_HOST_TESTS==="1"}})});
  gate.report.fixtureSource={file:"scripts/certops-kubernetes-host.js",sha256:crypto.createHash("sha256").update(require("node:fs").readFileSync(__filename)).digest("hex")};
  gate.report.artifactQualification=process.env.GITHUB_ACTIONS==="true"?"workflow-checkout-source":"local-worktree-source-baseline-sha-only";
  if (!await gate.preflight()) return;
  let primaryError;
  try {
    // A random name is reserved for this run; refuse any collision before
    // recording ownership so a partial create still receives teardown.
    const existing = JSON.parse(kubectl(["get", "namespaces", "-o", "json"]));
    assert.ok(!existing.items.some((item) => item.metadata.name === namespace));
    owned=true;
    const createdNamespace=JSON.parse(rawKubectl(["create","-f","-","-o","json"],JSON.stringify({apiVersion:"v1",kind:"Namespace",metadata:{name:namespace,labels:{[rbac.OWNER_LABEL]:namespaceOwner}}})));
    namespaceUid=rbac.verifyNamespace(createdNamespace,{namespace,owner:namespaceOwner});
    kubectl(["apply","-f","-"], JSON.stringify({apiVersion:"cert-manager.io/v1",kind:"Issuer",metadata:{name:"fixture",namespace},spec:{selfSigned:{}}}));
    kubectl(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"List",items:[
      {apiVersion:"v1",kind:"ServiceAccount",metadata:{name:"observe-fixture",namespace}},
      {apiVersion:"rbac.authorization.k8s.io/v1",kind:"Role",metadata:{name:"observe-fixture",namespace},rules:[{apiGroups:["cert-manager.io"],resources:["certificates","certificaterequests"],verbs:["get","list","watch"]}]},
      {apiVersion:"rbac.authorization.k8s.io/v1",kind:"RoleBinding",metadata:{name:"observe-fixture",namespace},subjects:[{kind:"ServiceAccount",name:"observe-fixture",namespace}],roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"Role",name:"observe-fixture"}}
    ]}));
    const client = {
      getCertificate:async({name,namespace:ns})=>JSON.parse(kubectl(["get","certificate",name,"-n",ns,"-o","json"])),
      createCertificate:async({certificate})=>JSON.parse(kubectl(["create","-f","-","-o","json"],JSON.stringify(certificate))),
      patchCertificate:async({name,namespace:ns,certificate})=>JSON.parse(kubectl(["patch","certificate",name,"-n",ns,"--type=merge","-p",JSON.stringify(certificate),"-o","json"]))
    };
    const command={schemaVersion:1,workspaceId:crypto.randomUUID(),clusterId:crypto.randomUUID(),managedCertificateId:crypto.randomUUID(),jobId:crypto.randomUUID(),namespace,certificateName:"owned",secretName:"owned-tls",dnsNames:["certops.invalid"],issuerRef:{group:"cert-manager.io",kind:"Issuer",name:"fixture"}};
    const provisioner=createCertificateProvisioner({client,workspaceId:command.workspaceId,clusterId:command.clusterId,watchNamespaces:[namespace],authorizeMutation:async()=>{}});
    await gate.scenario("controller-owned-provision",async()=>{
      assert.equal((await provisioner.reconcile(command)).operation,"created");
      kubectl(["wait","--for=condition=Ready","certificate/owned","-n",namespace,"--timeout=180s"]);
      // Read only public certificate data; never serialize the Secret tls.key.
      const publicPem=Buffer.from(kubectl(["get","secret","owned-tls","-n",namespace,"-o","jsonpath={.data.tls\\.crt}"]),"base64").toString("utf8");
      const { Readable } = require("node:stream");
      const { extractTlsCertificateFromSecretJson } = require("../apps/k8s-controller/src/tls-crt-secret-reader");
      // Only the public value enters this adapter; a synthetic non-key data
      // member exercises the shipped bounded streaming reader separately.
      const encodedPublic=Buffer.from(publicPem).toString("base64");
      const narrow=await extractTlsCertificateFromSecretJson(Readable.from([JSON.stringify({data:{"tls.crt":encodedPublic,"fixture.extra":"not-certificate-data"}})]));
      assert.equal(narrow,encodedPublic);
      const certificate=new crypto.X509Certificate(publicPem);
      assert.ok(certificate.subjectAltName.includes("certops.invalid"));
      const { parsePublicCertificateObservation } = require("../apps/k8s-controller/src/public-certificate-parser");
      const observed = parsePublicCertificateObservation(publicPem);
      assert.ok(observed.publicCertificate, "Product controller parser must accept the real issued leaf");
      const { mapCertificateObservation } = require("../apps/k8s-controller/src/cert-manager-observer");
      const resource = await client.getCertificate({namespace, name:"owned"});
      const mapped = mapCertificateObservation({certificate:resource,workspaceId:command.workspaceId,clusterId:command.clusterId});
      assert.equal(mapped.ready, true);
      assert.equal(mapped.secretName, "owned-tls");
      assert.equal(mapped.certificateUid, resource.metadata.uid);
      assert.equal((await provisioner.reconcile(command)).operation,"unchanged");
    },{evidenceLevel:"real-host",oracle:"Real cert-manager Ready and independently parsed public tls.crt"});
    await gate.scenario("controller-secret-fallback",async()=>{
      const fs=require("node:fs"),path=require("node:path");
      const pem=Buffer.from(kubectl(["get","secret","owned-tls","-n",namespace,"-o","jsonpath={.data.tls\\.crt}"]),"base64");
      const fingerprint=crypto.createHash("sha256").update(new crypto.X509Certificate(pem).raw).digest("hex");
      kubectl(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"List",items:[
        {apiVersion:"v1",kind:"Secret",metadata:{name:"malformed-public",namespace},type:"Opaque",data:{"tls.crt":Buffer.from("not a public certificate").toString("base64")}},
        {apiVersion:"v1",kind:"Secret",metadata:{name:"oversized-public",namespace},type:"Opaque",data:{"tls.crt":Buffer.alloc(70*1024,65).toString("base64")}},
        {apiVersion:"v1",kind:"ServiceAccount",metadata:{name:"fallback-fixture",namespace}},
        {apiVersion:"rbac.authorization.k8s.io/v1",kind:"Role",metadata:{name:"fallback-fixture",namespace},rules:[{apiGroups:[""],resources:["secrets"],resourceNames:["owned-tls","malformed-public","oversized-public"],verbs:["get"]}]},
        {apiVersion:"rbac.authorization.k8s.io/v1",kind:"RoleBinding",metadata:{name:"fallback-fixture",namespace},subjects:[{kind:"ServiceAccount",name:"fallback-fixture",namespace}],roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"Role",name:"fallback-fixture"}},
        {apiVersion:"v1",kind:"ConfigMap",metadata:{name:"fallback-fixture",namespace},data:{"fixture.js":fs.readFileSync(path.join(__dirname,"certops-kubernetes-secret-fallback.js"),"utf8")}},
        {apiVersion:"v1",kind:"Pod",metadata:{name:"fallback-fixture",namespace},spec:{restartPolicy:"Never",activeDeadlineSeconds:180,serviceAccountName:"fallback-fixture",containers:[{name:"client",image:"certops-controller:qualification",imagePullPolicy:"Never",command:["node","/qualification/fixture.js"],env:[{name:"CERTOPS_TEST_NAMESPACE",value:namespace},{name:"CERTOPS_TEST_FINGERPRINT",value:fingerprint}],securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},volumeMounts:[{name:"fixture",mountPath:"/qualification",readOnly:true}]}],volumes:[{name:"fixture",configMap:{name:"fallback-fixture"}}]}}
      ]}));
      kubectl(["wait","--for=jsonpath={.status.phase}=Succeeded","pod/fallback-fixture","-n",namespace,"--timeout=200s"]);
      assert.equal(kubectl(["logs","fallback-fixture","-n",namespace]).trim(),"CERTOPS_SECRET_FALLBACK_RESULT=passed");
    },{evidenceLevel:"real-host",oracle:"Production mounted-credential raw Secret reader and fallback consume actual cert-manager public leaf only; exact read-only Secret RBAC, foreign denial and genuine malformed/oversized refusals"});
    await gate.scenario("controller-incluster-client",async()=>{
      const fs=require("node:fs");
      const path=require("node:path");
      const podCommand={...command,certificateName:"incluster-owned",secretName:"incluster-owned-tls",managedCertificateId:crypto.randomUUID(),jobId:crypto.randomUUID()};
      kubectl(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"List",items:[
        {apiVersion:"v1",kind:"ServiceAccount",metadata:{name:"provision-fixture",namespace}},
        {apiVersion:"rbac.authorization.k8s.io/v1",kind:"Role",metadata:{name:"provision-fixture",namespace},rules:[{apiGroups:["cert-manager.io"],resources:["certificates"],verbs:["get","list","watch","create","patch"]}]},
        {apiVersion:"rbac.authorization.k8s.io/v1",kind:"RoleBinding",metadata:{name:"provision-fixture",namespace},subjects:[{kind:"ServiceAccount",name:"provision-fixture",namespace}],roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"Role",name:"provision-fixture"}},
        {apiVersion:"v1",kind:"ConfigMap",metadata:{name:"client-fixture",namespace},data:{"fixture.js":fs.readFileSync(path.join(__dirname,"certops-kubernetes-incluster.js"),"utf8")}},
        {apiVersion:"v1",kind:"Pod",metadata:{name:"client-fixture",namespace},spec:{restartPolicy:"Never",activeDeadlineSeconds:180,serviceAccountName:"provision-fixture",containers:[{name:"client",image:"certops-controller:qualification",imagePullPolicy:"Never",command:["node","/qualification/fixture.js"],env:[{name:"CERTOPS_TEST_COMMAND",value:JSON.stringify(podCommand)}],securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},volumeMounts:[{name:"fixture",mountPath:"/qualification",readOnly:true}]}],volumes:[{name:"fixture",configMap:{name:"client-fixture"}}]}}
      ]}));
      kubectl(["wait","--for=jsonpath={.status.phase}=Succeeded","pod/client-fixture","-n",namespace,"--timeout=200s"]);
      assert.equal(kubectl(["logs","client-fixture","-n",namespace]).trim(),"CERTOPS_INCLUSTER_RESULT=passed");
      kubectl(["wait","--for=condition=Ready","certificate/incluster-owned","-n",namespace,"--timeout=180s"]);
      const pem=Buffer.from(kubectl(["get","secret","incluster-owned-tls","-n",namespace,"-o","jsonpath={.data.tls\\.crt}"]),"base64").toString("utf8");
      assert.ok(new crypto.X509Certificate(pem).subjectAltName.includes("second.certops.invalid"));
    },{evidenceLevel:"real-host",oracle:"Production in-cluster client uses mounted scoped credentials for create, unchanged and merge patch; cert-manager issues updated public leaf"});
    await gate.scenario("controller-readonly-client",async()=>{
      const resource=await client.getCertificate({namespace,name:"incluster-owned"});
      const readCommand={...command,certificateName:"incluster-owned",secretName:"incluster-owned-tls",managedCertificateId:resource.metadata.labels["certops.tokentimer.io/managed-certificate-id"],dnsNames:["certops.invalid","second.certops.invalid"]};
      kubectl(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"Pod",metadata:{name:"readonly-client-fixture",namespace},spec:{restartPolicy:"Never",activeDeadlineSeconds:180,serviceAccountName:"observe-fixture",containers:[{name:"client",image:"certops-controller:qualification",imagePullPolicy:"Never",command:["node","/qualification/fixture.js"],env:[{name:"CERTOPS_TEST_COMMAND",value:JSON.stringify(readCommand)},{name:"CERTOPS_TEST_OBSERVE_ONLY",value:"1"}],securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},volumeMounts:[{name:"fixture",mountPath:"/qualification",readOnly:true}]}],volumes:[{name:"fixture",configMap:{name:"client-fixture"}}]}}));
      kubectl(["wait","--for=jsonpath={.status.phase}=Succeeded","pod/readonly-client-fixture","-n",namespace,"--timeout=200s"]);
      assert.equal(kubectl(["logs","readonly-client-fixture","-n",namespace]).trim(),"CERTOPS_INCLUSTER_RESULT=passed");
      const after=await client.getCertificate({namespace,name:"incluster-owned"});
      assert.deepEqual(after.spec,resource.spec);
      await assert.rejects(client.getCertificate({namespace,name:"forbidden-create"}),{statusCode:404});
    },{evidenceLevel:"real-host",oracle:"Production client under read-only mounted credentials receives actual Kubernetes 403 for create and patch, existing resource remains unchanged"});
    await gate.scenario(rbac.SCENARIO, async () => {
      await rbac.qualifyNativeRbac({kubectl,namespace,namespaceUid,namespaceOwner,command,gate});
    }, {evidenceLevel:"real-host",oracle:"Genuine mounted-SA403 list/watch/create denial, missed update relist by the same production observer, live watch recovery and production provisioning after namespace-only Role restoration"});
    await gate.scenario("controller-local-scope",async()=>{
      const identity=`system:serviceaccount:${namespace}:observe-fixture`;
      assert.equal(kubectl(["auth","can-i","list","certificates.cert-manager.io","-n",namespace,"--as",identity]).trim(),"yes");
      // kubectl intentionally returns exit 1 for a denied can-i result.
      for(const [verb,resource] of [["create","secrets"],["patch","certificaterequests.cert-manager.io"],["delete","certificates.cert-manager.io"]]) {
        const verdict=spawnSync("kubectl",["--context",process.env.CERTOPS_KUBE_CONTEXT,"auth","can-i",verb,resource,"-n",namespace,"--as",identity],{encoding:"utf8",timeout:15000});
        assert.equal(verdict.status,1); assert.equal(verdict.stdout.trim(),"no");
      }
      await assert.rejects(provisioner.reconcile({...command,workspaceId:crypto.randomUUID()}),{code:"CERTOPS_PROVISIONING_WORKSPACE_MISMATCH"});
      await assert.rejects(provisioner.reconcile({...command,clusterId:crypto.randomUUID()}),{code:"CERTOPS_PROVISIONING_CLUSTER_MISMATCH"});
      await assert.rejects(provisioner.reconcile({...command,namespace:"default"}),{code:"CERTOPS_PROVISIONING_NAMESPACE_FORBIDDEN"});
      const resource=await client.getCertificate({namespace,name:"owned"});
      resource.metadata.labels["certops.tokentimer.io/workspace-id"]=crypto.randomUUID();
      await client.patchCertificate({namespace,name:"owned",certificate:{metadata:{labels:resource.metadata.labels}}});
      await assert.rejects(provisioner.reconcile(command),{code:"CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT"});
      assert.equal((await client.getCertificate({namespace,name:"owned"})).metadata.labels["certops.tokentimer.io/workspace-id"],resource.metadata.labels["certops.tokentimer.io/workspace-id"]);
    },{evidenceLevel:"real-host",oracle:"Product local policy before actual Kubernetes mutation"});
    await gate.scenario("controller-native-watch-compaction",async()=>{
      await require("./certops-kubernetes-compaction").qualifyNativeCompaction({kubectl,namespace,gate});
    },{evidenceLevel:"real-host",oracle:"Actual owned etcd compaction and control-plane cache restart produce native410; shipped mounted-credential client and observer relist and receive a real Certificate watch update"});
  } catch(error) { primaryError=error; throw error; }
  finally {
    try {
    await gate.scenario("controller-fixture-cleanup",async()=>{
      if(owned) {
        const retained=rawKubectl(["get","namespace",namespace,"--ignore-not-found","-o","json"]).trim();
        if(retained) {
          rbac.verifyNamespace(JSON.parse(retained),{namespace,uid:namespaceUid,owner:namespaceOwner});
          kubectl(["delete","namespace",namespace,"--wait=true","--timeout=120s"]);
        }
      }
    },{evidenceLevel:"real-host",oracle:"Owned namespace deletion completes"});
    await gate.finish({requiredScenarios:["controller-owned-provision","controller-secret-fallback","controller-incluster-client","controller-readonly-client","controller-local-scope","controller-native-watch-compaction",rbac.SCENARIO,"controller-fixture-cleanup"]});
    } catch(error) {
      if(primaryError) throw new AggregateError([primaryError,error],"Kubernetes journey and cleanup/finalization failed");
      throw error;
    }
  }
}
if(require.main===module)main().catch(()=>{console.error("Kubernetes host qualification failed; inspect sanitized scenario report");process.exitCode=1;});
module.exports={main};
