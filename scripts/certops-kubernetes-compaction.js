"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),{spawnSync}=require("node:child_process");
function execute(binary,args){const result=spawnSync(binary,args,{encoding:"utf8",timeout:45000,maxBuffer:1024*1024});if(result.error||result.status!==0)throw new Error("Owned native compaction operation failed");return result.stdout;}
async function until(check,timeout=90000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await check();if(value)return value;await new Promise(resolve=>setTimeout(resolve,500));}throw new Error("Owned native compaction readiness deadline exceeded");}
function validateClusterIdentity({context,nodes,container,expectedContainerId}){
 assert.match(context,/^kind-certops-qualification-[a-z0-9-]+$/);const cluster=context.slice(5),node=`${cluster}-control-plane`;
 assert.equal(nodes.items.length,1);assert.equal(nodes.items[0].metadata.name,node);assert.ok(Object.hasOwn(nodes.items[0].metadata.labels,"node-role.kubernetes.io/control-plane"));
 assert.match(container.Id,/^[a-f0-9]{64}$/);if(expectedContainerId)assert.equal(container.Id,expectedContainerId);
 assert.equal(container.Name,`/${node}`);assert.equal(container.Config.Labels["io.x-k8s.kind.cluster"],cluster);assert.equal(container.Config.Labels["io.x-k8s.kind.role"],"control-plane");assert.equal(container.State.Running,true);return {cluster,node,containerId:container.Id};
}
function apiContainer(containers,node){const matching=containers.containers.filter(value=>value.metadata?.name==="kube-apiserver"&&value.state==="CONTAINER_RUNNING");assert.equal(matching.length,1);assert.match(matching[0].id,/^[a-f0-9]{64}$/);assert.equal(matching[0].labels["io.kubernetes.pod.namespace"],"kube-system");assert.equal(matching[0].labels["io.kubernetes.pod.name"],`kube-apiserver-${node}`);return matching[0].id;}
async function qualifyNativeCompaction({kubectl,namespace,gate}){
 assert.equal(process.platform,"linux");assert.equal(process.env.GITHUB_ACTIONS,"true");assert.equal(process.env.RUNNER_ENVIRONMENT,"github-hosted");assert.equal(process.env.CERTOPS_KUBE_HOST_TESTS,"1");
 assert.match(namespace,/^certops-[a-f0-9]{16}$/);
 const context=process.env.CERTOPS_KUBE_CONTEXT,cluster=context.slice(5),node=`${cluster}-control-plane`;
 let ownedContainerId;
 const inspect=()=>JSON.parse(execute("docker",["inspect",node]));const prove=()=>{const containers=inspect();assert.equal(containers.length,1);const measured=validateClusterIdentity({context,nodes:JSON.parse(kubectl(["get","nodes","-o","json"])),container:containers[0],expectedContainerId:ownedContainerId});ownedContainerId=measured.containerId;return measured;};prove();
 const nativeApi=()=>apiContainer(JSON.parse(execute("docker",["exec",node,"crictl","ps","--name","kube-apiserver","-o","json"])),node);
 const beforeApi=nativeApi();
 const etcdPod=JSON.parse(kubectl(["get","pod",`etcd-${node}`,"-n","kube-system","-o","json"]));assert.equal(etcdPod.spec.nodeName,node);assert.equal(etcdPod.metadata.labels.component,"etcd");assert.equal(etcdPod.spec.containers.filter(value=>value.name==="etcd").length,1);
 const etcd=args=>kubectl(["exec","-n","kube-system",`etcd-${node}`,"-c","etcd","--","etcdctl","--endpoints=https://127.0.0.1:2379","--cacert=/etc/kubernetes/pki/etcd/ca.crt","--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt","--key=/etc/kubernetes/pki/etcd/healthcheck-client.key",...args]);
 const fixtureFile="scripts/certops-kubernetes-compaction-incluster.js";gate.report.fixtureSources??=[];
 for(const file of ["scripts/certops-kubernetes-compaction.js",fixtureFile])gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",file))).digest("hex")});
 kubectl(["apply","-f","-"],JSON.stringify({apiVersion:"v1",kind:"List",items:[
  {apiVersion:"v1",kind:"ConfigMap",metadata:{name:"compaction-fixture",namespace},data:{"fixture.js":fs.readFileSync(path.resolve(__dirname,"..",fixtureFile),"utf8")}},
  {apiVersion:"v1",kind:"Pod",metadata:{name:"compaction-fixture",namespace},spec:{restartPolicy:"Never",activeDeadlineSeconds:420,serviceAccountName:"observe-fixture",containers:[{name:"client",image:"certops-controller:qualification",imagePullPolicy:"Never",command:["node","/qualification/fixture.js"],env:[{name:"CERTOPS_TEST_NAMESPACE",value:namespace}],securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},volumeMounts:[{name:"fixture",mountPath:"/qualification",readOnly:true}]}],volumes:[{name:"fixture",configMap:{name:"compaction-fixture"}}]}}
 ]}));
 kubectl(["wait","--for=condition=Ready","pod/compaction-fixture","-n",namespace,"--timeout=120s"]);
 const read=file=>JSON.parse(kubectl(["exec","compaction-fixture","-n",namespace,"--","node","-e","const fs=require('fs');const p=process.argv[1];process.stdout.write(fs.existsSync(p)?fs.readFileSync(p,'utf8'):'null');",`/tmp/${file}.json`]));
 const write=(file,value)=>kubectl(["exec","compaction-fixture","-n",namespace,"--","node","-e","require('fs').writeFileSync(process.argv[1],process.argv[2],{flag:'wx'});",`/tmp/${file}.json`,JSON.stringify(value)]);
 const checkpoint=await until(()=>read("checkpoint"));assert.match(checkpoint.resourceVersion,/^[1-9][0-9]*$/);
 // Bounded, owned namespace writes advance the actual etcd revision. No
 // revision, watch Status or Certificate observation is manufactured.
 for(let index=0;index<8;index++)kubectl(["annotate","certificate","owned","-n",namespace,`qualification-compaction=${index}`,"--overwrite"]);
 const status=JSON.parse(etcd(["endpoint","status","--write-out=json"]));assert.equal(status.length,1);const revision=status[0].Status.header.revision;assert.ok(Number.isSafeInteger(revision)&&BigInt(revision)>BigInt(checkpoint.resourceVersion));
 const compacted=etcd(["compact",String(revision)]);assert.match(compacted,new RegExp(`compacted revision ${revision}\\b`));
 // Clear only this already-proved disposable control plane's watch cache.
 // Kubelet restarts the static API server; no other cluster is addressed.
 prove();assert.equal(nativeApi(),beforeApi);execute("docker",["exec",node,"crictl","stop","--timeout","10",beforeApi]);
 const afterApi=await until(()=>{try{const value=nativeApi();return value!==beforeApi?value:null;}catch{return null;}});assert.notEqual(afterApi,beforeApi);
 await until(()=>{try{return kubectl(["get","--raw=/readyz"]).trim()==="ok";}catch{return false;}});prove();
 write("compacted",{revision:String(revision)});const relisted=await until(()=>read("relisted"));assert.equal(relisted.expiredStatus,410);assert.equal(relisted.ready,true);
 const changed=JSON.parse(kubectl(["patch","certificate","owned","-n",namespace,"--type=merge","-p",JSON.stringify({metadata:{annotations:{"qualification-compaction":"post-compaction-watch"}}}),"-o","json"]));write("changed",{resourceVersion:changed.metadata.resourceVersion});
 kubectl(["wait","--for=jsonpath={.status.phase}=Succeeded","pod/compaction-fixture","-n",namespace,"--timeout=120s"]);const result=JSON.parse(kubectl(["logs","compaction-fixture","-n",namespace]));assert.equal(result.expiredStatus,410);assert.equal(result.certificateUid,checkpoint.certificateUid);assert.equal(result.observedResourceVersion,changed.metadata.resourceVersion);assert.equal(result.compactedRevision,String(revision));
 gate.report.nativeCompaction={...result,controlPlaneRestarted:true,ownedSingleNodeCluster:true};
}
module.exports={qualifyNativeCompaction,validateClusterIdentity,apiContainer};
