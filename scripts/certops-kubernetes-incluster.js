"use strict";
// Runs only inside the disposable qualification cluster under its scoped
// ServiceAccount; production client loads the mounted in-cluster credentials.
const assert=require("node:assert/strict");
const {createInClusterCertManagerClient}=require("/app/apps/k8s-controller/src/cert-manager-client");
const {createCertificateProvisioner}=require("/app/apps/k8s-controller/src/certificate-provisioner");
async function main(){
  const command=JSON.parse(process.env.CERTOPS_TEST_COMMAND);
  let client=createInClusterCertManagerClient({provisionEnabled:true});
  await client.start();
  try{
    await assert.rejects(client.getCertificate({namespace:"default",name:command.certificateName}),error=>Number(error.code||error.statusCode||error.response?.statusCode)===403);
    await assert.rejects(client.readTlsCertificate({namespace:command.namespace,secretName:command.secretName}),{code:"CERTOPS_SECRET_FALLBACK_DISABLED"});
    const provisioner=createCertificateProvisioner({client,workspaceId:command.workspaceId,clusterId:command.clusterId,watchNamespaces:[command.namespace],authorizeMutation:async()=>{}});
    if(process.env.CERTOPS_TEST_OBSERVE_ONLY==="1"){
      const forbidden=error=>Number(error.code||error.statusCode||error.response?.statusCode)===403;
      assert.equal((await provisioner.reconcile(command)).operation,"unchanged");
      await assert.rejects(provisioner.reconcile({...command,certificateName:"forbidden-create",secretName:"forbidden-create-tls"}),forbidden);
      await assert.rejects(provisioner.reconcile({...command,dnsNames:[...command.dnsNames,"forbidden.certops.invalid"]}),forbidden);
      console.log("CERTOPS_INCLUSTER_RESULT=passed");
      return;
    }
    assert.equal((await provisioner.reconcile(command)).operation,"created");
    assert.equal((await provisioner.reconcile(command)).operation,"unchanged");
    const changed={...command,dnsNames:[...command.dnsNames,"second.certops.invalid"]};
    const snapshot=await client.list({resource:"Certificate",namespace:command.namespace});
    assert.ok(snapshot.items.some(item=>item.metadata.name===command.certificateName));
    let timer;
    let resolveEvent;
    let rejectEvent;
    const event=new Promise((resolve,reject)=>{resolveEvent=resolve;rejectEvent=reject;timer=setTimeout(()=>reject(new Error("Expected native watch update missing")),30000);});
    // Observe early stream failure even while the mutation is in flight.
    event.catch(()=>{});
    const watcher=await client.watch({resource:"Certificate",namespace:command.namespace,resourceVersion:snapshot.resourceVersion,onEvent:(phase,object)=>{
      if(phase==="MODIFIED"&&object.metadata.name===command.certificateName&&object.spec.dnsNames.includes("second.certops.invalid"))resolveEvent();
    },onError:error=>{if(error)rejectEvent(error);}});
    try{
      assert.equal((await provisioner.reconcile(changed)).operation,"reconciled");
      await event;
    }finally{clearTimeout(timer);watcher.close();}
    const object=await client.getCertificate({namespace:command.namespace,name:command.certificateName});
    const resource=object.body||object;
    assert.ok(resource.spec.dnsNames.includes("second.certops.invalid"));
    await client.close();
    client=createInClusterCertManagerClient({provisionEnabled:true});
    await client.start();
    const restarted=createCertificateProvisioner({client,workspaceId:command.workspaceId,clusterId:command.clusterId,watchNamespaces:[command.namespace],authorizeMutation:async()=>{}});
    assert.equal((await restarted.reconcile(changed)).operation,"unchanged");
    const reread=await client.getCertificate({namespace:command.namespace,name:command.certificateName});
    assert.equal((reread.body||reread).metadata.uid,resource.metadata.uid);
    console.log("CERTOPS_INCLUSTER_RESULT=passed");
  }finally{await client.close();}
}
main().catch(error=>{console.error("CERTOPS_INCLUSTER_RESULT=failed code="+(error.code||error.statusCode||"native-client-error"));process.exitCode=1;});
