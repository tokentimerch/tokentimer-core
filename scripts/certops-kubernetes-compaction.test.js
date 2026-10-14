"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {validateClusterIdentity,apiContainer}=require("./certops-kubernetes-compaction");
function fixture(){const context="kind-certops-qualification-12345",node="certops-qualification-12345-control-plane";return {context,nodes:{items:[{metadata:{name:node,labels:{"node-role.kubernetes.io/control-plane":""}}}]},container:{Id:"a".repeat(64),Name:`/${node}`,Config:{Labels:{"io.x-k8s.kind.cluster":"certops-qualification-12345","io.x-k8s.kind.role":"control-plane"}},State:{Running:true}}};}
test("compaction requires the exact owned single-node kind control plane",()=>{const value=fixture();assert.deepEqual(validateClusterIdentity(value),{cluster:"certops-qualification-12345",node:"certops-qualification-12345-control-plane",containerId:"a".repeat(64)});assert.equal(validateClusterIdentity({...value,expectedContainerId:"a".repeat(64)}).containerId,"a".repeat(64));});
test("compaction refuses foreign contexts nodes labels stopped nodes and replacement Docker identity",()=>{
 const changes=[value=>{value.context="production";},value=>{value.nodes.items.push(structuredClone(value.nodes.items[0]));},value=>{value.nodes.items[0].metadata.name="foreign-control-plane";},value=>{delete value.nodes.items[0].metadata.labels["node-role.kubernetes.io/control-plane"];},value=>{value.container.Name="/foreign";},value=>{value.container.Config.Labels["io.x-k8s.kind.cluster"]="foreign";},value=>{value.container.Config.Labels["io.x-k8s.kind.role"]="worker";},value=>{value.container.State.Running=false;},value=>{value.expectedContainerId="b".repeat(64);},value=>{value.container.Id="not-native-id";}];
 for(const mutate of changes){const value=fixture();mutate(value);assert.throws(()=>validateClusterIdentity(value));}
});
test("API restart selects exactly one native running API container from the same control-plane pod",()=>{
 const node="certops-qualification-12345-control-plane",entry={id:"c".repeat(64),metadata:{name:"kube-apiserver"},state:"CONTAINER_RUNNING",labels:{"io.kubernetes.pod.namespace":"kube-system","io.kubernetes.pod.name":`kube-apiserver-${node}`}};
 assert.equal(apiContainer({containers:[entry]},node),entry.id);
 for(const mutate of [value=>{value.state="CONTAINER_EXITED";},value=>{value.metadata.name="etcd";},value=>{value.labels["io.kubernetes.pod.namespace"]="foreign";},value=>{value.labels["io.kubernetes.pod.name"]="foreign";},value=>{value.id="unsafe";}]){const value=structuredClone(entry);mutate(value);assert.throws(()=>apiContainer({containers:[value]},node));}
 assert.throws(()=>apiContainer({containers:[entry,entry]},node));assert.throws(()=>apiContainer({containers:[]},node));
});
