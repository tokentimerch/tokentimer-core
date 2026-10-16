"use strict";
// Prevent hosted-image kubectl upgrades from silently exceeding the pinned
// disposable API server's supported minor-version skew in native qualification.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path");
test("native Kubernetes workflows install the verified matching client before creating their cluster",()=>{
 const root=path.resolve(__dirname,".."),yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");const installer=fs.readFileSync(path.join(__dirname,"certops-kubernetes-tools.sh"),"utf8");const version=installer.match(/https:\/\/dl\.k8s\.io\/release\/(v\d+\.\d+\.\d+)\/bin\/linux\/amd64\/kubectl/)?.[1];assert.ok(version);assert.match(installer,/sha256sum -c -/);assert.match(installer,/RUNNER_ENVIRONMENT/);
 for(const file of ["certops-kubernetes-qualification.yml","certops-kubernetes-http01-qualification.yml"]){const workflow=yaml.load(fs.readFileSync(path.join(root,".github/workflows",file),"utf8"));const steps=workflow.jobs["controller-host"].steps,installation=steps.findIndex(step=>step.run==="bash scripts/certops-kubernetes-tools.sh"),creation=steps.findIndex(step=>/kind create cluster/.test(step.run||""));assert.ok(installation>=0&&installation<creation);assert.ok(steps[creation].run.includes(`kindest/node:${version}@sha256:`));}
});
