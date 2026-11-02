"use strict";
// Reproduce the real Actions context error that YAML parsing misses, then
// enforce the pinned semantic validator over every qualification workflow.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os");
const {validate,discover}=require("./certops-actions-schema");
test("actual Actions schema validator catches job-level service context that valid YAML permits",()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),"certops-actions-schema-")),file=path.join(root,"fixture.yml");
 const base="name: Fixture\non: workflow_dispatch\njobs:\n  migration:\n    runs-on: ubuntu-24.04\n    env:\n      DB_PORT: ${{ job.services.postgres.ports[5432] }}\n    steps:\n      - run: echo fixture\n";
 try{fs.writeFileSync(file,base);const failed=validate([file]);assert.notEqual(failed.status,0);assert.match(failed.stdout,/context "job" is not allowed here/);assert.match(failed.stdout,/got "number"/);
 fs.writeFileSync(file,"name: Fixture\non: workflow_dispatch\njobs:\n  migration:\n    runs-on: ubuntu-24.04\n    steps:\n      - env:\n          DB_PORT: ${{ job.services.postgres.ports['5432'] }}\n        run: echo fixture\n");const accepted=validate([file]);assert.equal(accepted.status,0,accepted.stdout+accepted.stderr);
 }finally{fs.rmSync(root,{recursive:true});}
});
test("every current qualification workflow passes actual pinned Actions schema validation",()=>{const result=validate(discover());assert.equal(result.status,0,result.stdout+result.stderr);});
