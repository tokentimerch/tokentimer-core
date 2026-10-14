"use strict";
// Select only the trusted push's affected qualification lanes. This never
// dispatches paid labs; manual requests choose one bounded lane or all three.
const assert=require("node:assert/strict"),fs=require("node:fs"),{spawnSync}=require("node:child_process");
const LANES=Object.freeze(["tooling","windows","stack","all"]);
function all(reason){return {tooling:true,windows:true,stack:true,reason};}
function selectFiles(files){
 assert.ok(Array.isArray(files));const selected={tooling:true,windows:false,stack:false,reason:"changed-files"};
 for(const file of files){
  assert.equal(typeof file,"string");assert.ok(file&&!file.startsWith("/")&&!file.includes("\\")&&!file.split("/").includes("..")&&!/[\x00-\x1f]/.test(file));
  if(/\.md$/i.test(file))continue;
  if(/^(package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|\.npmrc)$/.test(file)||/^packages\/(shared|contracts)\//.test(file))return all("shared-runtime-or-dependencies");
  if(/^packages\/agent\//.test(file)){
   if(!/^packages\/agent\/scripts\/(host-gate(?:\.test)?\.js|.*(?:report|qualification).*\.js)$/.test(file)){selected.windows=true;selected.stack=true;}
  }
  if(/^packages\/(?!agent\/)/.test(file))selected.stack=true;
  if(/^apps\/(api|worker)\//.test(file)||/^deploy\/compose\//.test(file)||/^tests\/(e2e|integration)\//.test(file))selected.stack=true;
  if(/^scripts\/certops-(api-qualification|stack-report|stack-reporter|linux-discovery-report)\.js$/.test(file))selected.stack=true;
  if(/^\.github\/workflows\/certops-qualification\.yml$/.test(file))return all("qualification-workflow-changed");
 }
 return selected;
}
function manual(lane){assert.ok(LANES.includes(lane),"Unknown qualification lane");return lane==="all"?all("manual-all"):{tooling:lane==="tooling",windows:lane==="windows",stack:lane==="stack",reason:`manual-${lane}`};}
function git(args){const result=spawnSync("git",args,{encoding:"utf8",timeout:15000,maxBuffer:4*1024*1024});if(result.error||result.status!==0)throw new Error("Trusted candidate Git history unavailable");return result.stdout;}
function main(){
 assert.equal(process.env.GITHUB_REF,"refs/heads/main");const sha=process.env.GITHUB_SHA;assert.match(sha||"",/^[a-f0-9]{40}$/);assert.equal(git(["rev-parse","HEAD"]).trim(),sha,"Selector must inspect the exact checked-out candidate");
 const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,"utf8"));let selection;
 if(process.env.GITHUB_EVENT_NAME==="workflow_dispatch")selection=manual(process.env.CERTOPS_CI_LANE||"tooling");
 else{
  assert.equal(process.env.GITHUB_EVENT_NAME,"push");if(event.after)assert.equal(event.after,sha);const before=event.before;
  if(event.forced||!before||/^0{40}$/.test(before))selection=all("missing-or-forced-history");
  else{assert.match(before,/^[a-f0-9]{40}$/);try{const files=git(["diff","--name-only","--no-renames","-z",before,sha,"--"]).split("\0").filter(Boolean);selection=selectFiles(files);selection.changedFileCount=files.length;}catch{selection=all("history-unavailable");}}
 }
 fs.appendFileSync(process.env.GITHUB_OUTPUT,[...Object.entries(selection).filter(([key])=>["tooling","windows","stack"].includes(key)).map(([key,value])=>`${key}=${value}`),`candidate_sha=${sha}`,""].join("\n"));
 if(process.env.GITHUB_STEP_SUMMARY)fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,`CertOps lane selection for \`${sha}\`\n\nReason: ${selection.reason}.\n\n`+["tooling","windows","stack"].map(lane=>`- ${lane}: ${selection[lane]?"selected":"not selected"}`).join("\n")+"\n");
 console.log(JSON.stringify({...selection,candidateSha:sha}));
}
if(require.main===module)main();
module.exports={selectFiles,manual,LANES};
