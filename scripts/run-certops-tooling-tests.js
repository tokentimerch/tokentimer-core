"use strict";
// Discover framework regressions rather than maintaining a second partial list.
// These tests validate reports, ownership and CI plumbing, never provision labs.
const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict"),{spawnSync}=require("node:child_process");
// The growing source/provenance adversaries hash all declared native fixture
// dependencies. Keep a finite five-minute bound, within the 15-minute tooling
// job, without dropping coverage when slower Windows filesystems exceed 3min.
const TOOLING_TIMEOUT_MS=300000;
function discover(root=path.resolve(__dirname,"..")){const files=fs.readdirSync(path.join(root,"scripts")).filter(file=>/^certops-.*\.test\.js$/.test(file)).map(file=>`scripts/${file}`).sort();assert.ok(files.length>0,"No qualification framework tests discovered");return ["packages/agent/scripts/host-gate.test.js",...files];}
if(require.main===module){const result=spawnSync(process.execPath,["--test",...discover()],{stdio:"inherit",timeout:TOOLING_TIMEOUT_MS,env:{...process.env,NODE_ENV:"test"}});if(result.error)console.error("Qualification framework tests failed or exceeded their bound");process.exitCode=result.status===0?0:1;}
module.exports={discover,TOOLING_TIMEOUT_MS};
