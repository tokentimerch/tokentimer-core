"use strict";
// Expand explicitly selected manual qualification dimensions from committed
// allowlists. Defaults run one cell; only 'all' requests the complete matrix.
const assert=require("node:assert/strict"),fs=require("node:fs"),{spawnSync}=require("node:child_process");
const GROUPS=Object.keys(require("../tests/integration/certops-qualification-groups.json"));
const DEFINITIONS=Object.freeze({integration:{group:{values:GROUPS,default:"adcs"}},"linux-acme":{client:{values:["certbot","acme.sh"],default:"certbot"},eab:{values:["none","required"],default:"none"}},server:{os:{values:["ubuntu-22.04","ubuntu-24.04"],default:"ubuntu-24.04"},service:{values:["nginx","apache","haproxy"],default:"nginx"}}});
function matrixFor(kind,requested={}){
 assert.ok(Object.hasOwn(DEFINITIONS,kind),"Unknown manual qualification matrix");assert.ok(requested&&typeof requested==="object"&&!Array.isArray(requested));const definition=DEFINITIONS[kind];for(const key of Object.keys(requested))assert.ok(Object.hasOwn(definition,key),"Unknown matrix dimension");let include=[{}];
 for(const [key,rule]of Object.entries(definition)){const value=requested[key]===undefined?rule.default:requested[key];assert.equal(typeof value,"string");assert.ok(rule.values.includes(value)||value==="all",`Unknown ${key} selection`);const selected=value==="all"?rule.values:[value];assert.ok(selected.length>0);include=include.flatMap(cell=>selected.map(item=>({...cell,[key]:item})));}
 assert.ok(include.length>0&&include.length<=32,"Manual qualification expansion exceeds its bound");return {include};
}
function main(){assert.equal(process.env.GITHUB_REF,"refs/heads/main");assert.equal(process.env.GITHUB_EVENT_NAME,"workflow_dispatch");assert.match(process.env.GITHUB_SHA||"",/^[a-f0-9]{40}$/);const checked=spawnSync("git",["rev-parse","HEAD"],{encoding:"utf8",timeout:10000});assert.equal(checked.status,0);assert.equal(checked.stdout.trim(),process.env.GITHUB_SHA);const input=JSON.parse(process.env.CERTOPS_MATRIX_INPUTS_JSON||"{}");const matrix=matrixFor(process.argv[2],input);fs.appendFileSync(process.env.GITHUB_OUTPUT,`matrix=${JSON.stringify(matrix)}\n`);console.log(JSON.stringify({kind:process.argv[2],candidateSha:process.env.GITHUB_SHA,matrix}));}
if(require.main===module)main();
module.exports={DEFINITIONS,matrixFor};
