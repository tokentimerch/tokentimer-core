"use strict";
// Validate actual GitHub Actions expressions/schema, beyond YAML syntax.
// CI supplies the checksum-pinned official Actionlint binary; no jobs execute.
const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict"),{spawnSync}=require("node:child_process");
const VERSION="1.7.12";
function validate(files,{binary=process.env.CERTOPS_ACTIONLINT||"actionlint"}={}){assert.ok(Array.isArray(files)&&files.length>0);const version=spawnSync(binary,["-version"],{encoding:"utf8",timeout:10000});if(version.error||version.status!==0||version.stdout.split(/\r?\n/)[0]!==VERSION)throw new Error(`Official Actionlint ${VERSION} prerequisite missing or wrong version`);return spawnSync(binary,["-shellcheck=","-pyflakes=",...files],{encoding:"utf8",timeout:45000,maxBuffer:4*1024*1024});}
function discover(){return fs.readdirSync(path.resolve(__dirname,"../.github/workflows")).filter(file=>/^certops-.*\.yml$/.test(file)).sort().map(file=>path.resolve(__dirname,"../.github/workflows",file));}
if(require.main===module){const result=validate(discover());if(result.stdout)process.stdout.write(result.stdout);if(result.stderr)process.stderr.write(result.stderr);if(result.error)console.error("Qualification workflow schema validation failed or exceeded its bound");process.exitCode=result.status===0?0:1;}
module.exports={validate,discover,VERSION};
