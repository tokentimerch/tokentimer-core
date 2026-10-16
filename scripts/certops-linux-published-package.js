"use strict";
/* Verify the immutable public Linux predecessor and the candidate's real release
 * archive before extracting either into a fresh disposable runner directory.
 * Never substitutes source-built history or Windows binaries into a published asset.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),{spawnSync}=require("node:child_process");
const baseline=Object.freeze({tag:"v0.17.2",version:"0.17.2",assetId:612562598,size:410054,sha256:"c602fe36825c74d423c2c9b89680df3b1ac76542f71804de14dc5e2ec5aa85bf",url:"https://github.com/tokentimerch/tokentimer-core/releases/download/v0.17.2/tokentimer-agent-0.17.2.tgz"});
const sha=file=>crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
// Git's tar treats Windows drive letters as remote archive syntax. Bind the
// native Windows tool even when Git supplies OpenSSL earlier on PATH.
function run(args){const tar=process.platform==="win32"?path.join(process.env.SystemRoot,"System32","tar.exe"):"tar";const result=spawnSync(tar,args,{encoding:"utf8",timeout:60000,maxBuffer:4*1024*1024});assert.ifError(result.error);assert.equal(result.status,0,"Release archive inspection/extraction failed");return result.stdout;}
function validateMembers(members){assert.ok(members.length>0);assert.equal(new Set(members).size,members.length,"Duplicate archive members are refused");for(const name of members)assert.ok(name.startsWith("package/")&&!name.includes("\\")&&!name.split("/").includes("..")&&!/[\x00-\x1f]/.test(name),"Unsafe release archive member");}
// Read every regular file without following links. Names/hashes come from a
// separately extracted verified archive, never from the caller's source tree.
function treeInventory(directory){
 assert.equal(fs.lstatSync(directory).isDirectory(),true);assert.equal(fs.lstatSync(directory).isSymbolicLink(),false);const files=[];
 const walk=(current)=>{for(const name of fs.readdirSync(current).sort()){const full=path.join(current,name),stat=fs.lstatSync(full),relative=path.relative(directory,full).split(path.sep).join("/");assert.equal(stat.isSymbolicLink(),false,"Release tree links are refused");if(stat.isDirectory())walk(full);else{assert.equal(stat.isFile(),true,"Release tree special entries are refused");files.push({file:relative,sha256:sha(full),size:stat.size});}}};walk(directory);return files.sort((a,b)=>a.file.localeCompare(b.file));
}
function archiveInventory(archive){
 const directory=fs.mkdtempSync(path.join(require("node:os").tmpdir(),"certops-archive-inventory-"));
 try{run(["-xzf",archive,"--strip-components=1","--no-same-owner","--no-same-permissions","-C",directory]);const files=treeInventory(directory);assert.ok(files.length>0);return files;}
 finally{fs.rmSync(directory,{recursive:true,force:true});}
}
function verifyTree(directory,inventory,{installed=false}={}){
 assert.ok(Array.isArray(inventory)&&inventory.length>0);
 // install-agent.sh excludes exactly the package root's ./node_modules. It
 // atomically replaces the app tree, so extra installed runtime files fail.
 const expected=installed?inventory.filter(entry=>entry.file.split("/")[0]!=="node_modules"):inventory;
 assert.deepEqual(treeInventory(directory),expected,"Extracted/installed release tree differs from the verified archive");return true;
}
function laterVersion(candidate){assert.match(candidate,/^\d+\.\d+\.\d+$/);const left=candidate.split(".").map(Number),right=baseline.version.split(".").map(Number);const index=left.findIndex((value,i)=>value!==right[i]);assert.ok(index>=0&&left[index]>right[index],"Candidate must be a true later version than the published baseline");return candidate;}
function inspect(archive,checksum,published=false){
 const actual=sha(archive),name=path.basename(archive),line=fs.readFileSync(checksum,"utf8").trim();assert.equal(line,`${actual}  ${name}`,"Archive checksum file mismatch");
 const members=run(["-tzf",archive]).split(/\r?\n/).filter(Boolean);validateMembers(members);
 const types=run(["-tvzf",archive]).split(/\r?\n/).filter(Boolean);assert.ok(types.every(line=>line[0]==="-"||line[0]==="d"),"Archive links or special entries are not accepted");
 const pkg=JSON.parse(run(["-xOf",archive,"package/package.json"]));assert.deepEqual(pkg.dependencies||{},{});assert.equal(pkg.name,"@tokentimer/agent");
 for(const file of ["bin/tokentimer-agent.js","src/index.js","src/config/index.js","scripts/install-agent.sh","scripts/tokentimer-agent.service","scripts/host-sandbox.js","scripts/validate-server-url.js","vendor/contracts/agent-protocol-validator.generated.js"])assert.ok(members.includes(`package/${file}`),`Linux runtime archive prerequisite missing: ${file}`);
 if(published){assert.equal(name,`tokentimer-agent-${baseline.version}.tgz`);assert.equal(actual,baseline.sha256);assert.equal(fs.statSync(archive).size,baseline.size);assert.equal(pkg.version,baseline.version);}else laterVersion(pkg.version);
 return {version:pkg.version,archiveSha256:actual,archiveSize:fs.statSync(archive).size,fileInventory:archiveInventory(archive)};
}
function verifyReleaseMetadata(value){assert.equal(value.tag_name,baseline.tag);assert.equal(value.draft,false);assert.equal(value.prerelease,false);const matches=value.assets.filter(asset=>asset.id===baseline.assetId);assert.equal(matches.length,1);const asset=matches[0];assert.equal(asset.name,`tokentimer-agent-${baseline.version}.tgz`);assert.equal(asset.size,baseline.size);assert.equal(asset.digest,`sha256:${baseline.sha256}`);assert.equal(asset.browser_download_url,baseline.url);return true;}
function prepare(oldArchive,oldChecksum,newArchive,newChecksum,output){
 assert.equal(process.platform,"linux");require("./certops-linux-systemd-ownership").validateHostedEnvironment(process.env);assert.match(process.env.GITHUB_SHA||"",/^[a-f0-9]{40}$/);
 const temp=fs.realpathSync(process.env.RUNNER_TEMP),directory=path.resolve(output);assert.equal(path.dirname(directory),temp);assert.equal(path.basename(directory),"certops-linux-published-upgrade");assert.equal(fs.lstatSync(directory,{throwIfNoEntry:false}),undefined);
 const old=inspect(oldArchive,oldChecksum,true),candidate=inspect(newArchive,newChecksum);assert.equal(candidate.version,require("../packages/agent/package.json").version);
 fs.mkdirSync(directory,{mode:0o700});for(const [name,archive] of [["published",oldArchive],["candidate",newArchive]]){const target=path.join(directory,name);fs.mkdirSync(target,{mode:0o755});run(["-xzf",archive,"--strip-components=1","--no-same-owner","--no-same-permissions","-C",target]);}
 verifyTree(path.join(directory,"published"),old.fileInventory);verifyTree(path.join(directory,"candidate"),candidate.fileInventory);
 const manifest={schemaVersion:1,baseline:{...baseline,...old,directory:path.join(directory,"published"),archive:path.resolve(oldArchive),checksum:path.resolve(oldChecksum)},candidate:{...candidate,directory:path.join(directory,"candidate"),archive:path.resolve(newArchive),checksum:path.resolve(newChecksum),candidateSha:process.env.GITHUB_SHA}};
 fs.writeFileSync(path.join(directory,"inputs.json"),JSON.stringify(manifest),{flag:"wx",mode:0o600});return manifest;
}
function loadManifest(file){
 require("./certops-linux-systemd-ownership").validateHostedEnvironment(process.env);const directory=path.join(fs.realpathSync(process.env.RUNNER_TEMP),"certops-linux-published-upgrade");assert.equal(path.resolve(file),path.join(directory,"inputs.json"));assert.equal(fs.lstatSync(file).isSymbolicLink(),false);
 assert.equal(fs.lstatSync(directory).isSymbolicLink(),false);assert.equal(fs.lstatSync(file).isFile(),true);const value=JSON.parse(fs.readFileSync(file,"utf8"));assert.equal(value.schemaVersion,1);assert.equal(value.baseline.directory,path.join(directory,"published"));assert.equal(value.candidate.directory,path.join(directory,"candidate"));assert.equal(value.candidate.candidateSha,process.env.GITHUB_SHA);
 for(const [key,published] of [["baseline",true],["candidate",false]]){assert.equal(fs.lstatSync(value[key].directory).isSymbolicLink(),false);const actual=inspect(value[key].archive,value[key].checksum,published);assert.equal(actual.version,value[key].version);assert.equal(actual.archiveSha256,value[key].archiveSha256);assert.equal(actual.archiveSize,value[key].archiveSize);assert.equal(JSON.parse(fs.readFileSync(path.join(value[key].directory,"package.json"))).version,actual.version);verifyTree(value[key].directory,actual.fileInventory);value[key].fileInventory=actual.fileInventory;}
 assert.equal(value.baseline.assetId,baseline.assetId);assert.equal(value.baseline.sha256,baseline.sha256);assert.equal(value.candidate.version,require("../packages/agent/package.json").version);return value;
}
if(require.main===module){try{if(process.argv[2]==="--verify-release")verifyReleaseMetadata(JSON.parse(fs.readFileSync(process.argv[3],"utf8")));else prepare(...process.argv.slice(2));}catch(error){console.error(error.message);process.exitCode=1;}}
module.exports={baseline,inspect,prepare,loadManifest,validateMembers,laterVersion,verifyReleaseMetadata,treeInventory,verifyTree};
