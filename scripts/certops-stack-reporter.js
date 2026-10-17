"use strict";
/**
 * Node test reporter emitting bounded test events, measured host identity and current source hashes.
 * Selected with --test-reporter by qualification harnesses. It records actual Node test outcomes;
 * scope-specific native claims still require the matching mandatory journey and downstream verifier.
 */
const fs=require("node:fs");
const path=require("node:path");
const crypto=require("node:crypto");
const os=require("node:os");
const {spawnSync}=require("node:child_process");
function measuredEnvironment(){
  if(process.platform === "win32"){
    const result=spawnSync("powershell.exe",["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; $os=Get-CimInstance Win32_OperatingSystem; @{build=$os.BuildNumber; productType=$os.ProductType; language=(Get-UICulture).Name; identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name; sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}|ConvertTo-Json -Compress"],{encoding:"utf8",timeout:10000});
    if(result.status!==0)throw new Error("Native Windows qualification identity measurement failed");
    const value=JSON.parse(result.stdout);
    if(![1,2,3].includes(value.productType) || !/^\d+$/.test(value.build))throw new Error("Native Windows product type/build measurement missing");
    return {osFamily:"windows",osVersion: value.productType === 1 ? `desktop-${value.build}` : ({"17763":"2019","20348":"2022","26100":"2025"}[value.build] || "unsupported"),productType:value.productType,nativeLanguage:value.language,identity:value.sid === "S-1-5-18" ? "LocalSystem" : value.identity,measurement:"native"};
  }
  const distribution={};
  if(process.platform === "linux"){
    const release=fs.readFileSync("/etc/os-release","utf8");
    for(const [key,field] of [["ID","distributionId"],["VERSION_ID","distributionVersion"]]){
      const match=release.match(new RegExp(`^${key}=(.*)$`,"m"));
      if(match)distribution[field]=match[1].replace(/^(["'])(.*)\1$/,"$2");
    }
  }
  const libc = process.platform === "linux" ? (process.report.getReport().header.glibcVersionRuntime ? "glibc" : fs.existsSync("/lib/ld-musl-x86_64.so.1") || fs.existsSync("/lib/ld-musl-aarch64.so.1") ? "musl" : "unknown") : null;
  return {osFamily:process.platform,osVersion:os.release(),...distribution,executionSurface:fs.existsSync("/.dockerenv") ? "container" : "host",...(libc ? {libc} : {}),nativeLanguage:Intl.DateTimeFormat().resolvedOptions().locale,identity:`uid:${process.getuid()}`,measurement:"native"};
}
function supplementalSources(scope){
  let files;
  if(scope.startsWith("real-agent-windows-acme-iis/"))files=[...require("../tests/e2e/helpers/certops-windows-source-junction").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-installed-weak-acl").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-active-service-controls").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-credential-refusal").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-retention-config").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-public-retirement").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-config-encoding").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-service-controls").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-rename-refusal").requiredSources,...require("../tests/e2e/helpers/certops-windows-second-rename").requiredSources,...require("../tests/e2e/helpers/certops-windows-owned-process").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-installed-paths").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-installed-iis-refusal").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-windows-key-reuse-refusal").requiredSources,"scripts/certops-installer-pe.test.ps1","tests/e2e/helpers/certops-windows-public-issuance.js","tests/e2e/helpers/certops-api-fixture.js","tests/e2e/helpers/certops-windows-reregistration.js","tests/e2e/helpers/certops-windows-capability-refresh.js","tests/e2e/helpers/certops-windows-output-child.js","tests/e2e/helpers/certops-windows-output-privacy.js","tests/e2e/windows-real-journey.js",...require("../tests/e2e/helpers/certops-windows-installed-handoff").REQUIRED_SOURCES];
  else if(["real-agent-acme-filesystem","real-agent-acme-eab-filesystem","real-agent-acmesh-filesystem","real-agent-acmesh-eab-filesystem","real-agent-alpine-certbot","real-agent-alpine-acmesh"].includes(scope))files=[...new Set(["tests/e2e/acme-real-journey.js","scripts/certops-real-acme.js",...require("../tests/e2e/helpers/certops-acme-lease-loss").REQUIRED_SOURCES,"scripts/certops-stack-reporter.js",...require("../tests/e2e/helpers/certops-acme-key-reuse").requiredSources,...require("../tests/e2e/helpers/certops-acme-stage-faults").REQUIRED_SOURCES,"scripts/certops-acme-stage-report.js",...require("../tests/e2e/helpers/certops-acme-background-renewals").REQUIRED_SOURCES,"scripts/certops-acme-background-report.js","scripts/certops_acme_background_proof.py"])];
  else return undefined;
  if(scope==="real-agent-acme-filesystem")files.push(...require("../tests/e2e/helpers/certops-acme-renewal-alert").REQUIRED_SOURCES,"scripts/certops-acme-renewal-alert-report.js","scripts/certops_acme_renewal_alert_proof.py",...require("../tests/e2e/helpers/certops-acme-disabled-profile").REQUIRED_SOURCES,"scripts/certops-acme-disabled-profile-report.js","scripts/certops_acme_disabled_profile_proof.py",...require("../tests/e2e/helpers/certops-acme-certificate-outbox").REQUIRED_SOURCES,"scripts/certops-acme-certificate-outbox-report.js","scripts/certops_acme_certificate_outbox_proof.py",...require("../tests/e2e/helpers/certops-acme-native-adoption").REQUIRED_SOURCES,"scripts/certops-acme-native-adoption-report.js","scripts/certops_acme_native_adoption_proof.py",...require("../tests/e2e/helpers/certops-acme-bulk-renewal").REQUIRED_SOURCES,"scripts/certops-acme-bulk-report.js","scripts/certops_acme_bulk_proof.py");
  const root=path.resolve(__dirname,"..");return [...new Set(files)].map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
}
function windowsPublicIssueProof(scope,name,root=path.resolve(__dirname,"..")){
  if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
  const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows issue proof profile");
  const facts=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`windows-public-issue-${profile}.json`),"utf8"));
  require("../tests/e2e/helpers/certops-windows-public-issuance").verifyPublicIssuanceFacts(facts);return facts;
}
function windowsKeyReuseRefusalProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows reuse refusal profile");
 const proof=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`windows-key-reuse-refusal-${profile}.json`),"utf8"));require("../tests/e2e/helpers/certops-windows-key-reuse-refusal").verifyProof(proof);return proof;
}
function publicRetirementProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows retirement proof profile");
 const file=path.join(root,"qualification-results",`windows-public-retirement-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows retirement proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows retirement proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows retirement proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows retirement proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-public-retirement").verifyProof(value);return value;
}
function retentionConfigProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows retention policy proof profile");
 const file=path.join(root,"qualification-results",`windows-retention-config-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows retention policy proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows retention policy proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows retention policy proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows retention policy proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-retention-config").verifyProof(value);return value;
}
function signingPinRefusalProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows credential refusal proof profile");
 const file=path.join(root,"qualification-results",`windows-signing-pin-refusal-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows credential refusal proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows credential refusal proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows credential refusal proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows credential refusal proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").verifyProof(value);return value;
}
function credentialRefusalProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows credential refusal proof profile");
 const file=path.join(root,"qualification-results",`windows-credential-refusal-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows credential refusal proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows credential refusal proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows credential refusal proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows credential refusal proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-credential-refusal").verifyProof(value);return value;
}
function installedWeakAclProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows credential refusal proof profile");
 const file=path.join(root,"qualification-results",`windows-installed-weak-acl-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows credential refusal proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows credential refusal proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows credential refusal proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows credential refusal proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-installed-weak-acl").verifyProof(value);return value;
}
function sourceJunctionProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows credential refusal proof profile");
 const file=path.join(root,"qualification-results",`windows-source-junction-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows credential refusal proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows credential refusal proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows credential refusal proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows credential refusal proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-source-junction").verifyProof(value);return value;
}
function configEncodingProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows encoding proof profile");
 const file=path.join(root,"qualification-results",`windows-config-encoding-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows encoding proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows encoding proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows encoding proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows encoding proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-config-encoding").verifyProof(value);return value;
}
function serviceControlsProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows SCM proof profile");
 const file=path.join(root,"qualification-results",`windows-service-controls-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows SCM proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows SCM proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows SCM proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows SCM proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-service-controls").verifyProof(value);return value;
}
function activeServiceControlsProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows SCM proof profile");
 const file=path.join(root,"qualification-results",`windows-active-service-controls-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows SCM proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows SCM proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows SCM proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows SCM proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-active-service-controls").verifyProof(value);return value;
}
function installedVerifyRollbackProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid installed verification rollback profile");
 const helper=require("../tests/e2e/helpers/certops-windows-installed-verify-rollback"),value=JSON.parse(helper.readOwned(path.join(root,"qualification-results",`windows-installed-verify-rollback-${profile}.json`),16384).bytes.toString("utf8"));helper.verifyProof(value);return value;
}
function multiTargetAdmissionProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid Windows SCM proof profile");
 const file=path.join(root,"qualification-results",`windows-multi-target-admission-${profile}.json`),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>16384)throw new Error("Unsafe bounded Windows SCM proof");
 const fd=fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));let bytes;
 try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==stat.dev||opened.ino!==stat.ino||opened.size!==stat.size)throw new Error("Windows SCM proof replaced");const buffer=Buffer.alloc(16385);let length=0;while(length<buffer.length){const read=fs.readSync(fd,buffer,length,buffer.length-length,null);if(read===0)break;length+=read;}if(length!==stat.size||length>16384)throw new Error("Windows SCM proof exceeded byte bound");bytes=buffer.subarray(0,length);}finally{fs.closeSync(fd);}
 const after=fs.lstatSync(file);if(!after.isFile()||after.isSymbolicLink()||after.dev!==stat.dev||after.ino!==stat.ino||after.size!==bytes.length)throw new Error("Windows SCM proof ownership changed");
 const value=JSON.parse(bytes.toString("utf8"));require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").verifyProof(value);return value;
}
function installedPathsProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid installed paths profile");
 const value=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`windows-installed-paths-${profile}.json`),"utf8"));require("../tests/e2e/helpers/certops-windows-installed-paths").verifyProof(value);return value;
}
function installedCrashProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid installed crash profile");
 const value=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`windows-native-crash-${profile}.json`),"utf8"));require("../tests/e2e/helpers/certops-windows-owned-process").verifyPublicProof(value);return value;
}
function installedIisRefusalProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid installed IIS refusal profile");
 const value=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`windows-installed-iis-refusal-${profile}.json`),"utf8"));require("../tests/e2e/helpers/certops-windows-installed-iis-refusal").verifyProof(value);return value;
}
function installedHandoffProof(scope,name,root=path.resolve(__dirname,"..")){
 if(!scope.startsWith("real-agent-windows-acme-iis/")||name!=="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence")return undefined;
 const profile=scope.split("/")[1];if(!["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"].includes(profile))throw new Error("Invalid installed handoff profile");const proof=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`windows-installed-handoff-${profile}.json`),"utf8"));require("../tests/e2e/helpers/certops-windows-installed-handoff").verifyProof(proof);return proof;
}
function acmeKeyReuseProof(scope,name,root=path.resolve(__dirname,"..")){
  if(!["real-agent-acme-filesystem","real-agent-acme-eab-filesystem","real-agent-acmesh-filesystem","real-agent-acmesh-eab-filesystem","real-agent-alpine-acmesh"].includes(scope)||name!=="real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence")return undefined;
  const client=scope.includes("acmesh") ? "acme.sh" : "certbot";
  const proof=JSON.parse(fs.readFileSync(path.join(root,"qualification-results",`acme-key-reuse-${client === "certbot" ? "certbot" : "acmesh"}.json`),"utf8"));
  require("../tests/e2e/helpers/certops-acme-key-reuse").verifyProof(proof);if(proof.client!==client)throw new Error("ACME reuse client scope mismatch");return proof;
}
// Node's test reporter events preserve names and skip status without XML parsing.
module.exports = async function* report(events) {
  const qualificationEnvironment=measuredEnvironment();
  const fixtureSources=supplementalSources(process.env.CERTOPS_REPORT_SCOPE||"");
  for await (const event of events) {
    if (event.type === "test:pass" || event.type === "test:fail") {
      const source=event.data.file;
      const fixtureSource=source && fs.existsSync(source) ? {file:path.relative(path.resolve(__dirname,".."),source).replace(/\\/g,"/"),sha256:crypto.createHash("sha256").update(fs.readFileSync(source)).digest("hex")} : null;
      const publicProof=event.type === "test:pass" ? windowsPublicIssueProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const windowsReuseProof=event.type === "test:pass" ? windowsKeyReuseRefusalProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const retirementProof=event.type === "test:pass" ? publicRetirementProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const policyProof=event.type === "test:pass" ? retentionConfigProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const pinProof=event.type === "test:pass" ? signingPinRefusalProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const junctionProof=event.type === "test:pass" ? sourceJunctionProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const weakAclProof=event.type === "test:pass" ? installedWeakAclProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const credentialProof=event.type === "test:pass" ? credentialRefusalProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const encodingProof=event.type === "test:pass" ? configEncodingProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const verifyRollbackProof=event.type === "test:pass" ? installedVerifyRollbackProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const multiAdmissionProof=event.type === "test:pass" ? multiTargetAdmissionProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const activeScmProof=event.type === "test:pass" ? activeServiceControlsProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const scmProof=event.type === "test:pass" ? serviceControlsProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const pathsProof=event.type === "test:pass" ? installedPathsProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const crashProof=event.type === "test:pass" ? installedCrashProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const iisRefusalProof=event.type === "test:pass" ? installedIisRefusalProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const handoffProof=event.type === "test:pass" ? installedHandoffProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const stageProof=event.type === "test:pass" ? require("./certops-acme-stage-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const reuseProof=event.type === "test:pass" ? acmeKeyReuseProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const backgroundProof=event.type === "test:pass" ? require("./certops-acme-background-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      const bulkProof=event.type === "test:pass" ? require("./certops-acme-bulk-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      if(bulkProof)require("./certops-acme-bulk-report").verifyCrossJourney(bulkProof,reuseProof,backgroundProof);
      const adoptionProof=event.type === "test:pass" ? require("./certops-acme-native-adoption-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      if(adoptionProof)require("../tests/e2e/helpers/certops-acme-native-adoption").verifyAgainstBulk(adoptionProof,bulkProof);
      const certificateOutbox=event.type === "test:pass" ? require("./certops-acme-certificate-outbox-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      if(certificateOutbox)require("../tests/e2e/helpers/certops-acme-certificate-outbox").verifyAgainstJourney(certificateOutbox,bulkProof,adoptionProof);
      const disabledProfile=event.type === "test:pass" ? require("./certops-acme-disabled-profile-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      if(disabledProfile)require("../tests/e2e/helpers/certops-acme-disabled-profile").verifyAgainstBulk(disabledProfile,bulkProof);
      const renewalAlert=event.type === "test:pass" ? require("./certops-acme-renewal-alert-report").readProof(process.env.CERTOPS_REPORT_SCOPE||"",event.data.name) : undefined;
      if(renewalAlert)require("../tests/e2e/helpers/certops-acme-renewal-alert").verifyAgainstOutbox(renewalAlert,certificateOutbox);
      if(backgroundProof)require("./certops-acme-background-report").verifyForScope(backgroundProof,reuseProof,process.env.CERTOPS_REPORT_SCOPE);
      yield JSON.stringify({ ...(junctionProof?{nativeInstalledSourceJunction: junctionProof}:{}), ...(weakAclProof?{nativeInstalledWeakCredentialAcl:weakAclProof}:{}), ...(renewalAlert ? {nativeAcmeRenewalAlert:renewalAlert} : {}), ...(certificateOutbox ? {nativeAcmeCertificateOutbox:certificateOutbox} : {}), ...(disabledProfile ? {nativeAcmeDisabledProfile:disabledProfile} : {}), ...(pinProof ? {nativeInstalledSigningPinRefusal:pinProof} : {}), ...(verifyRollbackProof ? {nativeInstalledVerifyRollback:verifyRollbackProof} : {}), ...(adoptionProof ? {nativeAcmeRenewalSetup:adoptionProof} : {}), ...(bulkProof ? {nativeAcmeBulkRenewal:bulkProof} : {}), ...(multiAdmissionProof ? {nativeWindowsMultiTargetAdmission:multiAdmissionProof} : {}), ...(activeScmProof ? {nativeInstalledActiveServiceControls:activeScmProof} : {}), ...(credentialProof ? {nativeInstalledCredentialRefusal:credentialProof} : {}), ...(policyProof ? {nativeInstalledRetentionConfig:policyProof} : {}), ...(retirementProof ? {nativeInstalledPublicRetirement:retirementProof} : {}), ...(encodingProof ? {nativeInstalledConfigEncoding:encodingProof} : {}), ...(scmProof ? {nativeInstalledServiceControls:scmProof} : {}), ...(crashProof ? {nativeInstalledCrash:crashProof} : {}), ...(pathsProof ? {nativeInstalledPaths:pathsProof} : {}), ...(iisRefusalProof ? {nativeInstalledIisRefusal:iisRefusalProof} : {}), ...(windowsReuseProof ? {nativeWindowsKeyReuseRefusal:windowsReuseProof} : {}), ...(handoffProof ? {nativeInstalledStateHandoff:handoffProof} : {}), ...(publicProof ? {windowsPublicIssuance:publicProof} : {}), ...(reuseProof ? {nativeAcmeKeyReuse:reuseProof} : {}), ...(stageProof ? {nativeAcmeStageFaults:stageProof} : {}), ...(backgroundProof ? {nativeAcmeBackgroundRenewals:backgroundProof} : {}), type: event.type, name: event.data.name, file: source, fixtureSource, ...(fixtureSources ? {fixtureSources} : {}), qualificationEnvironment, artifactQualification:process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only", candidateSha: process.env.GITHUB_SHA || null, scope: process.env.CERTOPS_REPORT_SCOPE || "agent-protocol-api-worker", skip: event.data.skip || false, todo: event.data.todo || false }) + "\n";
    }
  }
};
module.exports.measuredEnvironment=measuredEnvironment;

module.exports.supplementalSources=supplementalSources;

module.exports.windowsPublicIssueProof=windowsPublicIssueProof;
module.exports.acmeKeyReuseProof=acmeKeyReuseProof;

module.exports.installedHandoffProof=installedHandoffProof;

module.exports.windowsKeyReuseRefusalProof=windowsKeyReuseRefusalProof;

module.exports.installedIisRefusalProof=installedIisRefusalProof;

module.exports.installedPathsProof=installedPathsProof;

module.exports.installedCrashProof=installedCrashProof;

module.exports.serviceControlsProof=serviceControlsProof;

module.exports.configEncodingProof=configEncodingProof;

module.exports.publicRetirementProof=publicRetirementProof;

module.exports.retentionConfigProof=retentionConfigProof;

module.exports.credentialRefusalProof=credentialRefusalProof;

module.exports.activeServiceControlsProof=activeServiceControlsProof;

module.exports.multiTargetAdmissionProof=multiTargetAdmissionProof;

module.exports.installedVerifyRollbackProof=installedVerifyRollbackProof;

module.exports.signingPinRefusalProof=signingPinRefusalProof;

module.exports.installedWeakAclProof=installedWeakAclProof;

module.exports.sourceJunctionProof=sourceJunctionProof;
