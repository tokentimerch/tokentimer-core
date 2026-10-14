"use strict";
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
  if(scope.startsWith("real-agent-windows-acme-iis/"))files=["tests/e2e/helpers/certops-windows-reregistration.js","tests/e2e/helpers/certops-windows-capability-refresh.js"];
  else if(["real-agent-acme-filesystem","real-agent-acme-eab-filesystem","real-agent-acmesh-filesystem","real-agent-acmesh-eab-filesystem","real-agent-alpine-certbot","real-agent-alpine-acmesh"].includes(scope))files=["tests/e2e/acme-real-journey.js","scripts/certops-real-acme.js","tests/e2e/helpers/certops-acme-lease-loss.js","tests/e2e/helpers/certops-acme-command-barrier.js"];
  else return undefined;
  const root=path.resolve(__dirname,"..");return files.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
}
// Node's test reporter events preserve names and skip status without XML parsing.
module.exports = async function* report(events) {
  const qualificationEnvironment=measuredEnvironment();
  const fixtureSources=supplementalSources(process.env.CERTOPS_REPORT_SCOPE||"");
  for await (const event of events) {
    if (event.type === "test:pass" || event.type === "test:fail") {
      const source=event.data.file;
      const fixtureSource=source && fs.existsSync(source) ? {file:path.relative(path.resolve(__dirname,".."),source).replace(/\\/g,"/"),sha256:crypto.createHash("sha256").update(fs.readFileSync(source)).digest("hex")} : null;
      yield JSON.stringify({ type: event.type, name: event.data.name, file: source, fixtureSource, ...(fixtureSources ? {fixtureSources} : {}), qualificationEnvironment, artifactQualification:process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only", candidateSha: process.env.GITHUB_SHA || null, scope: process.env.CERTOPS_REPORT_SCOPE || "agent-protocol-api-worker", skip: event.data.skip || false, todo: event.data.todo || false }) + "\n";
    }
  }
};
module.exports.measuredEnvironment=measuredEnvironment;

module.exports.supplementalSources=supplementalSources;
