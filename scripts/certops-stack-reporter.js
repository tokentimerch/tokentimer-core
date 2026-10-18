"use strict";
// Bounded source-bound outcomes for AD CS API and Vault supporting tests.
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),os=require("node:os"),{spawnSync}=require("node:child_process");
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
module.exports=async function*(events){const qualificationEnvironment=measuredEnvironment();for await(const event of events){if(!["test:pass","test:fail"].includes(event.type)||!event.data?.file)continue;const source=path.resolve(event.data.file);const fixtureSource={file:path.relative(path.resolve(__dirname,".."),source).replace(/\\/g,"/"),sha256:crypto.createHash("sha256").update(fs.readFileSync(source)).digest("hex")};yield JSON.stringify({type:event.type,name:event.data.name,file:source,fixtureSource,qualificationEnvironment,artifactQualification:process.env.GITHUB_ACTIONS==="true"?"workflow-checkout-source":"local-worktree-source-baseline-sha-only",candidateSha:process.env.GITHUB_SHA||null,scope:process.env.CERTOPS_REPORT_SCOPE||"",skip:event.data.skip||false,todo:event.data.todo||false})+"\n";}};

module.exports.measuredEnvironment=measuredEnvironment;
