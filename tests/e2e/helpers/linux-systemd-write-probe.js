"use strict";
const fs=require("node:fs"),assert=require("node:assert/strict");
const [allowed,denied,mode]=process.argv.slice(2);assert.ok(allowed&&denied&&process.getuid()>0);
if(mode==="dac"){
  for(const directory of [allowed,denied]){const file=`${directory}/dac-probe`;fs.writeFileSync(file,"owned DAC verification",{flag:"wx",mode:0o600});fs.unlinkSync(file);}
}else{
  fs.writeFileSync(`${allowed}/allowed-marker`,"actual installed-unit write permission",{mode:0o600});let deniedCode;
  try{fs.writeFileSync(`${denied}/denied-marker`,"must never succeed",{flag:"wx",mode:0o600});throw new Error("Unlisted peer was writable inside installed service sandbox");}catch(error){deniedCode=error.code;assert.equal(deniedCode,"EROFS","Refusal must come from mount namespace, not discretionary access control");}
  fs.writeFileSync(`${allowed}/result.json`,JSON.stringify({uid:process.getuid(),allowedWrite:true,deniedCode,deniedMarkerAbsent:!fs.existsSync(`${denied}/denied-marker`)}),{mode:0o600});
}
