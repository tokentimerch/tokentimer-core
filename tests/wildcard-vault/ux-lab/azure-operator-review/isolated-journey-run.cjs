"use strict";
// Start only a loopback bridge and the local public-API journey. Containers
// must already exist and their identities are verified by docker-role-transport.
const {spawn}=require("node:child_process"),crypto=require("node:crypto"),path=require("node:path");
const {createBridge}=require("./role-control-bridge.cjs"),{createDockerSender}=require("./docker-role-transport.cjs");
async function run({project,issuerContainerId,consumerContainerId,phase="all"}) {
  const send=createDockerSender({project,issuerContainerId,consumerContainerId}),token=crypto.randomBytes(32).toString("hex");
  const server=createBridge({send,token});
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
  try {
    return await new Promise((resolve,reject)=>{
      const child=spawn(process.execPath,[path.join(__dirname,"..","journey.cjs"),phase],{stdio:"inherit",env:{...process.env,TT_UX_CONTROL_PORT:String(server.address().port),TT_UX_CONTROL_TOKEN:token}});
      child.once("error",reject);child.once("exit",(code,signal)=>code===0?resolve():reject(new Error(`journey failed (${signal || code})`)));
    });
  } finally { await new Promise(resolve=>server.close(resolve)); }
}
if(require.main===module){const [project,issuerContainerId,consumerContainerId,phase]=process.argv.slice(2);run({project,issuerContainerId,consumerContainerId,phase}).catch(()=>{process.stderr.write("Isolated journey failed; inspect protected local evidence.\n");process.exitCode=1;});}
module.exports={run};
