"use strict";
// An owned, disposable loopback database. Never reads .env or existing labs.
const {spawnSync}=require("node:child_process");
const crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path");
const root=path.resolve(__dirname,".."),nonce=crypto.randomBytes(8).toString("hex"),container=`tt-distribution-lifecycle-${nonce}`;
const output=path.join(root,".tmp",container);fs.mkdirSync(output,{recursive:true});
function run(command,args,env=process.env,log){const r=spawnSync(command,args,{cwd:root,env,encoding:"utf8",windowsHide:true,timeout:600000,maxBuffer:32*1024*1024});
  if(log)fs.writeFileSync(path.join(output,log),(r.stdout||"")+(r.stderr||""));
  if(r.status!==0)throw new Error(`${command} failed (${r.status}); diagnostics: ${log?path.join(output,log):(r.stderr||r.error)}`);return r.stdout;}
async function main(){let created=false;try{
  run("docker",["run","-d","--name",container,"--label",`tokentimer.lifecycle-owner=${nonce}`,"--memory=512m","-p","127.0.0.1::5432","-e","POSTGRES_PASSWORD=synthetic-disposable-only","-e","POSTGRES_DB=postgres","postgres:17-alpine"]);created=true;
  const port=run("docker",["port",container,"5432/tcp"]).trim().match(/^127\.0\.0\.1:(\d+)$/)?.[1];if(!port)throw new Error("No owned loopback port");
  let ready=false;for(let i=0;i<60;i++){if(spawnSync("docker",["exec",container,"pg_isready","-U","postgres"],{windowsHide:true,stdio:"ignore"}).status===0){ready=true;break;}await new Promise(resolve=>setTimeout(resolve,250));}if(!ready)throw new Error("PostgreSQL unavailable");
  const database=`distribution_lifecycle_${nonce}_test`;run("docker",["exec",container,"createdb","-U","postgres",database]);
  const env={...process.env,NODE_ENV:"test",CERTOPS_ENABLED:"true",DB_HOST:"127.0.0.1",DB_PORT:port,DB_NAME:database,DB_USER:"postgres",DB_PASSWORD:"synthetic-disposable-only",
    CERTOPS_SIGNING_ENCRYPTION_KEY:crypto.randomBytes(32).toString("hex"),CERTOPS_REGISTRATION_ENCRYPTION_KEY:crypto.randomBytes(32).toString("hex")};
  run(process.execPath,["apps/api/migrations/migrate.js"],env,"migration.log");
  process.stdout.write(run(process.execPath,["--test","--test-force-exit","tests/postgres/distribution-lifecycle.test.js"],env,"tests.log"));
  const upgradeDatabase=`pr329_distribution_upgrade_${nonce}_test`;run("docker",["exec",container,"createdb","-U","postgres",upgradeDatabase]);
  process.stdout.write(run(process.execPath,["--test","--test-force-exit","tests/postgres/distribution-migration-upgrade.test.js"],{...env,DB_NAME:upgradeDatabase},"upgrade-tests.log"));
  console.log(`Real PostgreSQL lifecycle integration passed. Logs: ${output}`);
}finally{if(created)run("docker",["rm","-f",container]);}}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
