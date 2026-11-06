"use strict";
// Start the real API/dashboard against an explicitly retained, owned acceptance
// database. Credentials stay in protected .tmp files, outside evidence exports.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), net = require("node:net");
const { spawn, spawnSync } = require("node:child_process");
const { readProtectedFile, writeProtectedJson } = require("../packages/agent/src/material-store/index");
const root = path.resolve(__dirname, "..");
const evidence = path.resolve(process.argv[2] || "");
if (!evidence.startsWith(path.join(root, "qualification-results") + path.sep)) throw new Error("Expected this checkout's acceptance evidence directory");
const summary = JSON.parse(fs.readFileSync(path.join(evidence, "summary.json")));
const configFile = path.resolve(summary.retainedLabConfig);
if (!configFile.startsWith(path.join(root, ".tmp") + path.sep)) throw new Error("Expected a protected local fixture config");
const config = JSON.parse(readProtectedFile(configFile));
if (config.env.DB_HOST !== "127.0.0.1" || !/^distribution_lifecycle_[a-f0-9]+_test$/.test(config.env.DB_NAME)) throw new Error("Invalid fixture database");
for (const container of config.containers) {
  const owner = spawnSync("docker", ["inspect", "--format", '{{index .Config.Labels "tokentimer.cleanup-completion-owner"}}', container], { encoding: "utf8", windowsHide: true });
  if (owner.status !== 0 || owner.stdout.trim() !== config.owner) throw new Error("Fixture ownership changed");
}
async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function main() {
  const proof = JSON.parse(fs.readFileSync(path.join(evidence, "provider-completion.json")));
  const { Client } = require("pg");
  const db = new Client({ host: config.env.DB_HOST, port: Number(config.env.DB_PORT), user: config.env.DB_USER, password: config.env.DB_PASSWORD, database: config.env.DB_NAME });
  await db.connect();
  const user = (await db.query("SELECT created_by FROM workspaces WHERE id=$1", [proof.workspaceId])).rows[0].created_by;
  const email = `operator.${config.owner}@example.test`, password = crypto.randomBytes(24).toString("hex");
  await db.query("UPDATE users SET email=$2,display_name='Isolated CertOps operator',password_hash=$3,email_verified=true WHERE id=$1", [user,email,require("bcryptjs").hashSync(password,10)]);
  await db.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin') ON CONFLICT(workspace_id,user_id) DO NOTHING",[proof.workspaceId,user]);
  await db.query("UPDATE workspaces SET name='Isolated CertOps acceptance' WHERE id=$1", [proof.workspaceId]);
  const group = (await db.query("SELECT group_id FROM certops_material_cleanups WHERE id=$1", [proof.cleanupId])).rows[0].group_id;
  await db.end();
  const apiPort = await freePort(), dashboardPort = await freePort();
  const apiUrl = `http://127.0.0.1:${apiPort}`, dashboardUrl = `http://127.0.0.1:${dashboardPort}`;
  const privateUi = path.join(path.dirname(configFile), "ui-private.json");
  writeProtectedJson(privateUi, { email, password, apiUrl, dashboardUrl, workspaceId: proof.workspaceId, groupId: group, evidence });
  const env = { ...process.env, ...config.env, HOST: "127.0.0.1", PORT: String(apiPort), SESSION_SECRET: crypto.randomBytes(32).toString("hex"),
    APP_URL: dashboardUrl, API_URL: apiUrl, VITE_API_URL: apiUrl };
  const children = [];
  for (const [label, args, cwd] of [
    ["api", ["apps/api/index.js"], root],
    ["dashboard", [path.join(root, "apps/dashboard/node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", String(dashboardPort)], path.join(root,"apps/dashboard")],
  ]) {
    const fd = fs.openSync(path.join(path.dirname(configFile), `${label}.log`), "a");
    const child = spawn(process.execPath, args, { cwd, env, windowsHide: true, stdio: ["ignore", fd, fd] });
    fs.closeSync(fd); children.push(child);
  }
  const stop = () => { for (const child of children) child.kill(); process.exit(0); };
  process.on("SIGINT", stop); process.on("SIGTERM", stop);
  process.stdin.on("data", value => { if (String(value).trim() === "stop") stop(); });
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try {
      const responses = await Promise.all([fetch(apiUrl),fetch(dashboardUrl)]);
      if (responses.every(response=>response.ok)) {
        fs.writeFileSync(path.join(evidence,"ui-environment.json"),JSON.stringify({apiUrl,dashboardUrl,workspaceId:proof.workspaceId,groupId:group,
          scope:"real-api-and-dashboard-on-disposable-fixtures",limitation:"Synthetic publication metadata; cleanup receipt and provider deletion are genuine. This is not fleet or native artifact qualification."},null,2)+"\n");
        console.log(JSON.stringify({apiUrl,dashboardUrl,workspaceId:proof.workspaceId,groupId:group,privateUi}));
        return;
      }
    } catch { /* startup */ }
    if (children.some(child=>child.exitCode!==null)) throw new Error("Fixture application exited; inspect protected local startup logs");
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  throw new Error("Fixture UI startup timed out; inspect protected local startup logs");
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
