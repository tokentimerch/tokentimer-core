/**
 * Qualification: installed systemd lifecycle and write-path sandbox
 *
 * Use trusted-main certops-linux-systemd.yml on fresh Ubuntu 22.04/24.04 with migrated
 * API/Postgres, root, GITHUB_ACTIONS=true, CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST=1,
 * CERTOPS_PROTOCOL_DISPOSABLE_STACK=1 and live systemd. Refuse existing account/group,
 * install/unit/drop-in/polkit state. Real install-agent.sh consumes one actual token;
 * check registration, bootstrap.env removal, private config/credentials, nonroot UID and
 * soft/hard core limits in /proc/MainPID/limits. Candidate-Node ExecStart drop-in keeps
 * product sandbox/restart policy. Same service requires installed discovery sidecar. The
 * installer grants one owned /var/lib write-path. Benign ExecStartPre under unit
 * identity/mount namespace writes allowed path but gets EROFS on mode 0777 peer; host
 * runuser must independently write both. systemctl must show ProtectSystem=strict, exact
 * ReadWritePaths/no peer grant. This fixture probe is not an agent certificate write.
 * linux-systemd-writepath.json binds exact paths/receipt/probe+fixture hashes. Real
 * restart preserves credential/advances authenticated heartbeat; measured SIGKILL must
 * recover with new authenticated PID. retireAgent must yield exit86 and suppress restart
 * for more than two real restart intervals. Product uninstall removes app/ unit but
 * preserves state; fixture removes only its own preserved resources. A root-owned
 * mode-0600 receipt precedes installation; independent always cleanup validates source
 * hash, uninstalls and deletes exact owned paths/account/group ONLY after service/cgroup
 * drain. Unknown discovery/config restoration preserves host and DB state. Upload
 * sanitized execution/writepath reports, never tokens, state, environment/raw journals.
 * This lifecycle lane does not qualify certificates, browser, released package or ARM64.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
/**
 * Installed Linux agent journey, invoked through certops-linux-systemd.js on an owned VM.
 * Exercise the shipped installer, actual systemd identity/sandbox, restart recovery and
 * retirement. Unit/process ownership receipts constrain destructive cleanup; the host
 * must satisfy the explicit disposable GitHub-hosted qualification prerequisites. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const UNIT = "tokentimer-agent.service";
const ROOT = "/opt/tokentimer-agent";
const USER = "tokentimer-agent";
const UNIT_FILE = `/etc/systemd/system/${UNIT}`;
const DROPINS = `${UNIT_FILE}.d`;
const POLKIT = "/etc/polkit-1/rules.d/50-tokentimer-agent.rules";
function command(file, args, options = {}) {
  const result = spawnSync(file, args, { encoding: "utf8", timeout: 60000, ...options });
  assert.equal(result.status, 0, `${file} failed (${result.status}); diagnostics withheld to protect agent credentials`);
  return result.stdout.trim();
}
async function waitFor(predicate, description, timeout = 70000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timed out: ${description}`);
}
function serviceProperty(name) {
  const result = spawnSync("systemctl", ["show", UNIT, `--property=${name}`, "--value"], { encoding: "utf8", timeout: 10000 });
  if (result.status !== 0) {
    const absent = spawnSync("systemctl", ["show", UNIT, "--property=LoadState", "--value"], { encoding: "utf8", timeout: 10000 });
    assert.equal(absent.stdout.trim(), "not-found", "systemd property query failed for an existing unit");
  }
  return result.stdout.trim();
}
function mainPid() { return Number(serviceProperty("MainPID")); }
function digest(file) { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); }

module.exports = async function qualifyLinuxSystemd({ pool, baseUrl, workspaceId, userId, createBootstrap, repoRoot }) {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0, "installer qualification requires root on a disposable hosted runner");
  require("../../scripts/certops-linux-systemd-ownership").validateHostedEnvironment(process.env);
  assert.equal(process.env.CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST, "1");
  assert.equal(process.env.CERTOPS_PROTOCOL_DISPOSABLE_STACK, "1");
  assert.ok(process.env.RUNNER_TEMP && fs.existsSync(process.env.RUNNER_TEMP));
  assert.equal(new URL(baseUrl).hostname, "127.0.0.1");
  for (const target of [ROOT, UNIT_FILE, DROPINS, POLKIT]) {
    assert.equal(fs.lstatSync(target,{throwIfNoEntry:false}), undefined, `Refuse pre-existing ${target}, including dangling symlinks`);
  }
  assert.equal(spawnSync("getent", ["passwd", USER]).status, 2, "refuse an existing agent account");
  assert.equal(spawnSync("getent", ["group", USER]).status, 2, "refuse an existing agent group");
  assert.equal(serviceProperty("LoadState"), "not-found", "refuse any existing vendor/unit configuration");
  const manager = spawnSync("systemctl", ["is-system-running"], { encoding: "utf8", timeout: 10000 });
  assert.ok(["running", "degraded"].includes(manager.stdout.trim()), "a live systemd manager is required");
  const installer = path.join(repoRoot, "packages/agent/scripts/install-agent.sh");
  const published = process.env.CERTOPS_LINUX_PUBLISHED_INPUTS ? require("../../scripts/certops-linux-published-package").loadManifest(process.env.CERTOPS_LINUX_PUBLISHED_INPUTS) : null;
  const firstInstaller = published ? path.join(published.baseline.directory,"scripts/install-agent.sh") : installer;
  const nodeBinary = fs.realpathSync(process.execPath);
  assert.equal(nodeBinary.includes("\n") || nodeBinary.includes('"'), false);
  const stateDir = `${ROOT}/state`;
  const credential = `${stateDir}/credential`;
  const ownershipReceipt = path.join(process.env.RUNNER_TEMP, "certops-linux-systemd-owned.json");
  assert.equal(fs.lstatSync(ownershipReceipt,{throwIfNoEntry:false}), undefined, "refuse any existing cleanup receipt, including dangling symlinks");
  const runId=crypto.randomBytes(5).toString("hex");const writeRoot=`/var/lib/tokentimer-qualification-${runId}`;
  const writeFixture={runId,root:writeRoot,allowed:writeRoot+"/allowed",denied:writeRoot+"/denied",probe:writeRoot+"/write-probe.js",probeSha256:digest(path.join(repoRoot,"tests/e2e/helpers/linux-systemd-write-probe.js"))};
  require("../../scripts/certops-linux-systemd-ownership").validateWriteFixture(writeFixture);assert.equal(fs.lstatSync(writeRoot,{throwIfNoEntry:false}),undefined);
  const writeGate=require("../../packages/agent/scripts/host-gate").createHostGate({suite:"linux-systemd-writepath",strict:true,evidenceLevel:"real-host",reportPath:path.join(repoRoot,"qualification-results/linux-systemd-writepath.json"),fixtureSource:{file:"tests/e2e/linux-systemd-real-journey.js",sha256:digest(__filename)},requiredCapabilities:["linux","systemd"],probeCapabilities:()=>({linux:{available:process.platform==="linux"},systemd:{available:["running","degraded"].includes(manager.stdout.trim()),evidence:"native systemctl is-system-running"}})});
  let owned = false;
  let agentId;
  let primaryError;
  const cleanupErrors = [];
  const installedDiscovery=require("./helpers/certops-linux-installed-discovery");
  const discoveryResources=[];
  const ownershipPlan={root:ROOT,unit:UNIT,user:USER,installer,fixtureSha256:digest(__filename),writeFixture,installedDiscoveryRequired:true,installedDiscoveryNonce:crypto.randomBytes(32).toString("hex"),installedDiscoveryCompletion:installedDiscovery.completionPath(process.env.RUNNER_TEMP)};
  for(const file of [installedDiscovery.completionPath(process.env.RUNNER_TEMP),installedDiscovery.guardPath(process.env.RUNNER_TEMP)])assert.equal(fs.lstatSync(file,{throwIfNoEntry:false}),undefined,"Refuse a prior installed-discovery ownership marker");
  try {
    // Register ownership before installation can partially create files/user.
    require("../../scripts/certops-linux-systemd-ownership").claimOwnershipReceipt(ownershipReceipt, ownershipPlan);
    owned = true;
    await writeGate.preflight();
    fs.mkdirSync(writeRoot,{mode:0o755});fs.mkdirSync(writeFixture.allowed,{mode:0o777});fs.mkdirSync(writeFixture.denied,{mode:0o777});fs.chmodSync(writeFixture.allowed,0o777);fs.chmodSync(writeFixture.denied,0o777);
    fs.copyFileSync(path.join(repoRoot,"tests/e2e/helpers/linux-systemd-write-probe.js"),writeFixture.probe);fs.chmodSync(writeFixture.probe,0o644);
    fs.mkdirSync(DROPINS, { mode: 0o755 });
    // The service runs the exact candidate Node binary even when /usr/bin/node
    // on the image differs from actions/setup-node. ProtectHome remains intact.
    fs.writeFileSync(`${DROPINS}/99-qualification.conf`, `[Service]\nExecStartPre="${nodeBinary}" "${writeFixture.probe}" "${writeFixture.allowed}" "${writeFixture.denied}"\nExecStart=\nExecStart="${nodeBinary}" ${ROOT}/app/bin/tokentimer-agent.js\n`, { mode: 0o644 });
    const { plaintextToken } = await createBootstrap();
    command("sh", [firstInstaller, "--api-url", baseUrl, "--workspace-id", workspaceId,
      "--allow-insecure-local-http", "--no-trust-store", "--write-path", writeFixture.allowed], {
      env: { ...process.env, PATH: `${path.dirname(nodeBinary)}:/usr/sbin:/usr/bin:/sbin:/bin`,
        TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: plaintextToken },
    });
    await waitFor(() => fs.existsSync(credential) &&
      !fs.existsSync(`${stateDir}/bootstrap.env`), "real registration and bootstrap token removal");
    const config = JSON.parse(fs.readFileSync(`${stateDir}/config.json`, "utf8"));
    agentId = config.agentId;
    assert.ok(agentId, "registration must persist the actual generated identity");
    const account = command("getent", ["passwd", USER]).split(":");
    const uid = Number(account[2]);
    const gid = Number(account[3]);
    assert.ok(uid > 0);
    const checkPermissions = (file, mode) => {
      const stat = fs.statSync(file);
      assert.equal(stat.uid, uid);
      assert.equal(stat.gid, gid);
      assert.equal(stat.mode & 0o777, mode);
    };
    checkPermissions(stateDir, 0o700);
    checkPermissions(`${stateDir}/config.json`, 0o600);
    checkPermissions(credential, 0o600);
    assert.equal(config.serverUrl, baseUrl);
    assert.equal(config.workspaceId, workspaceId);
    const identity = (afterBootstrapRestart = true) => {
      const pid = mainPid();
      assert.ok(pid > 0);
      const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
      assert.match(status, new RegExp(`^Uid:\\s+${uid}\\s+${uid}\\s+${uid}\\s+${uid}$`, "m"));
      assert.match(fs.readFileSync(`/proc/${pid}/limits`, "utf8"), /^Max core file size\s+0\s+0\s+bytes$/m);
      assert.equal(fs.realpathSync(`/proc/${pid}/exe`), nodeBinary);
      if (afterBootstrapRestart) assert.equal(fs.readFileSync(`/proc/${pid}/environ`).includes(Buffer.from("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=")), false);
      return pid;
    };
    const firstPid = identity(false);
    const originalCredential = digest(credential);
    const lastSeen = async () => (await pool.query(
      "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId],
    )).rows[0]?.last_seen_at;
    await waitFor(async () => await lastSeen(), "authenticated API registration");
    const beforeRestart = await lastSeen();
    fs.chmodSync(writeFixture.allowed,0o777);fs.chmodSync(writeFixture.denied,0o777);
    command("runuser",["-u",USER,"--",nodeBinary,writeFixture.probe,writeFixture.allowed,writeFixture.denied,"dac"]);
    // Require this restart's actual ExecStartPre evidence rather than a result
    // left by initial installation before the independent host DAC proof.
    fs.unlinkSync(writeFixture.allowed+"/result.json");
    command("systemctl", ["restart", UNIT]);
    await waitFor(() => mainPid() > 0 && mainPid() !== firstPid, "service restart creates a fresh process");
    identity();
    await writeGate.scenario("linux-systemd-native-writepath-allowed-peer-erofs",async()=>{
      assert.equal(serviceProperty("ProtectSystem"),"strict");const writable=serviceProperty("ReadWritePaths");assert.ok(writable.split(/\s+/).includes(writeFixture.allowed));assert.equal(writable.split(/\s+/).includes(writeFixture.denied),false);
      assert.equal(fs.statSync(writeFixture.allowed).mode&0o777,0o777);assert.equal(fs.statSync(writeFixture.denied).mode&0o777,0o777);
      assert.equal(digest(writeFixture.probe),writeFixture.probeSha256);
      const preStart=serviceProperty("ExecStartPre");assert.ok(preStart.includes(nodeBinary)&&preStart.includes(writeFixture.probe));
      const resultStat=fs.lstatSync(writeFixture.allowed+"/result.json");assert.equal(resultStat.isFile(),true);assert.equal(resultStat.uid,uid);assert.equal(resultStat.mode&0o777,0o600);
      const native=JSON.parse(fs.readFileSync(writeFixture.allowed+"/result.json","utf8"));assert.equal(native.uid,uid);assert.equal(native.allowedWrite,true);assert.equal(native.deniedCode,"EROFS");assert.equal(native.deniedMarkerAbsent,true);assert.equal(fs.existsSync(writeFixture.denied+"/denied-marker"),false);
      writeGate.report.nativeWritePath={service:UNIT,installerWritePath:true,mainExecutableCandidate:true,probe:"bounded ExecStartPre Node fixture",probeSha256:writeFixture.probeSha256,samePeerDacMode:"0777",nonRootUid:uid,allowedWrite:true,deniedError:"EROFS",hostDacWriteVerified:true,freshExecStartPreEvidence:true};
    });
    await waitFor(async () => Date.parse(await lastSeen()) > Date.parse(beforeRestart), "fresh authenticated heartbeat after restart");
    assert.equal(digest(credential), originalCredential, "restart must reuse the stored credential");
    const beforeCrash = mainPid();
    const seenBeforeCrash = await lastSeen();
    process.kill(beforeCrash, "SIGKILL");
    await waitFor(() => mainPid() > 0 && mainPid() !== beforeCrash, "actual systemd crash recovery");
    identity();
    await waitFor(async () => Date.parse(await lastSeen()) > Date.parse(seenBeforeCrash), "recovered service authenticates again");
    assert.equal(digest(credential), originalCredential);
    if(published) await require("./helpers/linux-systemd-published-upgrade").qualifyPublishedUpgrade({published,pool,workspaceId,userId,agentId,baseUrl,repoRoot,nodeBinary,writeFixture,command,waitFor,mainPid,identity,lastSeen,createBootstrap,uid,gid});
    else await require("./helpers/linux-systemd-reapply").qualifyReapply({pool,workspaceId,agentId,baseUrl,repoRoot,installer,nodeBinary,writeFixture,command,waitFor,mainPid,serviceProperty,identity,lastSeen,createBootstrap,uid,gid});
    await installedDiscovery.qualifyInstalledDiscovery({pool,workspaceId,agentId,baseUrl,repoRoot,writeFixture,uid,gid,command,waitFor,mainPid,identity,serviceProperty,registerResource:resource=>discoveryResources.push(resource)});
    installedDiscovery.assertCompletion(ownershipPlan,process.env.RUNNER_TEMP);
    const { retireAgent } = require("../../apps/api/services/certops/agentRegistry");
    await retireAgent({ client: pool, workspaceId, agentId, retiredBy: userId, reason: "disposable installer qualification" });
    await waitFor(() => mainPid() === 0, "actual API retirement stops the installed service");
    assert.equal(serviceProperty("ExecMainStatus"), "86");
    assert.equal(serviceProperty("Result"), "success");
    const restarts = serviceProperty("NRestarts");
    // More than two production RestartSec=5 intervals proves exit86 suppression.
    await new Promise((resolve) => setTimeout(resolve, 11000));
    assert.equal(mainPid(), 0);
    assert.equal(serviceProperty("NRestarts"), restarts);
    installedDiscovery.assertCompletion(ownershipPlan,process.env.RUNNER_TEMP);
    command("sh", [installer, "--uninstall"]);
    assert.equal(fs.existsSync(UNIT_FILE), false);
    assert.equal(fs.existsSync(`${ROOT}/app`), false);
    assert.equal(serviceProperty("LoadState"), "not-found");
    assert.equal(digest(credential), originalCredential, "product uninstall intentionally preserves state");
    checkPermissions(stateDir, 0o700);
  } catch (error) { primaryError = error; }
  finally {
    let discoverySafe=true;
    let hostDrained=false,hostRemoved=false;
    if(owned)try{for(const resource of discoveryResources)resource.assertCleanupSafe();installedDiscovery.assertCompletion(ownershipPlan,process.env.RUNNER_TEMP);}catch(error){cleanupErrors.push(error);discoverySafe=false;}
    if (owned && discoverySafe) {
      const clean = (action) => { try { action(); } catch (error) { cleanupErrors.push(error); } };
      clean(() => {require("../../scripts/certops-linux-systemd-ownership").assertNoSymlinkTargets([ROOT,UNIT_FILE,DROPINS,POLKIT,writeFixture.root]);command("sh", [installer, "--uninstall"]);});
      if(!cleanupErrors.length)clean(() => {
        assert.equal(mainPid(), 0, "never remove state while the owned service still runs");
        const members=`/sys/fs/cgroup/system.slice/${UNIT}/cgroup.procs`;
        if(fs.existsSync(members))assert.equal(fs.readFileSync(members,"utf8").trim(),"","Preserve state while the owned systemd cgroup has processes");
        hostDrained=true;
      });
      if(hostDrained&&!cleanupErrors.length)clean(() => {
        for (const target of [ROOT, DROPINS,writeFixture.root]) {
          assert.equal(fs.lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink() || false, false);
          fs.rmSync(target, { recursive: true, force: true });
        }
      });
      if(hostDrained&&!cleanupErrors.length)clean(() => command("systemctl", ["daemon-reload"]));
      if(hostDrained&&!cleanupErrors.length)clean(() => {
        if (spawnSync("getent", ["passwd", USER]).status === 0) command("userdel", [USER]);
        if (spawnSync("getent", ["group", USER]).status === 0) command("groupdel", [USER]);
      });
      if(hostDrained&&!cleanupErrors.length)clean(() => {
        for (const target of [ROOT, UNIT_FILE, DROPINS, POLKIT,writeFixture.root]) assert.equal(fs.existsSync(target), false);
        assert.equal(spawnSync("getent", ["passwd", USER]).status, 2);
        assert.equal(serviceProperty("LoadState"), "not-found");
      });
      if (!cleanupErrors.length) clean(() => fs.unlinkSync(ownershipReceipt));
      hostRemoved=hostDrained&&cleanupErrors.length===0;
    }
    if (agentId && discoverySafe && hostDrained && hostRemoved) {
      try { await pool.query("DELETE FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId]); }
      catch (error) { cleanupErrors.push(error); }
    }
  }
  try{await writeGate.scenario("linux-systemd-native-writepath-owned-cleanup",async()=>{assert.equal(cleanupErrors.length,0);assert.equal(fs.existsSync(writeFixture.root),false);assert.equal(fs.existsSync(DROPINS),false);assert.equal(mainPid(),0);});await writeGate.finish({requiredScenarios:["linux-systemd-native-writepath-allowed-peer-erofs","linux-systemd-native-writepath-owned-cleanup"]});}catch(error){cleanupErrors.push(error);}
  if (cleanupErrors.length) throw new AggregateError(primaryError ? [primaryError, ...cleanupErrors] : cleanupErrors,
    "Linux installer qualification or owned cleanup failed", { cause: primaryError });
  if (primaryError) throw primaryError;
};
