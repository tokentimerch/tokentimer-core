"use strict";
/** Dedicated AD CS default-TTL cloud adapter. All mutations require immutable
 * original workflow provenance and exact owned VM/deployment identities. Its
 * serialized compare/readback protocol grants no Azure atomicity guarantee.
 * This module never handles a credential or officer password. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { execFileSync } = require("node:child_process");
const contract = require("./certops-adcs-ttl24h-contract");
const { downloadArtifactZip } = require("./certops-retention24h-azure");
const ROOT = path.resolve(__dirname, ".."),
  OUTPUT = path.join(ROOT, "qualification-results");
const REPOSITORY = "tokentimerch/tokentimer-core",
  WORKFLOW = ".github/workflows/certops-adcs-ttl24h-prepare.yml";
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function iso(value) {
  assert.equal(typeof value, "string");
  return new Date(value).toISOString();
}
const NATIVE_FINISH_TIMEOUT = 20 * 60000;
function requireFinalizationBudget(lease, remainingMinutes, now = Date.now()) {
  contract.verifyLease(lease);
  assert.ok([40, 45].includes(remainingMinutes));
  assert.ok(
    Number.isSafeInteger(now) &&
      now + remainingMinutes * 60000 < Date.parse(lease.hardExpiresAt),
    "Finalization requires full bounded native and cleanup budget",
  );
}
function command(file, args, binary = false, timeout = 180000) {
  assert.ok(
    [180000, 660000, 1200000].includes(timeout),
    "Unapproved command time budget",
  );
  return execFileSync(file, args, {
    encoding: binary ? undefined : "utf8",
    timeout,
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
}
const az = (args, timeout = 180000) =>
  JSON.parse(command("az", [...args, "-o", "json"], false, timeout));
const github = (route) =>
  JSON.parse(command("gh", ["api", `repos/${REPOSITORY}/${route}`]));
function exact(value, keys) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}
function groupName(lease) {
  return `tt-certops-${lease.runId}-${lease.runAttempt}`;
}
function verifyOwner(run, lease, { completed = false } = {}) {
  assert.equal(run.repository?.full_name, REPOSITORY);
  assert.equal(run.head_repository?.full_name, REPOSITORY);
  assert.equal(run.path, WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.equal(String(run.id), lease.runId);
  assert.equal(String(run.run_attempt), lease.runAttempt);
  assert.equal(run.head_sha, lease.candidateSha);
  assert.ok(["in_progress", "completed"].includes(run.status));
  if (completed) {
    assert.equal(run.status, "completed");
    assert.equal(run.conclusion, "success");
  }
  return true;
}
function verifyPrepareJob(run, response) {
  assert.ok(Number.isSafeInteger(run.id) && run.id > 0);
  assert.ok(Number.isInteger(run.run_attempt) && run.run_attempt > 0);
  assert.equal(run.repository?.full_name, REPOSITORY);
  assert.equal(run.head_repository?.full_name, REPOSITORY);
  assert.equal(run.path, WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.match(run.head_sha, /^[a-f0-9]{40}$/);
  assert.ok(["in_progress", "completed"].includes(run.status));
  assert.equal(response?.total_count, 1);
  assert.ok(Array.isArray(response.jobs) && response.jobs.length === 1);
  const job = response.jobs[0];
  assert.ok(Number.isSafeInteger(job.id) && job.id > 0);
  assert.equal(job.name, "prepare");
  assert.equal(job.run_id, run.id);
  assert.equal(job.head_sha, run.head_sha);
  if (Object.hasOwn(job, "run_attempt"))
    assert.equal(job.run_attempt, run.run_attempt);
  assert.ok(["in_progress", "completed"].includes(job.status));
  const startedAt = iso(job.started_at),
    start = Date.parse(startedAt);
  assert.ok(start >= Date.parse(iso(run.created_at)) - 5000);
  let completedAt = null;
  if (job.status === "completed") {
    completedAt = iso(job.completed_at);
    assert.ok(Date.parse(completedAt) >= start);
    if (run.updated_at !== undefined)
      assert.ok(
        Date.parse(completedAt) <= Date.parse(iso(run.updated_at)) + 5000,
      );
  } else {
    assert.equal(job.completed_at, null);
    assert.ok(run.status === "in_progress" || run.conclusion === "cancelled");
  }
  if (run.status === "completed" && run.conclusion === "success") {
    assert.equal(job.status, "completed");
    assert.equal(job.conclusion, "success");
  }
  return Object.freeze({ startedAt, completedAt, jobId: String(job.id) });
}
function fetchPrepareJobs(run) {
  assert.ok(Number.isSafeInteger(run.id) && run.id > 0);
  assert.ok(Number.isInteger(run.run_attempt) && run.run_attempt > 0);
  return github(
    `actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`,
  );
}
function verifyJobCreation(value, run, preparedJob) {
  const time = Date.parse(iso(value)),
    start = Date.parse(preparedJob.startedAt);
  assert.ok(time >= start - 5000 && time < start + contract.INITIAL + 5000);
  assert.ok(time >= Date.parse(iso(run.created_at)) - 5000);
  if (preparedJob.completedAt)
    assert.ok(time <= Date.parse(preparedJob.completedAt) + 5000);
  if (run.status === "completed" && run.updated_at !== undefined)
    assert.ok(time <= Date.parse(iso(run.updated_at)) + 5000);
  return time;
}

function guest(lease, script, timeout = 180000) {
  const result = az(
    [
      "vm",
      "run-command",
      "invoke",
      "--ids",
      lease.vmResourceId,
      "--command-id",
      "RunPowerShellScript",
      "--scripts",
      `$ErrorActionPreference='Stop';${script}`,
    ],
    timeout,
  );
  const matches = [
    ...result.value
      .map((row) => row.message)
      .join("\n")
      .matchAll(/CERTOPS_ADCS_TTL_PUBLIC=([A-Za-z0-9+/=]+)/g),
  ];
  assert.equal(matches.length, 1);
  const bytes = Buffer.from(matches[0][1], "base64");
  assert.ok(bytes.length > 0 && bytes.length <= 2048);
  return JSON.parse(bytes.toString("utf8"));
}



const {readGuestJson, readOwnedObservation} = require("./certops-retention24h-azure").createGuestReader({campaign: "adcs-ttl24h", marker: "CERTOPS_ADCS_TTL_PUBLIC", snapshotEnvironment: "TOKENTIMER_RETENTION_SNAPSHOT", verifyLease: contract.verifyLease, exact: exact, guest});

function prepareTags(group, lease) {
  assert.equal(group.name, groupName(lease));
  assert.equal(group.tags?.purpose, "certops-adcs-qualification");
  assert.equal(group.tags.candidateSha, lease.candidateSha);
  for (const [suffix, value] of Object.entries({
    Kind: contract.KIND,
    Nonce: lease.nonce,
    RunId: lease.runId,
    RunAttempt: lease.runAttempt,
  }))
    assert.equal(group.tags[`ttl24hPrepare${suffix}`], value);
}
function leaseTags(lease) {
  contract.verifyLease(lease);
  return Object.fromEntries(
    Object.entries({
      Kind: lease.kind,
      Phase: lease.phase,
      RunId: lease.runId,
      RunAttempt: lease.runAttempt,
      Nonce: lease.nonce,
      VmId: lease.vmId,
      NodeSha256: lease.nodeSha256,
      KeeperSha256: lease.keeperSha256,
      CreatedAt: lease.createdAt,
      HardExpiresAt: lease.hardExpiresAt,
    })
      .map(([key, value]) => [`ttl24h${key}`, value])
      .concat([["expiresAt", lease.expiresAt]]),
  );
}
function verifyAzure(lease, group, member, phase) {
  contract.verifyLease(lease);
  prepareTags(group, lease);
  assert.equal(
    group.id.toLowerCase(),
    lease.vmResourceId.split("/providers/")[0].toLowerCase(),
  );
  assert.equal(iso(group.tags.createdAt), lease.createdAt);
  assert.equal(iso(group.tags.expiresAt), lease.expiresAt);
  assert.equal(member.id.toLowerCase(), lease.vmResourceId.toLowerCase());
  assert.equal(member.vmId.toLowerCase(), lease.vmId);
  assert.equal(member.provisioningState, "Succeeded");
  assert.equal(member.tags?.purpose, "certops-adcs-qualification");
  assert.equal(member.tags.candidateSha, lease.candidateSha);
  if (phase) {
    assert.equal(lease.phase, phase);
    for (const [key, value] of Object.entries(leaseTags(lease)))
      assert.equal(group.tags[key], value);
  }
  return true;
}
function verifyDeployment(group, lease, deployment, job) {
  assert.equal(deployment.name, "qualification");
  assert.equal(
    deployment.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Resources/deployments/qualification`.toLowerCase(),
  );
  assert.equal(deployment.candidateSha, lease.candidateSha);
  assert.equal(deployment.provisioningState, "Succeeded");
  const timestamp = Date.parse(iso(deployment.timestamp)),
    start = Date.parse(job.startedAt);
  assert.ok(
    timestamp >= start - 5000 && timestamp < start + contract.INITIAL + 5000,
  );
  assert.ok(
    Array.isArray(deployment.outputResources) &&
      deployment.outputResources.length <= 128,
  );
  return new Set(
    deployment.outputResources.map((row) => {
      assert.equal(typeof row.id, "string");
      return row.id.toLowerCase();
    }),
  );
}
function infrastructureTargets(lease, group, member, vms, deployment, job) {
  verifyAzure(
    lease,
    group,
    member,
    lease.phase === "preparing" ? undefined : "resident-owned",
  );
  const outputs = verifyDeployment(group, lease, deployment, job);
  assert.ok(outputs.has(member.id.toLowerCase()));
  assert.ok(Array.isArray(vms) && vms.length === 2);
  assert.deepEqual(vms.map((vm) => vm.name).sort(), [
    "control-plane",
    "domain-ca",
  ]);
  const ids = new Set([member.vmId]);
  return vms.map((vm) => {
    assert.equal(
      vm.id.toLowerCase(),
      `${group.id}/providers/Microsoft.Compute/virtualMachines/${vm.name}`.toLowerCase(),
    );
    assert.equal(vm.tags?.purpose, "certops-adcs-qualification");
    assert.equal(vm.tags.candidateSha, lease.candidateSha);
    assert.match(vm.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert.ok(!ids.has(vm.vmId));
    ids.add(vm.vmId);
    assert.equal(vm.provisioningState, "Succeeded");
    assert.ok(outputs.has(vm.id.toLowerCase()));
    const time = Date.parse(iso(vm.timeCreated));
    assert.ok(
      time >= Date.parse(job.startedAt) - 5000 &&
        time < Date.parse(job.startedAt) + contract.INITIAL + 5000,
    );
    return {
      name: vm.name,
      resourceId: vm.id,
      vmId: vm.vmId,
      createdAt: iso(vm.timeCreated),
    };
  });
}
const OBSERVED_KEYS = [
  ...contract.IDENTITIES,
  "preparedSha256",
  "taskXmlSha256",
  "processId",
  "processCreatedAt",
  "bootTime",
  "principalSid",
  "taskState",
  "nativeVerificationStartedAt",
  "nativeVerificationFinishedAt",
  "monotonicElapsedMs",
  "soleAgentStoppedAndDrained",
  "originalCacheAndJournalUnmodified",
  "predecessorNativeCustodyVerified",
  "predecessorTrustedTlsVerified",
  "deferredUnacceptedNativeCustodyVerified",
];
function verifyObserved(value, prepared) {
  exact(value, OBSERVED_KEYS);
  for (const key of contract.IDENTITIES)
    assert.equal(value[key], prepared.lease[key]);
  assert.equal(value.preparedSha256, contract.preparedDigest(prepared));
  assert.match(value.taskXmlSha256, /^[a-f0-9]{64}$/);
  assert.equal(value.bootTime, prepared.bootTime);
  assert.ok(
    Number.isSafeInteger(value.processId) &&
      value.processId > 0 &&
      value.processId <= 0xffffffff,
  );
  assert.equal(value.principalSid, "S-1-5-18");
  assert.equal(value.taskState, "Running");
  assert.ok(
    Number.isSafeInteger(value.monotonicElapsedMs) &&
      value.monotonicElapsedMs >= 0 &&
      value.monotonicElapsedMs < contract.INITIAL,
  );
  for (const key of OBSERVED_KEYS.slice(-5)) assert.equal(value[key], true);
  const start = Date.parse(iso(value.nativeVerificationStartedAt)),
    end = Date.parse(iso(value.nativeVerificationFinishedAt));
  assert.ok(
    start >= Date.parse(prepared.preparedAt) &&
      end >= start &&
      end < Date.parse(prepared.lease.expiresAt),
  );
  assert.ok(
    Date.parse(iso(value.processCreatedAt)) >=
      Date.parse(prepared.preparedAt) &&
      Date.parse(value.processCreatedAt) <= start,
  );
  return true;
}
function verifyInfrastructureOwnership(rows, lease) {
  assert.ok(Array.isArray(rows) && rows.length === 2);
  assert.deepEqual(rows.map((row) => row.name).sort(), [
    "control-plane",
    "domain-ca",
  ]);
  const ids = new Set([lease.vmId]);
  for (const row of rows) {
    exact(row, ["name", "resourceId", "vmId", "createdAt"]);
    assert.equal(
      row.resourceId.toLowerCase(),
      lease.vmResourceId.replace(/windows-agent$/i, row.name).toLowerCase(),
    );
    assert.match(row.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert.ok(!ids.has(row.vmId));
    ids.add(row.vmId);
    assert.ok(
      Date.parse(iso(row.createdAt)) >= Date.parse(lease.createdAt) - 5000 &&
        Date.parse(row.createdAt) <
          Date.parse(lease.createdAt) + contract.INITIAL,
    );
  }
  return true;
}
function verifyControlObserved(
  value,
  lease,
  targets,
  { postDay = false } = {},
) {
  exact(value, [
    "resourceId",
    "vmId",
    "candidateSha",
    "observedAt",
    "composeServices",
    "noStandaloneCertOpsWorker",
    "containerIds",
  ]);
  const target = targets.find((row) => row.name === "control-plane");
  assert.equal(value.resourceId, target.resourceId);
  assert.equal(value.vmId, target.vmId);
  assert.equal(value.candidateSha, lease.candidateSha);
  assert.deepEqual(value.composeServices, ["api", "mailhog", "postgres"]);
  assert.equal(value.noStandaloneCertOpsWorker, true);
  assert.ok(
    Array.isArray(value.containerIds) && value.containerIds.length === 3,
  );
  assert.deepEqual(value.containerIds.map((row) => row.service).sort(), [
    "api",
    "mailhog",
    "postgres",
  ]);
  assert.equal(new Set(value.containerIds.map((row) => row.id)).size, 3);
  for (const row of value.containerIds) {
    exact(row, ["service", "id"]);
    assert.match(row.id, /^[a-f0-9]{64}$/);
  }

  assert.ok(
    Date.parse(iso(value.observedAt)) >= Date.parse(lease.createdAt) &&
      Date.parse(value.observedAt) <
        Date.parse(lease.createdAt) +
          (postDay ? contract.MAX : contract.INITIAL),
  );
  return true;
}
function verifyOriginal(value) {
  exact(value, [
    "schemaVersion",
    "kind",
    "lease",
    "publicPreparation",
    "taskObserved",
    "infrastructureOwnership",
    "controlPlaneObserved",
  ]);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, contract.KIND);
  contract.verifyPreparedReceipt(value.publicPreparation);
  contract.verifyLease(value.lease);
  assert.equal(value.lease.phase, "preparing");
  assert.deepEqual(value.lease, value.publicPreparation.lease);
  verifyObserved(value.taskObserved, value.publicPreparation);
  verifyInfrastructureOwnership(value.infrastructureOwnership, value.lease);
  verifyControlObserved(
    value.controlPlaneObserved,
    value.lease,
    value.infrastructureOwnership,
  );
  return true;
}
function extendLease(original, observed, at) {
  verifyOriginal(original);
  verifyObserved(observed, original.publicPreparation);
  for (const key of [
    "taskXmlSha256",
    "processId",
    "processCreatedAt",
    "bootTime",
  ])
    assert.equal(observed[key], original.taskObserved[key]);
  assert.ok(
    Date.parse(iso(at)) >= Date.parse(observed.nativeVerificationFinishedAt) &&
      Date.parse(at) < Date.parse(original.lease.expiresAt),
  );
  const lease = {
    ...original.lease,
    phase: "resident-owned",
    expiresAt: original.lease.hardExpiresAt,
  };
  contract.verifyLease(lease);
  return lease;
}

function deployment(group) {
  return az([
    "deployment",
    "group",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "qualification",
    "--query",
    "{id:id,name:name,candidateSha:properties.parameters.candidateSha.value,timestamp:properties.timestamp,provisioningState:properties.provisioningState,outputResources:properties.outputResources}",
  ]);
}
function inspect(lease, phase) {
  const group = az(["group", "show", "--name", groupName(lease)]),
    member = az(["vm", "show", "--ids", lease.vmResourceId]);
  verifyAzure(lease, group, member, phase);
  return { group, member };
}
function owner(lease, completed = false) {
  const run = github(
    `actions/runs/${lease.runId}/attempts/${lease.runAttempt}`,
  );
  verifyOwner(run, lease, { completed });
  const job = verifyPrepareJob(run, fetchPrepareJobs(run));
  verifyJobCreation(lease.createdAt, run, job);
  return { run, job };
}
function write(name, value) {
  assert.match(name, /^adcs-ttl24h-[a-z0-9-]+\.json$/);
  fs.mkdirSync(OUTPUT, { recursive: true });
  const file = path.join(OUTPUT, name);
  fs.writeFileSync(file, JSON.stringify(value) + "\n", { flag: "wx" });
  return file;
}
function currentIdentity() {
  assert.match(process.env.GITHUB_SHA, /^[a-f0-9]{40}$/);
  assert.match(process.env.GITHUB_RUN_ID, /^[1-9][0-9]*$/);
  assert.match(process.env.GITHUB_RUN_ATTEMPT, /^[1-9][0-9]*$/);
  assert.match(process.env.CERTOPS_ADCS_TTL24H_NONCE, /^[a-f0-9]{64}$/);
  return {
    candidateSha: process.env.GITHUB_SHA,
    runId: process.env.GITHUB_RUN_ID,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT,
    nonce: process.env.CERTOPS_ADCS_TTL24H_NONCE,
  };
}
async function artifact(lease, kind) {
  assert.ok(["original", "ownership"].includes(kind));
  const name = `adcs-ttl24h-${kind}-${lease.runAttempt}-${lease.nonce}`,
    member = `adcs-ttl24h-${kind}.json`,
    response = github(`actions/runs/${lease.runId}/artifacts?per_page=100`);
  assert.ok(
    Number.isInteger(response.total_count) &&
      response.total_count <= 100 &&
      Array.isArray(response.artifacts) &&
      response.artifacts.length === response.total_count,
  );
  const matches = response.artifacts.filter(
    (row) => row.name === name && !row.expired,
  );
  assert.equal(matches.length, 1);
  const entry = matches[0];
  assert.ok(
    Number.isSafeInteger(entry.id) &&
      entry.id > 0 &&
      Number.isSafeInteger(entry.size_in_bytes) &&
      entry.size_in_bytes > 0 &&
      entry.size_in_bytes <= 2 * 1024 * 1024,
  );
  assert.match(entry.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(String(entry.workflow_run.id), lease.runId);
  assert.equal(entry.workflow_run.head_sha, lease.candidateSha);
  const created = Date.parse(iso(entry.created_at));
  assert.ok(
    created >= Date.parse(lease.createdAt) - 5000 &&
      created < Date.parse(lease.createdAt) + contract.INITIAL + 5000,
  );
  const zip = await downloadArtifactZip(entry.id);
  assert.equal(sha(zip), entry.digest.slice(7));
  const script =
    "import io,sys,zipfile; z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())); assert z.namelist()==[sys.argv[1]]; i=z.infolist()[0]; assert not i.is_dir() and not(i.flag_bits&1) and 0<i.file_size<=65536; sys.stdout.buffer.write(z.read(i))";
  const bytes = execFileSync("python3", ["-c", script, member], {
    input: zip,
    timeout: 10000,
    maxBuffer: 65536,
  });
  return {
    value: JSON.parse(bytes.toString("utf8")),
    reference: {
      id: String(entry.id),
      name,
      archiveSha256: entry.digest.slice(7),
    },
  };
}
function verifyHandoff(value, original, reference) {
  exact(value, [
    "schemaVersion",
    "kind",
    "lease",
    "publicPreparation",
    "taskObserved",
    "originalArtifact",
    "handoffObserved",
    "infrastructureOwnership",
    "controlPlaneObserved",
  ]);
  verifyOriginal(original);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, contract.KIND);
  assert.deepEqual(value.publicPreparation, original.publicPreparation);
  assert.deepEqual(
    value.infrastructureOwnership,
    original.infrastructureOwnership,
  );
  assert.deepEqual(value.controlPlaneObserved, original.controlPlaneObserved);
  assert.deepEqual(value.taskObserved, original.taskObserved);
  assert.deepEqual(value.originalArtifact, reference);
  contract.verifyLease(value.lease);
  assert.equal(value.lease.phase, "resident-owned");
  for (const key of contract.LEASE_KEYS.filter(
    (key) => !["phase", "expiresAt"].includes(key),
  ))
    assert.equal(value.lease[key], original.lease[key]);
  verifyObserved(value.handoffObserved, original.publicPreparation);
  for (const key of [
    "taskXmlSha256",
    "processId",
    "processCreatedAt",
    "bootTime",
  ])
    assert.equal(value.handoffObserved[key], original.taskObserved[key]);
  return true;
}
function taskProducer(lease, mode, extra = "") {
  contract.verifyLease(lease);
  assert.ok(["Observe", "WriteLease", "Finalize"].includes(mode));
  return `$r=Get-Content 'C:\\ttqualification\\runtime.json' -Raw|ConvertFrom-Json;if($r.candidateSha -cne '${lease.candidateSha}'){throw 'Native candidate mismatch'};$result=& (Join-Path $r.source 'scripts/certops-adcs-ttl24h-task.ps1') -Mode ${mode} -Nonce '${lease.nonce}' ${extra};if($LASTEXITCODE -ne 0){throw 'Owned task observation refused'};$b=[Text.Encoding]::UTF8.GetBytes(($result -join [Environment]::NewLine));`;
}
function observe(lease, mode = "Observe") {
  return readOwnedObservation(lease, taskProducer(lease, mode));
}
function controlObserved(lease, targets, { postDay = false } = {}) {
  const target = targets.find((row) => row.name === "control-plane");
  const fresh = az(["vm", "show", "--ids", target.resourceId]);
  assert.equal(fresh.vmId, target.vmId);
  assert.equal(fresh.tags?.candidateSha, lease.candidateSha);
  const python = `import base64,json,subprocess,datetime
root='/opt/ttqualification'
def cmd(args):return subprocess.check_output(args,cwd=root,text=True).strip()
assert cmd(['git','rev-parse','HEAD'])=='${lease.candidateSha}'
services=sorted(cmd(['docker','compose','-f','deploy/compose/docker-compose.test.yml','ps','--services','--status','running']).splitlines())
assert services==['api','mailhog','postgres']
assert len(cmd(['docker','ps','-q']).splitlines())==3
containers=[]
for service in services:
 identifier=cmd(['docker','compose','-f','deploy/compose/docker-compose.test.yml','ps','-q',service])
 info=json.loads(cmd(['docker','inspect',identifier]))
 assert len(info)==1 and info[0]['Config']['Labels']['com.docker.compose.service']==service
 containers.append({'service':service,'id':info[0]['Id']})
processes=cmd(['ps','-eo','comm=,args=']).splitlines()
for line in processes:
 parts=line.strip().split(None,1)
 if parts and parts[0] in ('node','nodejs'):
  assert not any(marker in parts[-1] for marker in ('apps/worker/src/runner.js','certops-worker.js','worker:certops'))
value={'resourceId':'${target.resourceId}','vmId':'${target.vmId}','candidateSha':'${lease.candidateSha}','observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),'composeServices':services,'noStandaloneCertOpsWorker':True,'containerIds':containers}
print('CERTOPS_ADCS_TTL_PUBLIC='+base64.b64encode(json.dumps(value,separators=(',',':')).encode()).decode())
`;
  const script = `set -eu\npython3 - <<'CERTOPS_TTL_CONTROL'\n${python}CERTOPS_TTL_CONTROL`;
  const result = az([
    "vm",
    "run-command",
    "invoke",
    "--ids",
    target.resourceId,
    "--command-id",
    "RunShellScript",
    "--scripts",
    script,
  ]);
  const markers = [
    ...result.value
      .map((row) => row.message)
      .join("\n")
      .matchAll(/CERTOPS_ADCS_TTL_PUBLIC=([A-Za-z0-9+/=]+)/g),
  ];
  assert.equal(markers.length, 1);
  const bytes = Buffer.from(markers[0][1], "base64");
  assert.ok(bytes.length <= 4096);
  const value = JSON.parse(bytes);
  verifyControlObserved(value, lease, targets, { postDay });
  return value;
}
function initialMember(identity) {
  const group = az(["group", "show", "--name", groupName(identity)]);
  prepareTags(group, identity);
  const member = az([
    "vm",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "windows-agent",
  ]);
  assert.equal(
    member.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Compute/virtualMachines/windows-agent`.toLowerCase(),
  );
  assert.equal(member.tags?.candidateSha, identity.candidateSha);
  assert.equal(member.tags?.purpose, "certops-adcs-qualification");
  assert.equal(member.provisioningState, "Succeeded");
  return { group, member };
}
function seal() {
  const identity = currentIdentity();
  assert.equal(process.env.LAB_GROUP, groupName(identity));
  const { group, member } = initialMember(identity);
  const envelope = readGuestJson(
    { vmResourceId: member.id },
    `$b=[IO.File]::ReadAllBytes('C:\\ttqualification\\adcs-ttl24h\\${identity.nonce}\\prepare-public.json');`,
  );
  exact(envelope, ["schemaVersion", "kind", "prepared", "observed"]);
  assert.equal(envelope.schemaVersion, 1);
  assert.equal(envelope.kind, contract.KIND);
  const lease = envelope.prepared.lease;
  contract.verifyLease(lease);
  for (const [key, expected] of Object.entries(identity))
    assert.equal(lease[key], expected);
  const { job } = owner(lease);
  verifyAzure(lease, group, member);
  const vms = ["domain-ca", "control-plane"].map((name) =>
    az(["vm", "show", "--resource-group", group.name, "--name", name]),
  );
  const infrastructureOwnership = infrastructureTargets(
    lease,
    group,
    member,
    vms,
    deployment(group),
    job,
  );
  const controlPlaneObserved = controlObserved(lease, infrastructureOwnership);
  const value = {
    schemaVersion: 1,
    kind: contract.KIND,
    lease: envelope.prepared.lease,
    publicPreparation: envelope.prepared,
    taskObserved: envelope.observed,
    infrastructureOwnership,
    controlPlaneObserved,
  };
  verifyOriginal(value);
  for (const [key, expected] of Object.entries(identity))
    assert.equal(value.lease[key], expected);

  verifyAzure(value.lease, group, member);
  assert.equal(group.tags.ttl24hPhase, undefined);
  const outputs = verifyDeployment(group, value.lease, deployment(group), job);
  assert.ok(outputs.has(member.id.toLowerCase()));
  for (const row of value.publicPreparation.sources) {
    assert.equal(sha(fs.readFileSync(path.join(ROOT, row.file))), row.sha256);
  }
  write("adcs-ttl24h-original.json", value);
  return value;
}
function infrastructure(lease, action, expectedTargets) {
  assert.ok(
    Date.now() < Date.parse(lease.expiresAt) &&
      Date.now() < Date.parse(lease.hardExpiresAt),
  );
  verifyInfrastructureOwnership(expectedTargets, lease);
  assert.ok(["deallocate", "start"].includes(action));
  const { job } = owner(lease),
    { group, member } = inspect(lease, "resident-owned"),
    vms = ["domain-ca", "control-plane"].map((name) =>
      az(["vm", "show", "--resource-group", group.name, "--name", name]),
    ),
    targets = infrastructureTargets(
      lease,
      group,
      member,
      vms,
      deployment(group),
      job,
    );
  assert.deepEqual(targets, expectedTargets);
  for (const target of targets) {
    const fresh = az(["vm", "show", "--ids", target.resourceId]);
    assert.equal(fresh.vmId, target.vmId);
    assert.equal(fresh.tags?.candidateSha, lease.candidateSha);
    inspect(lease, "resident-owned");
    command("az", ["vm", action, "--ids", target.resourceId, "-o", "none"]);
    const state = az(["vm", "get-instance-view", "--ids", target.resourceId]);
    const after = az(["vm", "show", "--ids", target.resourceId]);
    assert.equal(after.id.toLowerCase(), target.resourceId.toLowerCase());
    assert.equal(after.vmId, target.vmId);
    assert.ok(Array.isArray(state.instanceView?.statuses));
    assert.equal(
      state.instanceView.statuses.filter((row) =>
        row.code?.startsWith("PowerState/"),
      ).length,
      1,
    );
    assert.ok(
      state.instanceView.statuses.some(
        (row) =>
          row.code ===
          `PowerState/${action === "start" ? "running" : "deallocated"}`,
      ),
    );
  }
  return targets;
}
async function handoff() {
  const identity = currentIdentity(),
    { group, member } = initialMember(identity),
    target = { ...identity, createdAt: iso(group.tags.createdAt) };
  const sealed = await artifact(target, "original"),
    original = sealed.value;
  verifyOriginal(original);
  for (const [key, value] of Object.entries(identity))
    assert.equal(original.lease[key], value);
  owner(original.lease);
  verifyAzure(original.lease, group, member);
  const observed = observe(original.lease);
  const lease = extendLease(original, observed, new Date().toISOString());
  inspect(original.lease);
  command("az", [
    "group",
    "update",
    "--name",
    groupName(lease),
    "--set",
    ...Object.entries(leaseTags(lease)).map(
      ([key, value]) => `tags.${key}=${value}`,
    ),
    "-o",
    "none",
  ]);
  inspect(lease, "resident-owned");
  const publicLease = Buffer.from(JSON.stringify(lease)).toString("base64");
  readOwnedObservation(
    lease,
    taskProducer(lease, "WriteLease", `-PublicLeaseBase64 '${publicLease}'`),
  );
  const handoffObserved = observe(lease);
  verifyObserved(handoffObserved, original.publicPreparation);
  for (const key of [
    "taskXmlSha256",
    "processId",
    "processCreatedAt",
    "bootTime",
  ])
    assert.equal(handoffObserved[key], original.taskObserved[key]);
  const costTargets = infrastructure(
    lease,
    "deallocate",
    original.infrastructureOwnership,
  );
  write("adcs-ttl24h-cost.json", {
    scope: "exact-owned-control-and-ca-deallocated-not-qualification",
    candidateSha: lease.candidateSha,
    runId: lease.runId,
    runAttempt: lease.runAttempt,
    nonce: lease.nonce,
    targets: costTargets,
    observedAt: new Date().toISOString(),
  });
  const value = {
    ...original,
    lease,
    originalArtifact: sealed.reference,
    handoffObserved,
  };
  verifyHandoff(value, original, sealed.reference);
  write("adcs-ttl24h-ownership.json", value);
  return value;
}

function readCaSnapshot(original, lease, freshRequestId, execute, freshFingerprint) {
  if (freshFingerprint != null) assert.match(freshFingerprint, /^[a-f0-9]{64}$/);
  verifyOriginal(original);
  contract.verifyLease(lease);
  const nonce = crypto.randomBytes(32).toString("hex"),
    directory = `C:\\Windows\\Temp\\certops-adcs-ttl24h-${lease.nonce}-${nonce}`,
    file = `${directory}\\public.json`;
  const sourceFile = "infra/certops-adcs/ttl24h-ca-observe.ps1",
    source = fs.readFileSync(path.join(ROOT, sourceFile), "utf8");
  const declared = original.publicPreparation.sources.filter(
    (row) => row.file === sourceFile,
  );
  assert.equal(declared.length, 1);
  assert.equal(sha(Buffer.from(source)), declared[0].sha256);
  const p = original.publicPreparation;
  for (const id of [
    p.predecessor.requestId,
    p.validation.requestId,
    ...(freshRequestId ? [freshRequestId] : []),
  ]) {
    assert.match(id, /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(id) <= 0xffffffff);
  }
  const identity = `function Get-ExactIdentity([string]$path){$s=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if($s.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Snapshot reparse refused'};$out=& "$env:SystemRoot\System32\fsutil.exe" file queryfileid $path;if($LASTEXITCODE -ne 0){throw 'Snapshot identity unavailable'};$m=[regex]::Matches(($out -join ' '),'0x[0-9a-fA-F]{16,32}');if($m.Count-ne 1){throw 'Snapshot identity ambiguous'};return $m[0].Value.ToLowerInvariant()};`;
  const marker =
    "$o|ConvertTo-Json -Depth 4 -Compress|ForEach-Object {'CERTOPS_ADCS_TTL_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_))}";
  let receipt,
    verified = false;
  try {
    receipt = execute(`${identity}# CERTOPS_CA_SNAPSHOT_CREATE
if(Test-Path -LiteralPath '${directory}'){throw 'Snapshot directory already exists'};$ancestor=Get-Item -LiteralPath 'C:\Windows\Temp';while($ancestor){if(!$ancestor.PSIsContainer-or($ancestor.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Snapshot ancestor refused'};$ancestor=$ancestor.Parent};$null=New-Item -ItemType Directory -Path '${directory}';$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');$acl.SetOwner($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));[IO.Directory]::SetAccessControl('${directory}',$acl);
$raw=& {${source}} -RunId '${p.run}' -InstalledRequestId ${p.predecessor.requestId} -DeferredRequestId ${p.validation.requestId} ${freshRequestId ? `-FreshRequestId ${freshRequestId}` : ""} ${freshFingerprint ? `-FreshFingerprintSha256 ${freshFingerprint}` : ""};$b=[Text.Encoding]::UTF8.GetBytes(($raw-join[Environment]::NewLine));if($b.Length-lt 1-or$b.Length-gt 65536){throw 'Public CA snapshot bound'};$stream=[IO.File]::Open('${file}',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$stream.Write($b,0,$b.Length);$stream.Flush($true)}finally{$stream.Dispose()};$o=@{length=$b.Length;sha256=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b))).Replace('-','').ToLowerInvariant();fileIdentity=(Get-ExactIdentity '${file}');directoryIdentity=(Get-ExactIdentity '${directory}')};${marker}`);
    exact(receipt, ["length", "sha256", "fileIdentity", "directoryIdentity"]);
    assert.ok(
      Number.isInteger(receipt.length) &&
        receipt.length > 0 &&
        receipt.length <= 65536,
    );
    assert.match(receipt.sha256, /^[a-f0-9]{64}$/);
    for (const key of ["fileIdentity", "directoryIdentity"])
      assert.match(receipt[key], /^0x[a-f0-9]{16,32}$/);
    verified = true;
    const guard = `${identity}if((Get-ExactIdentity '${file}')-cne '${receipt.fileIdentity}'-or(Get-ExactIdentity '${directory}')-cne '${receipt.directoryIdentity}') {throw 'CA snapshot ownership changed'};$b=[IO.File]::ReadAllBytes('${file}');if($b.Length-ne ${receipt.length}-or(Get-FileHash -LiteralPath '${file}' -Algorithm SHA256).Hash.ToLowerInvariant()-cne '${receipt.sha256}'){throw 'CA snapshot bytes changed'};`;
    const value = readGuestJson(lease, guard, (_lease, script) =>
      execute(script),
    );
    return value;
  } finally {
    if (verified) {
      const removed = execute(`${identity}# CERTOPS_CA_SNAPSHOT_CLEANUP
if((Get-ExactIdentity '${file}')-cne '${receipt.fileIdentity}'-or(Get-ExactIdentity '${directory}')-cne '${receipt.directoryIdentity}'-or(Get-FileHash -LiteralPath '${file}' -Algorithm SHA256).Hash.ToLowerInvariant()-cne '${receipt.sha256}'-or@(Get-ChildItem -LiteralPath '${directory}' -Force).Count-ne 1){throw 'CA snapshot cleanup ownership changed'};Remove-Item -LiteralPath '${file}' -Force;Remove-Item -LiteralPath '${directory}';if(Test-Path -LiteralPath '${directory}'){throw 'CA snapshot cleanup incomplete'};$o=@{removed=$true};${marker}`);
      exact(removed, ["removed"]);
      assert.equal(removed.removed, true);
    }
  }
}
function caObservation(original, lease, freshRequestId, freshFingerprint) {
  const target = original.infrastructureOwnership.find(
    (row) => row.name === "domain-ca",
  );
  owner(lease, true);
  inspect(lease, "resident-owned");
  const vm = az(["vm", "show", "--ids", target.resourceId]);
  assert.equal(vm.vmId, target.vmId);
  assert.equal(vm.tags?.candidateSha, lease.candidateSha);
  return readCaSnapshot(original, lease, freshRequestId, (script) => {
    const current = az(["vm", "show", "--ids", target.resourceId]);
    assert.equal(current.vmId, target.vmId);
    assert.equal(current.id.toLowerCase(), target.resourceId.toLowerCase());
    assert.equal(current.tags?.candidateSha, lease.candidateSha);
    const result = az([
      "vm",
      "run-command",
      "invoke",
      "--ids",
      target.resourceId,
      "--command-id",
      "RunPowerShellScript",
      "--scripts",
      `$ErrorActionPreference='Stop';${script}`,
    ]);
    const after = az(["vm", "show", "--ids", target.resourceId]);
    assert.equal(after.id.toLowerCase(), target.resourceId.toLowerCase());
    assert.equal(after.vmId, target.vmId);
    assert.equal(after.tags?.candidateSha, lease.candidateSha);
    const matches = [
      ...result.value
        .map((row) => row.message)
        .join("\n")
        .matchAll(/CERTOPS_ADCS_TTL_PUBLIC=([A-Za-z0-9+/=]+)/g),
    ];
    assert.equal(matches.length, 1);
    const bytes = Buffer.from(matches[0][1], "base64");
    assert.ok(bytes.length > 0 && bytes.length <= 2048);
    return JSON.parse(bytes);
  }, freshFingerprint);
}

function resolveFreshRequestId(requests, fresh) {
  assert.ok(Array.isArray(requests) && requests.length === 3);
  assert.match(fresh.fingerprints[2], /^[a-f0-9]{64}$/);
  const matched = requests.filter(row => {
    assert.ok(typeof row.certificateB64 === "string" && row.certificateB64.length <= 90000);
    return sha(new crypto.X509Certificate(Buffer.from(row.certificateB64, "base64")).raw) === fresh.fingerprints[2];
  });
  assert.equal(matched.length, 1, "Exact fresh native CA leaf required");
  const id = matched[0].requestId;
  assert.match(id, /^[1-9][0-9]{0,9}$/); assert.ok(Number(id) <= 0xffffffff);
  if (fresh.requestIds[2] != null) assert.equal(fresh.requestIds[2], id);
  assert.ok(!fresh.requestIds.slice(0, 2).includes(id), "Fresh native CA ID must be distinct");
  return id;
}
function verifyCaPublic(value, prepared, fresh) {
  contract.verifyPreparedReceipt(prepared);
  exact(value, [
    "scope",
    "observedAt",
    "nativeTotalRequestCount",
    "nativeRequesterCount",
    "requests",
    "caCertificateB64",
    "crlB64",
  ]);
  assert.equal(value.scope, "read-only-original-domain-ca-default-ttl24h");
  const at = iso(value.observedAt);
  assert.ok(
    Date.parse(at) > Date.parse(prepared.validation.deadlineAt) &&
      Date.parse(at) < Date.parse(prepared.lease.hardExpiresAt),
  );
  const ids = [
      prepared.predecessor.requestId,
      prepared.validation.requestId,
      ...(fresh ? [resolveFreshRequestId(value.requests, fresh)] : []),
    ],
    fingerprints = [
      prepared.predecessor.fingerprint,
      prepared.validation.leafFingerprint,
      ...(fresh ? [fresh.fingerprints[2]] : []),
    ];
  assert.equal(value.nativeRequesterCount, ids.length);
  assert.equal(
    value.nativeTotalRequestCount,
    prepared.caRequestCounts.deferred + (fresh ? 1 : 0),
  );
  assert.ok(
    Array.isArray(value.requests) && value.requests.length === ids.length,
  );
  const ca = new crypto.X509Certificate(
      Buffer.from(value.caCertificateB64, "base64"),
    ),
    pin = sha(ca.publicKey.export({ type: "spki", format: "der" }));
  assert.equal(pin, prepared.preflight.caKeySha256);
  assert.equal(ca.ca, true);
  assert.equal(ca.verify(ca.publicKey), true);
  for (let i = 0; i < ids.length; i++) {
    const rows = value.requests.filter((row) => row.requestId === ids[i]);
    assert.equal(rows.length, 1);
    exact(rows[0], ["requestId", "disposition", "certificateB64"]);
    assert.equal(rows[0].disposition, 20);
    assert.ok(
      typeof rows[0].certificateB64 === "string" &&
        rows[0].certificateB64.length <= 90000,
    );
    const leaf = new crypto.X509Certificate(
      Buffer.from(rows[0].certificateB64, "base64"),
    );
    assert.equal(sha(leaf.raw), fingerprints[i]);
    assert.equal(leaf.verify(ca.publicKey), true);
    assert.equal(
      leaf.checkHost(prepared.predecessor.domain),
      prepared.predecessor.domain,
    );
  }
  assert.ok(typeof value.crlB64 === "string" && value.crlB64.length <= 90000);
  const crl = Buffer.from(value.crlB64, "base64");
  assert.ok(crl.length >= 100 && crl.length <= 65536);
  const dir = fs.mkdtempSync(
      path.join(
        process.env.RUNNER_TEMP || require("node:os").tmpdir(),
        "certops-ttl-ca-public-",
      ),
    ),
    id = fs.lstatSync(dir, { bigint: true }).ino,
    file = path.join(dir, "public-ca.pem");
  try {
    fs.writeFileSync(file, ca.toString(), { flag: "wx", mode: 0o600 });
    const output = execFileSync(
      "openssl",
      [
        "crl",
        "-inform",
        "DER",
        "-noout",
        "-nextupdate",
        "-verify",
        "-CAfile",
        file,
      ],
      {
        input: crl,
        encoding: "utf8",
        timeout: 10000,
        maxBuffer: 4096,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    assert.match(output, /^nextUpdate=/);
    const crlNextUpdate = new Date(
      output.trim().slice("nextUpdate=".length),
    ).toISOString();
    assert.ok(Date.parse(crlNextUpdate) > Date.parse(at) + contract.HOUR);
    return {
      observedAt: at,
      nativeTotalRequestCount: value.nativeTotalRequestCount,
      nativeRequesterCount: value.nativeRequesterCount,
      requestIds: ids,
      fingerprints,
      caKeySha256: pin,
      crlSha256: sha(crl),
      crlNextUpdate,
    };
  } finally {
    assert.equal(fs.lstatSync(dir).isSymbolicLink(), false);
    assert.equal(fs.lstatSync(dir, { bigint: true }).ino, id);
    assert.equal(fs.lstatSync(file).isSymbolicLink(), false);
    assert.equal(fs.readFileSync(file, "utf8"), ca.toString());
    fs.unlinkSync(file);
    fs.rmdirSync(dir);
  }
}
function verifyPartialOwnership(group, run, jobsResponse, deploy, vms, nonce) {
  const expected = {
    runId: String(run.id),
    runAttempt: String(run.run_attempt),
    candidateSha: run.head_sha,
    nonce,
  };
  verifyOwner(run, expected);
  prepareTags(group, expected);
  assert.match(nonce, /^[a-f0-9]{64}$/);
  const job = verifyPrepareJob(run, jobsResponse);
  assert.equal(
    deploy.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Resources/deployments/qualification`.toLowerCase(),
  );
  assert.equal(deploy.name, "qualification");
  assert.equal(deploy.candidateSha, run.head_sha);
  assert.ok(
    ["Succeeded", "Failed", "Canceled", "Running", "Accepted"].includes(
      deploy.provisioningState,
    ),
  );
  verifyJobCreation(deploy.timestamp, run, job);
  assert.ok(Array.isArray(vms) && vms.length > 0 && vms.length <= 3);
  const seen = new Set();
  for (const vm of vms) {
    assert.ok(
      ["windows-agent", "domain-ca", "control-plane"].includes(vm.name) &&
        !seen.has(vm.name),
    );
    seen.add(vm.name);
    assert.equal(
      vm.id.toLowerCase(),
      `${group.id}/providers/Microsoft.Compute/virtualMachines/${vm.name}`.toLowerCase(),
    );
    assert.equal(vm.tags?.purpose, "certops-adcs-qualification");
    assert.equal(vm.tags.candidateSha, run.head_sha);
    assert.match(vm.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    verifyJobCreation(vm.timeCreated, run, job);
  }
  return job;
}
function cleanupDecision(original, handoff, run, job, now) {
  assert.ok(Number.isFinite(now));
  if (run.status === "completed" && run.conclusion !== "success")
    return { delete: true, reason: "terminal-failed-owner" };
  if (original) {
    verifyOriginal(original);
    const expiry = handoff
      ? (verifyHandoff(handoff, original, handoff.originalArtifact),
        handoff.lease.expiresAt)
      : original.lease.expiresAt;
    return {
      delete: now >= Date.parse(expiry),
      reason: "authenticated-lease-expiry",
    };
  }
  return {
    delete: now >= Date.parse(job.startedAt) + contract.MAX,
    reason: "conservative-original-job-start32h-orphan-cleanup",
  };
}
function deleteGroup(name) {
  assert.match(name, /^tt-certops-[1-9][0-9]*-[1-9][0-9]*$/);
  command("az", [
    "group",
    "delete",
    "--name",
    name,
    "--yes",
    "--no-wait",
    "-o",
    "none",
  ]);
  command(
    "az",
    [
      "group",
      "wait",
      "--name",
      name,
      "--deleted",
      "--timeout",
      "600",
      "--interval",
      "15",
    ],
    false,
    660000,
  );
  assert.equal(az(["group", "exists", "--name", name]), false);
  return new Date().toISOString();
}
function orphanReceipt(mode, name) {
  const value = {
    schemaVersion: 1,
    scope: "owned-adcs-ttl24h-cleanup-incomplete-not-qualification",
    mode,
    resourceGroup: name,
    observedAt: new Date().toISOString(),
    cleanupRequired: true,
    reason: "owner-artifact-deployment-vm-or-cloud-absence-unconfirmed",
  };
  process.stderr.write(`ADCS TTL orphan receipt: ${JSON.stringify(value)}\n`);
  if (process.env.GITHUB_STEP_SUMMARY)
    fs.appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `\nOwned AD CS TTL cleanup requires attention: ${name}. Independent expiry cleanup remains required.\n`,
    );
  write(`adcs-ttl24h-controller-failure-${mode}-${name}.json`, value);
}
async function abort() {
  const expected = currentIdentity();
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  const name = groupName(expected);
  try {
    if (az(["group", "exists", "--name", name]) === false) return;
    const run = github(
      `actions/runs/${expected.runId}/attempts/${expected.runAttempt}`,
    );
    verifyOwner(run, expected);
    const group = az(["group", "show", "--name", name]),
      vms = az(["vm", "list", "--resource-group", name]);
    verifyPartialOwnership(
      group,
      run,
      fetchPrepareJobs(run),
      deployment(group),
      vms,
      expected.nonce,
    );
    const local = path.join(OUTPUT, "adcs-ttl24h-original.json");
    if (fs.existsSync(local)) {
      const sealed = await artifact(
        { ...expected, createdAt: iso(group.tags.createdAt) },
        "original",
      );
      verifyOriginal(sealed.value);
      assert.equal(
        sealed.value.lease.vmId,
        vms.find((vm) => vm.name === "windows-agent")?.vmId,
      );
      assert.equal(sealed.value.lease.createdAt, iso(group.tags.createdAt));
    }
    const fresh = az(["group", "show", "--name", name]);
    prepareTags(fresh, expected);
    deleteGroup(name);
  } catch {
    orphanReceipt("abort", name);
    throw Error(
      "Owned default TTL abort refused; independent cleanup required",
    );
  }
}

function resumeControl(original, lease) {
  infrastructure(lease, "start", original.infrastructureOwnership);
  const target = original.infrastructureOwnership.find(
      (row) => row.name === "control-plane",
    ),
    ids = Object.fromEntries(
      original.controlPlaneObserved.containerIds.map((row) => [
        row.service,
        row.id,
      ]),
    );
  for (const id of Object.values(ids)) assert.match(id, /^[a-f0-9]{64}$/);
  const check = original.controlPlaneObserved.containerIds
    .map(
      (row) =>
        `test "$(docker inspect -f '{{.Id}} {{index .Config.Labels "com.docker.compose.service"}}' '${row.id}')" = '${row.id} ${row.service}'`,
    )
    .join("\n");
  const script = `set -eu
cd /opt/ttqualification
test "$(git rev-parse HEAD)" = '${lease.candidateSha}'
${check}
test "$(sha256sum /etc/ttqualification/api.pem | cut -d' ' -f1)" = '${original.publicPreparation.apiTrust.sha256}'
docker start '${ids.postgres}' >/dev/null
for attempt in $(seq 1 30); do test "$(docker inspect -f '{{.State.Health.Status}}' '${ids.postgres}')" != healthy || break; sleep 2; done
test "$(docker inspect -f '{{.State.Health.Status}}' '${ids.postgres}')" = healthy
docker start '${ids.mailhog}' '${ids.api}' >/dev/null
for attempt in $(seq 1 30); do if curl -fsS --cacert /etc/ttqualification/api.pem https://10.64.0.6/health >/dev/null; then break; fi; sleep 2; done
curl -fsS --cacert /etc/ttqualification/api.pem https://10.64.0.6/health >/dev/null
printf 'CERTOPS_TTL_CONTROL_RESUMED=verified-original-containers\n'
`;
  const vm = az(["vm", "show", "--ids", target.resourceId]);
  assert.equal(vm.vmId, target.vmId);
  const result = az([
    "vm",
    "run-command",
    "invoke",
    "--ids",
    target.resourceId,
    "--command-id",
    "RunShellScript",
    "--scripts",
    script,
  ]);
  assert.ok(
    result.value
      .map((row) => row.message)
      .join("\n")
      .includes("CERTOPS_TTL_CONTROL_RESUMED=verified-original-containers"),
  );
  const observed = controlObserved(lease, original.infrastructureOwnership, {
    postDay: true,
  });
  assert.deepEqual(
    observed.containerIds,
    original.controlPlaneObserved.containerIds,
  );
  return observed;
}
const CONTROLLER_SOURCES = Object.freeze([
  "scripts/certops-adcs-ttl24h-azure.js",
  "scripts/certops-adcs-ttl24h-contract.js",
  "scripts/certops-adcs-ttl24h-proof.js",
  "infra/certops-adcs/ttl24h-ca-observe.ps1",
  ".github/workflows/certops-adcs-ttl24h-prepare.yml",
  ".github/workflows/certops-adcs-ttl24h-finalize.yml",
]);
function finalizerProvenance() {
  const runId = process.env.GITHUB_RUN_ID,
    runAttempt = process.env.GITHUB_RUN_ATTEMPT;
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.match(runAttempt, /^[1-9][0-9]*$/);
  const run = github(`actions/runs/${runId}/attempts/${runAttempt}`),
    workflowPath = ".github/workflows/certops-adcs-ttl24h-finalize.yml";
  assert.equal(run.repository?.full_name, REPOSITORY);
  assert.equal(run.head_repository?.full_name, REPOSITORY);
  assert.equal(run.path, workflowPath);
  assert.equal(run.head_branch, "main");
  assert.ok(["schedule", "workflow_dispatch"].includes(run.event));
  assert.equal(run.head_sha, process.env.GITHUB_SHA);
  assert.equal(String(run.id), runId);
  assert.equal(String(run.run_attempt), runAttempt);
  assert.ok(["in_progress", "completed"].includes(run.status));
  return {
    repository: REPOSITORY,
    runId,
    runAttempt,
    headSha: run.head_sha,
    event: run.event,
    headBranch: "main",
    workflowPath,
    controllerSources: CONTROLLER_SOURCES.map((file) => ({
      file,
      sha256: sha(fs.readFileSync(path.join(ROOT, file))),
    })),
  };
}
function qualificationReport({
  original,
  handoff,
  originalArtifact,
  handoffArtifact,
  completed,
  proof,
  cleanupFinishedAt,
  finalizer,
}) {
  const native = require("./certops-adcs-ttl24h-proof");
  verifyOriginal(original);
  verifyHandoff(handoff, original, originalArtifact);
  contract.verifyCompletedTaskObservation(
    completed,
    original.publicPreparation,
    original.taskObserved,
  );
  native.verifyAgainstPrepared(
    proof,
    original.publicPreparation,
    original.taskObserved,
  );
  assert.ok(
    Date.parse(cleanupFinishedAt) >=
      Date.parse(completed.nativeVerificationFinishedAt),
  );
  const p = original.publicPreparation;
  assert.deepEqual(
    p.sources.map((row) => row.file).sort(),
    [...require("./certops-adcs-ttl24h-sources").REQUIRED_SOURCES].sort(),
  );
  const source = p.sources.find(
    (row) => row.file === "scripts/certops-adcs-ttl24h-resident.js",
  );
  assert.ok(source);
  const capabilities = Object.fromEntries(
    ["windows", "system", "domain", "api", "sameVmResidentKeeper"].map(
      (key) => [key, { available: true }],
    ),
  );
  return {
    schemaVersion: 1,
    suite: native.suite,
    platform: "win32",
    architecture: "x64",
    candidateSha: p.lease.candidateSha,
    strict: true,
    status: "passed",
    evidenceLevel: "real-host",
    startedAt: p.preflight.createdAt,
    finishedAt: cleanupFinishedAt,
    requiredCapabilities: Object.keys(capabilities),
    capabilities,
    missingCapabilities: [],
    requiredScenarios: native.REQUIRED_SCENARIOS,
    missingScenarios: [],
    scenarios: native.REQUIRED_SCENARIOS.map((id, index) => ({
      id,
      status: "passed",
      evidenceLevel: "real-host",
      startedAt:
        index === 0
          ? p.preflight.createdAt
          : index === 1
            ? proof.residentStartedAt
            : completed.nativeVerificationStartedAt,
      finishedAt:
        index === 0
          ? p.preparedAt
          : index === 1
            ? proof.residentFinishedAt
            : cleanupFinishedAt,
    })),
    cleanup: { status: "passed" },
    qualificationEnvironment: {
      osFamily: "windows",
      architecture: "x64",
      osVersion: "2022",
      nativeLanguage: "en-US",
      identity: "LocalSystem",
      measurement: "native",
    },
    fixtureSource: source,
    fixtureSources: p.sources,
    artifactQualification: "workflow-checkout-source",
    adcsTtl24hProvenance: {
      originalArtifact,
      handoffArtifact,
      finalizerProvenance: finalizer,
    },
    nativeAdcsTtl24h: proof,
  };
}
function finalizeCampaign(original, handoff, references, finalizer) {
  const lease = handoff.lease;
  owner(lease, true);
  inspect(lease, "resident-owned");
  requireFinalizationBudget(lease, 45);
  const state = guest(
    lease,
    `$t=Get-ScheduledTask -TaskName '${lease.taskName}' -ErrorAction Stop;'CERTOPS_ADCS_TTL_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{state=[string]$t.State}|ConvertTo-Json -Compress)))`,
  );
  exact(state, ["state"]);
  if (state.state === "Running") return { pending: true };
  assert.equal(state.state, "Ready");
  const completed = observe(lease, "Finalize");
  contract.verifyCompletedTaskObservation(
    completed,
    original.publicPreparation,
    original.taskObserved,
  );
  resumeControl(original, lease);
  const preCa = verifyCaPublic(
    caObservation(original, lease),
    original.publicPreparation,
  );
  requireFinalizationBudget(lease, 40);
  const encoded = Buffer.from(JSON.stringify(preCa)).toString("base64"),
    producer = `$r=Get-Content 'C:\\ttqualification\\runtime.json' -Raw|ConvertFrom-Json;$raw=& (Join-Path $r.source 'scripts/certops-adcs-ttl24h-finalize.ps1') -Nonce '${lease.nonce}' -PreCaSummaryBase64 '${encoded}';if($LASTEXITCODE-ne 0){throw 'Actual native postday qualifier refused'};$b=[Text.Encoding]::UTF8.GetBytes(($raw-join[Environment]::NewLine));`,
    nativeResult = readOwnedObservation(lease, producer, {
      execute: (ownedLease, script) =>
        guest(
          ownedLease,
          script,
          script.includes("CERTOPS_OBSERVATION_CREATE")
            ? NATIVE_FINISH_TIMEOUT
            : 180000,
        ),
    });
  exact(nativeResult, [
    "schemaVersion",
    "scope",
    "preparedSha256",
    "nativeFacts",
  ]);
  assert.equal(nativeResult.schemaVersion, 1);
  assert.equal(
    nativeResult.scope,
    "actual-native-default24h-outcome-awaiting-ca-crosscheck",
  );
  assert.equal(
    nativeResult.preparedSha256,
    original.taskObserved.preparedSha256,
  );
  const native = require("./certops-adcs-ttl24h-proof");
  native.verifyNativeFacts(
    nativeResult.nativeFacts,
    original.publicPreparation,
    original.taskObserved,
  );
  const facts = nativeResult.nativeFacts,
    postCa = verifyCaPublic(
      caObservation(original, lease, facts.requestIds[2], facts.fingerprints[2]),
      original.publicPreparation,
      facts,
    );
  assert.equal(postCa.caKeySha256, preCa.caKeySha256);
  const proof = {
    ...facts,
    requestIds: postCa.requestIds,
    caRequestCounts: [
      original.publicPreparation.caRequestCounts.before,
      original.publicPreparation.caRequestCounts.installed,
      preCa.nativeTotalRequestCount,
      postCa.nativeTotalRequestCount,
    ],
    noBackgroundSchedulerDuringResident: true,
    originalCaRequestNotResubmitted: true,
  };
  native.verifyAgainstPrepared(
    proof,
    original.publicPreparation,
    original.taskObserved,
  );
  const { group, member } = inspect(lease, "resident-owned"),
    { job } = owner(lease, true);
  const targets = infrastructureTargets(
    lease,
    group,
    member,
    ["domain-ca", "control-plane"].map((name) =>
      az(["vm", "show", "--resource-group", group.name, "--name", name]),
    ),
    deployment(group),
    job,
  );
  assert.deepEqual(targets, original.infrastructureOwnership);
  const cleanupFinishedAt = deleteGroup(groupName(lease));
  return qualificationReport({
    original,
    handoff,
    ...references,
    completed,
    proof,
    cleanupFinishedAt,
    finalizer,
  });
}

async function scan(mode) {
  assert.ok(["finalize", "janitor"].includes(mode));
  const finalizer = mode === "finalize" ? finalizerProvenance() : null,
    groups = az([
      "group",
      "list",
      "--query",
      `[?tags.ttl24hPrepareKind=='${contract.KIND}']`,
    ]);
  assert.ok(Array.isArray(groups) && groups.length <= 128);
  let failures = 0;
  for (const listed of groups) {
    const name = listed.name;
    try {
      assert.match(name, /^tt-certops-[1-9][0-9]*-[1-9][0-9]*$/);
      const group = az(["group", "show", "--name", name]),
        identity = {
          runId: group.tags.ttl24hPrepareRunId,
          runAttempt: group.tags.ttl24hPrepareRunAttempt,
          candidateSha: group.tags.candidateSha,
          nonce: group.tags.ttl24hPrepareNonce,
        };
      for (const key of ["runId", "runAttempt"])
        assert.match(identity[key], /^[1-9][0-9]{0,19}$/);
      assert.match(identity.nonce, /^[a-f0-9]{64}$/);
      assert.match(identity.candidateSha, /^[a-f0-9]{40}$/);
      assert.equal(name, groupName(identity));
      const run = github(
        `actions/runs/${identity.runId}/attempts/${identity.runAttempt}`,
      );
      verifyOwner(run, identity);
      const jobsResponse = fetchPrepareJobs(run),
        vms = az(["vm", "list", "--resource-group", name]),
        job = verifyPartialOwnership(
          group,
          run,
          jobsResponse,
          deployment(group),
          vms,
          identity.nonce,
        );
      let originalReceipt, handoffReceipt;
      try {
        originalReceipt = await artifact(
          { ...identity, createdAt: iso(group.tags.createdAt) },
          "original",
        );
        verifyOriginal(originalReceipt.value);
        for (const [key, value] of Object.entries(identity))
          assert.equal(originalReceipt.value.lease[key], value);
        const member = vms.find((vm) => vm.name === "windows-agent");
        assert.equal(member?.vmId, originalReceipt.value.lease.vmId);
        assert.equal(
          originalReceipt.value.lease.createdAt,
          iso(group.tags.createdAt),
        );
        try {
          handoffReceipt = await artifact(
            originalReceipt.value.lease,
            "ownership",
          );
          verifyHandoff(
            handoffReceipt.value,
            originalReceipt.value,
            originalReceipt.reference,
          );
        } catch {
          handoffReceipt = null;
        }
      } catch {
        originalReceipt = null;
        handoffReceipt = null;
      }
      const decision = cleanupDecision(
        originalReceipt?.value,
        handoffReceipt?.value,
        run,
        job,
        Date.now(),
      );
      if (decision.delete) {
        const fresh = az(["group", "show", "--name", name]);
        prepareTags(fresh, identity);
        verifyPartialOwnership(
          fresh,
          run,
          jobsResponse,
          deployment(fresh),
          az(["vm", "list", "--resource-group", name]),
          identity.nonce,
        );
        const cleanupFinishedAt = deleteGroup(name);
        write(
          `adcs-ttl24h-cleanup-${identity.runId}-${identity.runAttempt}-${identity.nonce}.json`,
          {
            schemaVersion: 1,
            scope: "authenticated-owned-adcs-ttl24h-cleanup-not-qualification",
            ...identity,
            reason: decision.reason,
            cleanupFinishedAt,
          },
        );
        continue;
      }
      if (
        mode !== "finalize" ||
        !originalReceipt ||
        !handoffReceipt ||
        run.status !== "completed" ||
        run.conclusion !== "success"
      )
        continue;
      const original = originalReceipt.value,
        handoff = handoffReceipt.value;
      if (
        Date.now() <
        Date.parse(original.publicPreparation.preparedAt) + contract.DAY
      )
        continue;
      try {
        const result = await finalizeCampaign(
          original,
          handoff,
          {
            originalArtifact: originalReceipt.reference,
            handoffArtifact: handoffReceipt.reference,
          },
          finalizer,
        );
        if (result.pending) continue;
        write(
          `adcs-ttl24h-qualification-${identity.runId}-${identity.runAttempt}-${identity.nonce}.json`,
          result,
        );
      } catch {
        try {
          const current = az(["group", "show", "--name", name]);
          prepareTags(current, identity);
          verifyPartialOwnership(
            current,
            run,
            jobsResponse,
            deployment(current),
            az(["vm", "list", "--resource-group", name]),
            identity.nonce,
          );
          deleteGroup(name);
        } catch {
          orphanReceipt(mode, name);
        }
        throw Error(
          "Owned native TTL finalization failed without qualification",
        );
      }
    } catch {
      failures++;
      orphanReceipt(
        mode,
        /^tt-certops-[1-9][0-9]*-[1-9][0-9]*$/.test(name)
          ? name
          : "invalid-owned-group",
      );
    }
  }
  if (failures) throw Error("Some owned ADCS TTL campaigns require attention");
}
module.exports = {
  resolveFreshRequestId,
  scan,
  resumeControl,
  qualificationReport,
  finalizeCampaign,
  finalizerProvenance,
  CONTROLLER_SOURCES,
  verifyCaPublic,
  verifyPartialOwnership,
  cleanupDecision,
  abort,
  readCaSnapshot,
  caObservation,
  seal,
  handoff,
  artifact,
  verifyHandoff,
  infrastructure,
  taskProducer,
  verifyOwner,
  verifyPrepareJob,
  verifyJobCreation,
  verifyAzure,
  verifyDeployment,
  infrastructureTargets,
  verifyObserved,
  verifyOriginal,
  extendLease,
  leaseTags,
  prepareTags,
  readGuestJson,
  readOwnedObservation,
  WORKFLOW,
  REPOSITORY,
  verifyInfrastructureOwnership,
  verifyControlObserved,
  OBSERVED_KEYS,
  requireFinalizationBudget,
  NATIVE_FINISH_TIMEOUT,
};

if (require.main === module) {
  (async () => {
    const mode = process.argv[2];
    if (mode === "seal") seal();
    else if (mode === "handoff") await handoff();
    else if (mode === "abort") await abort();
    else await scan(mode);
  })().catch(() => {
    process.stderr.write(
      "ADCS default TTL controller failed; independently authenticated cleanup remains required.\n",
    );
    process.exitCode = 1;
  });
}
