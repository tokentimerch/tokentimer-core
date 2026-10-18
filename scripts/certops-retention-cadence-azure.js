"use strict";
/** Hosted ownership controller for the separate installed-service timer lane.
 * No hosted job waits through the native timer. An authenticated immutable
 * four-hour receipt precedes the single sixteen-hour handoff. Cleanup writers
 * share the existing owned-Azure queue; compare/readback is not an Azure CAS.
 * Only exact owned groups/VMs are mutated. Guest output is bounded public JSON.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { performance } = require("node:perf_hooks");
let scanDeadline = Infinity;
const c = require("./certops-retention-cadence-contract");
const proof = require("./certops-retention-cadence-proof");
const {
  downloadArtifactZip,
  waitForOwnedDeletion,
} = require("./certops-retention24h-azure");
const ROOT = path.resolve(__dirname, "..");
const REPOSITORY = "tokentimerch/tokentimer-core";
const FINALIZER = ".github/workflows/certops-retention-cadence-finalize.yml";
const CONTROLLER_SOURCES = Object.freeze([
  "scripts/certops-retention-cadence-azure.js",
  "scripts/certops-retention24h-azure.js",
  "scripts/certops-retention-cadence-contract.js",
  "scripts/certops-retention-cadence-proof.js",
  ".github/workflows/certops-retention-cadence-finalize.yml",
]);
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const iso = (value) => {
  const result = new Date(value).toISOString();
  c.epoch(result);
  return result;
};
function command(file, args, binary = false, timeoutMs = 180000) {
  assert.ok([180000, 660000].includes(timeoutMs));
  const remaining = Math.floor(scanDeadline - performance.now());
  assert.ok(
    remaining > 0,
    "Controller invocation exhausted its monotonic budget",
  );
  return execFileSync(file, args, {
    encoding: binary ? undefined : "utf8",
    timeout: Math.min(timeoutMs, remaining),
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
}
function az(args) {
  return JSON.parse(command("az", [...args, "-o", "json"]));
}
function github(route) {
  return JSON.parse(command("gh", ["api", `repos/${REPOSITORY}/${route}`]));
}
function write(name, value) {
  assert.match(name, /^retention-cadence-[a-z0-9-]+\.json$/);
  const directory = path.join(ROOT, "qualification-results");
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, name), JSON.stringify(value), {
    flag: "wx",
    mode: 0o600,
  });
}
function groupName(owner) {
  for (const field of ["runId", "runAttempt"])
    assert.match(owner[field], /^[1-9][0-9]{0,19}$/);
  return `tt-certops-${owner.runId}-${owner.runAttempt}`;
}
function verifyPrepareRun(run, jobs) {
  assert.equal(run.repository?.full_name, REPOSITORY);
  assert.equal(run.head_repository?.full_name, REPOSITORY);
  assert.equal(run.path, c.PREPARE_WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.match(run.head_sha, /^[a-f0-9]{40}$/);
  assert.ok(Number.isSafeInteger(run.id) && run.id > 0);
  assert.ok(Number.isInteger(run.run_attempt) && run.run_attempt > 0);
  assert.ok(["in_progress", "completed"].includes(run.status));
  assert.equal(jobs.total_count, 1);
  assert.ok(Array.isArray(jobs.jobs) && jobs.jobs.length === 1);
  const job = jobs.jobs[0];
  assert.equal(job.name, "prepare");
  assert.equal(job.run_id, run.id);
  assert.equal(job.head_sha, run.head_sha);
  if (Object.hasOwn(job, "run_attempt"))
    assert.equal(job.run_attempt, run.run_attempt);
  assert.ok(Number.isSafeInteger(job.id) && job.id > 0);
  assert.ok(["in_progress", "completed"].includes(job.status));
  const startedAt = iso(job.started_at);
  assert.ok(c.epoch(startedAt) >= Date.parse(run.created_at) - 5000);
  const completedAt = job.status === "completed" ? iso(job.completed_at) : null;
  if (completedAt) {
    assert.ok(c.epoch(completedAt) >= c.epoch(startedAt));
    assert.ok(c.epoch(completedAt) <= Date.parse(run.updated_at) + 5000);
  } else assert.equal(job.completed_at, null);
  if (run.status === "completed" && run.conclusion === "success") {
    assert.equal(job.status, "completed");
    assert.equal(job.conclusion, "success");
  }
  return {
    repository: REPOSITORY,
    runId: String(run.id),
    runAttempt: String(run.run_attempt),
    candidateSha: run.head_sha,
    workflowPath: run.path,
    event: run.event,
    headBranch: run.head_branch,
    jobId: String(job.id),
    startedAt,
    completedAt,
  };
}
function verifyCreation(value, owner) {
  const instant = Date.parse(iso(value)),
    start = c.epoch(owner.startedAt);
  // The actual prepare job has a three-hour inclusive timeout. Approval wait
  // before its start cannot manufacture resource chronology or a longer lease.
  assert.ok(instant >= start - 5000 && instant <= start + 3 * c.HOUR + 5000);
  if (owner.completedAt)
    assert.ok(instant <= c.epoch(owner.completedAt) + 5000);
  return instant;
}
function verifyPrepareTags(group, owner) {
  assert.equal(group.name, groupName(owner));
  assert.equal(group.tags?.purpose, "certops-adcs-qualification");
  assert.equal(group.tags.candidateSha, owner.candidateSha);
  assert.equal(group.tags.cadencePrepareKind, c.KIND);
  assert.equal(group.tags.cadencePrepareNonce, owner.nonce);
  assert.equal(group.tags.cadencePrepareRunId, owner.runId);
  assert.equal(group.tags.cadencePrepareRunAttempt, owner.runAttempt);
}
function leaseTags(lease) {
  c.verifyLease(lease);
  return {
    cadenceKind: c.KIND,
    cadencePhase: lease.phase,
    cadenceRunId: lease.runId,
    cadenceRunAttempt: lease.runAttempt,
    cadenceNonce: lease.nonce,
    cadenceVmId: lease.vmId,
    cadenceNodeSha256: lease.nodeSha256,
    cadenceObserverSha256: lease.observerSha256,
    cadenceCreatedAt: lease.createdAt,
    cadenceHardExpiresAt: lease.hardExpiresAt,
    expiresAt: lease.expiresAt,
  };
}
function verifyAzure(lease, group, vm) {
  c.verifyLease(lease);
  verifyPrepareTags(group, lease);
  assert.equal(
    group.id.toLowerCase(),
    lease.vmResourceId.split("/providers/")[0].toLowerCase(),
  );
  assert.equal(iso(group.tags.createdAt), lease.createdAt);
  assert.equal(iso(group.tags.expiresAt), lease.expiresAt);
  assert.equal(vm.id.toLowerCase(), lease.vmResourceId.toLowerCase());
  assert.equal(vm.vmId.toLowerCase(), lease.vmId);
  assert.equal(vm.provisioningState, "Succeeded");
  if (lease.phase === "observer-owned")
    for (const [key, value] of Object.entries(leaseTags(lease)))
      assert.equal(group.tags[key], value);
  else
    assert.equal(
      group.tags.cadencePhase,
      undefined,
      "Never adopt a previous handoff",
    );
  return true;
}
function inspect(lease) {
  const group = az(["group", "show", "--name", groupName(lease)]),
    vm = az(["vm", "show", "--ids", lease.vmResourceId]);
  verifyAzure(lease, group, vm);
  return { group, vm };
}
function guest(lease, script) {
  inspect(lease);
  const response = az([
    "vm",
    "run-command",
    "invoke",
    "--ids",
    lease.vmResourceId,
    "--command-id",
    "RunPowerShellScript",
    "--scripts",
    `$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);${script}`,
  ]);
  inspect(lease);
  assert.ok(Array.isArray(response.value));
  const text = response.value.map((row) => row.message).join("\n");
  const matches = [
    ...text.matchAll(/CERTOPS_CADENCE_PUBLIC=([A-Za-z0-9+/=]+)/g),
  ];
  assert.equal(matches.length, 1, "One bounded public guest marker required");
  const bytes = Buffer.from(matches[0][1], "base64");
  assert.ok(bytes.length > 0 && bytes.length <= 2048);
  return JSON.parse(bytes.toString("utf8"));
}

// Snapshot/chunk implementation below executes a dynamic native observation
// once, pins its exact file identity/bytes, and deletes only that owned snapshot.




const {readGuestJson, readOwnedObservation} = require("./certops-retention24h-azure").createGuestReader({campaign: "retention-cadence", marker: "CERTOPS_CADENCE_PUBLIC", snapshotEnvironment: "TOKENTIMER_CADENCE_SNAPSHOT", verifyLease: c.verifyLease, exact: c.closed, guest});

function verifyPreparation(value, original, currentSources = false) {
  c.closed(value, [
    "schemaVersion",
    "kind",
    "preparedLease",
    "observed",
    "fixtureSources",
  ]);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, c.KIND);
  c.verifyOriginalLease(value.preparedLease, original);
  assert.equal(value.preparedLease.phase, "preparing");
  c.verifyObservation(value.observed, original);
  assert.ok(
    Array.isArray(value.fixtureSources) &&
      value.fixtureSources.length > 5 &&
      value.fixtureSources.length <= 128,
  );
  const names = new Set();
  for (const row of value.fixtureSources) {
    c.closed(row, ["file", "sha256"]);
    assert.match(
      row.file,
      /^(?:scripts|tests|packages|infra|apps|\.github)\/[a-zA-Z0-9_./-]+$/,
    );
    assert.ok(!row.file.split("/").includes("..") && !names.has(row.file));
    names.add(row.file);
    assert.match(row.sha256, /^[a-f0-9]{64}$/);
    if (currentSources)
      assert.equal(row.sha256, sha(fs.readFileSync(path.join(ROOT, row.file))));
  }
  for (const file of require("./certops-retention-cadence-sources")
    .REQUIRED_SOURCES)
    assert.ok(names.has(file), "Missing original critical source");
  return value;
}
function verifyOriginalReceipt(value) {
  c.closed(value, [
    "schemaVersion",
    "kind",
    "preparedLease",
    "preparation",
    "githubOwner",
    "azure",
    "sealedAt",
  ]);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, c.KIND);
  c.verifyLease(value.preparedLease);
  assert.equal(value.preparedLease.phase, "preparing");
  verifyPreparation(value.preparation, value.preparedLease);
  assert.ok(
    c.epoch(value.sealedAt) >= c.epoch(value.preparation.observed.verifiedAt) &&
      c.epoch(value.sealedAt) < c.epoch(value.preparedLease.expiresAt),
  );
  const owner = value.githubOwner;
  c.closed(owner, [
    "repository",
    "runId",
    "runAttempt",
    "candidateSha",
    "workflowPath",
    "event",
    "headBranch",
    "jobId",
    "startedAt",
    "completedAt",
  ]);
  assert.equal(owner.repository, REPOSITORY);
  assert.equal(owner.workflowPath, c.PREPARE_WORKFLOW);
  assert.equal(owner.event, "workflow_dispatch");
  assert.equal(owner.headBranch, "main");
  for (const key of ["runId", "runAttempt", "candidateSha"])
    assert.equal(owner[key], value.preparedLease[key]);
  assert.match(owner.jobId, /^[1-9][0-9]{0,19}$/);
  verifyCreation(value.preparedLease.createdAt, owner);
  c.closed(value.azure, [
    "groupId",
    "vmResourceId",
    "vmId",
    "vmCreatedAt",
    "deploymentCreatedAt",
  ]);
  assert.equal(
    value.azure.groupId.toLowerCase(),
    value.preparedLease.vmResourceId.split("/providers/")[0].toLowerCase(),
  );
  assert.equal(value.azure.vmResourceId, value.preparedLease.vmResourceId);
  assert.equal(value.azure.vmId, value.preparedLease.vmId);
  for (const key of ["vmCreatedAt", "deploymentCreatedAt"])
    assert.ok(
      verifyCreation(value.azure[key], owner) >=
        c.epoch(value.preparedLease.createdAt) - 5000 &&
        verifyCreation(value.azure[key], owner) <=
          c.epoch(value.preparation.observed.verifiedAt),
    );
  return value;
}
function taskObservation(lease, mode) {
  assert.ok(["Observe", "Finalize"].includes(mode));
  return readOwnedObservation(
    lease,
    `$o=& 'C:\\ttqualification\\source\\tokentimer-core-${lease.candidateSha}\\scripts\\certops-retention-cadence-task.ps1' -Mode ${mode} -Nonce '${lease.nonce}';if($LASTEXITCODE -ne 0){throw 'Owned cadence task observation failed'};$v=$o|ConvertFrom-Json;$b=[Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 12 -Compress));`,
  );
}
function fetchOwner(runId, attempt) {
  assert.match(runId, /^[1-9][0-9]{0,19}$/);
  assert.match(attempt, /^[1-9][0-9]{0,19}$/);
  const run = github(`actions/runs/${runId}/attempts/${attempt}`);
  assert.equal(String(run.id), runId);
  assert.equal(String(run.run_attempt), attempt);
  const owner = verifyPrepareRun(
    run,
    github(`actions/runs/${runId}/attempts/${attempt}/jobs?per_page=100`),
  );
  return { run, owner };
}
function currentOwner() {
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
  const { run, owner } = fetchOwner(
    process.env.GITHUB_RUN_ID,
    process.env.GITHUB_RUN_ATTEMPT,
  );
  assert.equal(run.head_sha, process.env.GITHUB_SHA);
  assert.equal(run.status, "in_progress");
  const nonce = process.env.CERTOPS_RETENTION_CADENCE_NONCE;
  assert.match(nonce, /^[a-f0-9]{64}$/);
  return { run, owner, nonce };
}
async function retrieveArtifact(runId, attempt, nonce, type) {
  assert.ok(["original", "ownership"].includes(type));
  assert.match(nonce, /^[a-f0-9]{64}$/);
  const { run, owner } = fetchOwner(runId, attempt),
    name = `retention-cadence-${type}-${attempt}-${nonce}`;
  const listing = github(`actions/runs/${runId}/artifacts?per_page=100`);
  assert.ok(
    Number.isInteger(listing.total_count) && listing.total_count <= 100,
  );
  assert.ok(Array.isArray(listing.artifacts));
  const found = listing.artifacts.filter(
    (item) => item.name === name && !item.expired,
  );
  assert.equal(found.length, 1);
  const item = found[0];
  assert.ok(Number.isSafeInteger(item.id) && item.id > 0);
  assert.equal(String(item.workflow_run?.id), runId);
  assert.equal(item.workflow_run.head_sha, run.head_sha);
  assert.equal(item.workflow_run.head_branch, "main");
  assert.match(item.digest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(verifyCreation(item.created_at, owner) >= c.epoch(owner.startedAt));
  assert.ok(
    Number.isInteger(item.size_in_bytes) &&
      item.size_in_bytes > 0 &&
      item.size_in_bytes <= 2 * 1024 * 1024,
  );
  const zip = await downloadArtifactZip(item.id);
  assert.ok(zip.length > 0 && zip.length <= 2 * 1024 * 1024);
  assert.equal(sha(zip), item.digest.slice(7));
  const script =
    "import io,sys,zipfile,stat; z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())); assert z.namelist()==[sys.argv[1]]; i=z.infolist()[0]; assert 0<i.file_size<=65536 and not i.flag_bits&1 and not stat.S_ISLNK(i.external_attr>>16); sys.stdout.buffer.write(z.read(i))";
  const bytes = execFileSync(
    process.platform === "win32" ? "python" : "python3",
    ["-c", script, `retention-cadence-${type}.json`],
    { input: zip, timeout: 10000, maxBuffer: 65536 },
  );
  return {
    value: JSON.parse(bytes.toString("utf8")),
    artifact: {
      id: String(item.id),
      name,
      archiveSha256: item.digest.slice(7),
    },
    owner,
    run,
  };
}
function seal() {
  const { owner, nonce } = currentOwner();
  const group = az(["group", "show", "--name", groupName(owner)]);
  verifyPrepareTags(group, { ...owner, nonce });
  const vm = az([
    "vm",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "windows-agent",
  ]);
  const stub = c.createLease(
    {
      ...owner,
      nonce,
      vmResourceId: vm.id,
      vmId: vm.vmId.toLowerCase(),
      taskName: `TokenTimer-RetentionCadence-${nonce}`,
      nodeSha256: "0".repeat(64),
      observerSha256: sha(
        fs.readFileSync(
          path.join(ROOT, "scripts/certops-retention-cadence-runtime.js"),
        ),
      ),
    },
    iso(group.tags.createdAt),
  );
  verifyCreation(stub.createdAt, owner);
  verifyAzure(stub, group, vm);
  assert.ok(Date.now() < c.epoch(stub.expiresAt));
  const preparation = readGuestJson(
    stub,
    "$b=[IO.File]::ReadAllBytes('C:\\ttqualification\\retention-cadence-prepare-public.json');",
  );
  const preparedLease = c.createLease(
    { ...stub, nodeSha256: preparation.preparedLease?.nodeSha256 },
    stub.createdAt,
  );
  verifyPreparation(preparation, preparedLease, true);
  const current = inspect(preparedLease);
  const deployment = az([
    "deployment",
    "group",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "qualification",
  ]);
  assert.equal(deployment.properties?.provisioningState, "Succeeded");
  const receipt = {
    schemaVersion: 1,
    kind: c.KIND,
    preparedLease,
    preparation,
    githubOwner: owner,
    azure: {
      groupId: current.group.id,
      vmResourceId: current.vm.id,
      vmId: current.vm.vmId.toLowerCase(),
      vmCreatedAt: iso(current.vm.timeCreated),
      deploymentCreatedAt: iso(deployment.properties.timestamp),
    },
    sealedAt: new Date().toISOString(),
  };
  verifyOriginalReceipt(receipt);
  write("retention-cadence-original.json", receipt);
  return receipt;
}
function verifyHandoffReceipt(value, original) {
  c.closed(value, [
    "schemaVersion",
    "kind",
    "preparedLease",
    "lease",
    "preparation",
    "observed",
    "originalArtifact",
    "handedOffAt",
  ]);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, c.KIND);
  assert.deepEqual(value.preparedLease, original.preparedLease);
  assert.deepEqual(value.preparation, original.preparation);
  c.verifyOriginalLease(value.lease, original.preparedLease);
  assert.equal(value.lease.phase, "observer-owned");
  c.verifyObservation(value.observed, original.preparedLease);
  for (const key of c.OBSERVATION_FIELDS.filter((key) => key !== "verifiedAt"))
    assert.deepEqual(value.observed[key], original.preparation.observed[key]);
  assert.ok(c.epoch(value.observed.verifiedAt) >= c.epoch(original.sealedAt));
  assert.ok(
    c.epoch(value.handedOffAt) >= c.epoch(value.observed.verifiedAt) &&
      c.epoch(value.handedOffAt) < c.epoch(original.preparedLease.expiresAt),
  );
  c.closed(value.originalArtifact, ["id", "name", "archiveSha256"]);
  assert.match(value.originalArtifact.id, /^[1-9][0-9]*$/);
  assert.equal(
    value.originalArtifact.name,
    `retention-cadence-original-${value.lease.runAttempt}-${value.lease.nonce}`,
  );
  assert.match(value.originalArtifact.archiveSha256, /^[a-f0-9]{64}$/);
  return value;
}
async function handoff() {
  const { owner, nonce } = currentOwner();
  const downloaded = await retrieveArtifact(
    owner.runId,
    owner.runAttempt,
    nonce,
    "original",
  );
  const original = verifyOriginalReceipt(downloaded.value),
    initial = original.preparedLease;
  assert.equal(initial.candidateSha, owner.candidateSha);
  assert.equal(original.githubOwner.jobId, owner.jobId);
  assert.ok(Date.now() < c.epoch(initial.expiresAt));
  verifyPreparation(original.preparation, initial, true);
  const observed = taskObservation(initial, "Observe");
  const lease = c.attestHandoff(initial, observed);
  for (const key of c.OBSERVATION_FIELDS.filter((key) => key !== "verifiedAt"))
    assert.deepEqual(observed[key], original.preparation.observed[key]);
  assert.ok(c.epoch(observed.verifiedAt) >= c.epoch(original.sealedAt));
  const current = inspect(initial);
  assert.ok(Date.now() < c.epoch(initial.expiresAt));
  az([
    "tag",
    "update",
    "--resource-id",
    current.group.id,
    "--operation",
    "Merge",
    "--tags",
    ...Object.entries(leaseTags(lease)).map(
      ([key, value]) => `${key}=${value}`,
    ),
  ]);
  inspect(lease);
  const encoded = Buffer.from(JSON.stringify(lease)).toString("base64");
  const publication = guest(
    lease,
    `& 'C:\\ttqualification\\source\\tokentimer-core-${lease.candidateSha}\\scripts\\certops-retention-cadence-task.ps1' -Mode WriteLease -Nonce '${nonce}' -PublicLeaseBase64 '${encoded}'|Out-Null;if($LASTEXITCODE -ne 0){throw 'Original lease publication failed'};'CERTOPS_CADENCE_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"published":true}'))`,
  );
  c.closed(publication, ["published"]);
  assert.equal(publication.published, true);
  const receipt = {
    schemaVersion: 1,
    kind: c.KIND,
    preparedLease: initial,
    lease,
    preparation: original.preparation,
    observed,
    originalArtifact: downloaded.artifact,
    handedOffAt: new Date().toISOString(),
  };
  verifyHandoffReceipt(receipt, original);
  write("retention-cadence-ownership.json", receipt);
  write("retention-cadence-cost.json", {
    schemaVersion: 1,
    runId: lease.runId,
    runAttempt: lease.runAttempt,
    hardExpiresAt: lease.hardExpiresAt,
    runningRoles: ["windows-agent", "control-plane", "domain-ca"],
    reason:
      "Preserve healthy installed-agent API polling and original domain services; no outage qualification is claimed",
  });
  return receipt;
}

function verifyCleanupOwnership(group, vm, deployment, owner, expectedNonce) {
  const nonce = expectedNonce ?? group.tags?.cadencePrepareNonce;
  assert.match(nonce, /^[a-f0-9]{64}$/);
  verifyPrepareTags(group, { ...owner, nonce });
  const createdAt = iso(group.tags.createdAt),
    created = verifyCreation(createdAt, owner);
  assert.match(
    group.id,
    new RegExp(
      `^/subscriptions/[a-f0-9-]{36}/resourceGroups/${groupName(owner)}$`,
      "i",
    ),
  );
  const extended = group.tags.cadencePhase !== undefined;
  assert.ok(!extended || group.tags.cadencePhase === "observer-owned");
  const deadline = created + (extended ? c.MAX : c.INITIAL);
  assert.equal(Date.parse(iso(group.tags.expiresAt)), deadline);
  if (extended) {
    assert.equal(group.tags.cadenceKind, c.KIND);
    for (const key of ["RunId", "RunAttempt", "Nonce"])
      assert.equal(
        group.tags[`cadence${key}`],
        { RunId: owner.runId, RunAttempt: owner.runAttempt, Nonce: nonce }[key],
      );
    assert.equal(group.tags.cadenceCreatedAt, createdAt);
    assert.equal(c.epoch(group.tags.cadenceHardExpiresAt), created + c.MAX);
    assert.match(
      group.tags.cadenceVmId,
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
    );
  }
  // Incomplete preparation may fail before VM creation. A group may be removed
  // only after the unique initial tags and actual job chronology are proved;
  // any existing VM/deployment must independently belong to that same window.
  if (vm) {
    assert.equal(vm.name, "windows-agent");
    assert.equal(
      vm.id.toLowerCase(),
      `${group.id}/providers/Microsoft.Compute/virtualMachines/windows-agent`.toLowerCase(),
    );
    assert.ok(verifyCreation(vm.timeCreated, owner) >= created - 5000);
    if (extended) assert.equal(vm.vmId.toLowerCase(), group.tags.cadenceVmId);
  }
  if (deployment) {
    assert.equal(deployment.name, "qualification");
    assert.equal(
      deployment.id.toLowerCase(),
      `${group.id}/providers/Microsoft.Resources/deployments/qualification`.toLowerCase(),
    );
    assert.ok(
      verifyCreation(deployment.properties?.timestamp, owner) >= created - 5000,
    );
  }
  return { nonce, createdAt, deadline, extended };
}
function cleanupDecision(run, owned, now = Date.now()) {
  assert.ok(Number.isFinite(now));
  if (run.status === "completed" && run.conclusion !== "success")
    return "failed-owner";
  if (now >= owned.deadline) return "expired";
  return "preserve";
}
function inspectForCleanup(group, owner, expectedNonce) {
  const vms = az(["vm", "list", "--resource-group", group.name]);
  assert.ok(Array.isArray(vms) && vms.length <= 3);
  assert.ok(
    vms.every((value) =>
      ["windows-agent", "domain-ca", "control-plane"].includes(value.name),
    ),
  );
  assert.equal(new Set(vms.map((value) => value.name)).size, vms.length);
  const deployments = az([
    "deployment",
    "group",
    "list",
    "--resource-group",
    group.name,
  ]);
  assert.ok(Array.isArray(deployments) && deployments.length <= 1);
  const vm = vms.find((value) => value.name === "windows-agent"),
    deployment = deployments[0];
  const owned = verifyCleanupOwnership(
    group,
    vm,
    deployment,
    owner,
    expectedNonce,
  );
  for (const value of vms) {
    assert.equal(
      value.id.toLowerCase(),
      `${group.id}/providers/Microsoft.Compute/virtualMachines/${value.name}`.toLowerCase(),
    );
    assert.ok(
      verifyCreation(value.timeCreated, owner) >=
        Date.parse(owned.createdAt) - 5000,
    );
  }
  return owned;
}
function deleteOwnedGroup(group, owner, nonce) {
  const fresh = az(["group", "show", "--name", group.name]);
  assert.equal(fresh.id.toLowerCase(), group.id.toLowerCase());
  // Re-check immutable owner, phase and expiry immediately before mutation.
  assert.deepEqual(fresh.tags, group.tags);
  inspectForCleanup(fresh, owner, nonce);
  assert.ok(
    scanDeadline - performance.now() >= 12 * 60000,
    "Insufficient owned deletion/upload budget",
  );
  command("az", [
    "group",
    "delete",
    "--name",
    group.name,
    "--yes",
    "--no-wait",
    "-o",
    "none",
  ]);
  waitForOwnedDeletion(group.name, { execute: command, query: az });
}
function abort() {
  const { owner, nonce } = currentOwner(),
    name = groupName(owner);
  const exists = az(["group", "exists", "--name", name]);
  assert.equal(typeof exists, "boolean");
  if (!exists) return;
  const group = az(["group", "show", "--name", name]);
  inspectForCleanup(group, owner, nonce);
  deleteOwnedGroup(group, owner, nonce);
}
async function authenticatedCampaign(group) {
  const runId = group.tags?.cadencePrepareRunId,
    attempt = group.tags?.cadencePrepareRunAttempt,
    nonce = group.tags?.cadencePrepareNonce;
  const original = await retrieveArtifact(runId, attempt, nonce, "original");
  verifyOriginalReceipt(original.value);
  const identity = original.value.githubOwner;
  for (const key of [
    "runId",
    "runAttempt",
    "candidateSha",
    "jobId",
    "startedAt",
  ])
    assert.equal(identity[key], original.owner[key]);
  const handoff = await retrieveArtifact(runId, attempt, nonce, "ownership");
  verifyHandoffReceipt(handoff.value, original.value);
  assert.deepEqual(handoff.value.originalArtifact, original.artifact);
  assert.equal(handoff.owner.jobId, original.owner.jobId);
  const lease = handoff.value.lease;
  assert.equal(lease.candidateSha, original.run.head_sha);
  verifyAzure(lease, group, az(["vm", "show", "--ids", lease.vmResourceId]));
  return { original, handoff, lease };
}
function finalizerProvenance(mode) {
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.ok(
    ["workflow_dispatch", "schedule"].includes(process.env.GITHUB_EVENT_NAME),
  );
  const runId = process.env.GITHUB_RUN_ID,
    attempt = process.env.GITHUB_RUN_ATTEMPT;
  assert.match(runId, /^[1-9][0-9]{0,19}$/);
  assert.match(attempt, /^[1-9][0-9]{0,19}$/);
  const run = github(`actions/runs/${runId}/attempts/${attempt}`);
  assert.equal(String(run.id), runId);
  assert.equal(String(run.run_attempt), attempt);
  assert.equal(run.repository?.full_name, REPOSITORY);
  assert.equal(run.head_repository?.full_name, REPOSITORY);
  assert.equal(
    run.path,
    mode === "finalize"
      ? FINALIZER
      : ".github/workflows/certops-retention-cadence-janitor.yml",
  );
  assert.equal(run.head_branch, "main");
  assert.equal(run.event, process.env.GITHUB_EVENT_NAME);
  assert.equal(run.head_sha, process.env.GITHUB_SHA);
  assert.match(run.head_sha, /^[a-f0-9]{40}$/);
  return {
    repository: REPOSITORY,
    runId,
    runAttempt: attempt,
    headSha: run.head_sha,
    event: run.event,
    headBranch: "main",
    workflowPath: run.path,
    controllerSources: CONTROLLER_SOURCES.map((file) => ({
      file,
      sha256: sha(fs.readFileSync(path.join(ROOT, file))),
    })),
  };
}
async function finalizeGroup(group, provenance) {
  const campaign = await authenticatedCampaign(group),
    { original, handoff, lease } = campaign;
  assert.equal(original.run.status, "completed");
  assert.equal(original.run.conclusion, "success");
  // A Running task is not a completed observation. This status is never itself
  // qualifying evidence and cannot extend the original hard lease.
  const state = guest(
    lease,
    `$t=Get-ScheduledTask -TaskName '${lease.taskName}' -ErrorAction Stop;'CERTOPS_CADENCE_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{state=[string]$t.State}|ConvertTo-Json -Compress)))`,
  );
  c.closed(state, ["state"]);
  assert.ok(["Running", "Ready"].includes(state.state));
  if (state.state === "Running") return "pending";
  assert.ok(
    Date.now() + 12 * 60000 < c.epoch(lease.hardExpiresAt),
    "Insufficient bounded cleanup headroom",
  );
  const completion = taskObservation(lease, "Finalize");
  const composite = {
    preparedLease: original.value.preparedLease,
    lease,
    preparation: original.value.preparation,
    completion,
    cleanup: "pending",
    cleanupFinishedAt: null,
  };
  proof.verifyCompositeProof(composite, { requireCleanup: false });
  assert.ok(
    c.epoch(completion.verifiedAt) <= Date.now() &&
      Date.now() - c.epoch(completion.verifiedAt) < 5 * 60000,
  );
  deleteOwnedGroup(inspect(lease).group, original.owner, lease.nonce);
  composite.cleanup = "completed";
  composite.cleanupFinishedAt = new Date().toISOString();
  proof.verifyCompositeProof(composite);
  const ownerChain = {
    originalArtifact: original.artifact,
    handoffArtifact: handoff.artifact,
    finalizerProvenance: provenance,
  };
  const report = proof.createQualificationReport(composite, ownerChain);
  const suffix = `${lease.runId}-${lease.runAttempt}-${lease.nonce}`;
  write(`retention-cadence-final-${suffix}.json`, composite);
  write(`retention-cadence-qualification-${suffix}.json`, report);
  return "completed";
}
function canInspectCampaign({ attempts, inspected, remainingMs }) {
  assert.ok(Number.isInteger(attempts) && attempts >= 0);
  assert.ok(Number.isInteger(inspected) && inspected >= 0);
  assert.ok(Number.isFinite(remainingMs));
  return attempts < 1 && inspected < 2 && remainingMs >= 15 * 60000;
}
async function scan(mode) {
  assert.ok(["finalize", "janitor"].includes(mode));
  // Leave three minutes for final artifact upload in the 25-minute job.
  scanDeadline = performance.now() + 22 * 60000;
  const provenance = finalizerProvenance(mode);
  const groups = az([
    "group",
    "list",
    "--query",
    `[?tags.cadencePrepareKind=='${c.KIND}']`,
  ]);
  assert.ok(Array.isArray(groups) && groups.length <= 32);
  const ordered = groups.sort(
    (a, b) => Date.parse(a.tags.createdAt) - Date.parse(b.tags.createdAt),
  );
  let mutations = 0,
    inspected = 0;
  const failures = [];
  for (const group of ordered) {
    if (
      !canInspectCampaign({
        attempts: mutations,
        inspected,
        remainingMs: scanDeadline - performance.now(),
      })
    )
      break;
    inspected++; // A pending campaign cannot consume an unbounded scan.
    try {
      const { run, owner } = fetchOwner(
        group.tags?.cadencePrepareRunId,
        group.tags?.cadencePrepareRunAttempt,
      );
      const owned = inspectForCleanup(group, owner);
      if (cleanupDecision(run, owned) !== "preserve") {
        mutations++; // Count the attempt even when deletion/readback fails.
        deleteOwnedGroup(group, owner, owned.nonce);
        continue;
      }
      if (
        mode === "finalize" &&
        run.status === "completed" &&
        run.conclusion === "success" &&
        owned.extended
      ) {
        mutations++; // Failed/pending attempts also consume this invocation.
        await finalizeGroup(group, provenance);
      }
    } catch {
      // Diagnostics contain only validated public owner coordinates. Never
      // serialize Azure/PowerShell errors, URLs, credentials or guest output.
      const id = String(group.name).match(
        /^tt-certops-([1-9][0-9]*)-([1-9][0-9]*)$/,
      );
      if (id)
        write(
          `retention-cadence-controller-failure-${mode}-${id[1]}-${id[2]}.json`,
          {
            schemaVersion: 1,
            mode,
            runId: id[1],
            runAttempt: id[2],
            status: "failed-preserved",
            observedAt: new Date().toISOString(),
          },
        );
      failures.push(true);
    }
  }
  if (failures.length)
    throw new Error(
      "One or more owned cadence campaigns failed validation or cleanup",
    );
}
module.exports = {
  REPOSITORY,
  FINALIZER,
  CONTROLLER_SOURCES,
  canInspectCampaign,
  verifyPrepareRun,
  verifyCreation,
  verifyPrepareTags,
  leaseTags,
  verifyAzure,
  verifyPreparation,
  verifyOriginalReceipt,
  verifyHandoffReceipt,
  verifyCleanupOwnership,
  cleanupDecision,
  readGuestJson,
  readOwnedObservation,
  groupName,
  seal,
  handoff,
  abort,
  scan,
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
      "Owned installed-timer controller failed; preserve bounded diagnostics for independent cleanup.\n",
    );
    process.exitCode = 1;
  });
}
