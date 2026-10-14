"use strict";
/** Trusted hosted-controller adapter. All cloud mutations target one verified
 * disposable group. GitHub workflow concurrency serializes participating writers;
 * compare/readback is deliberately not described as an Azure atomic transaction.
 * Guest strings never become local shell commands or arbitrary file paths.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const contract = require("./certops-retention24h-contract");
const controller = require("./certops-retention24h-controller");
const ROOT = path.resolve(__dirname, "..");
const OUTPUT = path.join(ROOT, "qualification-results");
const REPOSITORY = "tokentimerch/tokentimer-core";
const WORKFLOW = ".github/workflows/certops-retention24h-prepare.yml";
const ARTIFACT = "retention24h-prepare-ownership";
function command(file, args, binary = false) {
  return execFileSync(file, args, {
    encoding: binary ? undefined : "utf8",
    timeout: 180000,
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
function sha(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
const OBSERVATION_KEYS = [
  "replacementCngCustodyVerified",
  "replacementIisSniBindingVerified",
  "actualPredecessorCertificateAbsent",
  "actualPredecessorKeyAbsent",
  ...contract.IDENTITY,
  "taskXmlVerified",
  "vmIdentityVerified",
  "nodeHashVerified",
  "keeperHashVerified",
  "residentProcessVerified",
  "soleAgentStoppedAndDrained",
  "productionCutoverVerified",
  "nativeCustodyVerified",
  "trustedTlsVerified",
  "ledgerUnmodified",
  "principalSid",
  "taskState",
  "processId",
  "bootTime",
  "monotonicElapsedMs",
  "verifiedCutoverAt",
  "oldNotAfter",
  "cleanupDeadline",
  "taskXmlSha256",
  "nativeVerificationStartedAt",
  "nativeVerificationFinishedAt",
  "processCreatedAt",
  "configSha256",
];
const RESULT_KEYS = [
  "startedAt",
  "finishedAt",
  "scope",
  "monotonicElapsedMs",
  "keptSweepCount",
  "maximumSweepGapMs",
  "preDeadlineObservedAt",
  "collector",
  "retentionHours",
  "candidateSha",
  "nonce",
  "pid",
  "processCreatedAt",
  "bootTime",
  "configSha256",
  "nativeCustodyVerified",
  "trustedTlsVerified",
  "actualProductionLedgerVerified",
];
function exactKeys(value, keys) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}
function publicObservation(value, final = false) {
  exactKeys(
    value,
    final
      ? [...OBSERVATION_KEYS, "residentResult", "currentNativeDeletionVerified"]
      : OBSERVATION_KEYS,
  );
  contract.identity(value);
  assert.equal(value.actualPredecessorCertificateAbsent, final);
  assert.equal(value.actualPredecessorKeyAbsent, final);
  contract.epoch(value.nativeVerificationStartedAt);
  contract.epoch(value.nativeVerificationFinishedAt);
  assert.ok(
    Date.parse(value.nativeVerificationFinishedAt) >=
      Date.parse(value.nativeVerificationStartedAt),
  );
  for (const key of OBSERVATION_KEYS)
    if (
      key.endsWith("Verified") ||
      key === "ledgerUnmodified" ||
      key === "soleAgentStoppedAndDrained"
    )
      assert.equal(value[key], true);
  for (const key of ["taskXmlSha256", "configSha256"])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  assert.equal(value.principalSid, "S-1-5-18");
  assert.equal(value.taskState, final ? "Ready" : "Running");
  assert.ok(Number.isInteger(value.processId) && value.processId > 0);
  assert.ok(
    Number.isInteger(value.monotonicElapsedMs) && value.monotonicElapsedMs >= 0,
  );
  for (const key of [
    "bootTime",
    "processCreatedAt",
    "verifiedCutoverAt",
    "oldNotAfter",
    "cleanupDeadline",
  ]) {
    assert.equal(typeof value[key], "string");
    assert.ok(
      value[key].length <= 40 && Number.isFinite(Date.parse(value[key])),
    );
  }
  if (final) {
    contract.epoch(value.nativeVerificationStartedAt);
    contract.epoch(value.nativeVerificationFinishedAt);
    assert.ok(
      Date.parse(value.nativeVerificationFinishedAt) >=
        Date.parse(value.nativeVerificationStartedAt),
    );
    assert.equal(value.currentNativeDeletionVerified, true);
    publicResidentResult(value.residentResult);
  }
  return value;
}
function publicResidentResult(value) {
  exactKeys(value, RESULT_KEYS);
  contract.epoch(value.startedAt);
  contract.epoch(value.finishedAt);
  assert.ok(Date.parse(value.finishedAt) >= Date.parse(value.startedAt));
  assert.equal(value.scope, "resident-timing-only-native-oracles-required");
  assert.equal(value.collector, "production-default-clock");
  assert.equal(value.retentionHours, 24);
  assert.ok(
    Number.isInteger(value.monotonicElapsedMs) &&
      value.monotonicElapsedMs >= contract.DAY &&
      value.monotonicElapsedMs <= contract.DAY + contract.HOUR,
  );
  assert.ok(
    Number.isInteger(value.keptSweepCount) &&
      value.keptSweepCount >= 2 &&
      value.keptSweepCount <= 26,
  );
  assert.ok(
    Number.isInteger(value.maximumSweepGapMs) &&
      value.maximumSweepGapMs > 0 &&
      value.maximumSweepGapMs <= 65 * 60000,
  );
  contract.epoch(value.preDeadlineObservedAt);
  assert.match(value.candidateSha, /^[a-f0-9]{40}$/);
  assert.match(value.nonce, /^[a-f0-9]{64}$/);
  assert.match(value.configSha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isInteger(value.pid) && value.pid > 0);
  for (const key of [
    "nativeCustodyVerified",
    "trustedTlsVerified",
    "actualProductionLedgerVerified",
  ])
    assert.equal(value[key], true);
  for (const key of ["bootTime", "processCreatedAt"]) {
    assert.equal(typeof value[key], "string");
    assert.ok(
      value[key].length <= 40 && Number.isFinite(Date.parse(value[key])),
    );
  }
  return value;
}
function publicPreparation(value, checkCurrentSources = false) {
  exactKeys(value, [
    "scope",
    "startedAt",
    "finishedAt",
    "lease",
    "configSha256",
    "verifiedCutoverAt",
    "oldNotAfter",
    "cleanupDeadline",
    "task",
    "fixtureSources",
    "collectorHelper",
    "ledgerIdentitySha256",
    "generations",
    "sourceCount",
    "actualRequestIds",
    "fingerprints",
    "soleAgentStoppedAndDrained",
  ]);
  assert.equal(
    value.scope,
    "prepared-real-domain-adcs-retention24h-not-elapsed-qualified",
  );
  contract.epoch(value.startedAt);
  contract.epoch(value.finishedAt);
  assert.ok(Date.parse(value.finishedAt) >= Date.parse(value.startedAt));
  contract.verifyLease(value.lease);
  publicObservation(value.task);
  exactKeys(value.lease, [
    ...contract.IDENTITY,
    "schemaVersion",
    "kind",
    "phase",
    "createdAt",
    "expiresAt",
    "hardExpiresAt",
  ]);
  assert.equal(value.soleAgentStoppedAndDrained, true);
  for (const key of ["configSha256", "ledgerIdentitySha256"])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  for (const key of ["verifiedCutoverAt", "oldNotAfter", "cleanupDeadline"])
    assert.equal(value[key], value.task[key]);
  assert.equal(value.configSha256, value.task.configSha256);
  assert.ok(
    Array.isArray(value.fixtureSources) &&
      value.fixtureSources.length >= 5 &&
      value.fixtureSources.length <= 64,
  );
  assert.equal(value.sourceCount, value.fixtureSources.length);
  const seen = new Set();
  for (const item of value.fixtureSources) {
    exactKeys(item, ["file", "sha256"]);
    assert.match(
      item.file,
      /^(?:scripts|tests|packages|apps|infra|\.github)\/[A-Za-z0-9_./-]+$/,
    );
    assert.ok(item.file.length <= 256 && !item.file.split("/").includes(".."));
    assert.equal(seen.has(item.file), false);
    seen.add(item.file);
    assert.match(item.sha256, /^[a-f0-9]{64}$/);
    if (checkCurrentSources)
      assert.equal(
        item.sha256,
        sha(fs.readFileSync(path.join(ROOT, item.file))),
      );
  }
  for (const file of require("./certops-retention24h-runtime").REQUIRED_SOURCES)
    assert.ok(seen.has(file), "Missing producer-critical source");
  exactKeys(value.collectorHelper, ["file", "sha256"]);
  assert.match(
    value.collectorHelper.file,
    /^packages\/agent\/(?:bin\/tokentimer-adcs-chain-amd64.exe|reference\/adcs-chain\/dist\/tokentimer-adcs-chain-windows-amd64.exe)$/,
  );
  assert.match(value.collectorHelper.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Array.isArray(value.generations) && value.generations.length === 2);
  for (const item of value.generations) {
    exactKeys(item, [
      "thumbprint",
      "containerName",
      "requestId",
      "enrollmentId",
      "jobId",
      "serial",
      "spkiSha256",
    ]);
    assert.match(item.thumbprint, /^[A-F0-9]{40}$/);
    assert.match(item.spkiSha256, /^[a-f0-9]{64}$/);
    assert.match(item.serial, /^[A-Fa-f0-9]{1,64}$/);
    for (const key of ["enrollmentId", "jobId"])
      assert.match(item[key], /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert.equal(item.containerName, `tokentimer-enr-${item.enrollmentId}`);
    assert.match(item.requestId, /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(item.requestId) <= 0xffffffff);
  }
  assert.deepEqual(
    value.actualRequestIds,
    value.generations.map((item) => item.requestId),
  );
  assert.equal(new Set(value.actualRequestIds).size, 2);
  assert.ok(
    Array.isArray(value.fingerprints) &&
      value.fingerprints.length === 2 &&
      new Set(value.fingerprints).size === 2,
  );
  for (const fingerprint of value.fingerprints)
    assert.match(fingerprint, /^[a-f0-9]{64}$/);
  return value;
}
function iso(value) {
  const result = new Date(value).toISOString();
  contract.epoch(result);
  return result;
}
function groupName(lease) {
  contract.verifyLease(lease);
  return `tt-certops-${lease.runId}-${lease.runAttempt}`;
}
function verifyPrepareTags(group, expected) {
  assert.equal(
    group.name,
    `tt-certops-${expected.runId}-${expected.runAttempt}`,
  );
  assert.equal(group.tags?.purpose, "certops-adcs-qualification");
  assert.equal(group.tags.candidateSha, expected.candidateSha);
  assert.equal(group.tags.retentionPrepareKind, "certops-native-retention24h");
  assert.equal(group.tags.retentionPrepareNonce, expected.nonce);
  assert.equal(group.tags.retentionPrepareRunId, expected.runId);
  assert.equal(group.tags.retentionPrepareRunAttempt, expected.runAttempt);
}
function verifyAzure(lease, group, vm, expectedPhase) {
  contract.verifyLease(lease);
  verifyPrepareTags(group, lease);
  assert.equal(
    group.id.toLowerCase(),
    lease.vmResourceId.split("/providers/")[0].toLowerCase(),
  );
  assert.equal(group.name, groupName(lease));
  assert.equal(group.tags?.purpose, "certops-adcs-qualification");
  assert.equal(group.tags.candidateSha, lease.candidateSha);
  assert.equal(iso(group.tags.createdAt), lease.createdAt);
  assert.equal(iso(group.tags.expiresAt), lease.expiresAt);
  assert.equal(vm.id.toLowerCase(), lease.vmResourceId.toLowerCase());
  assert.equal(vm.vmId.toLowerCase(), lease.vmId);
  assert.equal(vm.provisioningState, "Succeeded");
  if (expectedPhase) {
    for (const [key, value] of Object.entries(leaseTags(lease)))
      assert.equal(group.tags[key], value, key);
    assert.equal(group.tags.retentionPhase, expectedPhase);
  }
  return true;
}
function leaseTags(lease) {
  contract.verifyLease(lease);
  return {
    retentionKind: lease.kind,
    retentionPhase: lease.phase,
    retentionRunId: lease.runId,
    retentionRunAttempt: lease.runAttempt,
    retentionNonce: lease.nonce,
    retentionVmId: lease.vmId,
    retentionNodeSha256: lease.nodeSha256,
    retentionKeeperSha256: lease.keeperSha256,
    retentionCreatedAt: lease.createdAt,
    retentionHardExpiresAt: lease.hardExpiresAt,
    expiresAt: lease.expiresAt,
  };
}
function inspect(lease, phase) {
  const group = az(["group", "show", "--name", groupName(lease)]);
  const vm = az(["vm", "show", "--ids", lease.vmResourceId]);
  verifyAzure(lease, group, vm, phase);
  return { group, vm };
}
function guest(lease, script) {
  const result = az([
    "vm",
    "run-command",
    "invoke",
    "--ids",
    lease.vmResourceId,
    "--command-id",
    "RunPowerShellScript",
    "--scripts",
    `$ErrorActionPreference='Stop';${script}`,
  ]);
  const text = result.value.map((row) => row.message).join("\n");
  const matches = [
    ...text.matchAll(/CERTOPS_RETENTION_PUBLIC=([A-Za-z0-9+/=]+)/g),
  ];
  assert.equal(
    matches.length,
    1,
    "Exact bounded guest response marker required",
  );
  const bytes = Buffer.from(matches[0][1], "base64");
  assert.ok(bytes.length > 0 && bytes.length <= 2048);
  return JSON.parse(bytes.toString("utf8"));
}
function readGuestFile(lease, name) {
  assert.ok(["prepare", "result"].includes(name));
  const file =
    name === "prepare"
      ? "C:\\ttqualification\\retention24h-prepare-public.json"
      : `C:\\ttqualification\\retention24h\\${lease.nonce}\\resident-result.json`;
  return readGuestJson(lease, `$b=[IO.File]::ReadAllBytes('${file}');`);
}
function readGuestJson(lease, producer, execute = guest) {
  const chunks = [];
  let length, hash;
  for (
    let offset = 0;
    length === undefined || offset < length;
    offset += 1024
  ) {
    const part = execute(
      lease,
      `${producer}if($b.Length -gt 65536){throw 'Public receipt bound'};$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b))).Replace('-','').ToLowerInvariant();$o=@{length=$b.Length;sha256=$h;chunk=[Convert]::ToBase64String($b,${offset},[Math]::Min(1024,$b.Length-${offset}))};'CERTOPS_RETENTION_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress)))`,
    );
    assert.ok(
      Number.isInteger(part.length) && part.length > 0 && part.length <= 65536,
    );
    assert.match(part.sha256, /^[a-f0-9]{64}$/);
    if (length === undefined) {
      length = part.length;
      hash = part.sha256;
    }
    assert.equal(part.length, length);
    assert.equal(part.sha256, hash);
    const bytes = Buffer.from(part.chunk, "base64");
    assert.equal(bytes.length, Math.min(1024, length - offset));
    chunks.push(bytes);
  }
  const bytes = Buffer.concat(chunks);
  assert.equal(sha(bytes), hash);
  return JSON.parse(bytes.toString("utf8"));
}
function readOwnedObservation(
  lease,
  producer,
  {
    execute = guest,
    requestNonce = crypto.randomBytes(32).toString("hex"),
  } = {},
) {
  contract.verifyLease(lease);
  assert.match(requestNonce, /^[a-f0-9]{64}$/);
  const directory = `C:\\ttqualification\\retention24h\\${lease.nonce}`;
  const file = `${directory}\\controller-observation-${requestNonce}.json`;
  // Only fixed public task JSON enters this private, exclusive snapshot. Dynamic
  // native checks execute once; later Azure calls read those same exact bytes.
  const ownership = `
$r=Get-Content -LiteralPath 'C:\\ttqualification\\runtime.json' -Raw|ConvertFrom-Json;
if($r.candidateSha -cne '${lease.candidateSha}' -or $r.node -cnotmatch '^C:\\\\ttqualification\\\\tools\\\\node-v24\\.[0-9]+\\.[0-9]+-win-x64\\\\node.exe$' -or (Get-FileHash -LiteralPath $r.node -Algorithm SHA256).Hash.ToLowerInvariant() -cne '${lease.nodeSha256}'){throw 'Snapshot runtime identity mismatch'};
$ancestor=Get-Item -LiteralPath '${directory}' -Force -ErrorAction Stop;
while($ancestor){if(!$ancestor.PSIsContainer -or ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Snapshot ancestor is not regular'};$ancestor=$ancestor.Parent};
function Get-SnapshotIdentity {
 param([Parameter(Mandatory)][string]$LiteralFile)
 if(-not [IO.Path]::IsPathRooted($LiteralFile)){throw 'Snapshot identity requires absolute path'};
 $prior=$env:TOKENTIMER_RETENTION_SNAPSHOT;$options=$env:NODE_OPTIONS;$nodePath=$env:NODE_PATH;
 try{$env:TOKENTIMER_RETENTION_SNAPSHOT=$LiteralFile;[Environment]::SetEnvironmentVariable('NODE_OPTIONS',$null,'Process');[Environment]::SetEnvironmentVariable('NODE_PATH',$null,'Process');
 $identity=& $r.node -p '(()=>{const s=require(''node:fs'').lstatSync(process.env.TOKENTIMER_RETENTION_SNAPSHOT,{bigint:true});if(!s.isFile()||s.isSymbolicLink())throw Error(''nonregular snapshot'');return s.dev.toString()+'':''+s.ino.toString()})()';
 if($LASTEXITCODE -ne 0 -or [string]$identity -notmatch '^\\d+:[1-9]\\d*$'){throw 'Snapshot file identity unavailable'};return ([string]$identity).Trim()
 }finally{[Environment]::SetEnvironmentVariable('TOKENTIMER_RETENTION_SNAPSHOT',$prior,'Process');[Environment]::SetEnvironmentVariable('NODE_OPTIONS',$options,'Process');[Environment]::SetEnvironmentVariable('NODE_PATH',$nodePath,'Process')}
};`;
  let receipt, originalError;
  let receiptVerified = false;
  try {
    receipt = execute(
      lease,
      `${ownership}
# CERTOPS_OBSERVATION_CREATE: execute the actual producer exactly once.
${producer}
if(!$b -or $b.Length -gt 65536){throw 'Public observation bound'};
$stream=[IO.File]::Open('${file}',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);
try{$stream.Write($b,0,$b.Length);$stream.Flush($true)}finally{$stream.Dispose()};
$o=@{length=$b.Length;sha256=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b))).Replace('-','').ToLowerInvariant();fileIdentity=(Get-SnapshotIdentity -LiteralFile '${file}')};
'CERTOPS_RETENTION_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress)))`,
    );
    exactKeys(receipt, ["length", "sha256", "fileIdentity"]);
    assert.ok(
      Number.isInteger(receipt.length) &&
        receipt.length > 0 &&
        receipt.length <= 65536,
    );
    assert.match(receipt.sha256, /^[a-f0-9]{64}$/);
    assert.match(receipt.fileIdentity, /^\d+:[1-9]\d*$/);
    assert.ok(receipt.fileIdentity.length <= 64);
    Object.freeze(receipt);
    receiptVerified = true;
    return readGuestJson(
      lease,
      `$b=[IO.File]::ReadAllBytes('${file}');if($b.Length -ne ${receipt.length} -or ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b))).Replace('-','').ToLowerInvariant() -cne '${receipt.sha256}'){throw 'Public snapshot bytes changed'};`,
      execute,
    );
  } catch (error) {
    originalError = error;
    throw error;
  } finally {
    // A missing creation receipt never authorizes deletion of an unknown file.
    // Changed identity or bytes are preserved for exact owned-lab cleanup.
    if (receiptVerified) {
      try {
        const cleanup = execute(
          lease,
          `${ownership}
# CERTOPS_OBSERVATION_CLEANUP: refuse a replacement, link or altered snapshot.
$item=Get-Item -LiteralPath '${file}' -Force -ErrorAction Stop;
if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-SnapshotIdentity -LiteralFile '${file}') -cne '${receipt.fileIdentity}' -or $item.Length -ne ${receipt.length} -or (Get-FileHash -LiteralPath '${file}' -Algorithm SHA256).Hash.ToLowerInvariant() -cne '${receipt.sha256}'){throw 'Snapshot cleanup ownership changed'};
Remove-Item -LiteralPath '${file}' -Force -ErrorAction Stop;
if(Test-Path -LiteralPath '${file}'){throw 'Owned snapshot cleanup incomplete'};
'CERTOPS_RETENTION_PUBLIC='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"removed":true}'))`,
        );
        exactKeys(cleanup, ["removed"]);
        assert.equal(cleanup.removed, true);
      } catch (error) {
        if (originalError)
          throw new AggregateError(
            [originalError, error],
            "Public observation read and owned snapshot cleanup failed",
          );
        throw error;
      }
    }
  }
}
function observe(lease, receipt, mode) {
  assert.ok(["Observe", "Finalize"].includes(mode));
  assert.match(receipt.configSha256, /^[a-f0-9]{64}$/);
  const source = `C:\\ttqualification\\source\\tokentimer-core-${lease.candidateSha}`;
  const config = `C:\\ttqualification\\retention24h\\${lease.nonce}\\keeper-config.json`;
  return readOwnedObservation(
    lease,
    `$o=& '${source}\\scripts\\certops-retention24h-task.ps1' -Mode ${mode} -ConfigPath '${config}' -ConfigSha256 '${receipt.configSha256}';if($LASTEXITCODE -ne 0){throw 'Task observation failed'};$v=$o|ConvertFrom-Json;$b=[Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 8 -Compress));`,
  );
}
function write(name, value) {
  fs.mkdirSync(OUTPUT, { recursive: true });
  fs.writeFileSync(path.join(OUTPUT, name), JSON.stringify(value), {
    flag: "wx",
    mode: 0o600,
  });
}
function owner(run, lease) {
  assert.equal(run.id.toString(), lease.runId);
  assert.equal(run.run_attempt.toString(), lease.runAttempt);
  return {
    ...lease,
    repository: run.repository.full_name,
    event: run.event,
    headBranch: run.head_branch,
    workflowPath: run.path,
    status: run.status,
    conclusion: run.conclusion,
    candidateSha: run.head_sha,
  };
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
function verifyPreparedReceipt(receipt) {
  assert.equal(receipt.schemaVersion, 1);
  contract.verifyLease(receipt.preparedLease);
  contract.verifyOriginalLease(receipt.lease, receipt.preparedLease);
  assert.equal(receipt.lease.phase, "keeper-owned");
  assert.match(receipt.configSha256, /^[a-f0-9]{64}$/);
  assert.equal(
    receipt.scope,
    "host-verified-retention24h-handoff-not-elapsed-qualified",
  );
  contract.attestHandoff(
    receipt.preparedLease,
    receipt.observed,
    receipt.observedAt,
  );
  publicObservation(receipt.observed);
  publicPreparation(receipt.publicPreparation);
  assert.equal(receipt.observed.configSha256, receipt.configSha256);
  return true;
}
function seal() {
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
  const runId = process.env.GITHUB_RUN_ID,
    attempt = process.env.GITHUB_RUN_ATTEMPT;
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.match(attempt, /^[1-9][0-9]*$/);
  assert.match(process.env.CERTOPS_RETENTION24H_NONCE, /^[a-f0-9]{64}$/);
  const run = github(`actions/runs/${runId}/attempts/${attempt}`);
  assert.equal(String(run.id), runId);
  assert.equal(String(run.run_attempt), attempt);
  assert.equal(run.head_sha, process.env.GITHUB_SHA);
  const preparedJob = verifyPrepareJob(run, fetchPrepareJobs(run));
  const group = az([
    "group",
    "show",
    "--name",
    `tt-certops-${runId}-${attempt}`,
  ]);
  const vm = az([
    "vm",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "windows-agent",
  ]);
  // Construct the original authority independently of guest lease claims.
  const stub = {
    candidateSha: process.env.GITHUB_SHA,
    runId,
    runAttempt: attempt,
    nonce: process.env.CERTOPS_RETENTION24H_NONCE,
    vmResourceId: vm.id,
    vmId: vm.vmId,
    taskName: `TokenTimer-Retention24h-${process.env.CERTOPS_RETENTION24H_NONCE}`,
    nodeSha256: "0".repeat(64),
    keeperSha256: sha(
      fs.readFileSync(
        path.join(ROOT, "scripts/certops-retention24h-runtime.js"),
      ),
    ),
  };
  // First read does not authorize mutation; every identity field is checked below.
  const initial = contract.createLease(stub, iso(group.tags.createdAt));
  verifyJobCreation(initial.createdAt, run, preparedJob);
  verifyPrepareTags(group, stub);
  const prepared = readGuestFile(initial, "prepare");
  contract.verifyLease(prepared.lease);
  publicPreparation(prepared, true);
  stub.nodeSha256 = prepared.lease.nodeSha256;
  const preparedLease = contract.createLease(stub, iso(group.tags.createdAt));
  contract.verifyOriginalLease(prepared.lease, preparedLease);
  verifyAzure(preparedLease, group, vm);
  assert.equal(
    group.tags.retentionPhase,
    undefined,
    "Never renew an existing handoff",
  );
  const observed = observe(preparedLease, prepared, "Observe"),
    observedAt = new Date().toISOString();
  publicObservation(observed);
  contract.attestHandoff(preparedLease, observed, observedAt);
  write("retention24h-original.json", {
    schemaVersion: 1,
    scope:
      "host-verified-original-four-hour-retention24h-not-elapsed-qualified",
    preparedLease,
    configSha256: prepared.configSha256,
    observed,
    observedAt,
    publicPreparation: prepared,
  });
}
async function handoff() {
  const runId = process.env.GITHUB_RUN_ID,
    attempt = process.env.GITHUB_RUN_ATTEMPT;
  const { value: original, artifact: originalArtifact } =
    await retrieveArtifact(
      runId,
      attempt,
      `retention24h-original-${attempt}-${process.env.CERTOPS_RETENTION24H_NONCE}`,
      "retention24h-original.json",
    );
  verifyOriginalReceipt(original);
  const run = github(`actions/runs/${runId}/attempts/${attempt}`),
    preparedLease = original.preparedLease;
  assert.equal(run.repository.full_name, REPOSITORY);
  assert.equal(run.path, WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.equal(run.head_sha, preparedLease.candidateSha);
  assert.equal(run.id.toString(), preparedLease.runId);
  assert.equal(run.run_attempt.toString(), preparedLease.runAttempt);
  assert.equal(process.env.GITHUB_SHA, preparedLease.candidateSha);
  verifyJobCreation(
    preparedLease.createdAt,
    run,
    verifyPrepareJob(run, fetchPrepareJobs(run)),
  );
  inspect(preparedLease);
  const observed = observe(preparedLease, original, "Observe"),
    observedAt = new Date().toISOString();
  publicObservation(observed);
  const intent = controller.handoffIntent({
    lease: preparedLease,
    preparedLease,
    observed,
    observedAt,
  });
  const before = inspect(preparedLease);
  assert.equal(before.group.tags.retentionPhase, undefined);
  assert.ok(Date.now() < contract.epoch(preparedLease.expiresAt));
  az([
    "group",
    "update",
    "--name",
    groupName(preparedLease),
    "--set",
    ...Object.entries(leaseTags(intent.lease)).map(
      ([key, value]) => `tags.${key}=${value}`,
    ),
  ]);
  inspect(intent.lease, "keeper-owned");
  deallocateInfrastructure(intent.lease);
  write("retention24h-ownership.json", {
    schemaVersion: 1,
    scope: "host-verified-retention24h-handoff-not-elapsed-qualified",
    preparedLease,
    lease: intent.lease,
    configSha256: original.configSha256,
    observed,
    observedAt,
    originalArtifact,
    publicPreparation: original.publicPreparation,
    actualRequestIds: original.publicPreparation.actualRequestIds,
    fingerprints: original.publicPreparation.fingerprints,
  });
}
function verifyOriginalReceipt(receipt) {
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(
    receipt.scope,
    "host-verified-original-four-hour-retention24h-not-elapsed-qualified",
  );
  contract.verifyLease(receipt.preparedLease);
  assert.equal(receipt.preparedLease.phase, "preparing");
  assert.match(receipt.configSha256, /^[a-f0-9]{64}$/);
  contract.attestHandoff(
    receipt.preparedLease,
    receipt.observed,
    receipt.observedAt,
  );
  contract.verifyOriginalLease(
    receipt.publicPreparation.lease,
    receipt.preparedLease,
  );
  publicObservation(receipt.observed);
  publicPreparation(receipt.publicPreparation);
  assert.equal(receipt.observed.configSha256, receipt.configSha256);
  assert.equal(receipt.publicPreparation.configSha256, receipt.configSha256);
  return true;
}
async function retrieveOwnership(runId, attempt, nonce) {
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.match(attempt, /^[1-9][0-9]*$/);
  assert.match(nonce, /^[a-f0-9]{64}$/);
  const run = github(`actions/runs/${runId}/attempts/${attempt}`);
  assert.equal(run.repository.full_name, REPOSITORY);
  assert.equal(run.path, WORKFLOW);
  const { value: original, artifact: originalArtifact } =
    await retrieveArtifact(
      runId,
      attempt,
      `retention24h-original-${attempt}-${nonce}`,
      "retention24h-original.json",
    );
  verifyOriginalReceipt(original);
  const { value: receipt, artifact: handoffArtifact } = await retrieveArtifact(
    runId,
    attempt,
    `${ARTIFACT}-${attempt}-${nonce}`,
    "retention24h-ownership.json",
  );
  verifyPreparedReceipt(receipt);
  assert.deepEqual(receipt.preparedLease, original.preparedLease);
  assert.equal(receipt.configSha256, original.configSha256);
  assert.deepEqual(receipt.publicPreparation, original.publicPreparation);
  assert.deepEqual(receipt.originalArtifact, originalArtifact);
  const lease = receipt.lease;
  assert.equal(lease.runId, runId);
  assert.equal(lease.runAttempt, attempt);
  const githubOwner = owner(run, lease);
  contract.verifyOwner(lease, githubOwner);
  const preparedJob = verifyPrepareJob(run, fetchPrepareJobs(run));
  verifyJobCreation(lease.createdAt, run, preparedJob);
  githubOwner.prepareJobStartedAt = preparedJob.startedAt;
  return {
    receipt,
    githubOwner,
    prepareArtifactProvenance: {
      original: originalArtifact,
      handoff: handoffArtifact,
    },
  };
}
async function retrieveArtifact(runId, attempt, name, member) {
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.match(attempt, /^[1-9][0-9]*$/);
  assert.match(
    name,
    new RegExp(
      `^(?:retention24h-original|${ARTIFACT})-${attempt}-[a-f0-9]{64}$`,
    ),
  );
  assert.ok(
    ["retention24h-original.json", "retention24h-ownership.json"].includes(
      member,
    ),
  );
  const artifacts = github(`actions/runs/${runId}/artifacts?per_page=100`);
  assert.ok(artifacts.total_count <= 100);
  const found = artifacts.artifacts.filter(
    (item) => item.name === name && !item.expired,
  );
  assert.equal(found.length, 1);
  const artifact = found[0];
  assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(artifact.workflow_run.id.toString(), runId);
  const run = github(`actions/runs/${runId}/attempts/${attempt}`);
  assert.equal(artifact.workflow_run.head_sha, run.head_sha);
  const zip = await downloadArtifactZip(artifact.id);
  assert.equal(`sha256:${sha(zip)}`, artifact.digest);
  const script =
    "import io,sys,zipfile; z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())); assert z.namelist()==[sys.argv[1]]; i=z.infolist()[0]; assert 0<i.file_size<=65536; sys.stdout.buffer.write(z.read(i))";
  const bytes = execFileSync("python3", ["-c", script, member], {
    input: zip,
    timeout: 10000,
    maxBuffer: 65536,
  });
  return {
    value: JSON.parse(bytes.toString("utf8")),
    artifact: {
      id: String(artifact.id),
      name,
      archiveSha256: artifact.digest.slice(7),
    },
  };
}
function allowedBlobUrl(value) {
  assert.equal(typeof value, "string");
  assert.ok(value.length <= 16384);
  const url = new URL(value);
  assert.equal(url.protocol, "https:");
  assert.equal(url.username, "");
  assert.equal(url.password, "");
  assert.equal(url.port, "");
  assert.ok(
    url.hostname.endsWith(".blob.core.windows.net") ||
      url.hostname.endsWith(".githubusercontent.com") ||
      url.hostname.endsWith(".actions.githubusercontent.com"),
  );
  return url.href;
}
async function downloadArtifactZip(
  id,
  { fetchImpl = fetch, token = process.env.GH_TOKEN } = {},
) {
  assert.ok(Number.isSafeInteger(id) && id > 0);
  assert.equal(typeof token, "string");
  assert.ok(token.length > 0);
  const response = await fetchImpl(
    `https://api.github.com/repos/${REPOSITORY}/actions/artifacts/${id}/zip`,
    {
      redirect: "manual",
      signal: AbortSignal.timeout(120000),
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    },
  );
  assert.equal(response.status, 302);
  const location = allowedBlobUrl(response.headers.get("location"));
  // Signed blob request has NO GitHub Authorization header and does not follow
  // another host redirect. Neither signed URLs nor credentials enter artifacts.
  const blob = await fetchImpl(location, {
    redirect: "manual",
    signal: AbortSignal.timeout(120000),
  });
  assert.equal(blob.status, 200);
  const declared = blob.headers.get("content-length");
  if (declared !== null)
    assert.ok(Number(declared) > 0 && Number(declared) <= 2 * 1024 * 1024);
  const chunks = [];
  let total = 0;
  for await (const chunk of blob.body) {
    total += chunk.length;
    assert.ok(total <= 2 * 1024 * 1024);
    chunks.push(Buffer.from(chunk));
  }
  assert.ok(total > 0);
  return Buffer.concat(chunks);
}
function leaseFromGroup(group) {
  assert.match(group.name, /^tt-certops-[1-9][0-9]*-[1-9][0-9]*$/);
  assert.equal(group.tags.purpose, "certops-adcs-qualification");
  assert.equal(group.tags.retentionKind, "certops-native-retention24h");
  assert.match(group.tags.retentionRunId, /^[1-9][0-9]{0,19}$/);
  assert.match(group.tags.retentionRunAttempt, /^[1-9][0-9]{0,19}$/);
  assert.equal(
    group.name,
    `tt-certops-${group.tags.retentionRunId}-${group.tags.retentionRunAttempt}`,
  );
  return {
    runId: group.tags.retentionRunId,
    runAttempt: group.tags.retentionRunAttempt,
  };
}
function publicDeployment(group) {
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
function verifyDeploymentChronology(
  group,
  runStart,
  candidate,
  deployment,
  states = ["Succeeded"],
  precisionMs = 0,
) {
  assert.equal(deployment.name, "qualification");
  assert.equal(
    deployment.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Resources/deployments/qualification`.toLowerCase(),
  );
  assert.equal(deployment.candidateSha, candidate);
  assert.ok(states.includes(deployment.provisioningState));
  const timestamp = Date.parse(iso(deployment.timestamp));
  assert.ok(
    timestamp >= runStart - precisionMs &&
      timestamp < runStart + contract.INITIAL + precisionMs,
  );
}
function ownedDeallocationTargets(lease, group, member, vms, deployment) {
  verifyAzure(lease, group, member, "keeper-owned");
  const created = contract.epoch(lease.createdAt);
  verifyDeploymentChronology(group, created, lease.candidateSha, deployment);
  assert.ok(Array.isArray(vms) && vms.length === 2);
  assert.deepEqual(vms.map((vm) => vm.name).sort(), [
    "control-plane",
    "domain-ca",
  ]);
  assert.ok(
    Array.isArray(deployment.outputResources) &&
      deployment.outputResources.length <= 128,
  );
  const outputs = new Set(
    deployment.outputResources.map((item) => item.id.toLowerCase()),
  );
  assert.ok(outputs.has(member.id.toLowerCase()));
  const identities = new Set([member.vmId]);
  return vms.map((vm) => {
    assert.equal(
      vm.id.toLowerCase(),
      `${group.id}/providers/Microsoft.Compute/virtualMachines/${vm.name}`.toLowerCase(),
    );
    assert.equal(vm.tags?.purpose, "certops-adcs-qualification");
    assert.equal(vm.tags.candidateSha, lease.candidateSha);
    assert.match(vm.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert.equal(identities.has(vm.vmId), false);
    identities.add(vm.vmId);
    assert.ok(outputs.has(vm.id.toLowerCase()));
    assert.equal(vm.provisioningState, "Succeeded");
    const time = Date.parse(iso(vm.timeCreated));
    assert.ok(time >= created && time < created + contract.INITIAL);
    return {
      name: vm.name,
      resourceId: vm.id,
      vmId: vm.vmId,
      createdAt: iso(vm.timeCreated),
    };
  });
}
function deallocateInfrastructure(lease) {
  const { group, vm: member } = inspect(lease, "keeper-owned");
  const vms = ["domain-ca", "control-plane"].map((name) =>
    az(["vm", "show", "--resource-group", group.name, "--name", name]),
  );
  const targets = ownedDeallocationTargets(
    lease,
    group,
    member,
    vms,
    publicDeployment(group),
  );
  for (const target of targets) {
    const fresh = az(["vm", "show", "--ids", target.resourceId]);
    assert.equal(fresh.id, target.resourceId);
    assert.equal(fresh.vmId, target.vmId);
    assert.equal(fresh.tags?.purpose, "certops-adcs-qualification");
    assert.equal(fresh.tags.candidateSha, lease.candidateSha);
    inspect(lease, "keeper-owned");
    command("az", [
      "vm",
      "deallocate",
      "--ids",
      target.resourceId,
      "-o",
      "none",
    ]);
    const after = az(["vm", "show", "--ids", target.resourceId]);
    assert.equal(after.vmId, target.vmId);
    const view = az(["vm", "get-instance-view", "--ids", target.resourceId]);
    assert.ok(Array.isArray(view.instanceView?.statuses));
    assert.equal(
      view.instanceView.statuses.filter((item) =>
        item.code?.startsWith("PowerState/"),
      ).length,
      1,
    );
    assert.ok(
      view.instanceView.statuses.some(
        (item) => item.code === "PowerState/deallocated",
      ),
    );
  }
  const retained = inspect(lease, "keeper-owned").vm;
  assert.equal(retained.vmId, member.vmId);
  const memberView = az([
    "vm",
    "get-instance-view",
    "--ids",
    lease.vmResourceId,
  ]);
  assert.ok(
    memberView.instanceView?.statuses?.some(
      (item) => item.code === "PowerState/running",
    ),
  );
  write("retention24h-cost.json", {
    schemaVersion: 1,
    scope:
      "owned-infrastructure-deallocated-member-retained-not-elapsed-qualification",
    candidateSha: lease.candidateSha,
    runId: lease.runId,
    runAttempt: lease.runAttempt,
    nonce: lease.nonce,
    deallocated: targets,
    memberVmId: member.vmId,
    memberRetainedRunning: true,
    verifiedAt: new Date().toISOString(),
  });
}
function verifyAbortOwnership(
  group,
  run,
  nonce,
  vm,
  deployment,
  original,
  jobs,
) {
  assert.match(nonce, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(run.id) && run.id > 0);
  assert.ok(Number.isInteger(run.run_attempt) && run.run_attempt > 0);
  assert.equal(run.repository?.full_name, REPOSITORY);
  assert.equal(run.head_repository?.full_name, REPOSITORY);
  assert.equal(run.path, WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.match(run.head_sha, /^[a-f0-9]{40}$/);
  const expected = {
    candidateSha: run.head_sha,
    runId: String(run.id),
    runAttempt: String(run.run_attempt),
    nonce,
  };
  verifyPrepareTags(group, expected);
  const preparedJob = verifyPrepareJob(run, jobs);
  const start = Date.parse(preparedJob.startedAt),
    created = verifyJobCreation(group.tags.createdAt, run, preparedJob);
  assert.equal(
    vm.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Compute/virtualMachines/windows-agent`.toLowerCase(),
  );
  assert.equal(vm.tags?.purpose, "certops-adcs-qualification");
  assert.equal(vm.tags.candidateSha, run.head_sha);
  assert.match(vm.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  const vmTime = Date.parse(iso(vm.timeCreated));
  assert.ok(vmTime >= created - 5000);
  verifyJobCreation(vm.timeCreated, run, preparedJob);
  verifyDeploymentChronology(
    group,
    start,
    run.head_sha,
    deployment,
    ["Succeeded", "Failed", "Canceled", "Running", "Accepted"],
    5000,
  );
  verifyJobCreation(deployment.timestamp, run, preparedJob);
  if (original) {
    verifyOriginalReceipt(original);
    const lease = original.preparedLease;
    for (const [key, value] of Object.entries(expected))
      assert.equal(lease[key], value);
    assert.equal(lease.vmId, vm.vmId);
    assert.equal(lease.vmResourceId.toLowerCase(), vm.id.toLowerCase());
    assert.equal(lease.createdAt, iso(group.tags.createdAt));
  }
  return true;
}
async function abort() {
  const runId = process.env.GITHUB_RUN_ID,
    attempt = process.env.GITHUB_RUN_ATTEMPT,
    nonce = process.env.CERTOPS_RETENTION24H_NONCE;
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.match(attempt, /^[1-9][0-9]*$/);
  assert.match(nonce, /^[a-f0-9]{64}$/);
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  const name = `tt-certops-${runId}-${attempt}`;
  try {
    if (az(["group", "exists", "--name", name]) === false) return;
    const run = github(`actions/runs/${runId}/attempts/${attempt}`);
    assert.equal(String(run.id), runId);
    assert.equal(String(run.run_attempt), attempt);
    assert.equal(run.head_sha, process.env.GITHUB_SHA);
    const group = az(["group", "show", "--name", name]);
    const vm = az([
        "vm",
        "show",
        "--resource-group",
        name,
        "--name",
        "windows-agent",
      ]),
      deployment = publicDeployment(group);
    const inventory = github(`actions/runs/${runId}/artifacts?per_page=100`);
    assert.ok(inventory.total_count <= 100);
    let original;
    const artifactName = `retention24h-original-${attempt}-${nonce}`;
    if (inventory.artifacts.some((item) => item.name === artifactName))
      original = (
        await retrieveArtifact(
          runId,
          attempt,
          artifactName,
          "retention24h-original.json",
        )
      ).value;
    const jobs = fetchPrepareJobs(run);
    verifyAbortOwnership(group, run, nonce, vm, deployment, original, jobs);
    const fresh = az(["group", "show", "--name", name]);
    assert.equal(fresh.id, group.id);
    assert.deepEqual(fresh.tags, group.tags);
    const freshVm = az(["vm", "show", "--ids", vm.id]);
    assert.equal(freshVm.vmId, vm.vmId);
    verifyAbortOwnership(
      fresh,
      run,
      nonce,
      freshVm,
      publicDeployment(fresh),
      original,
      jobs,
    );
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
    command("az", [
      "group",
      "wait",
      "--name",
      name,
      "--deleted",
      "--timeout",
      "600",
      "--interval",
      "15",
    ]);
    assert.equal(az(["group", "exists", "--name", name]), false);
  } catch {
    const receipt = {
      schemaVersion: 1,
      scope: "unproven-owned-abort-preserved-not-qualification",
      resourceGroup: name,
      cleanupRequired: true,
      status: "failed",
      observedAt: new Date().toISOString(),
      reason:
        "exact-current-owner-or-deployment-or-native-vm-or-cloud-absence-unconfirmed",
    };
    // Abort is the last workflow step: retain its bounded receipt in the job log
    // even when the local file cannot be uploaded or written.
    process.stderr.write(
      `Retention abort orphan receipt: ${JSON.stringify(receipt)}\n`,
    );
    write(
      `retention24h-controller-failure-abort-${runId}-${attempt}.json`,
      receipt,
    );
    throw new Error(
      "Owned abort refused; independent expiry cleanup and orphan inspection required",
    );
  }
}
function deleteOwned(lease) {
  inspect(lease, "keeper-owned");
  command("az", [
    "group",
    "delete",
    "--name",
    groupName(lease),
    "--yes",
    "--no-wait",
    "-o",
    "none",
  ]);
  command("az", [
    "group",
    "wait",
    "--name",
    groupName(lease),
    "--deleted",
    "--timeout",
    "600",
    "--interval",
    "15",
  ]);
  assert.equal(az(["group", "exists", "--name", groupName(lease)]), false);
}
function taggedCleanupDecision(group, run, vm, deployment, now, jobs) {
  const ids = leaseFromGroup(group);
  assert.equal(group.name, `tt-certops-${ids.runId}-${ids.runAttempt}`);
  assert.equal(run.id.toString(), ids.runId);
  assert.equal(run.run_attempt.toString(), ids.runAttempt);
  assert.equal(run.repository.full_name, REPOSITORY);
  assert.equal(run.path, WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.equal(run.head_sha, group.tags.candidateSha);
  assert.match(run.head_sha, /^[a-f0-9]{40}$/);
  const preparedJob = verifyPrepareJob(run, jobs);
  const start = Date.parse(preparedJob.startedAt);
  assert.ok(Number.isFinite(now) && now >= start);
  assert.equal(
    vm.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Compute/virtualMachines/windows-agent`.toLowerCase(),
  );
  assert.equal(vm.tags.purpose, "certops-adcs-qualification");
  assert.equal(vm.tags.candidateSha, run.head_sha);
  verifyJobCreation(vm.timeCreated, run, preparedJob);
  assert.equal(deployment.name, "qualification");
  assert.equal(deployment.candidateSha, run.head_sha);
  assert.equal(deployment.provisioningState, "Succeeded");
  assert.equal(
    deployment.id.toLowerCase(),
    `${group.id}/providers/Microsoft.Resources/deployments/qualification`.toLowerCase(),
  );
  verifyJobCreation(deployment.timestamp, run, preparedJob);
  // The independently authenticated prepare job begins after approval. Its
  // start supplies a conservative cleanup cap, never a recovered lease.
  // Mutable created/expiry tags cannot extend this independently bounded cap.
  if (now >= start + contract.MAX) return "delete-conservative-orphan-cap";
  if (
    [
      "cancelled",
      "failure",
      "timed_out",
      "action_required",
      "stale",
      "startup_failure",
    ].includes(run.conclusion)
  )
    return "delete-failed-owner";
  return "retain";
}
function fallbackJanitor(group) {
  const ids = leaseFromGroup(group),
    run = github(`actions/runs/${ids.runId}/attempts/${ids.runAttempt}`);
  const jobs = fetchPrepareJobs(run);
  const vm = az([
    "vm",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "windows-agent",
  ]);
  // Query only public candidate/chronology; never domain password parameters.
  const query =
    "{id:id,name:name,candidateSha:properties.parameters.candidateSha.value,timestamp:properties.timestamp,provisioningState:properties.provisioningState}";
  const deployment = az([
    "deployment",
    "group",
    "show",
    "--resource-group",
    group.name,
    "--name",
    "qualification",
    "--query",
    query,
  ]);
  if (
    taggedCleanupDecision(group, run, vm, deployment, Date.now(), jobs) ===
    "retain"
  )
    return false;
  const current = az(["group", "show", "--name", group.name]);
  assert.equal(current.id, group.id);
  assert.deepEqual(current.tags, group.tags);
  assert.notEqual(
    taggedCleanupDecision(current, run, vm, deployment, Date.now(), jobs),
    "retain",
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
  command("az", [
    "group",
    "wait",
    "--name",
    group.name,
    "--deleted",
    "--timeout",
    "600",
    "--interval",
    "15",
  ]);
  assert.equal(az(["group", "exists", "--name", group.name]), false);
  return true;
}
function currentFinalizer() {
  assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  const runId = process.env.GITHUB_RUN_ID,
    runAttempt = process.env.GITHUB_RUN_ATTEMPT;
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.match(runAttempt, /^[1-9][0-9]*$/);
  const run = github(`actions/runs/${runId}/attempts/${runAttempt}`);
  assert.equal(run.repository.full_name, REPOSITORY);
  assert.equal(run.head_branch, "main");
  assert.equal(run.path, ".github/workflows/certops-retention24h-finalize.yml");
  assert.ok(["schedule", "workflow_dispatch"].includes(run.event));
  assert.equal(run.head_sha, process.env.GITHUB_SHA);
  assert.equal(run.id.toString(), runId);
  assert.equal(run.run_attempt.toString(), runAttempt);
  assert.equal(run.status, "in_progress");
  assert.equal(run.conclusion, null);
  const files = [
    "scripts/certops-retention24h-azure.js",
    "scripts/certops-retention24h-contract.js",
    "scripts/certops-retention24h-controller.js",
    "scripts/certops-retention24h-proof.js",
    ".github/workflows/certops-retention24h-finalize.yml",
  ];
  return {
    repository: REPOSITORY,
    runId,
    runAttempt,
    headSha: run.head_sha,
    event: run.event,
    headBranch: run.head_branch,
    workflowPath: run.path,
    controllerSources: files.map((file) => ({
      file,
      sha256: sha(fs.readFileSync(path.join(ROOT, file))),
    })),
  };
}
async function scan(mode) {
  assert.ok(["finalize", "janitor"].includes(mode));
  const finalizerProvenance = mode === "finalize" ? currentFinalizer() : null;
  const groups = az([
    "group",
    "list",
    "--tag",
    "retentionKind=certops-native-retention24h",
  ]);
  assert.ok(Array.isArray(groups) && groups.length <= 128);
  const failures = [];
  for (const group of groups) {
    try {
      if (mode === "janitor" && fallbackJanitor(group)) continue;
      const ids = leaseFromGroup(group);
      const { receipt, githubOwner, prepareArtifactProvenance } =
        await retrieveOwnership(
          ids.runId,
          ids.runAttempt,
          group.tags.retentionNonce,
        );
      const lease = receipt.lease;
      inspect(lease, "keeper-owned");
      const at = new Date().toISOString();
      if (
        contract.cleanupDecision(lease, githubOwner, at) !==
        "retain-within-owned-lease"
      ) {
        deleteOwned(lease);
        continue;
      }
      if (mode === "janitor") continue;
      // A queued short finalizer does not spend a hosted runner waiting a day.
      // The same resident task must finish; absent evidence never qualifies.
      if (
        Date.now() <
        Date.parse(receipt.observedAt) + contract.DAY + 15 * 60000
      )
        continue;
      const observed = observe(lease, receipt, "Finalize");
      publicObservation(observed, true);
      assert.equal(observed.taskXmlSha256, receipt.observed.taskXmlSha256);
      controller.finalizeIntent({
        lease,
        preparedLease: receipt.preparedLease,
        githubOwner,
        observed,
        observedAt: at,
      });
      const result = readGuestFile(lease, "result");
      publicResidentResult(result);
      assert.deepEqual(result, observed.residentResult);
      assert.ok(
        Date.parse(result.preDeadlineObservedAt) <
          Date.parse(receipt.observed.cleanupDeadline),
      );
      assert.equal(result.candidateSha, lease.candidateSha);
      assert.equal(result.nonce, lease.nonce);
      assert.equal(result.pid, receipt.observed.processId);
      assert.equal(result.configSha256, receipt.configSha256);
      assert.ok(
        Number.isInteger(result.monotonicElapsedMs) &&
          result.monotonicElapsedMs >= contract.DAY,
      );
      assert.ok(result.monotonicElapsedMs < contract.MAX);
      for (const flag of [
        "nativeCustodyVerified",
        "trustedTlsVerified",
        "actualProductionLedgerVerified",
      ])
        assert.equal(result[flag], true);
      assert.equal(result.retentionHours, 24);
      assert.equal(result.collector, "production-default-clock");
      assert.equal(result.processCreatedAt, receipt.observed.processCreatedAt);
      assert.equal(result.bootTime, receipt.observed.bootTime);
      // Preserve bounded public evidence before deletion. No private config,
      // enrollment journals, credentials, task XML or raw command output escape.
      const composite = {
        schemaVersion: 1,
        scope: "actual-domain-adcs-same-process-native-retention24h",
        candidateSha: lease.candidateSha,
        prepareRunId: lease.runId,
        prepareRunAttempt: lease.runAttempt,
        immutablePrepareArtifactVerified: true,
        retention24hProvenance: {
          originalArtifact: prepareArtifactProvenance.original,
          handoffArtifact: prepareArtifactProvenance.handoff,
          finalizerProvenance,
        },
        preparedLease: receipt.preparedLease,
        lease,
        handoffObserved: receipt.observed,
        finalObserved: observed,
        residentResult: result,
        publicPreparation: receipt.publicPreparation,
        actualRequestIds: receipt.actualRequestIds,
        fingerprints: receipt.fingerprints,
        collectedAt: new Date().toISOString(),
        cleanup: "pending",
        cleanupFinishedAt: null,
      };
      const proof = require("./certops-retention24h-proof");
      proof.verifyCompositeProof(composite, { requireCleanup: false });
      write(
        `retention24h-final-${lease.runId}-${lease.runAttempt}-${lease.nonce}.json`,
        composite,
      );
      deleteOwned(lease);
      const output = path.join(
        OUTPUT,
        `retention24h-final-${lease.runId}-${lease.runAttempt}-${lease.nonce}.json`,
      );
      const report = JSON.parse(fs.readFileSync(output, "utf8"));
      report.cleanup = "completed";
      report.cleanupFinishedAt = new Date().toISOString();
      proof.verifyCompositeProof(report);
      fs.writeFileSync(output, JSON.stringify(report), { mode: 0o600 });
      write(
        `retention24h-qualification-${lease.runId}-${lease.runAttempt}-${lease.nonce}.json`,
        proof.createQualificationReport(report),
      );
    } catch {
      // No unchecked fallback deletion: the independent original four-hour
      // janitor also protects interrupted handoff and damaged ownership receipts.
      failures.push(group.name);
      const safeName = /^tt-certops-[1-9][0-9]*-[1-9][0-9]*$/.test(group.name)
        ? group.name
        : `unverified-${failures.length}`;
      write(`retention24h-controller-failure-${mode}-${safeName}.json`, {
        schemaVersion: 1,
        scope: "owned-lab-cleanup-incomplete-not-qualification",
        mode,
        resourceGroup: safeName,
        status: "failed",
        cleanupRequired: true,
        observedAt: new Date().toISOString(),
        reason:
          "ownership-evidence-or-native-finalization-or-cloud-deletion-unconfirmed",
      });
    }
  }
  if (failures.length)
    throw new Error("Owned retention controller could not finish every group");
}
module.exports = {
  verifyAzure,
  leaseTags,
  verifyPreparedReceipt,
  taggedCleanupDecision,
  owner,
  seal,
  handoff,
  scan,
  verifyOriginalReceipt,
  allowedBlobUrl,
  downloadArtifactZip,
  publicObservation,
  publicResidentResult,
  publicPreparation,
  readOwnedObservation,
  verifyPrepareTags,
  ownedDeallocationTargets,
  verifyAbortOwnership,
  verifyPrepareJob,
  verifyJobCreation,
  groupName,
  REPOSITORY,
  WORKFLOW,
  ARTIFACT,
};
if (require.main === module) {
  (async () => {
    if (process.argv[2] === "seal") seal();
    else if (process.argv[2] === "handoff") await handoff();
    else if (process.argv[2] === "abort") await abort();
    else await scan(process.argv[2]);
  })().catch(() => {
    process.stderr.write(
      "Retention controller failed; independently owned cleanup remains required.\n",
    );
    process.exitCode = 1;
  });
}
