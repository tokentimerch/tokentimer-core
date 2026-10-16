"use strict";
/** Real installed-service path qualification. The parent changes only its owned
 * installer root, then executes the original registration/issuance journey.
 * This is not canonical default-root or relocated-state qualification. Native
 * observations remain private; the public proof contains bounded facts only. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const PREFIX = "certops Windows-é-[literal]-";
const SCOPE = "installed-system-agent-unicode-spaces-literal-brackets-root";
const scenarioName = "windows-installed-unicode-spaces-literal-brackets";
const FLAGS = Object.freeze([
  "ownedRootIdentityPreserved",
  "exactScmArgumentPaths",
  "actualSystemHostAndChild",
  "exactServiceConfigurationPath",
  "candidateEntryAndHostBytes",
  "actualSignedIssuance",
  "claimBoundResultEvidence",
  "actualCngIisTrustedTls",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-installed-paths.js",
  "tests/e2e/windows-real-journey.js",
  "scripts/certops-windows-e2e.js",
  "packages/agent/scripts/install-agent.ps1",
  "packages/agent/windows-service-host/main.go",
  "packages/agent/windows-service-host/host.go",
  "packages/agent/windows-service-host/service_windows.go",
  "packages/agent/src/config/index.js",
  "packages/agent/src/index.js",
  "apps/api/services/certops/agentDispatch.js",
]);
function identity(file) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(
    !st.isSymbolicLink() && st.ino > 0n,
    "Owned path identity required",
  );
  return `${st.dev}:${st.ino}`;
}
function createOwnedRoot(parent, historicalSupportingOnly = false) {
  assert.equal(typeof historicalSupportingOnly, "boolean");
  assert.ok(fs.lstatSync(parent).isDirectory());
  const root = fs.mkdtempSync(
    path.join(
      parent,
      historicalSupportingOnly ? "certops-historical-supporting-" : PREFIX,
    ),
  );
  return { root, identity: identity(root), historicalSupportingOnly };
}
function assertOwnedRoot(receipt) {
  assert.ok(
    receipt &&
      typeof receipt.historicalSupportingOnly === "boolean" &&
      path
        .basename(receipt.root)
        .startsWith(
          receipt.historicalSupportingOnly
            ? "certops-historical-supporting-"
            : PREFIX,
        ),
  );
  assert.equal(
    identity(receipt.root),
    receipt.identity,
    "Replaced owned path preserves state",
  );
  return true;
}
/** Await all supporting cleanup before current qualification. A failed first
 * subrun cannot start a second service, and the caller's environment is restored
 * even when current qualification fails. No native outcome is substituted. */
async function runHistoricalThenCurrent(run, environment = process.env) {
  assert.equal(typeof run, "function");
  const historical = environment.CERTOPS_WINDOWS_HISTORICAL_PACKAGE;
  assert.ok(typeof historical === "string" && historical.length > 0);
  await run(true);
  delete environment.CERTOPS_WINDOWS_HISTORICAL_PACKAGE;
  try {
    return await run(false);
  } finally {
    environment.CERTOPS_WINDOWS_HISTORICAL_PACKAGE = historical;
  }
}
// CommandLineToArgvW independently decodes actual SCM and live process command
// lines; substring matching cannot prove quoted argument custody.
function observationScript() {
  return `
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if(-not ('CertOpsPathArgv' -as [type])){Add-Type @'
using System;using System.Runtime.InteropServices;
public static class CertOpsPathArgv {
[DllImport("shell32.dll",SetLastError=true)]static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)]string c,out int n);
[DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
public static string[] Parse(string c){int n;IntPtr p=CommandLineToArgvW(c,out n);if(p==IntPtr.Zero)throw new Exception("argv unavailable");try{string[] a=new string[n];for(int i=0;i<n;i++)a[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(p,i*IntPtr.Size));return a;}finally{LocalFree(p);}}}
'@}
$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'" -ErrorAction Stop
if(!$s -or $s.State -cne 'Running' -or $s.ProcessId -le 0){throw 'Installed running service absent'}
$h=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)" -ErrorAction Stop
$children=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($s.ProcessId)" -ErrorAction Stop)
if(!$h -or $children.Count -ne 1){throw 'Exact owned host child unavailable'}
$c=$children[0];$ho=Invoke-CimMethod -InputObject $h -MethodName GetOwnerSid;$co=Invoke-CimMethod -InputObject $c -MethodName GetOwnerSid
$e=@((Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent' -Name Environment -ErrorAction Stop).Environment)
[pscustomobject]@{serviceArgs=@([CertOpsPathArgv]::Parse($s.PathName));hostExe=$h.ExecutablePath;hostId=[long]$h.ProcessId;hostCreation=[string]$h.CreationDate;hostSid=$ho.Sid;childArgs=@([CertOpsPathArgv]::Parse($c.CommandLine));childExe=$c.ExecutablePath;childId=[long]$c.ProcessId;childCreation=[string]$c.CreationDate;childSid=$co.Sid;parentId=[long]$c.ParentProcessId;environment=$e}|ConvertTo-Json -Depth 4 -Compress
`;
}
function validateObservation(value, expected) {
  const eq = (a, b) =>
    typeof a === "string" &&
    typeof b === "string" &&
    path.win32.normalize(a).toLowerCase() ===
      path.win32.normalize(b).toLowerCase();
  assert.ok(
    value && Array.isArray(value.serviceArgs) && value.serviceArgs.length === 3,
  );
  assert.ok(
    value.serviceArgs.every((v, i) =>
      eq(v, [expected.host, expected.node, expected.entry][i]),
    ),
    "Exact SCM argv required",
  );
  assert.ok(
    eq(value.hostExe, expected.host) && eq(value.childExe, expected.node),
    "Native executable identity differs",
  );
  assert.ok(
    Array.isArray(value.childArgs) &&
      value.childArgs.length === 2 &&
      eq(value.childArgs[0], expected.node) &&
      eq(value.childArgs[1], expected.entry),
    "Exact child argv required",
  );
  for (const k of ["hostId", "childId"])
    assert.ok(
      Number.isInteger(value[k]) && value[k] > 0 && value[k] <= 0xffffffff,
    );
  assert.notEqual(value.hostId, value.childId);
  assert.equal(value.parentId, value.hostId);
  for (const k of ["hostCreation", "childCreation"])
    assert.ok(
      typeof value[k] === "string" &&
        value[k].length > 0 &&
        value[k].length < 100,
    );
  assert.equal(value.hostSid, "S-1-5-18");
  assert.equal(value.childSid, "S-1-5-18");
  assert.ok(Array.isArray(value.environment));
  const configs = value.environment.filter((v) =>
    /^TOKENTIMER_AGENT_CONFIG_DIR=/i.test(v),
  );
  assert.ok(
    configs.length === 1 &&
      eq(configs[0].slice(configs[0].indexOf("=") + 1), expected.config),
    "Exact service state environment required",
  );
  assert.ok(
    !value.environment.some((v) =>
      /^TOKENTIMER_AGENT_BOOTSTRAP_TOKEN(?:_ID)?=/i.test(v),
    ),
    "Bootstrap secret must be scrubbed",
  );
  return true;
}
function verifyProof(value) {
  assert.ok(
    value &&
      Object.keys(value).sort().join(",") ===
        ["scope", ...FLAGS].sort().join(","),
  );
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
async function qualifyInstalledPaths({
  receipt,
  configDir,
  candidateRoot,
  ps,
  pool,
  workspaceId,
  jobId,
  agentId,
  publicIssuanceFacts,
}) {
  assert.equal(process.platform, "win32");
  assert.equal(
    receipt.historicalSupportingOnly,
    false,
    "Historical ASCII subrun cannot qualify Unicode paths",
  );
  assertOwnedRoot(receipt);
  assert.equal(path.resolve(configDir), path.join(receipt.root, "state"));
  const expected = {
    host: path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  validateObservation(JSON.parse(ps(observationScript())), expected);
  const hash = (file) =>
    crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  for (const relative of [
    "bin/tokentimer-agent-host-amd64.exe",
    "bin/tokentimer-agent.js",
  ]) {
    const actual = path.join(receipt.root, "app", relative),
      source = path.join(candidateRoot, relative);
    identity(actual);
    identity(source);
    assert.equal(
      hash(actual),
      hash(source),
      "Installed candidate bytes differ",
    );
  }
  const row = (
    await pool.query(
      "SELECT j.status,j.operation,j.claim_id,j.claimed_by_agent_id,a.agent_id FROM certificate_jobs j JOIN certops_agents a ON a.id=j.claimed_by_agent_id AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
      [workspaceId, jobId],
    )
  ).rows[0];
  assert.ok(
    row &&
      row.status === "succeeded" &&
      row.operation === "issue" &&
      row.agent_id === agentId &&
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(row.claim_id),
    "Actual same installed-agent issuance required",
  );
  assert.ok(
    (
      await pool.query(
        "SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",
        [workspaceId, jobId],
      )
    ).rows.length > 0,
    "Actual issuance result evidence required",
  );
  assert.equal(publicIssuanceFacts.nativeJobSucceeded, true);
  assert.equal(publicIssuanceFacts.nativeCngIisTrustedTlsVerified, true);
  assertOwnedRoot(receipt);
  const proof = {
    scope: SCOPE,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  PREFIX,
  SCOPE,
  scenarioName,
  FLAGS,
  REQUIRED_SOURCES,
  createOwnedRoot,
  assertOwnedRoot,
  runHistoricalThenCurrent,
  observationScript,
  validateObservation,
  verifyProof,
  qualifyInstalledPaths,
};
