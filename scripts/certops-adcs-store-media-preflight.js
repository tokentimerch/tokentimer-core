"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const REPOSITORY = "tokentimerch/tokentimer-core";
const RECEIPT_LIMIT = 16384;
const PROTECTED_PACKAGE = "tokentimer-agent-0.20.0-windows-amd64";
const LAUNCHER_FILENAME = "tokentimer-agent-launcher.exe";
const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ARTIFACT_DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[1-9][0-9]{0,18}$/;
const OFFLINE_DEADLINE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/;
const SOURCES = Object.freeze({
  package: {
    workflow: ".github/workflows/windows-agent-signing-pilot.yml",
    artifact: "windows-amd64-pilot-sealed-",
  },
  launcher: {
    workflow: ".github/workflows/windows-agent-launcher-signing-pilot.yml",
    artifact: "windows-amd64-launcher-sealed-",
  },
});

function requireVerifiedGitHubCommit(read, sha) {
  const commit = read("commits/" + sha);
  assert.ok(commit?.sha === sha && commit.commit?.verification?.verified === true,
    "GitHub did not verify an exact reviewed source or workflow commit");
}

function requireOfficialMedia(read, type, receipt, workflowCommit) {
  const source = SOURCES[type];
  const runId = receipt[type + "Run"];
  const attempt = receipt[type + "Attempt"];
  const artifactId = receipt[type + "ArtifactId"];
  const workflowPath = source.workflow;
  const workflow = read("contents/" + workflowPath + "?ref=" + workflowCommit);
  assert.ok(workflow?.encoding === "base64" && typeof workflow.content === "string",
    "Exact signing workflow cannot be read");
  const pinned = Buffer.from(workflow.content, "base64").toString("utf8")
    .match(/^  PILOT_SOURCE: '([a-f0-9]{40})'$/gm);
  assert.deepEqual(pinned, ["  PILOT_SOURCE: '" + receipt.sourceCommit + "'"],
    "Signing workflow did not pin the exact reviewed package source");

  const run = read("actions/runs/" + runId + "/attempts/" + attempt);
  assert.ok(String(run?.id) === runId && String(run?.run_attempt) === attempt &&
    run.head_repository?.full_name === REPOSITORY && run.head_sha === workflowCommit &&
    run.head_branch === "main" && run.event === "workflow_dispatch" &&
    run.status === "completed" && run.conclusion === "success" &&
    [workflowPath, workflowPath + "@refs/heads/main"].includes(run.path),
  "Expected a successful exact protected signing attempt on Core main");

  const artifact = read("actions/artifacts/" + artifactId);
  assert.ok(String(artifact?.id) === artifactId && String(artifact?.workflow_run?.id) === runId &&
    artifact.name === source.artifact + attempt && artifact.digest === receipt[type + "ArtifactDigest"],
  "Sealed artifact differs from the independently pinned receipt");
  return { runId, attempt, artifactId, artifactDigest: artifact.digest, sha256: receipt[type + "Sha256"],
    receiptSha256: receipt[type + "ReceiptSha256"] };
}

function parseApprovedReceipt(raw, receiptSha256, now) {
  assert.match(receiptSha256, SHA256);
  assert.ok(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= RECEIPT_LIMIT,
    "A bounded custody receipt is required");
  assert.equal(createHash("sha256").update(raw).digest("hex"), receiptSha256, "Custody receipt digest mismatch");
  const receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  assert.equal(receipt?.channel, "windows-amd64-fresh-install-lab-only");
  assert.match(receipt.sourceCommit, SHA);
  const hasSeparateWorkflowCommits = Object.hasOwn(receipt, "packageWorkflowCommit") ||
    Object.hasOwn(receipt, "launcherWorkflowCommit");
  assert.ok(!hasSeparateWorkflowCommits || !Object.hasOwn(receipt, "workflowCommit"),
    "Custody receipt must use either a shared workflow commit or separate package and launcher commits");
  const packageWorkflowCommit = hasSeparateWorkflowCommits ? receipt.packageWorkflowCommit : receipt.workflowCommit;
  const launcherWorkflowCommit = hasSeparateWorkflowCommits ? receipt.launcherWorkflowCommit : receipt.workflowCommit;
  assert.ok(typeof packageWorkflowCommit === "string" && SHA.test(packageWorkflowCommit), "Custody package signing workflow must be an exact commit");
  assert.ok(typeof launcherWorkflowCommit === "string" && SHA.test(launcherWorkflowCommit), "Custody launcher signing workflow must be an exact commit");
  for (const type of ["package", "launcher"]) {
    assert.match(receipt[type + "Run"], ID);
    assert.match(receipt[type + "Attempt"], ID);
    assert.match(receipt[type + "ArtifactId"], ID);
    assert.match(receipt[type + "ArtifactDigest"], ARTIFACT_DIGEST);
    assert.match(receipt[type + "Sha256"], SHA256);
    assert.match(receipt[type + "ReceiptSha256"], SHA256);
  }
  assert.match(receipt.policySha256, SHA256);
  assert.match(receipt.issuerSha256, SHA256);
  assert.match(receipt.packagePublisherLeafSha256, SHA256);
  assert.equal(receipt.launcherPublisherLeafSha256, receipt.packagePublisherLeafSha256,
    "Launcher publisher differs from the package policy binding");
  assert.match(receipt.packageOfflinePublisherNotAfterUtc, OFFLINE_DEADLINE);
  assert.ok(Date.parse(receipt.packageOfflinePublisherNotAfterUtc) > now, "Offline publisher admission expired");
  return { ...receipt, packageWorkflowCommit, launcherWorkflowCommit };
}

function verifyMediaPreflight(raw, {
  receiptSha256, expectedSource, expectedWorkflow: expectedPackageWorkflow,
  expectedLauncherWorkflow = expectedPackageWorkflow, read, now = Date.now(),
}) {
  assert.match(expectedSource, SHA);
  assert.match(expectedPackageWorkflow, SHA);
  assert.match(expectedLauncherWorkflow, SHA);
  const receipt = parseApprovedReceipt(raw, receiptSha256, now);
  const { packageWorkflowCommit, launcherWorkflowCommit } = receipt;
  assert.equal(receipt.sourceCommit, expectedSource, "Signed media source differs from the reviewed candidate");
  assert.equal(packageWorkflowCommit, expectedPackageWorkflow,
    "Custody package signing workflow differs from the reviewed main commit");
  assert.equal(launcherWorkflowCommit, expectedLauncherWorkflow,
    "Custody launcher signing workflow differs from the reviewed main commit");
  requireVerifiedGitHubCommit(read, expectedSource);
  requireVerifiedGitHubCommit(read, packageWorkflowCommit);
  if (launcherWorkflowCommit !== packageWorkflowCommit) requireVerifiedGitHubCommit(read, launcherWorkflowCommit);
  return {
    scope: "adcs-named-store-media-metadata",
    sourceCommit: receipt.sourceCommit,
    ...(packageWorkflowCommit === launcherWorkflowCommit ? { workflowCommit: packageWorkflowCommit } : {}),
    packageWorkflowCommit,
    launcherWorkflowCommit,
    package: requireOfficialMedia(read, "package", receipt, packageWorkflowCommit),
    launcher: requireOfficialMedia(read, "launcher", receipt, launcherWorkflowCommit),
    policySha256: receipt.policySha256,
    issuerSha256: receipt.issuerSha256,
    publisherLeafSha256: receipt.packagePublisherLeafSha256,
    custodyReceiptSha256: receiptSha256,
    offlinePublisherNotAfterUtc: receipt.packageOfflinePublisherNotAfterUtc,
  };
}

function measureRegularFile(file, limit, retainBytes = false) {
  const entry = fs.lstatSync(file);
  assert.ok(entry.isFile() && entry.size > 0 && entry.size <= limit, "Expected a bounded regular staged file");
  const fd = fs.openSync(file, "r");
  try {
    const opened = fs.fstatSync(fd);
    assert.ok(opened.isFile() && opened.dev === entry.dev && opened.ino === entry.ino && opened.size === entry.size,
      "Staged file changed before measurement");
    const bytes = retainBytes ? Buffer.alloc(opened.size) : null;
    const buffer = Buffer.allocUnsafe(Math.min(65536, opened.size));
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < opened.size) {
      const length = fs.readSync(fd, buffer, 0, Math.min(buffer.length, opened.size - offset), offset);
      assert.ok(length > 0, "Staged file changed during measurement");
      hash.update(buffer.subarray(0, length));
      if (bytes) buffer.copy(bytes, offset, 0, length);
      offset += length;
    }
    assert.equal(fs.readSync(fd, buffer, 0, 1, offset), 0, "Staged file changed during measurement");
    return { bytes, sha256: hash.digest("hex") };
  } finally {
    fs.closeSync(fd);
  }
}

function readOfficialReceipt(file, expectedSha256, label) {
  const { bytes, sha256 } = measureRegularFile(file, RECEIPT_LIMIT, true);
  assert.equal(sha256, expectedSha256, label + " receipt digest mismatch");
  const receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  assert.match(receipt?.encryptedHandoffSha256, SHA256, "Official outer sealed receipt required");
  return receipt;
}

function verifyStagedMedia(raw, { receiptSha256, packageReceiptPath, launcherReceiptPath, packageStage, launcherPath, now = Date.now() }) {
  const approved = parseApprovedReceipt(raw, receiptSha256, now);
  const pkg = readOfficialReceipt(packageReceiptPath, approved.packageReceiptSha256, "Package");
  const launcher = readOfficialReceipt(launcherReceiptPath, approved.launcherReceiptSha256, "Launcher");

  const exactArchive = PROTECTED_PACKAGE + ".tgz";
  assert.ok(pkg.sourceCommit === approved.sourceCommit && pkg.workflowCommit === approved.packageWorkflowCommit &&
    pkg.runId === approved.packageRun && pkg.runAttempt === approved.packageAttempt &&
    pkg.architecture === "amd64" && pkg.disposition === "lab-only" && pkg.launcherRequiredBeforeInstallation === true &&
    pkg.archive === exactArchive && pkg.archiveSha256 === approved.packageSha256 &&
    pkg.launcherPolicySha256 === approved.policySha256, "Official package receipt differs from the approved signed package");
  assert.ok(launcher.sourceCommit === approved.sourceCommit && launcher.workflowCommit === approved.launcherWorkflowCommit &&
    launcher.runId === approved.launcherRun && launcher.runAttempt === approved.launcherAttempt &&
    launcher.architecture === "amd64" && launcher.disposition === "lab-only" && launcher.launcher === LAUNCHER_FILENAME &&
    launcher.signedLauncherSha256 === approved.launcherSha256 &&
    launcher.packageWorkflowCommit === approved.packageWorkflowCommit && launcher.packageRunId === approved.packageRun &&
    launcher.packageRunAttempt === approved.packageAttempt && launcher.packageArtifactId === approved.packageArtifactId &&
    launcher.launcherPolicySha256 === approved.policySha256, "Official launcher receipt does not bind the approved exact package");
  assert.match(pkg.cmsSha256, SHA256);
  assert.match(pkg.sbomSha256, SHA256);
  assert.ok(fs.lstatSync(packageStage).isDirectory(), "Expected a regular package staging directory");
  assert.equal(path.basename(launcherPath), LAUNCHER_FILENAME, "Expected the official staged launcher filename");

  for (const [file, limit, expected] of [
    [path.join(packageStage, exactArchive), 128 << 20, approved.packageSha256],
    [path.join(packageStage, PROTECTED_PACKAGE + ".inventory.json.p7"), 8 << 20, pkg.cmsSha256],
    [path.join(packageStage, PROTECTED_PACKAGE + ".cdx.json"), 16 << 20, pkg.sbomSha256],
    [path.join(packageStage, "launcher-policy.json"), RECEIPT_LIMIT, approved.policySha256],
    [launcherPath, 32 << 20, approved.launcherSha256],
  ]) {
    assert.equal(measureRegularFile(file, limit).sha256, expected, "Staged digest mismatch for " + path.basename(file));
  }
  return { scope: "adcs-named-store-staged-bytes", sourceCommit: approved.sourceCommit, custodyReceiptSha256: receiptSha256,
    packageSha256: approved.packageSha256, launcherSha256: approved.launcherSha256, policySha256: approved.policySha256,
    cmsSha256: pkg.cmsSha256, sbomSha256: pkg.sbomSha256 };
}

function readGitHubMetadata(apiPath, invoke = execFileSync) {
  const args = ["api", "--method", "GET", "repos/" + REPOSITORY + "/" + apiPath];
  if (apiPath.startsWith("commits/") && SHA.test(apiPath.slice("commits/".length))) {
    // Commit responses include diffs that can exceed the local metadata buffer.
    args.push("--jq", "{sha,commit:{verification:{verified:.commit.verification.verified}}}");
  }
  try {
    return JSON.parse(invoke("gh", args,
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15000, maxBuffer: 256 * 1024 }));
  } catch {
    throw new Error("GitHub metadata could not be independently verified");
  }
}

function main(args) {
  if (args[0] === "--staged") {
    assert.equal(args.length, 7,
      "Expected --staged <custody-receipt> <approved-receipt-sha256> <package-receipt> <launcher-receipt> <package-stage> <launcher-exe>");
    const [, file, receiptSha256, packageReceiptPath, launcherReceiptPath, packageStage, launcherPath] = args;
    const { bytes } = measureRegularFile(file, RECEIPT_LIMIT, true);
    const result = verifyStagedMedia(bytes, { receiptSha256, packageReceiptPath, launcherReceiptPath, packageStage, launcherPath });
    process.stdout.write(JSON.stringify(result) + "\n");
    return;
  }
  assert.ok(args.length === 4 || args.length === 5,
    "Expected custody receipt path, approved receipt SHA-256, signed candidate SHA, reviewed package workflow SHA and optional reviewed launcher workflow SHA");
  const [file, receiptSha256, expectedSource, expectedWorkflow, expectedLauncherWorkflow] = args;
  const { bytes } = measureRegularFile(file, RECEIPT_LIMIT, true);
  const result = verifyMediaPreflight(bytes, {
    receiptSha256, expectedSource, expectedWorkflow, expectedLauncherWorkflow, read: readGitHubMetadata,
  });
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write("Named Store media preflight refused: " + error.message.split("\n")[0] + "\n"); process.exitCode = 1; }
}
module.exports = { readGitHubMetadata, verifyMediaPreflight, verifyStagedMedia };
