"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");

const REPOSITORY = "tokentimerch/tokentimer-core";
const RECEIPT_LIMIT = 16384;
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
  assert.match(runId, ID);
  assert.match(attempt, ID);
  assert.match(artifactId, ID);
  assert.match(receipt[type + "ArtifactDigest"], ARTIFACT_DIGEST);
  assert.match(receipt[type + "Sha256"], SHA256);
  assert.match(receipt[type + "ReceiptSha256"], SHA256);

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

function verifyMediaPreflight(raw, {
  receiptSha256, expectedSource, expectedWorkflow: expectedPackageWorkflow,
  expectedLauncherWorkflow = expectedPackageWorkflow, read, now = Date.now(),
}) {
  assert.match(receiptSha256, SHA256);
  assert.match(expectedSource, SHA);
  assert.match(expectedPackageWorkflow, SHA);
  assert.match(expectedLauncherWorkflow, SHA);
  assert.ok(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= RECEIPT_LIMIT,
    "A bounded custody receipt is required");
  assert.equal(createHash("sha256").update(raw).digest("hex"), receiptSha256, "Custody receipt digest mismatch");
  const receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  assert.equal(receipt?.channel, "windows-amd64-fresh-install-lab-only");
  assert.equal(receipt.sourceCommit, expectedSource, "Signed media source differs from the reviewed candidate");
  const hasSeparateWorkflowCommits = Object.hasOwn(receipt, "packageWorkflowCommit") ||
    Object.hasOwn(receipt, "launcherWorkflowCommit");
  assert.ok(!hasSeparateWorkflowCommits || !Object.hasOwn(receipt, "workflowCommit"),
    "Custody receipt must use either a shared workflow commit or separate package and launcher commits");
  const packageWorkflowCommit = hasSeparateWorkflowCommits ? receipt.packageWorkflowCommit : receipt.workflowCommit;
  const launcherWorkflowCommit = hasSeparateWorkflowCommits ? receipt.launcherWorkflowCommit : receipt.workflowCommit;
  assert.equal(packageWorkflowCommit, expectedPackageWorkflow,
    "Custody package signing workflow differs from the reviewed main commit");
  assert.equal(launcherWorkflowCommit, expectedLauncherWorkflow,
    "Custody launcher signing workflow differs from the reviewed main commit");
  assert.match(receipt.policySha256, SHA256);
  assert.match(receipt.issuerSha256, SHA256);
  assert.match(receipt.packagePublisherLeafSha256, SHA256);
  assert.equal(receipt.launcherPublisherLeafSha256, receipt.packagePublisherLeafSha256,
    "Launcher publisher differs from the package policy binding");
  assert.match(receipt.packageOfflinePublisherNotAfterUtc, OFFLINE_DEADLINE);
  assert.ok(Date.parse(receipt.packageOfflinePublisherNotAfterUtc) > now, "Offline publisher admission expired");
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

function main(args) {
  assert.ok(args.length === 4 || args.length === 5,
    "Expected custody receipt path, approved receipt SHA-256, signed candidate SHA, reviewed package workflow SHA and optional reviewed launcher workflow SHA");
  const [file, receiptSha256, expectedSource, expectedWorkflow, expectedLauncherWorkflow] = args;
  const info = fs.lstatSync(file);
  assert.ok(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= RECEIPT_LIMIT,
    "The custody receipt must be a bounded regular file");
  const read = (apiPath) => {
    try {
      return JSON.parse(execFileSync("gh", ["api", "--method", "GET", "repos/" + REPOSITORY + "/" + apiPath],
        { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15000, maxBuffer: 256 * 1024 }));
    } catch {
      throw new Error("GitHub metadata could not be independently verified");
    }
  };
  const result = verifyMediaPreflight(fs.readFileSync(file), {
    receiptSha256, expectedSource, expectedWorkflow, expectedLauncherWorkflow, read,
  });
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write("Named Store media preflight refused: " + error.message.split("\n")[0] + "\n"); process.exitCode = 1; }
}
module.exports = { verifyMediaPreflight };
