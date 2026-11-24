"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const test = require("node:test");
const { verifyMediaPreflight } = require("./certops-adcs-store-media-preflight");

const candidate = "a".repeat(40);
const workflow = "b".repeat(40);
const newerWorkflow = "c".repeat(40);
const now = Date.parse("2030-01-01T00:00:00Z");
const artifactHash = (digit) => "sha256:" + digit.repeat(64);
const packagePath = ".github/workflows/windows-agent-signing-pilot.yml";
const launcherPath = ".github/workflows/windows-agent-launcher-signing-pilot.yml";

function fixture({ launcherWorkflow = workflow } = {}) {
  const receipt = {
    channel: "windows-amd64-fresh-install-lab-only", sourceCommit: candidate,
    ...(launcherWorkflow === workflow ? { workflowCommit: workflow } : {
      packageWorkflowCommit: workflow, launcherWorkflowCommit: launcherWorkflow,
    }),
    policySha256: "c".repeat(64), issuerSha256: "1".repeat(64),
    packagePublisherLeafSha256: "2".repeat(64), launcherPublisherLeafSha256: "2".repeat(64),
    packageOfflinePublisherNotAfterUtc: "2030-01-02T00:00:00.0000000Z",
    packageRun: "100", packageAttempt: "2", packageArtifactId: "300", packageArtifactDigest: artifactHash("d"),
    packageSha256: "e".repeat(64), packageReceiptSha256: "f".repeat(64),
    launcherRun: "200", launcherAttempt: "1", launcherArtifactId: "400", launcherArtifactDigest: artifactHash("a"),
    launcherSha256: "b".repeat(64), launcherReceiptSha256: "c".repeat(64),
  };
  const responses = new Map();
  for (const sha of [candidate, workflow, launcherWorkflow]) {
    responses.set("commits/" + sha, { sha, commit: { verification: { verified: true } } });
  }
  for (const [path, sha] of [[packagePath, workflow], [launcherPath, launcherWorkflow]]) {
    responses.set("contents/" + path + "?ref=" + sha,
      { encoding: "base64", content: Buffer.from("env:\n  PILOT_SOURCE: '" + candidate + "'\n").toString("base64") });
  }
  const job = { head_repository: { full_name: "tokentimerch/tokentimer-core" }, head_branch: "main",
    event: "workflow_dispatch", status: "completed", conclusion: "success" };
  responses.set("actions/runs/100/attempts/2", { ...job, head_sha: workflow, id: 100, run_attempt: 2, path: packagePath });
  responses.set("actions/runs/200/attempts/1", { ...job, head_sha: launcherWorkflow, id: 200, run_attempt: 1,
    path: launcherPath + "@refs/heads/main" });
  responses.set("actions/artifacts/300", { id: 300, workflow_run: { id: 100 },
    name: "windows-amd64-pilot-sealed-2", digest: receipt.packageArtifactDigest });
  responses.set("actions/artifacts/400", { id: 400, workflow_run: { id: 200 },
    name: "windows-amd64-launcher-sealed-1", digest: receipt.launcherArtifactDigest });
  function verify({ approvedDigest, expectedSource = candidate, expectedWorkflow = workflow, expectedLauncherWorkflow } = {}) {
    const raw = Buffer.from(JSON.stringify(receipt));
    return verifyMediaPreflight(raw, { receiptSha256: approvedDigest ?? createHash("sha256").update(raw).digest("hex"),
      expectedSource, expectedWorkflow, expectedLauncherWorkflow, read: (path) => responses.get(path), now });
  }
  return { verify, receipt, responses };
}

test("independently verifies exact protected package and launcher coordinates as metadata only", () => {
  const { verify, receipt } = fixture();
  const output = verify();
  assert.equal(output.scope, "adcs-named-store-media-metadata");
  assert.equal(output.workflowCommit, workflow);
  assert.equal(output.packageWorkflowCommit, workflow);
  assert.equal(output.launcherWorkflowCommit, workflow);
  assert.equal(output.package.attempt, "2");
  assert.equal(output.launcher.sha256, receipt.launcherSha256);
  assert.equal(output.policySha256, receipt.policySha256);
  assert.equal(output.qualified, undefined);
});

test("refuses an unpinned, expired or unsigned custody receipt", () => {
  const { verify, receipt, responses } = fixture();
  assert.throws(() => verify({ approvedDigest: "0".repeat(64) }), /digest mismatch/);
  assert.throws(() => verify({ expectedSource: "0".repeat(40) }), /differs from the reviewed candidate/);
  assert.throws(() => verify({ expectedWorkflow: "0".repeat(40) }), /differs from the reviewed main commit/);
  responses.get("commits/" + candidate).commit.verification.verified = false;
  assert.throws(() => verify(), /did not verify/);
  receipt.packageOfflinePublisherNotAfterUtc = "2029-12-31T00:00:00Z";
  assert.throws(() => verify(), /expired/);
});

test("refuses a wrong source pin, plausible alternate run and mismatching artifact", () => {
  const { verify, receipt, responses } = fixture();
  receipt.launcherPublisherLeafSha256 = "3".repeat(64);
  assert.throws(() => verify(), /Launcher publisher differs/);
  receipt.launcherPublisherLeafSha256 = receipt.packagePublisherLeafSha256;
  const pinned = responses.get("contents/" + launcherPath + "?ref=" + workflow);
  const original = pinned.content;
  pinned.content = Buffer.from("env:\n  PILOT_SOURCE: '" + "0".repeat(40) + "'\n").toString("base64");
  assert.throws(() => verify(), /did not pin/);
  pinned.content = original;
  const run = responses.get("actions/runs/100/attempts/2");
  run.run_attempt = 3;
  assert.throws(() => verify(), /protected signing attempt/);
  run.run_attempt = 2;
  run.head_branch = "feature";
  assert.throws(() => verify(), /protected signing attempt/);
  run.head_branch = "main";
  responses.get("actions/artifacts/400").digest = artifactHash("0");
  assert.throws(() => verify(), /independently pinned receipt/);
});

test("verifies each protected attempt and workflow file at its separately reviewed commit", () => {
  const { verify, responses } = fixture({ launcherWorkflow: newerWorkflow });
  const reviewed = { expectedLauncherWorkflow: newerWorkflow };
  const output = verify(reviewed);
  assert.equal(output.packageWorkflowCommit, workflow);
  assert.equal(output.launcherWorkflowCommit, newerWorkflow);
  assert.equal(output.workflowCommit, undefined);

  for (const [path, otherCommit] of [
    ["actions/runs/100/attempts/2", newerWorkflow],
    ["actions/runs/200/attempts/1", workflow],
  ]) {
    const run = responses.get(path);
    const exactCommit = run.head_sha;
    run.head_sha = otherCommit;
    assert.throws(() => verify(reviewed), /protected signing attempt/);
    run.head_sha = exactCommit;
  }
  responses.get("commits/" + newerWorkflow).commit.verification.verified = false;
  assert.throws(() => verify(reviewed), /did not verify/);
});

test("refuses partial, ambiguous or independently unapproved workflow commits", () => {
  const { verify, receipt } = fixture({ launcherWorkflow: newerWorkflow });
  const reviewed = { expectedLauncherWorkflow: newerWorkflow };
  assert.throws(() => verify(), /launcher signing workflow differs/);
  assert.throws(() => verify({ ...reviewed, expectedWorkflow: newerWorkflow }), /package signing workflow differs/);
  receipt.workflowCommit = workflow;
  assert.throws(() => verify(reviewed), /either a shared workflow commit or separate/);
  delete receipt.workflowCommit;
  delete receipt.launcherWorkflowCommit;
  assert.throws(() => verify(reviewed), /launcher signing workflow differs/);
});
