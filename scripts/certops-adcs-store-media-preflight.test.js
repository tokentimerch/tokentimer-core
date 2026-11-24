"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { verifyMediaPreflight, verifyStagedMedia } = require("./certops-adcs-store-media-preflight");

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
  assert.throws(() => verify(reviewed), /launcher signing workflow must be an exact commit/);
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function stagedFixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "store-staging-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const { receipt } = fixture({ launcherWorkflow: newerWorkflow });
  const packageStage = path.join(dir, "package");
  const launcherStage = path.join(dir, "launcher");
  fs.mkdirSync(packageStage);
  fs.mkdirSync(launcherStage);
  const packageReceiptPath = path.join(packageStage, "receipt.json");
  const launcherReceiptPath = path.join(launcherStage, "receipt.json");
  const stem = "tokentimer-agent-0.20.0-windows-amd64";
  const archive = stem + ".tgz";
  const launcher = "tokentimer-agent-launcher.exe";
  const launcherPath = path.join(launcherStage, launcher);
  const cms = path.join(packageStage, stem + ".inventory.json.p7");
  const sbom = path.join(packageStage, stem + ".cdx.json");
  const policyPath = path.join(packageStage, "launcher-policy.json");
  const create = (file, contents) => {
    fs.writeFileSync(file, contents);
    return sha256(contents);
  };
  receipt.packageSha256 = create(path.join(packageStage, archive), "fixture archive");
  receipt.launcherSha256 = create(launcherPath, "fixture launcher");
  receipt.policySha256 = create(policyPath, "fixture policy");
  const pkg = {
    sourceCommit: candidate, workflowCommit: workflow, runId: receipt.packageRun, runAttempt: receipt.packageAttempt,
    architecture: "amd64", disposition: "lab-only", launcherRequiredBeforeInstallation: true, archive,
    archiveSha256: receipt.packageSha256, launcherPolicySha256: receipt.policySha256,
    cmsSha256: create(cms, "fixture cms"), sbomSha256: create(sbom, "fixture sbom"), encryptedHandoffSha256: "4".repeat(64),
  };
  const signedLauncher = {
    sourceCommit: candidate, workflowCommit: newerWorkflow, runId: receipt.launcherRun, runAttempt: receipt.launcherAttempt,
    architecture: "amd64", disposition: "lab-only", launcher, signedLauncherSha256: receipt.launcherSha256,
    packageWorkflowCommit: workflow, packageRunId: receipt.packageRun, packageRunAttempt: receipt.packageAttempt,
    packageArtifactId: receipt.packageArtifactId, launcherPolicySha256: receipt.policySha256, encryptedHandoffSha256: "5".repeat(64),
  };
  const custody = path.join(dir, "approved.json");
  const pins = { packageReceiptPath, launcherReceiptPath, packageStage, launcherPath };
  function pinReceipts() {
    receipt.packageReceiptSha256 = create(packageReceiptPath, JSON.stringify(pkg));
    receipt.launcherReceiptSha256 = create(launcherReceiptPath, JSON.stringify(signedLauncher));
    const bytes = Buffer.from(JSON.stringify(receipt));
    fs.writeFileSync(custody, bytes);
    return bytes;
  }
  const verify = (bytes = fs.readFileSync(custody), options) => verifyStagedMedia(bytes, { receiptSha256: sha256(bytes), ...pins, now, ...options });
  pinReceipts();
  return { custody, pins, receipt, pkg, signedLauncher, pinReceipts, verify, cms, sbom, policyPath };
}

test("staged mode locally checks exact signed producer receipts and launcher input hashes", (t) => {
  const { custody, pins, receipt, verify } = stagedFixture(t);
  const output = verify();
  assert.equal(output.scope, "adcs-named-store-staged-bytes");
  assert.equal(output.packageSha256, receipt.packageSha256);
  assert.equal(output.launcherSha256, receipt.launcherSha256);
  assert.equal(output.qualified, undefined);
  const cli = spawnSync(process.execPath, [
    path.resolve(__dirname, "certops-adcs-store-media-preflight.js"), "--staged", custody, output.custodyReceiptSha256,
    pins.packageReceiptPath, pins.launcherReceiptPath, pins.packageStage, pins.launcherPath,
  ], { env: { PATH: "" }, encoding: "utf8", timeout: 10000, windowsHide: true });
  assert.equal(cli.status, 0, cli.stderr);
  assert.deepEqual(JSON.parse(cli.stdout), output);
});

test("staged mode refuses another package and unapproved official receipt bytes", (t) => {
  const f = stagedFixture(t);
  const approved = fs.readFileSync(f.custody);
  assert.throws(() => f.verify(approved, { receiptSha256: "0".repeat(64) }), /Custody receipt digest mismatch/);
  f.signedLauncher.packageArtifactId = "301";
  assert.throws(() => f.verify(f.pinReceipts()), /does not bind the approved exact package/);
  assert.throws(() => f.verify(approved), /Launcher receipt digest mismatch/);
  f.signedLauncher.packageArtifactId = f.receipt.packageArtifactId;
  f.pkg.archive = "other.tgz";
  assert.throws(() => f.verify(f.pinReceipts()), /differs from the approved signed package/);
});

test("staged mode refuses changed launcher inputs, package policy and an unbounded receipt", (t) => {
  const f = stagedFixture(t);
  for (const file of [f.cms, f.sbom, f.policyPath, f.pins.launcherPath]) {
    const original = fs.readFileSync(file);
    fs.writeFileSync(file, "changed");
    assert.throws(() => f.verify(), /Staged digest mismatch/);
    fs.writeFileSync(file, original);
  }
  fs.writeFileSync(f.pins.packageReceiptPath, Buffer.alloc(16385));
  assert.throws(() => f.verify(), /bounded regular staged file/);
});
