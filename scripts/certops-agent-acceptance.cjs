"use strict";
// A reviewed acceptance decision binds immutable evidence to the shipped bytes.
// This validator never creates a decision or upgrades a scoped provider verdict.
const assert = require("node:assert/strict"), fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const { CAPABILITIES, TOOLCHAIN } = require("./certops-azure-keyvault-package.cjs");
const REPOSITORY = "tokentimerch/tokentimer-core";
const RECEIPT = ".github/releases/0.20.0-agent-acceptance.json";
// The advertised Azure auth modes remain required until explicitly rescoped.
const REQUIRED = Object.freeze(["azure-provider-and-cleanup", "azure-operator-http-real-ca", "openbao-operator-http-real-ca",
  "azure-imds-managed-identity", "azure-natural-access-token-expiration"]);
function keys(value, expected) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}
function verify(receipt, expectedSha256) {
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  keys(receipt, ["schemaVersion", "status", "packageVersion", "packageSha256", "packageSourceSha", "capabilities",
    "toolchain", "packageArtifact", "review", "nativeAgentEvidence", "evidence"]);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.status, "accepted");
  assert.equal(receipt.packageVersion, "0.20.0");
  assert.equal(receipt.packageSha256, expectedSha256);
  assert.match(receipt.packageSourceSha, /^[a-f0-9]{40}$/);
  assert.deepEqual(receipt.capabilities, CAPABILITIES);
  assert.deepEqual(receipt.toolchain, TOOLCHAIN);
  keys(receipt.review, ["pullRequest", "reviewer"]);
  assert.ok(Number.isSafeInteger(receipt.review.pullRequest) && receipt.review.pullRequest > 0);
  assert.match(receipt.review.reviewer, /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/);
  assert.ok(["azure-operator-http-real-ca", "openbao-operator-http-real-ca"].includes(receipt.nativeAgentEvidence));
  keys(receipt.evidence, REQUIRED);
  for (const proof of [receipt.packageArtifact, ...Object.values(receipt.evidence)]) {
    keys(proof, ["runId", "artifactId", "artifactSha256", "sourceSha"]);
    for (const key of ["runId", "artifactId"]) assert.match(proof[key], /^[1-9][0-9]{0,15}$/);
    assert.match(proof.artifactSha256, /^[a-f0-9]{64}$/);
    assert.match(proof.sourceSha, /^[a-f0-9]{40}$/);
  }
  assert.equal(receipt.packageArtifact.sourceSha, receipt.packageSourceSha);
  return receipt;
}
async function verifyGithub(receipt, { read, isAncestor }) {
  const prefix = `repos/${REPOSITORY}`;
  const pr = await read(`${prefix}/pulls/${receipt.review.pullRequest}`);
  assert.equal(pr.merged, true);
  assert.equal(pr.base.ref, "main");
  assert.equal(pr.head.repo.full_name, REPOSITORY);
  assert.notEqual(pr.user.login.toLowerCase(), receipt.review.reviewer.toLowerCase());
  assert.match(pr.merge_commit_sha, /^[a-f0-9]{40}$/);
  assert.ok(isAncestor(pr.merge_commit_sha) && isAncestor(receipt.packageSourceSha));
  const reviews = await read(`${prefix}/pulls/${receipt.review.pullRequest}/reviews?per_page=100`);
  assert.ok(Array.isArray(reviews) && reviews.length < 100);
  const lastReview = reviews.filter(row => row.user.login.toLowerCase() === receipt.review.reviewer.toLowerCase())
    .filter(row => ["APPROVED", "CHANGES_REQUESTED", "DISMISSED"].includes(row.state)).at(-1);
  assert.equal(lastReview?.state, "APPROVED");
  assert.equal(lastReview.commit_id, pr.head.sha);
  const decision = await read(`${prefix}/commits/${pr.merge_commit_sha}`);
  assert.equal(decision.commit.verification.verified, true);
  const file = await read(`${prefix}/contents/${RECEIPT}?ref=${pr.merge_commit_sha}`);
  assert.equal(file.encoding, "base64");
  assert.deepEqual(JSON.parse(Buffer.from(file.content, "base64").toString("utf8")), receipt);
  await Promise.all([receipt.packageArtifact, ...Object.values(receipt.evidence)].map(async proof => {
    assert.ok(isAncestor(proof.sourceSha));
    const [run, artifact] = await Promise.all([
      read(`${prefix}/actions/runs/${proof.runId}`), read(`${prefix}/actions/artifacts/${proof.artifactId}`),
    ]);
    assert.equal(String(run.id), proof.runId);
    assert.equal(run.status, "completed");
    assert.equal(run.conclusion, "success");
    assert.equal(run.event, "workflow_dispatch");
    assert.equal(run.head_branch, "main");
    assert.equal(run.run_attempt, 1);
    assert.equal(run.head_sha, proof.sourceSha);
    assert.match(run.path, /^\.github\/workflows\/certops-[a-z0-9-]+\.yml$/);
    assert.equal(String(artifact.id), proof.artifactId);
    assert.equal(String(artifact.workflow_run.id), proof.runId);
    assert.equal(artifact.workflow_run.head_sha, proof.sourceSha);
    assert.equal(artifact.expired, false);
    assert.equal(artifact.digest, `sha256:${proof.artifactSha256}`);
  }));
}
async function main(file, expectedSha256, env = process.env) {
  assert.equal(file, RECEIPT);
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(env.GITHUB_EVENT_NAME, "push");
  assert.match(env.GITHUB_REF || "", /^refs\/tags\/v0\.20\.0(?:-[0-9A-Za-z.-]+)?$/);
  assert.match(env.GITHUB_SHA || "", /^[a-f0-9]{40}$/);
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.size < 16384);
  const receipt = verify(JSON.parse(fs.readFileSync(file, "utf8")), expectedSha256);
  assert.ok(env.GH_TOKEN);
  const read = async endpoint => {
    const response = await fetch(`https://api.github.com/${endpoint}`, {
      headers: { Authorization: `Bearer ${env.GH_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
      redirect: "error", signal: AbortSignal.timeout(15000),
    });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(body.length < 2 * 1024 * 1024);
    return JSON.parse(body);
  };
  const isAncestor = sha => {
    execFileSync("git", ["merge-base", "--is-ancestor", sha, "HEAD"], { stdio: "ignore", timeout: 15000 });
    return true;
  };
  assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", timeout: 15000 }).trim(), env.GITHUB_SHA);
  await verifyGithub(receipt, { read, isAncestor });
}
module.exports = { REQUIRED, RECEIPT, verify, verifyGithub, main };
if (require.main === module) main(...process.argv.slice(2)).catch(() => {
  console.error("CERTOPS_AGENT_ACCEPTANCE_REJECTED"); process.exitCode = 1;
});
