"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const artifactZip = require("../../scripts/certops-artifact-zip.cjs");

const REPOSITORY = "tokentimerch/tokentimer-core";
const REF = "refs/heads/main";
const WORKFLOW = ".github/workflows/certops-adcs-store-qualification-preflight.yml";
const PREPARE = ".github/workflows/certops-adcs-store-noiis-prepare.yml";
const REQUIRED_JOBS = ["register", "verify", "prepare"];
const ID = /^[1-9][0-9]{0,15}$/;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const VM_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const REPORT_LIMIT = 64 * 1024;
const utf8 = new TextDecoder("utf-8", { fatal: true });

function readContext(env) {
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_REF, REF);
  assert.equal(env.GITHUB_WORKFLOW_REF, REPOSITORY + "/" + WORKFLOW + "@" + REF);
  assert.equal(env.GITHUB_SHA, env.STORE_REVIEWED_WORKFLOW_SHA);
  assert.equal(env.GITHUB_WORKFLOW_SHA, env.GITHUB_SHA);
  assert.ok(env.GH_TOKEN, "GitHub read token required");
  const context = {
    repoId: env.GITHUB_REPOSITORY_ID,
    workflowSha: env.GITHUB_SHA,
    prepareSha: env.STORE_PREPARE_WORKFLOW_SHA,
    runId: env.STORE_PREPARE_RUN_ID,
    attempt: env.STORE_PREPARE_ATTEMPT,
    registrationId: env.STORE_REGISTRATION_ARTIFACT_ID,
    preparationId: env.STORE_PREPARATION_ARTIFACT_ID,
    mediaSource: env.STORE_MEDIA_SOURCE,
    custodyDigest: env.STORE_MEDIA_RECEIPT_SHA,
  };
  for (const key of ["repoId", "runId", "attempt", "registrationId", "preparationId"])
    assert.match(context[key], ID);
  for (const key of ["workflowSha", "prepareSha", "mediaSource"])
    assert.match(context[key], SHA);
  assert.match(context.custodyDigest, DIGEST);
  assert.notEqual(context.runId, env.GITHUB_RUN_ID);
  assert.notEqual(context.registrationId, context.preparationId);
  return context;
}

function assertVerifiedCommit(commit, sha) {
  assert.equal(commit.sha, sha);
  assert.equal(commit.commit.verification.verified, true);
}

function verifyRun(run, jobs, context) {
  assert.equal(String(run.id), context.runId);
  assert.equal(run.path, PREPARE);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.equal(run.head_sha, context.prepareSha);
  assert.equal(String(run.run_attempt), context.attempt);
  assert.equal(String(run.head_repository.id), context.repoId);
  assert.equal(String(run.repository.id), context.repoId);
  assert.equal(run.status, "completed");
  assert.equal(run.conclusion, "success");
  assert.ok(Array.isArray(jobs.jobs) && jobs.total_count === jobs.jobs.length && jobs.jobs.length <= 4);
  for (const name of REQUIRED_JOBS) {
    const matches = jobs.jobs.filter(job => job.name === name);
    assert.equal(matches.length, 1);
    const [job] = matches;
    assert.equal(String(job.run_id), context.runId);
    assert.equal(String(job.run_attempt), context.attempt);
    assert.equal(job.head_sha, context.prepareSha);
    assert.equal(job.status, "completed");
    assert.equal(job.conclusion, "success");
  }
}

function utc(value) {
  assert.match(value, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|\+00:00)$/);
  const ms = Date.parse(value);
  assert.ok(Number.isFinite(ms));
  return ms;
}

function verifyArtifact(artifact, id, name, context, now) {
  assert.equal(String(artifact.id), id);
  assert.equal(artifact.name, name);
  assert.equal(artifact.expired, false);
  assert.ok(utc(artifact.expires_at) > now);
  assert.equal(String(artifact.workflow_run.id), context.runId);
  assert.equal(String(artifact.workflow_run.repository_id), context.repoId);
  assert.equal(String(artifact.workflow_run.head_repository_id), context.repoId);
  assert.equal(artifact.workflow_run.head_branch, "main");
  assert.equal(artifact.workflow_run.head_sha, context.prepareSha);
  assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 &&
    artifact.size_in_bytes <= REPORT_LIMIT);
}

const hash = value => createHash("sha256").update(value).digest("hex");
const parse = value => JSON.parse(utf8.decode(value));

function verifyReceipts(registration, readiness, context, now) {
  assert.deepEqual([...registration.keys()].sort(), ["store-noiis-registration.json", "store-noiis-registration.sha256"]);
  assert.deepEqual([...readiness.keys()].sort(), ["store-noiis-infrastructure.json", "store-noiis-member.json"]);
  const registrationBytes = registration.get("store-noiis-registration.json");
  const registrationDigest = hash(registrationBytes);
  const memberBytes = readiness.get("store-noiis-member.json");
  assert.equal(utf8.decode(registration.get("store-noiis-registration.sha256")).trimEnd(), registrationDigest);
  const registered = parse(registrationBytes);
  const resourceGroup = "tt-certops-" + context.runId + "-" + context.attempt;
  assert.equal(registered.schema, "certops-adcs-store-registration-v1");
  assert.equal(registered.resourceGroup, resourceGroup);
  assert.equal(registered.runId, context.runId);
  assert.equal(registered.runAttempt, context.attempt);
  assert.equal(registered.workflowCommit, context.prepareSha);
  assert.equal(registered.mediaSourceCommit, context.mediaSource);
  assert.equal(registered.mediaReceiptSha256, context.custodyDigest);
  assert.equal(registered.workflowOwnedGroupVerified, true);
  assert.equal(registered.independentExpiryVerified, true);
  for (const key of ["registrationNonce", "subscriptionSha256", "provisionClientSha256", "cleanupClientSha256"])
    assert.match(registered[key], DIGEST);
  assert.notEqual(registered.cleanupClientSha256, registered.provisionClientSha256);
  assert.match(registered.janitorRunId, ID);
  assert.match(registered.janitorCommit, SHA);
  const created = utc(registered.createdAt);
  const observed = utc(registered.observedAt);
  const expires = utc(registered.expiresAt);
  assert.equal(expires - created, 4 * 60 * 60 * 1000);
  assert.ok(created <= observed && observed <= now && now < expires, "Original lab lease is unavailable");
  const prepared = parse(readiness.get("store-noiis-infrastructure.json"));
  assert.equal(prepared.scope, "store-noiis-infrastructure-preparation");
  assert.equal(prepared.status, "store-noiis-infrastructure-prepared");
  assert.equal(prepared.resourceGroup, resourceGroup);
  assert.equal(prepared.registrationSha256, registrationDigest);
  assert.equal(prepared.memberReadinessSha256, hash(memberBytes));
  assert.equal(prepared.workflowCommit, context.prepareSha);
  assert.equal(prepared.sourceCommit, context.mediaSource);
  assert.equal(prepared.mediaReceiptSha256, context.custodyDigest);
  assert.equal(prepared.expiresAt, registered.expiresAt);
  assert.equal(prepared.memberName, "windows-agent");
  assert.match(prepared.memberVmId, VM_ID);
  assert.equal(prepared.qualificationPassed, false);
  assert.equal(prepared.agentInstalledByPreparation, false);
  assert.deepEqual(parse(memberBytes), {
    scope: "store-noiis-clean-member-readiness",
    windowsBuild: "20348",
    architecture: "x64",
    localSystem: true,
    ownedDomain: true,
    iisAbsent: true,
    agentServiceAbsent: true,
    caRpcPing: true,
  });
  return {
    scope: "store-preparation-inputs-only",
    resourceGroup,
    memberVmId: prepared.memberVmId,
    registrationDigest,
    preparationDigest: hash(readiness.get("store-noiis-infrastructure.json")),
    expiresAt: registered.expiresAt,
    prepareRunId: context.runId,
    prepareAttempt: context.attempt,
    prepareWorkflowSha: context.prepareSha,
    mediaSource: context.mediaSource,
    custodyDigest: context.custodyDigest,
  };
}

async function verifyInputs(env = process.env) {
  const context = readContext(env);
  const read = async route => {
    const response = await fetch("https://api.github.com/repos/" + REPOSITORY + route, {
      redirect: "error", signal: AbortSignal.timeout(30000),
      headers: {
        Authorization: "Bearer " + env.GH_TOKEN,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    assert.ok(response.ok);
    return response.json();
  };
  const runRoute = "/actions/runs/" + context.runId;
  const signedCommits = new Set([context.workflowSha, context.prepareSha, context.mediaSource]);
  const readCommit = async sha => assertVerifiedCommit(await read("/commits/" + sha), sha);
  const [run, jobs, registration, readiness] = await Promise.all([
    read(runRoute),
    read(runRoute + "/attempts/" + context.attempt + "/jobs?per_page=100"),
    read("/actions/artifacts/" + context.registrationId),
    read("/actions/artifacts/" + context.preparationId),
    ...Array.from(signedCommits, readCommit),
  ]);
  verifyRun(run, jobs, context);
  const now = Date.now();
  verifyArtifact(registration, context.registrationId,
    "disposable-store-registration-" + context.runId + "-" + context.attempt, context, now);
  verifyArtifact(readiness, context.preparationId,
    "disposable-store-noiis-preparation-" + context.attempt, context, now);
  const [registrationZip, readinessZip] = await Promise.all([
    artifactZip.download(REPOSITORY, context.registrationId, registration, env.GH_TOKEN, REPORT_LIMIT),
    artifactZip.download(REPOSITORY, context.preparationId, readiness, env.GH_TOKEN, REPORT_LIMIT),
  ]);
  return verifyReceipts(artifactZip.read(registrationZip), artifactZip.read(readinessZip), context, Date.now());
}

module.exports = { readContext, assertVerifiedCommit, verifyRun, verifyArtifact, verifyReceipts, verifyInputs };
if (require.main === module) {
  verifyInputs().then(() => {
    console.log("Verified the signed workflow inputs and exact protected no-IIS preparation artifacts.");
  }).catch(() => {
    console.error("CERTOPS_STORE_PREPARATION_INPUTS_REJECTED");
    process.exitCode = 1;
  });
}
