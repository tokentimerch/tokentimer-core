"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const lab = require("../infra/certops-azure-keyvault/lab");
const policy = require("../infra/certops-azure-keyvault/policy");
const zip = require("./certops-artifact-zip.cjs");
const pkg = require("./certops-azure-keyvault-package.cjs");

const ID = /^[1-9][0-9]{0,15}$/;
const SHA = /^[a-f0-9]{40}$/;
const API = `/repos/${policy.REPOSITORY}/actions`;
const ARCHIVE = "tokentimer-agent-0.20.0.tgz";
const FILES = ["artifact.json", ARCHIVE, ARCHIVE + ".sha256"];

function verifyRun(run, id, repoId) {
  assert.equal(String(run.id), id);
  assert.equal(run.path, policy.WORKFLOW);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.equal(run.run_attempt, 1);
  assert.equal(String(run.head_repository.id), repoId);
  assert.equal(String(run.repository.id), repoId);
  assert.match(run.head_sha, SHA);
}

function verifyJobs(page) {
  assert.ok(Array.isArray(page.jobs) && page.total_count === page.jobs.length && page.jobs.length < 100);
  return page.jobs;
}

function verifyProducer(run, jobs, artifact, { runId, artifactId, repoId }) {
  verifyRun(run, runId, repoId);
  assert.equal(run.status, "completed");
  assert.equal(run.conclusion, "success");
  const collectors = verifyJobs(jobs).filter(job => job.name === "collect-final-package");
  assert.equal(collectors.length, 1);
  const [collector] = collectors;
  assert.equal(String(collector.run_id), runId);
  assert.equal(collector.head_sha, run.head_sha);
  assert.equal(collector.status, "completed");
  assert.equal(collector.conclusion, "success");
  assert.equal(String(artifact.id), artifactId);
  assert.equal(artifact.name, "azure-release-candidate");
  assert.equal(artifact.expired, false);
  assert.equal(String(artifact.workflow_run.id), runId);
  assert.equal(String(artifact.workflow_run.repository_id), repoId);
  assert.equal(String(artifact.workflow_run.head_repository_id), repoId);
  assert.equal(artifact.workflow_run.head_branch, "main");
  assert.equal(artifact.workflow_run.head_sha, run.head_sha);
  assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= zip.LIMIT);
  return run.head_sha;
}

function stage(bytes, directory, { candidateSha, artifactId, runId, packageSha256 }) {
  const files = zip.read(bytes);
  assert.deepEqual([...files.keys()].sort(), FILES);
  zlib.gunzipSync(files.get(ARCHIVE), { maxOutputLength: 64 * 1024 * 1024 });
  fs.mkdirSync(directory, { mode: 0o700 });
  const created = [];
  try {
    for (const name of FILES) {
      const target = path.join(directory, name);
      const fd = fs.openSync(target, "wx", 0o600);
      created.push(target);
      try { fs.writeFileSync(fd, files.get(name)); } finally { fs.closeSync(fd); }
    }
    const { receipt } = pkg.inspect(directory, candidateSha, packageSha256);
    return pkg.verifyIdentity({ candidateSha, artifactId, runId, packageSha256,
      packageVersion: receipt.packageVersion, capabilities: receipt.capabilities });
  } catch (error) {
    for (const file of created) fs.unlinkSync(file);
    fs.rmdirSync(directory);
    throw error;
  }
}

async function main(runId, artifactId, packageSha256, directory, env = process.env) {
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REPOSITORY, policy.REPOSITORY);
  assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.match(runId, ID);
  assert.match(artifactId, ID);
  assert.match(env.GITHUB_REPOSITORY_ID, ID);
  assert.notEqual(runId, env.GITHUB_RUN_ID);
  assert.match(packageSha256, /^[a-f0-9]{64}$/);
  assert.ok(env.GH_TOKEN && path.isAbsolute(directory));
  assert.ok(!fs.existsSync(directory));
  const [run, jobs, artifact] = await Promise.all([
    lab.github(`${API}/runs/${runId}`, env),
    lab.github(`${API}/runs/${runId}/attempts/1/jobs?per_page=100`, env),
    lab.github(`${API}/artifacts/${artifactId}`, env),
  ]);
  const candidateSha = verifyProducer(run, jobs, artifact, { runId, artifactId, repoId: env.GITHUB_REPOSITORY_ID });
  const bytes = await zip.download(policy.REPOSITORY, artifactId, artifact, env.GH_TOKEN);
  return stage(bytes, directory, { candidateSha, artifactId, runId, packageSha256 });
}

module.exports = { main, verifyRun, verifyJobs, verifyProducer, stage };
if (require.main === module)
  main(...process.argv.slice(2)).then(identity => {
    console.log(JSON.stringify(identity));
  }).catch(() => {
    console.error("CERTOPS_FINAL_PACKAGE_SOURCE_REJECTED");
    process.exitCode = 1;
  });
