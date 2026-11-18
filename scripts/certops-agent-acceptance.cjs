"use strict";
// A reviewed acceptance decision binds immutable evidence to the shipped bytes.
// This validator never creates a decision or upgrades a scoped provider verdict.
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { CAPABILITIES, TOOLCHAIN } = require("./certops-azure-keyvault-package.cjs");
const zip = require("./certops-artifact-zip.cjs"), profiles = require("./certops-final-package-evidence.cjs");
const REPOSITORY = "tokentimerch/tokentimer-core";
const RECEIPT = ".github/releases/0.20.0-agent-acceptance.json";
const ARCHIVE = "tokentimer-agent-0.20.0.tgz";
const CAPABILITY_DIRECTORY = "packages/agent/src/capabilities";
const PROJECTED_SOURCE_FILES = new Set([
  `${CAPABILITY_DIRECTORY}/qualified-capabilities.json`,
  `${CAPABILITY_DIRECTORY}/qualified-capabilities.generated.js`,
  `${CAPABILITY_DIRECTORY}/capabilities.test.js`,
]);
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
  const approver = Object.hasOwn(receipt.review, "maintainer") ? "maintainer" : "reviewer";
  keys(receipt.review, ["pullRequest", approver]);
  assert.ok(Number.isSafeInteger(receipt.review.pullRequest) && receipt.review.pullRequest > 0);
  assert.match(receipt.review[approver], /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/);
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
async function verifyMetadata(receipt, { read, isAncestor }) {
  const prefix = `repos/${REPOSITORY}`;
  const pr = await read(`${prefix}/pulls/${receipt.review.pullRequest}`);
  assert.equal(pr.merged, true);
  assert.equal(pr.base.ref, "main");
  assert.equal(pr.head.repo.full_name, REPOSITORY);
  assert.match(pr.merge_commit_sha, /^[a-f0-9]{40}$/);
  assert.ok(isAncestor(pr.merge_commit_sha) && isAncestor(receipt.packageSourceSha));

  async function verifySignedReceipt(sha) {
    assert.match(sha, /^[a-f0-9]{40}$/);
    const decision = await read(`${prefix}/commits/${sha}`);
    assert.equal(decision.commit.verification.verified, true);
    const file = await read(`${prefix}/contents/${RECEIPT}?ref=${sha}`);
    assert.equal(file.encoding, "base64");
    assert.deepEqual(JSON.parse(Buffer.from(file.content, "base64").toString("utf8")), receipt);
    return decision;
  }

  if (Object.hasOwn(receipt.review, "maintainer")) {
    const maintainer = receipt.review.maintainer.toLowerCase();
    assert.equal(pr.user.login.toLowerCase(), maintainer);
    assert.equal(pr.merged_by?.login.toLowerCase(), maintainer);
    const decision = await verifySignedReceipt(pr.head.sha);
    assert.equal(decision.author?.login.toLowerCase(), maintainer);
  } else {
    const reviewer = receipt.review.reviewer.toLowerCase();
    assert.notEqual(pr.user.login.toLowerCase(), reviewer);
    const reviews = await read(`${prefix}/pulls/${receipt.review.pullRequest}/reviews?per_page=100`);
    assert.ok(Array.isArray(reviews) && reviews.length < 100);
    const lastReview = reviews.filter(row => row.user.login.toLowerCase() === reviewer)
      .filter(row => ["APPROVED", "CHANGES_REQUESTED", "DISMISSED"].includes(row.state)).at(-1);
    assert.equal(lastReview?.state, "APPROVED");
    assert.equal(lastReview.commit_id, pr.head.sha);
  }
  await verifySignedReceipt(pr.merge_commit_sha);
  return Promise.all([receipt.packageArtifact, ...Object.values(receipt.evidence)].map(async proof => {
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
    assert.ok(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= zip.LIMIT);
    return { proof, run, artifact };
  }));
}
function json(files, name) {
  const bytes = files.get(name); assert.ok(bytes && bytes.length < 131072);
  return JSON.parse(bytes.toString("utf8"));
}
function packageIdentity(receipt) {
  return { artifactId: receipt.packageArtifact.artifactId, runId: receipt.packageArtifact.runId,
    candidateSha: receipt.packageSourceSha, packageSha256: receipt.packageSha256, packageVersion: "0.20.0", capabilities: CAPABILITIES };
}
function verifyPackage(receipt, files) {
  assert.deepEqual([...files.keys()].sort(), ["artifact.json", ARCHIVE, ARCHIVE + ".sha256"].sort());
  const base = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(base, "tt-accepted-package-"));
  assert.equal(path.dirname(directory), base);
  try {
    for (const [name, bytes] of files) fs.writeFileSync(path.join(directory, name), bytes, { flag: "wx", mode: 0o600 });
    require("./certops-azure-keyvault-package.cjs").inspect(directory, receipt.packageSourceSha, receipt.packageSha256);
    // Bound tar expansion before the existing traversal/link-safe extractor.
    require("node:zlib").gunzipSync(files.get(ARCHIVE), { maxOutputLength: 64 * 1024 * 1024 });
    const { files: installed } = require("./certops-agent-package").extractVerified({ tarball: path.join(directory, ARCHIVE),
      expectedSha256: receipt.packageSha256, destination: path.join(directory, "extracted") });
    assert.ok(!Object.hasOwn(installed, "src/capabilities/capabilities.test.js"));
    return installed;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function verifyContent(receipt, scope, files, metadata, installedFiles) {
  const identity = packageIdentity(receipt), proof = receipt.evidence[scope];
  if (scope === "azure-provider-and-cleanup") {
    assert.equal(proof.runId, receipt.packageArtifact.runId);
    assert.deepEqual([...files.keys()].sort(), ["azure-keyvault-cleanup.json", "azure-keyvault-evidence.json"]);
    const reports = require("./certops-azure-keyvault-report");
    const report = json(files, "azure-keyvault-evidence.json"), cleanup = json(files, "azure-keyvault-cleanup.json");
    reports.verify(report, { sourceSha: proof.sourceSha }); reports.verifyCleanup(cleanup, proof.sourceSha);
    assert.equal(cleanup.cleanup, "completed"); assert.deepEqual(report.packageArtifact, identity);
  } else {
    const file = profiles.PROFILES[scope].file;
    assert.deepEqual([...files.keys()], [file]);
    profiles.verify(scope, json(files, file), { sourceSha: proof.sourceSha, runId: proof.runId, packageIdentity: identity,
      files: installedFiles, requireNative: receipt.nativeAgentEvidence === scope, run: metadata.run });
  }
}
async function verifyGithub(receipt, { read, isAncestor, download }) {
  const metadata = await verifyMetadata(receipt, { read, isAncestor }), contents = new Map();
  // Download one artifact at a time; retain only bounded decoded members.
  for (const item of metadata) {
    if (contents.has(item.proof.artifactId)) continue;
    const bytes = await download(item.proof.artifactId);
    assert.equal(bytes.length, item.artifact.size_in_bytes);
    assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), item.proof.artifactSha256);
    contents.set(item.proof.artifactId, zip.read(bytes));
  }
  const packageFiles = contents.get(receipt.packageArtifact.artifactId);
  const installedFiles = verifyPackage(receipt, packageFiles);
  for (const scope of REQUIRED) verifyContent(receipt, scope, contents.get(receipt.evidence[scope].artifactId),
    metadata.find(item => item.proof === receipt.evidence[scope]), installedFiles);
  return packageFiles;
}

function requireReleaseAgentSource(changedPaths, manifest, generated) {
  for (const changedPath of changedPaths) {
    assert.ok(PROJECTED_SOURCE_FILES.has(changedPath), "Agent sources changed since qualification");
  }
  assert.deepEqual(JSON.parse(manifest), { qualified: CAPABILITIES });
  assert.equal(generated, require("../packages/agent/scripts/build-qualified-capabilities").renderGeneratedModule(CAPABILITIES));
}

function stageReleaseArchive(directory, files) {
  fs.mkdirSync(directory);
  for (const name of [ARCHIVE, ARCHIVE + ".sha256"]) {
    fs.writeFileSync(path.join(directory, name), files.get(name), { flag: "wx" });
  }
}

async function main(file, expectedSha256, directory, env = process.env) {
  assert.equal(file, RECEIPT);
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(env.GITHUB_EVENT_NAME, "push");
  assert.equal(directory, "agent-dist");
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
  const download = async id => {
    const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/actions/artifacts/${id}/zip`, {
      headers: { Authorization: `Bearer ${env.GH_TOKEN}`, Accept: "application/vnd.github+json" },
      redirect: "manual", signal: AbortSignal.timeout(60000),
    });
    assert.equal(response.status, 302);
    const url = new URL(response.headers.get("location"));
    assert.equal(url.protocol, "https:");
    assert.ok(url.hostname.endsWith(".blob.core.windows.net") || url.hostname.endsWith(".actions.githubusercontent.com"));
    const archive = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(60000) });
    assert.equal(archive.status, 200);
    const chunks = []; let size = 0;
    for await (const chunk of archive.body) { size += chunk.length; assert.ok(size <= zip.LIMIT); chunks.push(chunk); }
    return Buffer.concat(chunks);
  };
  assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", timeout: 15000 }).trim(), env.GITHUB_SHA);
  const changedPaths = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z",
    receipt.packageSourceSha, env.GITHUB_SHA, "--", "packages/agent"], { encoding: "utf8", timeout: 15000 });
  const readCapability = name => {
    const file = `${CAPABILITY_DIRECTORY}/${name}`;
    const stat = fs.lstatSync(file);
    assert.ok(stat.isFile() && (stat.mode & 0o111) === 0);
    return fs.readFileSync(file, "utf8");
  };
  requireReleaseAgentSource(changedPaths.split("\0").filter(Boolean),
    readCapability("qualified-capabilities.json"), readCapability("qualified-capabilities.generated.js"));
  const files = await verifyGithub(receipt, { read, isAncestor, download });
  stageReleaseArchive(directory, files);
  assert.ok(env.GITHUB_OUTPUT);
  fs.appendFileSync(env.GITHUB_OUTPUT,
    `source_sha=${receipt.packageSourceSha}\nproducer_run_id=${receipt.packageArtifact.runId}\n`);
}
module.exports = { REQUIRED, RECEIPT, verify, verifyMetadata, verifyGithub, verifyPackage, verifyContent, packageIdentity,
  requireReleaseAgentSource, stageReleaseArchive, main };
if (require.main === module) main(...process.argv.slice(2)).catch(() => {
  console.error("CERTOPS_AGENT_ACCEPTANCE_REJECTED"); process.exitCode = 1;
});
