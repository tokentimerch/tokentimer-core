"use strict";

const { execFileSync } = require("node:child_process");
const { appendFileSync } = require("node:fs");

const releaseBranch = "main";
const ciWorkflow = ".github/workflows/ci.yml";
const commitPattern = /^[a-f0-9]{40}$/;
const versionRefPattern = /^refs\/tags\/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?<prerelease>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?$/;

function releaseVersion(ref) {
  // The images use the version without "v" as a registry tag (128 characters).
  if (typeof ref !== "string" || ref.length > "refs/tags/v".length + 128) return null;
  const version = versionRefPattern.exec(ref);
  if (!version || version.groups.prerelease?.split(".").some(part => /^0[0-9]+$/.test(part))) {
    return null;
  }
  return { prerelease: Boolean(version.groups.prerelease) };
}

function releaseRepository(repo) {
  if (!/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(repo)) {
    throw new Error("Unable to resolve the release repository.");
  }
  return repo;
}

function runCommand(command, args, errorMessage) {
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 60_000,
    }).trim();
  } catch {
    throw new Error(errorMessage);
  }
}

function releaseCommit({ GITHUB_EVENT_NAME: event, GITHUB_REF: ref, GITHUB_SHA: sha },
  git = (args, errorMessage) => runCommand("git", args, errorMessage)) {
  if (event !== "push" || !releaseVersion(ref) || !commitPattern.test(sha)) {
    throw new Error("Release provenance requires a version tag push and its original commit SHA.");
  }
  const originalCommit = git(["rev-parse", "--verify", `${sha}^{commit}`],
    "Unable to resolve the original release event to a commit.");
  const checkedOut = git(["rev-parse", "--verify", "HEAD^{commit}"],
    "Unable to resolve the checked-out release commit.");
  const tagCommit = git(["rev-parse", "--verify", `${ref}^{commit}`],
    "Unable to resolve the release tag to a commit. Confirm the original tag still exists.");
  if (!commitPattern.test(originalCommit) || checkedOut !== originalCommit || tagCommit !== originalCommit) {
    throw new Error("Release SHA mismatch: the checkout and current tag must match the original tag push.");
  }
  const branchCommit = git(["rev-parse", "--verify", `refs/remotes/origin/${releaseBranch}^{commit}`],
    `Unable to resolve origin/${releaseBranch}. Release provenance requires the release branch and full history.`);
  git(["merge-base", "--is-ancestor", originalCommit, branchCommit],
    `Release branch ancestry could not be established: ${originalCommit} must be contained in origin/${releaseBranch}.`);
  return originalCommit;
}

function successfulPushRun(response, repo, commit) {
  if (!Array.isArray(response?.workflow_runs)) {
    throw new Error("The authoritative CI workflow returned an invalid response.");
  }
  return response.workflow_runs.find(run =>
    run?.head_sha === commit &&
    run.head_branch === releaseBranch &&
    run.head_repository?.full_name?.toLowerCase() === repo.toLowerCase() &&
    run.path === ciWorkflow &&
    run.event === "push" &&
    run.status === "completed" &&
    run.conclusion === "success" &&
    Number.isSafeInteger(run.id) && run.id > 0
  );
}

function verifyCurrentTag(env, gh = (args, message) => runCommand("gh", args, message)) {
  const repo = releaseRepository(env.GITHUB_REPOSITORY);
  const ref = env.GITHUB_REF;
  const expected = env.EXPECTED_RELEASE_COMMIT;
  if (!releaseVersion(ref) || !commitPattern.test(expected)) {
    throw new Error("A verified release tag and commit are required before publication.");
  }
  // The fully qualified ref disambiguates same-named branches and the commits
  // endpoint resolves an annotated tag to its underlying commit.
  const current = gh(["api", `repos/${repo}/commits/${encodeURIComponent(ref)}`, "--jq", ".sha"],
    "Unable to resolve the current release tag. Confirm the tag still exists before retrying.");
  if (current !== expected) {
    throw new Error("The current release tag does not match the verified commit. Stop and recover the original release.");
  }
}

function verifyRelease(env) {
  const repo = releaseRepository(env.GITHUB_REPOSITORY);
  const commit = releaseCommit(env);
  const result = runCommand("gh", ["api", "--method", "GET",
    `repos/${repo}/actions/workflows/ci.yml/runs`,
    "--raw-field", `branch=${releaseBranch}`,
    "--raw-field", "event=push",
    "--raw-field", `head_sha=${commit}`,
    "--raw-field", "status=success",
    "--field", "per_page=100",
  ], "Unable to query the authoritative CI workflow. Check Actions read permissions and retry.");
  const run = successfulPushRun(JSON.parse(result), repo, commit);
  if (!run) {
    throw new Error(`No successful completed CI push run on ${releaseBranch} matches ${commit}. Wait for that exact run or rerun it before retrying release.`);
  }
  if (env.GITHUB_OUTPUT) {
    const { prerelease } = releaseVersion(env.GITHUB_REF);
    appendFileSync(env.GITHUB_OUTPUT, `commit=${commit}\nprerelease=${prerelease}\n`);
  }
  console.log(`Release commit ${commit} passed the provenance check via CI run ${run.id}.`);
}

if (require.main === module) {
  try {
    if (process.argv[2] === "--verify-tag") verifyCurrentTag(process.env);
    else verifyRelease(process.env);
  } catch (error) {
    console.error(error instanceof SyntaxError ? "The authoritative CI workflow returned invalid JSON." : error.message);
    process.exitCode = 1;
  }
}

module.exports = { releaseCommit, releaseVersion, successfulPushRun, verifyCurrentTag };
