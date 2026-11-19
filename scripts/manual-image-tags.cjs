"use strict";

const { createHash } = require("node:crypto");
const { appendFileSync } = require("node:fs");
const { execFileSync } = require("node:child_process");

const workflowRef = "refs/heads/main";
const sourceRefPattern = /^refs\/(?:heads|tags)\/(.+)$/;

function readSourceCommit(repo, ref) {
  try {
    execFileSync("git", ["check-ref-format", ref], { stdio: "ignore", timeout: 5_000 });
  } catch {
    throw new Error("Choose a valid refs/heads/... or refs/tags/... for source_ref.");
  }
  try {
    return execFileSync("gh", ["api", `repos/${repo}/commits/${encodeURIComponent(ref)}`, "--jq", ".sha"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    }).trim();
  } catch {
    throw new Error("Unable to resolve source_ref to a commit in this repository.");
  }
}

function manualSource(env, resolveCommit = readSourceCommit) {
  if (env.GITHUB_EVENT_NAME !== "workflow_dispatch" || env.GITHUB_REF !== workflowRef) {
    throw new Error("Dispatch Publish Images from main and use source_ref for other development sources.");
  }
  const ref = env.SOURCE_REF || workflowRef;
  if (ref === workflowRef) return { ref, sha: env.GITHUB_SHA };
  if (!sourceRefPattern.test(ref) || !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(env.GITHUB_REPOSITORY)) {
    throw new Error("Choose a branch or tag from this repository as a fully qualified source_ref.");
  }
  return { ref, sha: resolveCommit(env.GITHUB_REPOSITORY, ref) };
}

function manualImageTags({ ref, sha, extra = "", pushLatest = false }) {
  if (pushLatest) {
    throw new Error("Manual publication cannot push latest. Omit push_latest and use the release workflow for versioned images.");
  }
  if (extra && (extra.length > 128 || !/^(?:staging|debug)-[a-z0-9][a-z0-9_.-]*$/i.test(extra) || /^debug-ref-/i.test(extra))) {
    throw new Error("Use a staging-* or debug-* image tag, excluding the generated debug-ref-* namespace.");
  }
  const refName = sourceRefPattern.exec(ref)?.[1];
  if (!refName || !/^[a-f0-9]{40}$/.test(sha)) {
    throw new Error("Manual publication requires a selected branch or tag and its exact commit SHA.");
  }
  const slug = refName.replace(/[^a-z0-9_.-]+/gi, "-").toLowerCase().slice(0, 100);
  const refHash = createHash("sha256").update(ref).digest("hex").slice(0, 16);
  return { sha, refTag: `debug-ref-${slug}-${refHash}`, extraTag: extra };
}

if (require.main === module) {
  try {
    const { sha, refTag, extraTag } = manualImageTags({
      ...manualSource(process.env),
      extra: process.env.TAG_SUFFIX,
      pushLatest: process.env.PUSH_LATEST === "true",
    });
    appendFileSync(process.env.GITHUB_OUTPUT, `sha=${sha}\nref_tag=${refTag}\nextra_tag=${extraTag}\n`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { manualImageTags, manualSource };
