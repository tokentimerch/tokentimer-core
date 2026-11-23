"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");
const { releaseCommit, releaseVersion, successfulPushRun, verifyCurrentTag } = require("../../scripts/check-release-provenance.cjs");
const { manualImageTags, manualSource } = require("../../scripts/manual-image-tags.cjs");
const { planPublication } = require("../../scripts/check-release-registry-version.cjs");

const sha = "a".repeat(40);
const otherCommit = "b".repeat(40);
const annotatedTag = "c".repeat(40);
const ref = "refs/tags/v1.2.3-beta.1";
const repo = "tokentimerch/tokentimer-core";
const event = { GITHUB_EVENT_NAME: "push", GITHUB_REF: ref, GITHUB_SHA: sha };

test("release gate peels the tag and checks the exact commit on the release branch", () => {
  const calls = [];
  const replies = [sha, sha, sha, otherCommit, ""];
  const git = args => { calls.push(args); return replies.shift(); };

  assert.equal(releaseCommit({ ...event, GITHUB_SHA: annotatedTag }, git), sha);
  assert.deepEqual(calls, [
    ["rev-parse", "--verify", `${annotatedTag}^{commit}`],
    ["rev-parse", "--verify", "HEAD^{commit}"],
    ["rev-parse", "--verify", `${ref}^{commit}`],
    ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    ["merge-base", "--is-ancestor", sha, otherCommit],
  ]);
});

test("release gate rejects manual dispatch, non-version refs, and a moved tag", () => {
  const unexpected = () => assert.fail("Git should not run for an unsupported event or ref");
  for (const changes of [
    { GITHUB_EVENT_NAME: "workflow_dispatch" },
    { GITHUB_REF: "refs/heads/main" },
    { GITHUB_REF: "refs/tags/vnext" },
  ]) {
    assert.throws(() => releaseCommit({ ...event, ...changes }, unexpected), /version tag push/);
  }
  const replies = [sha, sha, otherCommit];
  assert.throws(() => releaseCommit(event, () => replies.shift()), /SHA mismatch/);
});

test("release gate fails when ancestry cannot be proved", () => {
  assert.throws(() => releaseCommit(event, (args, message) => {
    if (args[0] === "merge-base") throw new Error(message);
    return sha;
  }), /branch ancestry.*origin\/main/);
});

test("only a successful completed push run of the repository's exact CI qualifies", () => {
  const run = {
    id: 42,
    head_sha: sha,
    head_branch: "main",
    head_repository: { full_name: repo },
    path: ".github/workflows/ci.yml",
    event: "push",
    status: "completed",
    conclusion: "success",
  };
  const unrelated = [
    { ...run, head_sha: otherCommit },
    { ...run, head_branch: "master" },
    { ...run, head_repository: { full_name: "fork/tokentimer-core" } },
    { ...run, path: ".github/workflows/other.yml" },
    { ...run, event: "workflow_dispatch" },
    { ...run, status: "in_progress" },
    { ...run, conclusion: "failure" },
  ];
  assert.equal(successfulPushRun({ workflow_runs: unrelated }, repo, sha), undefined);
  assert.equal(successfulPushRun({ workflow_runs: [...unrelated, run] }, repo, sha), run);
  assert.throws(() => successfulPushRun({}, repo, sha), /invalid response/);
});

test("release classification skips GitHub publication for every accepted prerelease suffix", () => {
  assert.deepEqual(releaseVersion("refs/tags/v1.2.3"), { prerelease: false });
  for (const suffix of ["alpha", "beta.1", "rc.2", "preview.3", "custom-rc.0"]) {
    assert.deepEqual(releaseVersion(`refs/tags/v1.2.3-${suffix}`), { prerelease: true });
  }
  assert.equal(releaseVersion("refs/tags/v1.2.3-01"), null);
  assert.equal(releaseVersion("refs/tags/v1.2.3-beta.01"), null);
  assert.deepEqual(releaseVersion(`refs/tags/v1.2.3-${"a".repeat(122)}`), { prerelease: true });
  assert.equal(releaseVersion(`refs/tags/v1.2.3-${"a".repeat(123)}`), null);
});

test("release publication rechecks the current fully qualified tag against the verified commit", () => {
  const publication = { GITHUB_REF: ref, GITHUB_REPOSITORY: repo, EXPECTED_RELEASE_COMMIT: sha };
  verifyCurrentTag(publication, args => {
    assert.deepEqual(args, ["api", `repos/${repo}/commits/refs%2Ftags%2Fv1.2.3-beta.1`, "--jq", ".sha"]);
    return sha;
  });
  assert.throws(() => verifyCurrentTag(publication, () => otherCommit), /does not match the verified commit/);
  assert.throws(() => verifyCurrentTag(publication, (_args, message) => {
    throw new Error(message);
  }), /Unable to resolve the current release tag/);
  assert.throws(() => verifyCurrentTag({ ...publication, EXPECTED_RELEASE_COMMIT: "" }), /verified release tag and commit/);
});

test("manual images preserve the exact SHA and safely namespace branch, tag and staging aliases", () => {
  const publish = manualImageTags({ ref: "refs/heads/feature/test", sha, extra: "staging-latest" });
  assert.equal(publish.sha, sha);
  assert.equal(publish.extraTag, "staging-latest");
  assert.match(publish.refTag, /^debug-ref-feature-test-[a-f0-9]{16}$/);
  const normalizedCollision = manualImageTags({ ref: "refs/heads/feature-test", sha });
  assert.notEqual(publish.refTag, normalizedCollision.refTag);
  assert.match(manualImageTags({ ref: "refs/heads/latest", sha }).refTag, /^debug-ref-latest-/);
  assert.match(manualImageTags({ ref, sha }).refTag, /^debug-ref-v1\.2\.3-beta\.1-/);
  assert.ok(manualImageTags({ ref: `refs/heads/${"a".repeat(300)}`, sha }).refTag.length <= 128);
});

test("manual images reject release tags, malformed aliases, and explicit latest requests", () => {
  for (const extra of ["latest", "Latest", "v1.2.3", "1.2.3-rc.2", "production", "debug-ref-owned",
    "staging-one staging-two", "staging-good\nother=latest", "debug-slash/tag", `debug-${"a".repeat(123)}`]) {
    assert.throws(() => manualImageTags({ ref, sha, extra }), /staging-\* or debug-\*/);
  }
  assert.throws(() => manualImageTags({ ref, sha, pushLatest: true }), /cannot push latest/);
  assert.throws(() => manualImageTags({ ref, sha: "main" }), /exact commit SHA/);
});

test("manual dispatch validates on main and separately pins a requested development source", () => {
  const dispatch = {
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: repo,
    GITHUB_REF: "refs/heads/main",
    GITHUB_SHA: sha,
  };
  const unexpected = () => assert.fail("Source resolution should not run");
  assert.deepEqual(manualSource(dispatch, unexpected), { ref: "refs/heads/main", sha });
  assert.deepEqual(manualSource({ ...dispatch, SOURCE_REF: ref }, (actualRepo, actualRef) => {
    assert.equal(actualRepo, repo);
    assert.equal(actualRef, ref);
    return otherCommit;
  }), { ref, sha: otherCommit });
  assert.throws(() => manualSource({ ...dispatch, GITHUB_REF: "refs/heads/debug" }, unexpected), /Dispatch Publish Images from main/);
  assert.throws(() => manualSource({ ...dispatch, SOURCE_REF: "v1.2.3" }, unexpected), /fully qualified source_ref/);
});

test("privileged workflow jobs use the verified source and keep the release preflight in their dependency chain", () => {
  const yaml = require("node:module").createRequire(require.resolve("mocha/package.json"))("js-yaml");
  const workflow = name => yaml.load(readFileSync(
    join(__dirname, "../../.github/workflows", name + ".yml"), "utf8",
  )).jobs;
  const release = workflow("release");
  const verifiedCommit = "${{ needs.verify-provenance.outputs.commit }}";
  for (const name of ["build-and-push-docker", "build-helm-chart", "pack-agent", "sign-images", "publish-helm-chart", "create-release"]) {
    const job = release[name];
    assert.ok([job.needs].flat().includes("verify-provenance"), name);
    assert.equal(job.steps.find(step => step.uses?.startsWith("actions/checkout@")).with.ref, verifiedCommit, name);
  }
  for (const name of ["build-and-push-docker", "sign-images", "publish-helm-chart", "create-release"]) {
    const step = release[name].steps.find(step => step.run?.includes("check-release-provenance.cjs --verify-tag"));
    assert.equal(step.env.EXPECTED_RELEASE_COMMIT, verifiedCommit, name);
  }
  assert.equal(release["create-release"].if, "needs.verify-provenance.outputs.prerelease == 'false'");
  const createRelease = release["create-release"].steps.find(step => step.run?.includes("gh release create"));
  const upload = createRelease.run.slice(createRelease.run.indexOf("gh release create"));
  assert.match(upload, /--verify-tag/);
  assert.equal(upload.trim().split("\n").at(-1).trim(), '"$LINUX_ARCHIVE" "${LINUX_ARCHIVE}.sha256"');
  assert.doesNotMatch(upload, /agent-dist\/\*.(?:tgz|sha256)/);
  const manual = workflow("publish");
  assert.equal(manual["validate-tags"].permissions.contents, "read");
  assert.equal(manual["validate-tags"].permissions.packages, undefined);
  assert.equal(manual.publish.needs, "validate-tags");
  assert.equal(manual.publish.steps[0].with.ref, "${{ needs.validate-tags.outputs.sha }}");
  for (const [job, label] of [
    ["build-and-push-docker", "Publish the scanned OCI archive"],
    ["publish-helm-chart", "Push chart to OCI registry"],
  ]) {
    const publish = release[job].steps.find(step => step.name === label);
    assert.match(publish.run, /check-release-registry-version\.cjs[\s\S]+if \[ "\$DECISION" = "publish" \]/);
  }
  const chart = release["build-helm-chart"];
  const agent = release["pack-agent"];
  const packStep = agent.steps.find(step => step.name === "Pack agent release tarball");
  assert.equal(packStep.if, "steps.accepted-agent.outcome == 'skipped'");
  assert.equal(packStep.env?.EXPECTED_RELEASE_COMMIT, verifiedCommit);
  const commands = packStep.run.replace(/\\\n[ \t]*/g, "").split("\n");
  const sourceCheck = commands.indexOf('test "$(git rev-parse HEAD)" = "$EXPECTED_RELEASE_COMMIT"');
  const cleanCheck = commands.indexOf("git diff --quiet HEAD -- packages/agent");
  const packCommand = commands.indexOf("node packages/agent/scripts/pack-release.js --out-dir agent-dist");
  const restore = commands.findIndex(command => command.startsWith("git restore "));
  assert.equal(commands.filter(command => command.startsWith("git restore ")).length, 1);
  assert.ok(sourceCheck >= 0 && sourceCheck < cleanCheck && cleanCheck < packCommand && packCommand < restore,
    "The exact clean source must be checked before packaging and generated outputs restored afterward");
  assert.deepEqual(commands[restore].split(/\s+/), [
    "git", "restore", '--source="$EXPECTED_RELEASE_COMMIT"', "--worktree", "--",
    "packages/agent/bin/tokentimer-observed-revocation-linux-amd64",
    "packages/agent/bin/tokentimer-observed-revocation-linux-arm64",
  ]);
  assert.ok(agent.steps.indexOf(packStep) < agent.steps.findIndex(
    step => step.name === "Verify shipped native toolchain and provenance"));
  const expression = value => "${{ " + value + " }}";
  for (const [job, uploader, name] of [
    [chart, "upload-chart", "helm-chart"],
    [agent, "upload-agent", "agent-release"],
  ]) {
    assert.equal(job.outputs["artifact-id"], expression(`steps.${uploader}.outputs.artifact-id`));
    assert.equal(job.steps.find(step => step.id === uploader).with.name, `${name}-attempt-` + expression("github.run_attempt"));
  }
  for (const [job, label, expected] of [
    ["verify-release", "Download Helm package artifact", "needs.build-helm-chart.outputs.artifact-id"],
    ["verify-release", "Download agent release artifacts", "needs.pack-agent.outputs.artifact-id"],
    ["publish-helm-chart", "Download Helm package artifact", "needs.verify-release.outputs.chart-artifact-id"],
    ["create-release", "Download agent release artifacts", "needs.verify-release.outputs.agent-artifact-id"],
  ]) {
    const download = release[job].steps.find(step => step.name === label);
    assert.equal(download.with["artifact-ids"], expression(expected));
    assert.equal(download.with.name, undefined);
  }
});

const version = "1.2.3";
const repository = "tokentimerch/charts/tokentimer";
const digest = content => "sha256:" + createHash("sha256").update(content).digest("hex");

function registryResponse(status, content) {
  return async (url, options) => {
    if (url instanceof URL) {
      assert.equal(url.host, "ghcr.io");
      assert.equal(url.searchParams.get("scope"), `repository:${repository}:pull`);
      return Response.json({ token: "synthetic-read-token" });
    }
    assert.equal(url, `https://ghcr.io/v2/${repository}/manifests/${version}`);
    assert.equal(options.headers.authorization, "Bearer synthetic-read-token");
    assert.equal(options.redirect, "error");
    return new Response(content, { status });
  };
}

test("an image retry reuses only an exact registry manifest or publishes if the registry confirms absence", async () => {
  const manifest = '{"schemaVersion":2,"manifests":[]}';
  const image = { kind: "image", repository, version, expectedDigest: digest(manifest) };
  assert.deepEqual(await planPublication(image, registryResponse(200, manifest)), {
    action: "reuse",
    manifestDigest: image.expectedDigest,
  });
  assert.deepEqual(await planPublication(image, registryResponse(404, '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')), {
    action: "publish",
  });
  await assert.rejects(
    planPublication(image, registryResponse(200, '{"schemaVersion":2,"manifests":[{}]}')),
    /published image version has digest/,
  );
});

test("a chart retry compares the Helm archive layer and rejects ambiguous missing responses", async () => {
  const chart = { kind: "chart", repository, version, expectedDigest: digest("chart-bytes") };
  const layer = { mediaType: "application/vnd.cncf.helm.chart.content.v1.tar+gzip", digest: chart.expectedDigest };
  const manifest = JSON.stringify({ schemaVersion: 2, layers: [layer] });
  assert.deepEqual(await planPublication(chart, registryResponse(200, manifest)), {
    action: "reuse",
    manifestDigest: digest(manifest),
  });
  await assert.rejects(
    planPublication(chart, registryResponse(200, JSON.stringify({ schemaVersion: 2, layers: [layer, layer] }))),
    /no unique Helm archive digest/,
  );
  await assert.rejects(
    planPublication({ ...chart, expectedDigest: digest("other-bytes") }, registryResponse(200, manifest)),
    /published chart version has digest/,
  );
  for (const status of [401, 403, 404, 500]) {
    await assert.rejects(planPublication(chart, registryResponse(status, '{"errors":[{"code":"DENIED"}]}')),
      /Unable to inspect the current registry version/);
  }
});
