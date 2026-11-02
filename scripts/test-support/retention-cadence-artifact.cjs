"use strict";
/** Offline owner/artifact fixtures exercise real validators; never native evidence. */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const p = require("../certops-retention-cadence-proof");
const c = require("../certops-retention-cadence-contract");
const a = require("../certops-retention-cadence-azure");
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function fixture() {
  const composite =
    require("../fixtures/certops-retention-cadence.cjs").fixture();
  const l = composite.preparedLease;
  const root = path.resolve(__dirname, "../..");
  composite.preparation.fixtureSources =
    require("../certops-retention-cadence-sources").REQUIRED_SOURCES.map(
      (file) => ({ file, sha256: sha(fs.readFileSync(path.join(root, file))) }),
    );
  const runtimeSha = composite.preparation.fixtureSources.find(
    (row) => row.file === "scripts/certops-retention-cadence-runtime.js",
  ).sha256;
  for (const value of [
    l,
    composite.lease,
    composite.preparation.observed,
    composite.completion.originalObservation,
  ])
    value.observerSha256 = runtimeSha;
  const run = {
    id: 12,
    run_attempt: 1,
    path: c.PREPARE_WORKFLOW,
    event: "workflow_dispatch",
    head_branch: "main",
    head_sha: l.candidateSha,
    status: "completed",
    conclusion: "success",
    repository: { full_name: a.REPOSITORY },
    head_repository: { full_name: a.REPOSITORY },
    created_at: "2026-10-14T12:00:00.000Z",
    updated_at: "2026-10-15T00:11:00.000Z",
  };
  const jobs = {
    total_count: 1,
    jobs: [
      {
        id: 13,
        name: "prepare",
        run_id: 12,
        run_attempt: 1,
        head_sha: l.candidateSha,
        status: "completed",
        conclusion: "success",
        started_at: l.createdAt,
        completed_at: run.updated_at,
      },
    ],
  };
  const owner = a.verifyPrepareRun(run, jobs);
  const original = {
    schemaVersion: 1,
    kind: c.KIND,
    preparedLease: l,
    preparation: composite.preparation,
    githubOwner: { ...owner, completedAt: null },
    azure: {
      groupId: l.vmResourceId.split("/providers/")[0],
      vmResourceId: l.vmResourceId,
      vmId: l.vmId,
      vmCreatedAt: "2026-10-15T00:00:10.000Z",
      deploymentCreatedAt: "2026-10-15T00:00:20.000Z",
    },
    sealedAt: "2026-10-15T00:03:00.000Z",
  };
  const originalArtifact = {
    id: "14",
    name: `retention-cadence-original-1-${l.nonce}`,
    archiveSha256: "3".repeat(64),
  };
  const handoff = {
    schemaVersion: 1,
    kind: c.KIND,
    preparedLease: l,
    lease: composite.lease,
    preparation: composite.preparation,
    observed: {
      ...composite.preparation.observed,
      verifiedAt: "2026-10-15T00:05:00.000Z",
    },
    originalArtifact,
    handedOffAt: "2026-10-15T00:06:00.000Z",
  };
  const provenance = {
    originalArtifact,
    handoffArtifact: {
      id: "15",
      name: `retention-cadence-ownership-1-${l.nonce}`,
      archiveSha256: "4".repeat(64),
    },
    finalizerProvenance: {
      repository: a.REPOSITORY,
      runId: "16",
      runAttempt: "1",
      headSha: "9".repeat(40),
      event: "schedule",
      headBranch: "main",
      workflowPath: a.FINALIZER,
      controllerSources: a.CONTROLLER_SOURCES.map((file) => ({
        file,
        sha256: sha(fs.readFileSync(path.join(root, file))),
      })),
    },
  };
  return {
    composite,
    original,
    handoff,
    run,
    jobs,
    provenance,
    report: p.createQualificationReport(composite, provenance),
  };
}
module.exports = { fixture };
if (require.main === module) process.stdout.write(JSON.stringify(fixture()));
