"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { createRequire } = require("node:module");
const { join } = require("node:path");
const { download } = require("./certops-artifact-zip.cjs");
const { validateWorkflow } = require("./certops-workflow-security");
const { readContext, assertVerifiedCommit, verifyRun, verifyArtifact, verifyReceipts } =
  require("../infra/certops-adcs/store-noiis-qualification-inputs.cjs");

const now = Date.parse("2026-10-01T11:00:00Z");
const hash = value => createHash("sha256").update(value).digest("hex");
const json = value => Buffer.from(JSON.stringify(value));
const context = {
  repoId: "20", workflowSha: "a".repeat(40), prepareSha: "b".repeat(40),
  runId: "100", attempt: "2", registrationId: "300", preparationId: "400",
  mediaSource: "c".repeat(40), custodyDigest: "d".repeat(64),
};
const group = "tt-certops-100-2";
const expires = "2026-10-01T14:00:00.1234567+00:00";
const originalMember = {
  scope: "store-noiis-clean-member-readiness", windowsBuild: "20348", architecture: "x64",
  localSystem: true, ownedDomain: true, iisAbsent: true, agentServiceAbsent: true, caRpcPing: true,
};

test("the preflight passes the repository workflow guard with read-only permissions and the exact main condition", () => {
  const yaml = createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
  const name = "certops-adcs-store-qualification-preflight.yml";
  const workflow = yaml.load(readFileSync(join(__dirname, "../.github/workflows", name), "utf8"));
  assert.deepEqual(validateWorkflow(workflow, name), []);
  for (const mutate of [
    value => { value.permissions = {}; },
    value => { value.jobs.verify.if = "always()"; },
    value => { value.jobs.verify.permissions["id-token"] = "write"; },
  ]) {
    const denied = structuredClone(workflow);
    mutate(denied);
    assert.ok(validateWorkflow(denied, name).length);
  }
});

function preparation({ registration = {}, readiness = {}, member = {} } = {}) {
  const report = json({
    schema: "certops-adcs-store-registration-v1", workflowCommit: context.prepareSha,
    resourceGroup: group, runId: context.runId, runAttempt: context.attempt,
    mediaSourceCommit: context.mediaSource, mediaReceiptSha256: context.custodyDigest,
    workflowOwnedGroupVerified: true, independentExpiryVerified: true,
    registrationNonce: "1".repeat(64), subscriptionSha256: "2".repeat(64),
    provisionClientSha256: "3".repeat(64), cleanupClientSha256: "4".repeat(64),
    janitorRunId: "56", janitorCommit: context.prepareSha,
    createdAt: "2026-10-01T10:00:00.1234567+00:00", observedAt: "2026-10-01T10:12:00Z",
    expiresAt: expires, ...registration,
  });
  const memberBytes = json({ ...originalMember, ...member });
  const infrastructure = json({
    scope: "store-noiis-infrastructure-preparation", status: "store-noiis-infrastructure-prepared",
    resourceGroup: group, workflowCommit: context.prepareSha, sourceCommit: context.mediaSource,
    mediaReceiptSha256: context.custodyDigest, registrationSha256: hash(report),
    memberReadinessSha256: hash(memberBytes), expiresAt: expires, memberName: "windows-agent",
    memberVmId: "12345678-1234-1234-1234-123456789abc",
    qualificationPassed: false, agentInstalledByPreparation: false, ...readiness,
  });
  return [
    new Map([["store-noiis-registration.json", report], ["store-noiis-registration.sha256", Buffer.from(hash(report) + "\r\n")]]),
    new Map([["store-noiis-infrastructure.json", infrastructure], ["store-noiis-member.json", memberBytes]]),
  ];
}

test("intake accepts only the exact protected main dispatch and reviewed source inputs", () => {
  const env = {
    GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "tokentimerch/tokentimer-core", GITHUB_REPOSITORY_ID: "20",
    GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_RUN_ID: "199",
    GITHUB_WORKFLOW_REF: "tokentimerch/tokentimer-core/.github/workflows/certops-adcs-store-qualification-preflight.yml@refs/heads/main",
    GH_TOKEN: "fixture", GITHUB_SHA: context.workflowSha, GITHUB_WORKFLOW_SHA: context.workflowSha,
    STORE_REVIEWED_WORKFLOW_SHA: context.workflowSha, STORE_PREPARE_WORKFLOW_SHA: context.prepareSha,
    STORE_PREPARE_RUN_ID: context.runId, STORE_PREPARE_ATTEMPT: context.attempt,
    STORE_REGISTRATION_ARTIFACT_ID: context.registrationId, STORE_PREPARATION_ARTIFACT_ID: context.preparationId,
    STORE_MEDIA_SOURCE: context.mediaSource, STORE_MEDIA_RECEIPT_SHA: context.custodyDigest,
  };
  assert.deepEqual(readContext(env), context);
  for (const mutation of [
    { GITHUB_REPOSITORY: "other/tokentimer-core" }, { GITHUB_REF: "refs/heads/test" },
    { GITHUB_EVENT_NAME: "pull_request_target" }, { GITHUB_WORKFLOW_REF: "other" },
    { GITHUB_WORKFLOW_SHA: context.prepareSha }, { STORE_REVIEWED_WORKFLOW_SHA: context.prepareSha },
    { STORE_PREPARE_RUN_ID: "../100" }, { STORE_PREPARE_ATTEMPT: "02" },
    { STORE_REGISTRATION_ARTIFACT_ID: context.preparationId }, { STORE_MEDIA_RECEIPT_SHA: "missing" },
  ]) assert.throws(() => readContext({ ...env, ...mutation }));
  assert.doesNotThrow(() => assertVerifiedCommit({ sha: context.prepareSha, commit: { verification: { verified: true } } }, context.prepareSha));
  assert.throws(() => assertVerifiedCommit({ sha: context.workflowSha, commit: { verification: { verified: true } } }, context.prepareSha));
  assert.throws(() => assertVerifiedCommit({ sha: context.prepareSha, commit: { verification: { verified: false } } }, context.prepareSha));
});

test("exact prepare attempt requires separate successful evidence for registration, verification and preparation", () => {
  const run = {
    id: 100, path: ".github/workflows/certops-adcs-store-noiis-prepare.yml", event: "workflow_dispatch",
    head_branch: "main", head_sha: context.prepareSha, run_attempt: 2, repository: { id: 20 },
    head_repository: { id: 20 }, status: "completed", conclusion: "success",
  };
  const rows = ["register", "verify", "prepare"].map(name => ({
    name, run_id: 100, run_attempt: 2, head_sha: context.prepareSha, status: "completed", conclusion: "success",
  }));
  const jobs = { total_count: 3, jobs: rows };
  assert.doesNotThrow(() => verifyRun(run, jobs, context));
  assert.throws(() => verifyRun({ ...run, run_attempt: 3 }, jobs, context));
  assert.throws(() => verifyRun({ ...run, head_repository: { id: 99 } }, jobs, context));
  assert.throws(() => verifyRun({ ...run, path: "lookalike.yml" }, jobs, context));
  for (const replacement of [{ conclusion: "failure" }, { run_attempt: 1 }, { name: "register" }, { run_id: 99 }])
    assert.throws(() => verifyRun(run, { ...jobs, jobs: [rows[0], { ...rows[1], ...replacement }, rows[2]] }, context));
});

test("artifact must belong to the original exact run, repository, attempt name and digest", () => {
  const artifact = {
    id: 300, name: "disposable-store-registration-100-2", expired: false, expires_at: expires,
    digest: "sha256:" + "a".repeat(64), size_in_bytes: 1,
    workflow_run: { id: 100, repository_id: 20, head_repository_id: 20, head_branch: "main", head_sha: context.prepareSha },
  };
  const check = value => verifyArtifact(value, context.registrationId, artifact.name, context, now);
  assert.doesNotThrow(() => check(artifact));
  for (const mutation of [
    { id: 400 }, { name: "disposable-store-registration-100-1" }, { expired: true },
    { expires_at: "2026-10-01T10:59:59Z" }, { size_in_bytes: 65537 }, { digest: "none" },
    { workflow_run: { ...artifact.workflow_run, id: 99 } },
    { workflow_run: { ...artifact.workflow_run, head_sha: context.workflowSha } },
  ]) assert.throws(() => check({ ...artifact, ...mutation }));
});

test("artifact download verifies exact bytes and keeps GitHub credentials off the storage request", async t => {
  const contents = Buffer.from("verified content");
  const artifact = { size_in_bytes: contents.length, digest: "sha256:" + hash(contents) };
  const storage = "https://fixture.blob.core.windows.net/private/file?signature=test";
  const fetchMock = t.mock.method(globalThis, "fetch", async (url, options) => {
    if (typeof url === "string") {
      assert.equal(url, "https://api.github.com/repos/tokentimerch/tokentimer-core/actions/artifacts/300/zip");
      assert.equal(options.headers.Authorization, "Bearer fixture-token");
      assert.equal(options.redirect, "manual");
      return new Response(null, { status: 302, headers: { location: storage } });
    }
    assert.equal(url.href, storage);
    assert.equal(options.headers, undefined);
    assert.equal(options.redirect, "error");
    return new Response(contents);
  });
  const read = metadata => download("tokentimerch/tokentimer-core", "300", metadata, "fixture-token", 64);
  assert.deepEqual(await read(artifact), contents);
  await assert.rejects(read({ ...artifact, digest: "sha256:" + "f".repeat(64) }));
  await assert.rejects(read({ ...artifact, size_in_bytes: contents.length - 1 }));
  await assert.rejects(read({ ...artifact, size_in_bytes: 65 }));
  fetchMock.mock.mockImplementationOnce(async () =>
    new Response(null, { status: 302, headers: { location: "https://fixture.invalid/archive" } }));
  await assert.rejects(read(artifact));
  assert.equal(fetchMock.mock.callCount(), 7);
});

test("joined receipts bind a live four-hour lease, clean member, approved media and distinct cleanup role", () => {
  const receipt = verifyReceipts(...preparation(), context, now);
  assert.equal(receipt.scope, "store-preparation-inputs-only");
  assert.equal(receipt.prepareAttempt, context.attempt);
  assert.equal(receipt.custodyDigest, context.custodyDigest);
  assert.equal(receipt.resourceGroup, group);
  assert.equal(receipt.expiresAt, expires);
  // A recent scheduled janitor may have run on an earlier main commit.
  assert.doesNotThrow(() => verifyReceipts(...preparation({
    registration: { janitorCommit: context.workflowSha },
  }), context, now));
  for (const mutation of [
    { registration: { independentExpiryVerified: false } },
    { registration: { workflowOwnedGroupVerified: "true" } },
    { registration: { cleanupClientSha256: "3".repeat(64) } },
    { registration: { expiresAt: "2026-10-01T15:00:00.1234567+00:00" } },
    { registration: { observedAt: "2026-10-01T11:00:01Z" } },
    { registration: { janitorCommit: "unknown" } },
    { registration: { runAttempt: "1" } },
    { readiness: { status: "failure" } },
    { readiness: { mediaReceiptSha256: "0".repeat(64) } },
    { readiness: { qualificationPassed: true } },
    { readiness: { agentInstalledByPreparation: true } },
    { readiness: { memberReadinessSha256: "0".repeat(64) } },
    { readiness: { memberVmId: "missing" } },
    { member: { agentServiceAbsent: false } },
    { member: { iisAbsent: false } },
    { member: { extra: "unexpected" } },
  ]) assert.throws(() => verifyReceipts(...preparation(mutation), context, now));
  assert.throws(() => verifyReceipts(...preparation(), context, Date.parse(expires)));
  const [registration, readiness] = preparation();
  registration.set("store-noiis-registration.sha256", Buffer.from("0".repeat(64)));
  assert.throws(() => verifyReceipts(registration, readiness, context, now));
  const [otherRegistration, otherReadiness] = preparation();
  otherReadiness.set("other-file.json", Buffer.from("{}"));
  assert.throws(() => verifyReceipts(otherRegistration, otherReadiness, context, now));
});

test("optional recovery readiness binds the private TLS fingerprint and final clean-member observation", () => {
  const steps = [
    "CERTOPS_STAGE=protected-store-registration-and-expiry-read-back",
    "CERTOPS_STAGE=forest-created-reboot-required",
    "CERTOPS_STAGE=enterprise-ca-service-running",
    "CERTOPS_STAGE=member-joined-reboot-required",
    "CERTOPS_STAGE=store-noiis-clean-member-ready",
    "CERTOPS_STAGE=isolated-template-matrix-published",
    "CERTOPS_STAGE=private-https-control-plane-running",
    "CERTOPS_STAGE=store-noiis-clean-member-ready",
  ];
  const readiness = {
    status: "store-noiis-recovery-infrastructure-prepared",
    controllerTlsCertificateSha256: "f".repeat(64), stages: steps,
  };
  const proof = verifyReceipts(...preparation({ readiness }), context, now);
  assert.equal(proof.controllerTlsCertificateSha256, readiness.controllerTlsCertificateSha256);
  assert.throws(() => verifyReceipts(...preparation({ readiness: { ...readiness, stages: steps.slice(0, -1) } }), context, now));
  assert.throws(() => verifyReceipts(...preparation({ readiness: { ...readiness, controllerTlsCertificateSha256: undefined } }), context, now));
  assert.throws(() => verifyReceipts(...preparation({ readiness: {
    ...readiness, status: "store-noiis-infrastructure-prepared",
  } }), context, now));
});
