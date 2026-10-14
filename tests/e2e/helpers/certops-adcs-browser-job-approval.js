"use strict";
/** Browser job approval on the capacity fixture's actual two native jobs.
 * This is the control-plane two-person gate, not CA officer approval. Real
 * dashboard navigation/confirmation and persisted payload/intent bindings are
 * required; the capacity fixture independently verifies native CA/CNG/IIS/TLS. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { isDeepStrictEqual } = require("node:util");
const session = require("./certops-adcs-browser-session");
const approvals = require("../../../apps/api/services/certops/jobApprovals");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-browser-job-approval-cancel-and-confirm",
  "adcs-real-browser-job-approval-native-capacity-completion",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    ...session.REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-adcs-browser-job-approval.js",
    "tests/e2e/helpers/certops-adcs-capacity.js",
    "apps/dashboard/src/components/certops/ExecutorJobsPanel.jsx",
    "apps/dashboard/src/components/certops/ApprovalDecisionModal.jsx",
    "apps/dashboard/src/components/certops/JobDetailsButton.jsx",
    "apps/dashboard/src/components/certops/certopsJobsApi.js",
    "apps/dashboard/src/hooks/useCertOpsUrlState.js",
    "apps/api/routes/certops.js",
    "apps/api/services/certops/jobApprovals.js",
    "packages/agent/src/issuers/adcs-enrollment-journal.js",
    "infra/certops-adcs/owned-request-observation.ps1",
    "packages/agent/src/windows-cert-store/index.js",
  ]),
]);
const FLAGS = Object.freeze([
  "twoDistinctOwnedPendingJobs",
  "distinctManagerApprover",
  "exactJobVisibleInActualDashboard",
  "cancelDidNotMutate",
  "twoExactPublicApprovalPosts",
  "appendOnlyDecisionsBoundToActor",
  "payloadAndCanonicalIntentHashesVerified",
  "browserAndTrustDrained",
  "sameApprovedJobsInstalledNatively",
  "capacityGenerationsCrossBound",
  "oneExactPublicRejectionPost",
  "rejectedJobNeverClaimedOrSubmitted",
  "rejectedIntentAndNativeAbsencePreserved",
]);
const SCOPE =
  "browser-control-plane-job-approval-for-two-real-adcs-capacity-installations";
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "approvePosts",
      "cancelPosts",
      "caOfficerApprovalQualified",
      "jobIds",
      "enrollmentIds",
      "payloadHashes",
      "requestIds",
      "fingerprints",
      "rejectPosts",
      "rejectedJobId",
      "rejectedEnrollmentId",
      "rejectedPayloadHash",
      "rejectedCanonicalIntentHash",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.equal(value.approvePosts, 2);
  assert.equal(value.cancelPosts, 0);
  assert.equal(value.rejectPosts, 1);
  assert.match(value.rejectedJobId, uuid);
  assert.match(value.rejectedEnrollmentId, uuid);
  assert.match(value.rejectedPayloadHash, /^[a-f0-9]{64}$/);
  assert.match(value.rejectedCanonicalIntentHash, /^[a-f0-9]{64}$/);
  assert.ok(!value.jobIds.includes(value.rejectedJobId));
  assert.ok(!value.enrollmentIds.includes(value.rejectedEnrollmentId));
  assert.equal(value.caOfficerApprovalQualified, false);
  for (const [key, pattern] of [
    ["jobIds", uuid],
    ["enrollmentIds", uuid],
    ["payloadHashes", /^[a-f0-9]{64}$/],
    ["requestIds", /^[1-9][0-9]{0,9}$/],
    ["fingerprints", /^[a-f0-9]{64}$/],
  ]) {
    assert.ok(Array.isArray(value[key]) && value[key].length === 2);
    assert.equal(new Set(value[key]).size, 2);
    for (const item of value[key]) assert.match(item, pattern);
  }
  for (const id of value.requestIds) assert.ok(Number(id) <= 0xffffffff);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function verifyCrossProof(value, capacity) {
  verifyProof(value);
  require("./certops-adcs-capacity").verifyProof(capacity);
  for (const key of ["jobIds", "enrollmentIds", "requestIds", "fingerprints"])
    assert.deepEqual(
      value[key],
      capacity[key],
      `Browser approvals must bind both actual capacity ${key}`,
    );
  assert.equal(capacity.nativeCompleted, 2);
  return true;
}
function verifyDecision(row, before, approverUserId, reason) {
  assert.equal(row.decision, "approved");
  assert.equal(String(row.approved_by_user_id), String(approverUserId));
  assert.equal(row.reason, reason);
  assert.equal(
    row.payload_hash,
    approvals.computeJobPayloadApprovalHash(before.payload),
  );
  assert.equal(
    row.canonical_intent_hash,
    approvals.computeCanonicalIntentHash({
      operation: before.operation,
      subjectType: before.subject_type,
      subjectId: before.subject_id,
      payload: before.payload,
    }),
  );
  return true;
}
function verifyRejection(before, current, decision, actorId, reason) {
  assert.equal(current.status, "rejected");
  assert.equal(current.error_code, "CERTOPS_APPROVAL_REJECTED");
  assert.equal(current.enrollment_state, "requested");
  assert.equal(current.request_id, null);
  assert.equal(current.claim_id, null);
  assert.equal(current.attempt_count, 0);
  const intent = (job) => ({
    operation: job.operation,
    subjectType: job.subject_type,
    subjectId: job.subject_id,
    payload: job.payload,
  });
  assert.equal(
    approvals.computeJobPayloadApprovalHash(current.payload),
    approvals.computeJobPayloadApprovalHash(before.payload),
  );
  assert.equal(
    approvals.computeCanonicalIntentHash(intent(current)),
    approvals.computeCanonicalIntentHash(intent(before)),
  );
  assert.equal(decision.decision, "rejected");
  assert.equal(String(decision.approved_by_user_id), String(actorId));
  assert.equal(decision.reason, reason);
  assert.equal(decision.payload_hash, null);
  assert.equal(decision.canonical_intent_hash, null);
  return true;
}
function verifyApprovalRequest(request, expected) {
  try {
    const url = new URL(request.url);
    return (
      request.method === "POST" &&
      url.origin === expected.origin &&
      url.pathname === expected.pathname &&
      !url.search &&
      !url.hash &&
      !url.username &&
      !url.password &&
      request.body !== null &&
      typeof request.body === "object" &&
      !Array.isArray(request.body) &&
      Object.keys(request.body).length === 1 &&
      Object.hasOwn(request.body, "reason") &&
      request.body.reason === expected.reason
    );
  } catch {
    return false;
  }
}
function createBrowserJobApprovalActor(context) {
  const { gate, fixture, configDir, command } = context,
    root = path.resolve(__dirname, "../../.."),
    approved = [];
  let rejected;
  const row = async (jobId, enrollmentId) =>
    (
      await fixture.pool.query(
        "SELECT j.*,e.state AS enrollment_state,e.request_id,e.current_job_id FROM certificate_jobs j JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.id=$3 WHERE j.workspace_id=$1 AND j.id=$2 AND e.current_job_id=j.id",
        [fixture.workspaceId, jobId, enrollmentId],
      )
    ).rows[0];
  const decisions = async (jobId) =>
    (
      await fixture.pool.query(
        "SELECT decision,approved_by_user_id,payload_hash,canonical_intent_hash,reason FROM certops_job_approvals WHERE workspace_id=$1 AND job_id=$2 ORDER BY created_at,id",
        [fixture.workspaceId, jobId],
      )
    ).rows;
  const hashes = (current) => ({
    payload: approvals.computeJobPayloadApprovalHash(current.payload),
    intent: approvals.computeCanonicalIntentHash({
      operation: current.operation,
      subjectType: current.subject_type,
      subjectId: current.subject_id,
      payload: current.payload,
    }),
  });
  async function pending(jobId, enrollmentId, approver) {
    assert.equal(process.platform, "win32");
    assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
    assert.match(jobId, uuid);
    assert.match(enrollmentId, uuid);
    assert.notEqual(String(approver.userId), String(fixture.userId));
    const membership = (
      await fixture.pool.query(
        "SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
        [fixture.workspaceId, approver.userId],
      )
    ).rows;
    assert.equal(membership.length, 1);
    assert.equal(membership[0].role, "workspace_manager");
    const authority = (
      await fixture.pool.query(
        "SELECT u.is_admin,w.created_by FROM users u CROSS JOIN workspaces w WHERE u.id=$1 AND w.id=$2",
        [approver.userId, fixture.workspaceId],
      )
    ).rows;
    assert.equal(authority.length, 1);
    assert.equal(authority[0].is_admin, false);
    assert.notEqual(String(authority[0].created_by), String(approver.userId));
    const before = await row(jobId, enrollmentId);
    assert.ok(before);
    assert.equal(before.status, "pending_approval");
    assert.equal(before.enrollment_state, "requested");
    assert.equal(before.request_id, null);
    assert.equal(before.claim_id, null);
    assert.equal(before.attempt_count, 0);
    assert.equal(String(before.requested_by_user_id), String(fixture.userId));
    assert.equal((await decisions(jobId)).length, 0);
    assert.equal(
      readEnrollmentJournal(configDir, enrollmentId).kind,
      "not_found",
    );
    for (const file of REQUIRED_SOURCES) {
      gate.report.fixtureSources ??= [];
      const sha256 = crypto
          .createHash("sha256")
          .update(fs.readFileSync(path.join(root, file)))
          .digest("hex"),
        prior = gate.report.fixtureSources.find((item) => item.file === file);
      if (prior) assert.equal(prior.sha256, sha256);
      else gate.report.fixtureSources.push({ file, sha256 });
    }
    return before;
  }
  async function decide({ jobId, enrollmentId, approver, decision, before }) {
    assert.ok(["approve", "reject"].includes(decision));
    const label = decision === "approve" ? "Approve" : "Reject",
      reason =
        decision === "approve"
          ? "Independent manager confirms owned AD CS job"
          : "Independent manager rejects never-submitted AD CS job",
      writes = [];
    await session.withOwnedAdcsBrowserPage(
      {
        ...context,
        fixture: { ...approver, workspaceId: fixture.workspaceId },
      },
      async (page, { origin }) => {
        const expected = {
          origin,
          pathname: `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobId}/${decision}`,
          reason,
        };
        page.on("request", (request) => {
          const url = new URL(request.url());
          if (
            /^\/api\/v1\/workspaces\/[^/]+\/certops(?:\/|$)/.test(
              url.pathname,
            ) &&
            ["POST", "PUT", "PATCH", "DELETE"].includes(request.method())
          ) {
            let body;
            try {
              body = request.postDataJSON();
            } catch {
              body = null;
            }
            writes.push(
              verifyApprovalRequest(
                { url: request.url(), method: request.method(), body },
                expected,
              ),
            );
          }
        });
        const destination = new URL("/certops/jobs", origin);
        destination.searchParams.set("workspace", fixture.workspaceId);
        destination.searchParams.set("q", jobId);
        destination.searchParams.set("job", jobId);
        const listPromise = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return (
            url.origin === origin &&
            url.pathname ===
              `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs` &&
            url.searchParams.get("q") === jobId &&
            response.request().method() === "GET"
          );
        });
        await page.goto(destination.href);
        const list = await listPromise;
        assert.equal(list.status(), 200);
        const body = await list.json();
        assert.equal(body.items.length, 1);
        assert.equal(body.items[0].id, jobId);
        const button = page.getByRole("button", { name: label, exact: true });
        await button.waitFor();
        assert.equal(await button.count(), 1);
        await page
          .getByRole("button", { name: "Job details", exact: true })
          .click();
        await page.getByText(jobId, { exact: true }).first().waitFor();
        await page.keyboard.press("Escape");
        await button.click();
        let dialog = page.getByRole("dialog");
        await dialog.getByText(`${label} job`, { exact: true }).waitFor();
        await dialog
          .getByRole("button", { name: "Cancel", exact: true })
          .click();
        await dialog.waitFor({ state: "hidden" });
        assert.equal(writes.length, 0);
        assert.ok(
          isDeepStrictEqual(await row(jobId, enrollmentId), before),
          "Cancelling the decision dialog changed the owned job",
        );
        assert.equal((await decisions(jobId)).length, 0);
        await button.click();
        dialog = page.getByRole("dialog");
        await dialog.getByText(`${label} job`, { exact: true }).waitFor();
        await dialog.locator("textarea").fill(reason);
        const responsePromise = page.waitForResponse((response) => {
          let body;
          try {
            body = response.request().postDataJSON();
          } catch {
            return false;
          }
          return verifyApprovalRequest(
            { url: response.url(), method: response.request().method(), body },
            expected,
          );
        });
        await dialog.getByRole("button", { name: label, exact: true }).click();
        assert.equal((await responsePromise).status(), 200);
        await dialog.waitFor({ state: "hidden" });
        assert.deepEqual(writes, [true]);
      },
    );
    return reason;
  }
  return {
    async approveJob({ jobId, enrollmentId, approver }) {
      assert.ok(
        approved.length < 2 &&
          !approved.some(
            (item) =>
              item.jobId === jobId || item.enrollmentId === enrollmentId,
          ),
      );
      const before = await pending(jobId, enrollmentId, approver),
        reason = await decide({
          jobId,
          enrollmentId,
          approver,
          decision: "approve",
          before,
        }),
        history = await decisions(jobId);
      assert.equal(history.length, 1);
      verifyDecision(history[0], before, approver.userId, reason);
      approved.push({
        jobId,
        enrollmentId,
        payloadHash: history[0].payload_hash,
        approverUserId: approver.userId,
        reason,
      });
    },
    async rejectJob({ item, approver }) {
      assert.equal(rejected, undefined);
      assert.equal(approved.length, 2);
      const { jobId, enrollmentId, domain } = item;
      assert.match(
        domain,
        /^certops-adcs-[a-f0-9]{10}-capacity[0-5]\.example\.test$/,
      );
      assert.ok(
        !approved.some(
          (value) =>
            value.jobId === jobId || value.enrollmentId === enrollmentId,
        ),
      );
      const before = await pending(jobId, enrollmentId, approver),
        original = hashes(before),
        container =
          require("../../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(
            enrollmentId,
          );
      const absent = () => {
        assert.equal(
          readEnrollmentJournal(configDir, enrollmentId).kind,
          "not_found",
        );
        const inventory = command("certutil.exe", [
          "-csp",
          "Microsoft Software Key Storage Provider",
          "-key",
        ]);
        for (const owned of approved) {
          const positive =
            require("../../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(
              owned.enrollmentId,
            );
          assert.equal(
            inventory.includes(positive),
            true,
            "Actual provider inventory must retain both independently installed positive keys",
          );
        }
        assert.equal(
          inventory.includes(container),
          false,
          "Never-approved rejected key must remain absent",
        );
        const observation = JSON.parse(
          command("powershell.exe", [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            path.join(root, "infra/certops-adcs/owned-request-observation.ps1"),
            "-CommonName",
            domain,
            "-Discover",
          ]),
        );
        assert.equal(observation.subjectRequestCount, 0);
      };
      absent();
      const reason = await decide({
          jobId,
          enrollmentId,
          approver,
          decision: "reject",
          before,
        }),
        current = await row(jobId, enrollmentId),
        history = await decisions(jobId);
      assert.equal(current.status, "rejected");
      assert.equal(current.error_code, "CERTOPS_APPROVAL_REJECTED");
      assert.equal(current.enrollment_state, "requested");
      assert.equal(current.request_id, null);
      assert.equal(current.claim_id, null);
      assert.equal(current.attempt_count, 0);
      assert.ok(
        isDeepStrictEqual(hashes(current), original),
        "Rejection changed the actual execution intent",
      );
      assert.equal(history.length, 1);
      verifyRejection(before, current, history[0], approver.userId, reason);
      assert.equal(history[0].decision, "rejected");
      assert.equal(
        String(history[0].approved_by_user_id),
        String(approver.userId),
      );
      assert.equal(history[0].reason, reason);
      assert.equal(history[0].payload_hash, null);
      assert.equal(history[0].canonical_intent_hash, null);
      absent();
      rejected = {
        jobId,
        enrollmentId,
        payloadHash: original.payload,
        intentHash: original.intent,
      };
    },
    async observeNativeCompletion(capacity) {
      assert.equal(approved.length, 2);
      assert.ok(rejected);
      await gate.scenario(
        REQUIRED_SCENARIOS[0],
        () => {
          assert.equal(new Set(approved.map((item) => item.jobId)).size, 2);
          assert.ok(
            approved.every(
              (item) => item.approverUserId === approved[0].approverUserId,
            ),
          );
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "Two actualApprove and oneReject dashboarddialogs each require Cancel0writes and exactConfirmpublic200, distinctmanager actor, persisted decisions and unchanged rejectedintent/nativeabsence; browser/trustdrained",
        },
      );
      await gate.scenario(
        REQUIRED_SCENARIOS[1],
        async () => {
          for (const [index, item] of approved.entries()) {
            const current = await row(item.jobId, item.enrollmentId);
            assert.equal(current.status, "succeeded");
            assert.equal(current.enrollment_state, "installed");
            assert.ok(current.claim_id);
            assert.equal(
              String(current.approved_by_user_id),
              String(item.approverUserId),
            );
            assert.equal(current.approved_payload_hash, item.payloadHash);
            assert.equal(
              String(current.request_id),
              capacity.requestIds[index],
            );
            const receipt = readEnrollmentJournal(configDir, item.enrollmentId);
            assert.equal(receipt.kind, "valid");
            assert.equal(receipt.journal.state, "installed");
            assert.equal(
              String(receipt.journal.requestId),
              String(current.request_id),
            );
            const history = await decisions(item.jobId);
            assert.equal(history.length, 1);
            verifyDecision(
              history[0],
              current,
              item.approverUserId,
              item.reason,
            );
            assert.equal(
              current.approved_payload_hash,
              history[0].payload_hash,
            );
            assert.equal(
              current.approved_canonical_intent_hash,
              history[0].canonical_intent_hash,
            );
          }
          const value = {
            scope: SCOPE,
            approvePosts: 2,
            rejectPosts: 1,
            cancelPosts: 0,
            caOfficerApprovalQualified: false,
            jobIds: approved.map((item) => item.jobId),
            enrollmentIds: approved.map((item) => item.enrollmentId),
            payloadHashes: approved.map((item) => item.payloadHash),
            rejectedJobId: rejected.jobId,
            rejectedEnrollmentId: rejected.enrollmentId,
            rejectedPayloadHash: rejected.payloadHash,
            rejectedCanonicalIntentHash: rejected.intentHash,
            requestIds: capacity.requestIds,
            fingerprints: capacity.fingerprints,
            ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
          };
          verifyCrossProof(value, capacity);
          gate.report.nativeBrowserJobApproval = value;
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "Same two UI-approved jobs have actualclaim-bound installeddatabase/journalresults bound to independent capacityCA/CNG/IIS/trustedTLS generations; rejectedjob neverclaimed/submitted; noCAofficerclaim",
        },
      );
      return gate.report.nativeBrowserJobApproval;
    },
  };
}
module.exports = {
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  SCOPE,
  verifyProof,
  verifyCrossProof,
  verifyDecision,
  verifyApprovalRequest,
  verifyRejection,
  createBrowserJobApprovalActor,
};
