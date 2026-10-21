"use strict";
/** Actual manual-job UI admission for the dedicated native ACME lifecycle lane.
 * The caller owns/authenticates the browser and registers returned jobs before
 * waiting on native execution. This helper never substitutes HTTP responses or
 * claims that UI admission alone proves issuance, renewal or browser cleanup. */
const assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  { isDeepStrictEqual } = require("node:util");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-acme-browser-job-admission.js",
  "apps/dashboard/src/components/certops/CreateManualJobModal.jsx",
  "apps/dashboard/src/components/certops/ExecutorJobsPanel.jsx",
  "apps/dashboard/src/components/certops/certopsJobsApi.js",
  "apps/dashboard/src/components/certops/certopsApi.js",
  "apps/dashboard/src/components/certops/certopsRenewalApi.js",
  "apps/dashboard/src/utils/apiClient.js",
  "apps/dashboard/src/components/certops/useCertOps.js",
  "apps/dashboard/src/components/certops/useCertOpsAgents.js",
  "apps/dashboard/src/components/certops/certopsJobsFormat.js",
  "tests/e2e/helpers/certops-api-fixture.js",
  "apps/api/services/rbac.js",
  "apps/api/middleware/auth.js",
  "apps/api/middleware/workspace-access-policy.js",
  "apps/api/routes/certops.js",
  "apps/api/services/certops/jobs.js",
  "apps/api/services/certops/renewalProfile.js",
]);
function verifyRequest(
  { url, method, body },
  { apiOrigin, workspaceId, expectedBody },
) {
  const target = new URL(url),
    origin = new URL(apiOrigin);
  assert.equal(method, "POST");
  assert.equal(target.origin, origin.origin);
  assert.equal(
    target.pathname,
    `/api/v1/workspaces/${workspaceId}/certops/jobs`,
  );
  assert.equal(target.search, "");
  assert.equal(target.hash, "");
  assert.equal(target.username, "");
  assert.equal(target.password, "");
  assert.ok(
    isDeepStrictEqual(body, expectedBody),
    "Actual browser job payload differs from owned native request",
  );
  return true;
}
function isWrite(request) {
  return (
    ["POST", "PUT", "PATCH", "DELETE"].includes(request.method()) &&
    /^\/api\/v1\/workspaces\/[^/]+\/certops(?:\/|$)/.test(
      new URL(request.url()).pathname,
    )
  );
}
function validateInput(body) {
  assert.ok(body && typeof body === "object" && !Array.isArray(body));
  assert.ok(["issue", "renew"].includes(body.operation));
  assert.match(body.idempotencyKey, UUID);
  if (body.operation === "issue") {
    assert.deepEqual(
      Object.keys(body).sort(),
      ["operation", "idempotencyKey", "payload"].sort(),
    );
    assert.ok(
      body.payload &&
        typeof body.payload === "object" &&
        !Array.isArray(body.payload),
    );
  } else {
    assert.deepEqual(
      Object.keys(body).sort(),
      [
        "operation",
        "idempotencyKey",
        "subjectType",
        "subjectId",
        "payload",
      ].sort(),
    );
    assert.equal(body.subjectType, "managed_certificate");
    assert.match(body.subjectId, UUID);
    assert.deepEqual(Object.keys(body.payload), ["reason"]);
    assert.ok(
      typeof body.payload.reason === "string" &&
        body.payload.reason.length > 0 &&
        body.payload.reason.length <= 512,
    );
  }
}
async function admitBrowserJob({
  page,
  uiOrigin,
  apiOrigin,
  workspaceId,
  expectedBody,
  pool,
  registerOwnedJob,
}) {
  validateInput(expectedBody);
  assert.match(workspaceId, UUID);
  assert.equal(typeof registerOwnedJob, "function");
  const snapshots = async () =>
    (
      await pool.query(
        "SELECT id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",
        [workspaceId],
      )
    ).rows.map((row) => row.id);
  const baseline = await snapshots();
  let writes = 0,
    matchingWrites = 0,
    wrongWrite = false;
  const listener = (request) => {
    if (!isWrite(request)) return;
    writes++;
    try {
      verifyRequest(
        {
          url: request.url(),
          method: request.method(),
          body: request.postDataJSON(),
        },
        { apiOrigin, workspaceId, expectedBody },
      );
      matchingWrites++;
    } catch {
      wrongWrite = true;
    }
  };
  page.on("request", listener);
  try {
    const destination = new URL("/certops/jobs", uiOrigin);
    destination.searchParams.set("workspace", workspaceId);
    const listing = page.waitForResponse(
      (response) => {
        const url = new URL(response.url());
        return (
          response.request().method() === "GET" &&
          url.origin === new URL(apiOrigin).origin &&
          url.pathname === `/api/v1/workspaces/${workspaceId}/certops/jobs`
        );
      },
      { timeout: 30000 },
    );
    await page.goto(destination.href);
    assert.equal(
      (await listing).status(),
      200,
      "Actual owned workspace jobs must load before native submission",
    );
    const fill = async () => {
      await page
        .getByRole("button", { name: "Create manual job", exact: true })
        .click();
      const modal = page.getByRole("dialog");
      await modal
        .getByLabel("Operation", { exact: true })
        .selectOption(expectedBody.operation);
      if (expectedBody.operation === "renew") {
        await modal
          .getByLabel("Subject type", { exact: true })
          .selectOption("managed_certificate");
        await modal
          .getByLabel("Subject ID", { exact: true })
          .fill(expectedBody.subjectId);
      }
      await modal
        .getByLabel("Idempotency key", { exact: true })
        .fill(expectedBody.idempotencyKey);
      await modal.getByRole("button", { name: "JSON", exact: true }).click();
      await modal
        .locator("textarea")
        .fill(JSON.stringify(expectedBody.payload));
      assert.equal(
        await modal
          .getByRole("checkbox", {
            name: "Require approval before this job can run",
            exact: true,
          })
          .isChecked(),
        false,
        "Native lane must not silently depend on unapproved jobs",
      );
      assert.equal(
        await modal
          .getByRole("button", { name: "Create job", exact: true })
          .isEnabled(),
        true,
      );
      return modal;
    };
    let modal = await fill();
    await modal.getByRole("button", { name: "Cancel", exact: true }).click();
    await modal.waitFor({ state: "hidden" });
    assert.equal(
      writes,
      0,
      "Cancelling native job form must not mutate any CertOps route",
    );
    assert.ok(
      isDeepStrictEqual(await snapshots(), baseline),
      "Cancelled native form created a job",
    );
    modal = await fill();
    const responsePromise = page.waitForResponse(
      (response) => {
        try {
          return (
            response.request().method() === "POST" &&
            new URL(response.url()).origin === new URL(apiOrigin).origin &&
            new URL(response.url()).pathname ===
              `/api/v1/workspaces/${workspaceId}/certops/jobs`
          );
        } catch {
          return false;
        }
      },
      { timeout: 30000 },
    );
    await modal
      .getByRole("button", { name: "Create job", exact: true })
      .click();
    const response = await responsePromise;
    assert.equal(
      response.status(),
      201,
      "Actual browser job admission must succeed",
    );
    const result = await response.json();
    assert.match(result?.job?.id, UUID);
    // Record exact ownership immediately, before further assertions or waits.
    registerOwnedJob(result.job.id);
    assert.equal(writes, 1);
    assert.equal(matchingWrites, 1);
    assert.equal(wrongWrite, false);
    const rows = (
      await pool.query(
        "SELECT id,operation,source,subject_id,requested_by_user_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [workspaceId, result.job.id],
      )
    ).rows;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].operation, expectedBody.operation);
    assert.equal(rows[0].source, "api");
    assert.match(rows[0].subject_id, UUID);
    if (expectedBody.operation === "renew")
      assert.equal(rows[0].subject_id, expectedBody.subjectId);
    assert.ok(
      isDeepStrictEqual(
        (await snapshots()).filter((id) => !baseline.includes(id)),
        [result.job.id],
      ),
      "Browser admission created unexpected jobs",
    );
    await modal.getByRole("button", { name: "Close", exact: true }).click();
    await modal.waitFor({ state: "hidden" });
    return {
      jobId: result.job.id,
      certificateId: rows[0].subject_id,
      operation: expectedBody.operation,
      requestSha256: crypto
        .createHash("sha256")
        .update(JSON.stringify(expectedBody))
        .digest("hex"),
      cancelWrites: 0,
      confirmWrites: 1,
      publicJob: result.job,
    };
  } catch {
    throw new Error(
      "Actual native ACME browser job admission failed; preserve registered operation ownership",
    );
  } finally {
    page.off("request", listener);
  }
}
module.exports = {
  REQUIRED_SOURCES,
  verifyRequest,
  isWrite,
  validateInput,
  admitBrowserJob,
};
