"use strict";
/** Pure browser-job proof/decision controls; no browser, API, role change,
 * approval, CA, machine key or installed agent executes in this test. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  h = require("../tests/e2e/helpers/certops-adcs-browser-job-approval"),
  approval = require("../apps/api/services/certops/jobApprovals");
const ids = [
  "11111111-1111-1111-1111-111111111111",
  "22222222-2222-2222-2222-222222222222",
];
function proof() {
  return {
    scope: h.SCOPE,
    approvePosts: 2,
    cancelPosts: 0,
    rejectPosts: 1,
    rejectedJobId: "55555555-5555-5555-5555-555555555555",
    rejectedEnrollmentId: "66666666-6666-6666-6666-666666666666",
    rejectedPayloadHash: "e".repeat(64),
    rejectedCanonicalIntentHash: "f".repeat(64),
    caOfficerApprovalQualified: false,
    jobIds: ids,
    enrollmentIds: [
      "33333333-3333-3333-3333-333333333333",
      "44444444-4444-4444-4444-444444444444",
    ],
    payloadHashes: ["a".repeat(64), "b".repeat(64)],
    requestIds: ["17", "18"],
    fingerprints: ["c".repeat(64), "d".repeat(64)],
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
test("browser job approval refuses omitted facts and cannot qualify CA officer actions", () => {
  h.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const missing = proof();
    delete missing[key];
    assert.throws(() => h.verifyProof(missing), key);
  }
  for (const flag of h.FLAGS) {
    const value = proof();
    value[flag] = false;
    assert.throws(() => h.verifyProof(value));
  }
  for (const change of [
    { approvePosts: true },
    { cancelPosts: 1 },
    { caOfficerApprovalQualified: true },
    { requestIds: ["17", "4294967296"] },
    { jobIds: [ids[0], ids[0]] },
    { scope: "ca-officer-approval" },
    { rawApprovalPayload: "forbidden" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...change }));
});
test("browser approval proof is bound to both actual native capacity generations", () => {
  const value = proof(),
    capacity = {
      scope: require("../tests/e2e/helpers/certops-adcs-capacity").SCOPE,
      cap: 5,
      initialAccepted: 5,
      initialRefused: 1,
      ...Object.fromEntries(
        require("../tests/e2e/helpers/certops-adcs-capacity").FLAGS.map(
          (flag) => [flag, true],
        ),
      ),
      nativeCompleted: 2,
      ...Object.fromEntries(
        ["jobIds", "enrollmentIds", "requestIds", "fingerprints"].map((key) => [
          key,
          value[key],
        ]),
      ),
    };
  h.verifyCrossProof(value, capacity);
  const incomplete = { ...capacity };
  delete incomplete.freshConfirmedIssuer;
  assert.throws(() => h.verifyCrossProof(value, incomplete));
  for (const key of ["jobIds", "enrollmentIds", "requestIds", "fingerprints"]) {
    const wrong = { ...capacity, [key]: [...capacity[key]].reverse() };
    assert.throws(() => h.verifyCrossProof(value, wrong), key);
  }
  assert.throws(() =>
    h.verifyCrossProof(value, { ...capacity, nativeCompleted: 1 }),
  );
});
test("append-only decision independently binds exact actor, reason, payload and canonical intent", () => {
  const before = {
      operation: "adcs",
      subject_type: "managed_certificate",
      subject_id: ids[0],
      payload: {
        enrollmentId: ids[1],
        target: { reference: "owned.example.test" },
      },
    },
    reason = "Owned approval",
    row = {
      decision: "approved",
      approved_by_user_id: 7,
      reason,
      payload_hash: approval.computeJobPayloadApprovalHash(before.payload),
      canonical_intent_hash: approval.computeCanonicalIntentHash({
        operation: before.operation,
        subjectType: before.subject_type,
        subjectId: before.subject_id,
        payload: before.payload,
      }),
    };
  h.verifyDecision(row, before, 7, reason);
  for (const [key, value] of Object.entries({
    decision: "rejected",
    approved_by_user_id: 8,
    reason: "other",
    payload_hash: "0".repeat(64),
    canonical_intent_hash: "0".repeat(64),
  }))
    assert.throws(
      () => h.verifyDecision({ ...row, [key]: value }, before, 7, reason),
      key,
    );
  assert.throws(() =>
    h.verifyDecision(row, { ...before, subject_id: ids[1] }, 7, reason),
  );
});
test("source manifest binds actual supported job UI, route and approval service", () => {
  assert.equal(new Set(h.REQUIRED_SOURCES).size, h.REQUIRED_SOURCES.length);
  for (const file of h.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile());
  const source = fs.readFileSync(
    path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-adcs-browser-job-approval.js",
    ),
    "utf8",
  );
  assert.ok(source.includes('searchParams.set("q", jobId)'));
  assert.ok(source.includes("getByText(`${label} job`"));
  assert.equal(source.includes('getByRole("heading"'), false);
  assert.equal(h.REQUIRED_SCENARIOS.length, 2);
});

test("exact decision request permits only the owned origin/path and closed reason body", () => {
  const expected = {
      origin: "https://10.64.0.6",
      pathname: `/api/v1/workspaces/${ids[0]}/certops/jobs/${ids[1]}/approve`,
      reason: "Owned approval",
    },
    request = {
      url: expected.origin + expected.pathname,
      method: "POST",
      body: { reason: expected.reason },
    };
  assert.equal(h.verifyApprovalRequest(request, expected), true);
  for (const change of [
    { url: request.url + "?other=1" },
    { url: request.url + "#fragment" },
    { url: request.url.replace("https://", "https://user:password@") },
    { url: request.url.replace(ids[0], ids[1]) },
    { url: request.url + "/extra" },
    { url: request.url.replace("approve", "reject") },
    { method: "PATCH" },
    { body: { reason: expected.reason, privateTrace: "forbidden" } },
    { body: { reason: "other" } },
    { body: null },
    { body: "invalid" },
    { body: [] },
    { url: "malformed" },
  ])
    assert.equal(
      h.verifyApprovalRequest({ ...request, ...change }, expected),
      false,
    );
});
test("rejection keeps the genuine null-hash decision contract while preserving execution intent", () => {
  const before = {
      operation: "adcs",
      subject_type: "managed_certificate",
      subject_id: ids[0],
      payload: { enrollmentId: ids[1] },
    },
    current = {
      ...before,
      status: "rejected",
      error_code: "CERTOPS_APPROVAL_REJECTED",
      enrollment_state: "requested",
      request_id: null,
      claim_id: null,
      attempt_count: 0,
    },
    decision = {
      decision: "rejected",
      approved_by_user_id: 7,
      reason: "Owned reject",
      payload_hash: null,
      canonical_intent_hash: null,
    };
  h.verifyRejection(before, current, decision, 7, "Owned reject");
  for (const change of [
    { status: "pending" },
    { claim_id: ids[1] },
    { request_id: 17 },
    { attempt_count: 1 },
    { enrollment_state: "installed" },
    { payload: { enrollmentId: ids[0] } },
  ])
    assert.throws(() =>
      h.verifyRejection(
        before,
        { ...current, ...change },
        decision,
        7,
        "Owned reject",
      ),
    );
  for (const change of [
    { decision: "approved" },
    { approved_by_user_id: 8 },
    { reason: "other" },
    { payload_hash: "a".repeat(64) },
    { canonical_intent_hash: "b".repeat(64) },
  ])
    assert.throws(() =>
      h.verifyRejection(
        before,
        current,
        { ...decision, ...change },
        7,
        "Owned reject",
      ),
    );
});
