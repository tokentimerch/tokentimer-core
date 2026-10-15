"use strict";
/** Real public issue jobs with owned HTTPS refusal before CA order/finalization.
 * Genuine native clients, signed production admission, CA observations and DNS
 * cleanup are required; this never labels a proxy response as a CA response. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { identifiersDigest } = require("./certops-acme-transparent-proxy");
const SCOPE = "native-public-acme-client-owned-stage-transport-refusal";
const STAGES = ["new-order", "finalize"];
const SCENARIOS = STAGES.map((stage) => `real-acme-${stage}-transport-refusal`);
const FLAGS = [
  "actualPublicIssueJobs",
  "actualClientReachedBothStages",
  "unmodifiedSignedRequests",
  "pinnedUpstreamTls",
  "ownedOrdersAndAuthorizationsBound",
  "noFaultStageForwarded",
  "noLeafInstalledOrActivated",
  "ownedDnsValuesCleaned",
  "realCaIssuanceRecovered",
  "trustedPositiveTlsVerified",
];
const REQUIRED_SOURCES = [
  "tests/e2e/helpers/certops-acme-stage-faults.js",
  "tests/e2e/helpers/certops-acme-transparent-proxy.js",
  "tests/e2e/acme-real-journey.js",
  "scripts/certops-real-acme.js",
  ".github/workflows/certops-real-acme.yml",
  "packages/agent/src/acme/index.js",
  "packages/agent/src/index.js",
  "apps/api/routes/certops.js",
  "apps/api/services/certops/jobs.js",
  "tests/e2e/helpers/certops-acme-key-reuse.js",
  "packages/agent/src/keys/index.js",
  "packages/agent/src/signing/index.js",
  "apps/api/services/certops/renewalProfileAdmin.js",
  "apps/api/services/certops/renewalProfile.js",
  "apps/api/services/certops/renewalScheduler.js",
  "apps/api/services/certops/agentDispatch.js",
  "scripts/certops-stack-reporter.js",
  "scripts/certops-stack-report.js",
  "packages/agent/src/acme/command.js",
  "packages/agent/src/exec-env.js",
  "packages/agent/src/policy/index.js",
  "packages/agent/src/dns/index.js",
  "packages/agent/src/dns/internal.js",
  "packages/agent/src/dns/lockfile.js",
  "packages/agent/src/dns/hook.js",
  "packages/agent/src/dns/zone.js",
  "packages/agent/src/dns/propagate.js",
  "packages/agent/src/dns/providers/pebble-challtestsrv.js",
  "packages/agent/bin/tokentimer-agent.js",
  "packages/agent/bin/certops-dns-hook.js",
  "packages/agent/bin/dns_certops.sh",
];
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const digest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function verifyCases(cases) {
  assert.ok(Array.isArray(cases) && cases.length === 2);
  for (const [index, row] of cases.entries()) {
    assert.deepEqual(
      Object.keys(row).sort(),
      [
        "stage",
        "jobId",
        "certificateId",
        "refusedRequests",
        "forwardedFaultRequests",
        "acceptedAccounts",
        "acceptedOrders",
        "authorizationCount",
        "validAuthorizationCount",
        "identifiersSha256",
      ].sort(),
    );
    assert.equal(row.stage, STAGES[index]);
    assert.ok(uuid(row.jobId) && uuid(row.certificateId));
    for (const name of ["refusedRequests", "acceptedAccounts"])
      assert.ok(
        Number.isInteger(row[name]) && row[name] >= 1 && row[name] <= 10000,
      );
    assert.equal(row.forwardedFaultRequests, 0);
    assert.ok(digest(row.identifiersSha256));
    if (index === 0) {
      assert.equal(row.acceptedOrders, 0);
      assert.equal(row.authorizationCount, 0);
      assert.equal(row.validAuthorizationCount, 0);
    } else {
      assert.ok(
        Number.isInteger(row.acceptedOrders) &&
          row.acceptedOrders >= 1 &&
          row.acceptedOrders <= 32,
      );
      assert.ok(
        Number.isInteger(row.authorizationCount) &&
          row.authorizationCount >= 1 &&
          row.authorizationCount <= 16,
      );
      assert.equal(row.validAuthorizationCount, row.authorizationCount);
    }
  }
  assert.equal(new Set(cases.map((row) => row.jobId.toLowerCase())).size, 2);
  assert.equal(new Set(cases.map((row) => row.certificateId.toLowerCase())).size, 2);
  assert.equal(cases[0].identifiersSha256, cases[1].identifiersSha256);
  return true;
}
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "client",
      "failureOrigin",
      "cases",
      "positiveJobId",
      "positiveFingerprint",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.ok(["certbot", "acme.sh"].includes(value.client));
  assert.equal(value.failureOrigin, "owned-proxy-before-upstream-forwarding");
  verifyCases(value.cases);
  assert.ok(uuid(value.positiveJobId) && digest(value.positiveFingerprint));
  assert.ok(
    value.cases.every(
      (row) => row.jobId.toLowerCase() !== value.positiveJobId.toLowerCase(),
    ),
  );
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
async function qualifyStageRefusals(context) {
  const {
    proxy,
    publicSession,
    pool,
    workspaceId,
    requestedNames,
    domain,
    workDir,
    commandRef,
    caEndpoint,
    acmeKind,
    eabRef,
    agent,
    ownedJobIds,
    ownedCertificateIds,
    waitUntil,
    verifyDnsCleanup,
    runScenario,
  } = context;
  assert.equal(process.platform, "linux");
  assert.ok(["certbot", "acme.sh"].includes(acmeKind));
  const cases = [],
    identifiersSha256 = identifiersDigest(
      requestedNames.map((value) => ({ type: "dns", value })),
    );
  for (const [index, stage] of STAGES.entries())
    await runScenario(SCENARIOS[index], async () => {
      const before = proxy.snapshot(),
        certPath = path.join(workDir, "deployed", `${stage}-refused.pem`);
      assert.equal(fs.existsSync(certPath), false);
      proxy.setFailure(stage);
      try {
        const admitted = await publicSession.request(
          `/api/v1/workspaces/${workspaceId}/certops/jobs`,
          "POST",
          {
            operation: "issue",
            idempotencyKey: crypto.randomUUID(),
            payload: {
              sans: requestedNames,
              target: { type: "domain", reference: domain },
              certPath,
              commandRef,
              caEndpoint,
              acmeKind,
              ...(eabRef ? { eabRef } : {}),
              dnsProvider: "pebble-challtestsrv",
              dnsZone: "example.test",
            },
          },
        );
        assert.equal(admitted.status, 201);
        const job = admitted.body.job;
        assert.ok(uuid(job.id) && uuid(job.subjectId));
        ownedJobIds.push(job.id);
        ownedCertificateIds.push(job.subjectId);
        await waitUntil(async () => {
          assert.equal(agent.exitCode, null);
          assert.equal(agent.signalCode, null);
          const row = (
            await pool.query(
              "SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
              [workspaceId, job.id],
            )
          ).rows[0];
          assert.ok(
            !["succeeded", "dry_run_complete", "cancelled"].includes(
              row?.status,
            ),
            "Transport-refused native issue must not succeed",
          );
          return row?.status === "failed";
        });
        const after = proxy.snapshot();
        assert.equal(after.transportFailed, false);
        const refusedRequests =
          after.perStage[stage].refused - before.perStage[stage].refused;
        const forwardedFaultRequests =
          after.perStage[stage].forwarded - before.perStage[stage].forwarded;
        assert.ok(refusedRequests >= 1);
        assert.equal(forwardedFaultRequests, 0);
        assert.ok(after.acceptedAccounts >= 1);
        assert.equal(after.issuedResponses, before.issuedResponses);
        assert.equal(fs.existsSync(certPath), false);
        const certificate = (
          await pool.query(
            "SELECT status FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
            [workspaceId, job.subjectId],
          )
        ).rows[0];
        assert.ok(certificate && certificate.status !== "active");
        await verifyDnsCleanup();
        const row = {
          stage,
          jobId: job.id,
          certificateId: job.subjectId,
          refusedRequests,
          forwardedFaultRequests,
          acceptedAccounts: after.acceptedAccounts,
          acceptedOrders: after.acceptedOrders - before.acceptedOrders,
          authorizationCount: 0,
          validAuthorizationCount: 0,
          identifiersSha256,
        };
        if (stage === "finalize") {
          const actual = after.lastRefusedFinalize;
          assert.ok(actual?.knownOrder && actual.allAuthorizationsValid);
          assert.equal(actual.identifiersSha256, identifiersSha256);
          row.authorizationCount = actual.authorizationCount;
          row.validAuthorizationCount = actual.validAuthorizationCount;
        }
        cases.push(row);
      } finally {
        proxy.setFailure(null);
      }
    });
  verifyCases(cases);
  return cases;
}
function completeProof({
  cases,
  client,
  proxy,
  positiveJobId,
  certificatePem,
  trustedPeerFingerprint,
  requestedNames,
}) {
  verifyCases(cases);
  const leaf = new crypto.X509Certificate(certificatePem),
    positiveFingerprint = crypto
      .createHash("sha256")
      .update(leaf.raw)
      .digest("hex");
  assert.equal(
    trustedPeerFingerprint.replaceAll(":", "").toLowerCase(),
    positiveFingerprint,
  );
  const actualNames = leaf.subjectAltName.split(/,\s*/).map((name) => {
    assert.ok(name.startsWith("DNS:"));
    return { type: "dns", value: name.slice(4) };
  });
  assert.equal(identifiersDigest(actualNames), cases[0].identifiersSha256);
  assert.equal(
    identifiersDigest(requestedNames.map((value) => ({ type: "dns", value }))),
    cases[0].identifiersSha256,
  );
  const observed = proxy.snapshot();
  assert.equal(observed.transportFailed, false);
  assert.ok(
    observed.forwardedFinalizations >= 1 &&
      observed.issuedResponses >= 1 &&
      observed.unchangedBodies >= 1,
  );
  const proof = {
    schemaVersion: 1,
    scope: SCOPE,
    client,
    failureOrigin: "owned-proxy-before-upstream-forwarding",
    cases,
    positiveJobId,
    positiveFingerprint,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  STAGES,
  SCENARIOS,
  FLAGS,
  REQUIRED_SOURCES,
  verifyCases,
  verifyProof,
  qualifyStageRefusals,
  completeProof,
};
