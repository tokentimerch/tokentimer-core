/**
 * Approval/retirement race qualification through real public API and registered claims.
 * Complete linked agent-local profiles are explicit SQL prerequisites; all certificates,
 * jobs, approvals and retirement transitions use public routes. A protocol-only active
 * claim proves routing/signature eligibility, not installed-agent or CA execution.
 * Requires disposable API/PostgreSQL; reports and cleanup are owned by this suite.
 */
"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture"),
  { createRegisteredAgent } = require("./helpers/certops-registered-agent"),
  { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = [
  "retirement-approval-active-signed-control",
  "retirement-before-approval-refusal",
  "retirement-after-approval-cancels",
  "retirement-approval-concurrent-revocation",
  "retirement-approval-concurrent-decommission",
  "retirement-approval-dispatch-fence",
  "retirement-approval-owned-cleanup",
];
module.exports = { scenarios };
test(
  "operator retirement fences concurrent approvals and actual registered-agent dispatch",
  { timeout: 180000 },
  async (t) => {
    const baseUrl = process.env.CERTOPS_CSR_API_URL;
    if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
      // skip-reason: no-host - requires disposable authenticated API PostgreSQL OpenSSL and registered protocol claims
      t.skip("Disposable API fixture required");
      return;
    }
    assert.ok(baseUrl);
    const fixture = await createApiFixture(baseUrl),
      directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "certops-retire-approval-"),
      ),
      retired = [];
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
      source = "tests/e2e/certops-retirement-approval-e2e.test.js";
    const gate = createHostGate({
      suite: "retirement-approval-api",
      strict: true,
      evidenceLevel: "integration",
      reportPath: process.env.CERTOPS_RETIREMENT_APPROVAL_REPORT,
      fixtureSource: {
        file: source,
        sha256: crypto
          .createHash("sha256")
          .update(fs.readFileSync(__filename))
          .digest("hex"),
      },
      requiredCapabilities: ["api", "postgres", "openssl"],
      probeCapabilities: () => ({
        api: { available: true },
        postgres: { available: true },
        openssl: { available: spawnSync("openssl", ["version"]).status === 0 },
      }),
    });
    gate.report.fixtureSources = [
      "tests/e2e/helpers/certops-api-fixture.js",
      "tests/e2e/helpers/certops-registered-agent.js",
      "apps/api/services/certops/certificateIdentity.js",
      "apps/api/services/certops/agentDispatch.js",
    ].map((file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
        .digest("hex"),
    }));
    gate.report.fixturePrerequisite =
      "Complete linked agent-local profile/key-mode prerequisites only; all jobs/approvals/retirements and actual signed claims are public. Active claim completion is a protocol-reported failure without host execution; no native certificate outcome is claimed.";
    const names = [
      "control",
      "before",
      "after",
      ...Array.from({ length: 3 }, (_, i) => `revoke-race-${i}`),
      ...Array.from({ length: 3 }, (_, i) => `decomm-race-${i}`),
    ];
    let approver,
      agent,
      ready = false,
      failure;
    const row = async (id) =>
      (
        await fixture.pool.query(
          "SELECT status,attempt_count,payload,approved_payload_hash FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [fixture.workspaceId, id],
        )
      ).rows[0];
    const claim = async () => {
      const result = await agent.machine("jobs/claim", "claim", {
        maxJobs: 10,
        supportedActions: ["renew"],
        supportedDnsProviders: ["cloudflare"],
      });
      assert.equal(result.status, 200);
      return result.body.jobs;
    };
    const approve = (item) =>
      approver.request(`${prefix}/jobs/${item.jobId}/approve`, "POST", {
        reason: "Independent approver of owned renewal",
      });
    const retire = (item, status) =>
      fixture.request(
        `${prefix}/certificate-identities/${item.identityId}/retire`,
        "POST",
        {
          status,
          expectedFingerprintSha256: item.fingerprint,
          reason: "Owned retirement approval boundary",
          acknowledgeUncertainty: true,
        },
      );
    const create = async (name) => {
      const host = `${name}.example.test`;
      assert.equal(
        spawnSync(
          "openssl",
          [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            `${name}.key`,
            "-out",
            `${name}.crt`,
            "-days",
            "2",
            "-subj",
            `/CN=${host}`,
            "-addext",
            `subjectAltName=DNS:${host}`,
          ],
          { cwd: directory, stdio: "ignore", timeout: 20000 },
        ).status,
        0,
      );
      const pem = fs.readFileSync(path.join(directory, `${name}.crt`), "utf8"),
        fingerprint = new crypto.X509Certificate(pem).fingerprint256
          .replace(/:/g, "")
          .toLowerCase();
      const imported = await fixture.request(`${prefix}/certificates`, "POST", {
        certificatePem: pem,
      });
      assert.equal(imported.status, 201);
      const certificateId = imported.body.items[0].id;
      const identityId = (
        await fixture.pool.query(
          "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
          [fixture.workspaceId, fingerprint],
        )
      ).rows[0].id;
      const target = {
          type: "domain",
          reference: host,
          certPath: path.join(directory, `${name}-deployed.crt`),
        },
        profile = {
          schemaVersion: 1,
          profileId: null,
          profileName: name,
          sanPolicy: { mode: "exact", sans: [host], allowWildcards: false },
          keyAlgorithm: "rsa",
          keySize: 2048,
          keyRotationPolicy: { rotateOnRenew: true },
          preferredChain: null,
          ca: {
            endpoint: `https://${name}.invalid/directory`,
            accountRef: null,
            eabRef: null,
          },
          acme: { kind: "certbot", commandRef: "owned.retire-race" },
          dns: { provider: "cloudflare", zone: "example.test" },
          deploymentTargets: [target],
          target,
          verification: { host, port: 443, requireMatch: true },
        };
      const profileId = (
        await fixture.pool.query(
          "INSERT INTO certificate_profiles(workspace_id,name,key_mode,public_metadata,created_by) VALUES($1,$2,'agent-local',$3,$4) RETURNING id",
          [
            fixture.workspaceId,
            name,
            JSON.stringify({ renewalProfile: profile }),
            fixture.userId,
          ],
        )
      ).rows[0].id;
      await fixture.pool.query(
        "UPDATE managed_certificates SET key_mode='agent-local',profile_id=$3 WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, certificateId, profileId],
      );
      const response = await fixture.request(`${prefix}/jobs`, "POST", {
        operation: "renew",
        subjectId: certificateId,
        idempotencyKey: crypto.randomUUID(),
      });
      assert.equal(response.status, 201);
      assert.equal(response.body.job.status, "pending_approval");
      return {
        certificateId,
        identityId,
        fingerprint,
        jobId: response.body.job.id,
      };
    };
    const assertFenced = async (item, status) => {
      const jobs = await claim();
      assert.ok(
        !jobs.some((job) => (job.jobId || job.id) === item.jobId),
        "Retired renewal must not be dispatched",
      );
      assert.deepEqual(
        jobs,
        [],
        "No unrelated eligible work exists in this owned workspace",
      );
      const job = await row(item.jobId);
      assert.equal(job.attempt_count, 0);
      assert.ok(
        ["cancelled", "pending", "approved", "pending_approval"].includes(
          job.status,
        ),
      );
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT lifecycle_status FROM certops_certificate_identities WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, item.identityId],
          )
        ).rows[0].lifecycle_status,
        status,
      );
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT cert_lifecycle_status FROM tokens WHERE workspace_id=$1 AND id=(SELECT token_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2)",
            [fixture.workspaceId, item.certificateId],
          )
        ).rows[0].cert_lifecycle_status,
        status,
      );
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT count(*)::int n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_RETIRED' AND metadata->>'identityId'=$2",
            [fixture.workspaceId, item.identityId],
          )
        ).rows[0].n,
        1,
      );
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT count(*)::int n FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",
            [fixture.workspaceId, item.jobId],
          )
        ).rows[0].n,
        0,
      );
    };
    try {
      await gate.preflight();
      ready = true;
      approver = await createApiFixture(baseUrl);
      await fixture.pool.query(
        "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')",
        [fixture.workspaceId, approver.userId],
      );
      assert.equal(
        (
          await fixture.request(`${prefix}/settings`, "PUT", {
            certOpsRequireApprovalAlways: true,
            reason: "Owned retirement approval fixture",
          })
        ).status,
        200,
      );
      agent = await createRegisteredAgent(
        fixture,
        baseUrl,
        ["evidence-claim-binding-v1"],
        {
          declaredTargetSelectors: names.map((name) => `${name}.example.test`),
          declaredCommandProfileNames: ["owned.retire-race"],
          supportedDnsProviders: ["cloudflare"],
        },
      );
      await gate.scenario(scenarios[0], async () => {
        const item = await create("control");
        assert.equal((await approve(item)).status, 200);
        const jobs = await claim();
        assert.equal(jobs.length, 1);
        const job = jobs[0];
        assert.equal(job.jobId || job.id, item.jobId);
        assert.deepEqual(
          require("../../packages/agent/src/signing").verifyJobSignature({
            job,
            publicKeyPem: agent.signingPublicKeyPem,
            pinnedSigningKeyId: agent.signingKeyId,
          }),
          { allowed: true },
        );
        assert.equal((await row(item.jobId)).attempt_count, 1);
        const reported = await agent.machine("jobs/results", "result", {
          jobId: item.jobId,
          attemptId: job.attemptId,
          nonce: job.nonce,
          status: "failed",
          errorMessage:
            "Protocol-only claim control ended without native execution",
        });
        assert.equal(reported.status, 200);
      });
      await gate.scenario(scenarios[1], async () => {
        const item = await create("before");
        assert.equal((await retire(item, "revoked")).status, 200);
        assert.equal((await approve(item)).status, 409);
        assert.equal((await row(item.jobId)).status, "cancelled");
        retired.push({ ...item, status: "revoked" });
        await assertFenced(item, "revoked");
      });
      await gate.scenario(scenarios[2], async () => {
        const item = await create("after");
        assert.equal((await approve(item)).status, 200);
        assert.equal((await row(item.jobId)).status, "pending");
        assert.equal((await retire(item, "decommissioned")).status, 200);
        assert.equal((await row(item.jobId)).status, "cancelled");
        retired.push({ ...item, status: "decommissioned" });
        await assertFenced(item, "decommissioned");
      });
      for (const [scenario, status, prefixName] of [
        [scenarios[3], "revoked", "revoke-race"],
        [scenarios[4], "decommissioned", "decomm-race"],
      ])
        await gate.scenario(scenario, async () => {
          for (let index = 0; index < 3; index++) {
            const item = await create(`${prefixName}-${index}`);
            const [decision, retirement] = await Promise.all([
              approve(item),
              retire(item, status),
            ]);
            assert.equal(retirement.status, 200);
            assert.ok([200, 409].includes(decision.status));
            retired.push({ ...item, status });
            await assertFenced(item, status);
          }
        });
      await gate.scenario(scenarios[5], async () => {
        for (let index = 0; index < 3; index++)
          assert.deepEqual(await claim(), []);
        assert.equal(retired.length, 8);
        for (const item of retired) await assertFenced(item, item.status);
      });
    } catch (error) {
      failure = error;
    } finally {
      const cleanup = async () => {
        const errors = [];
        for (const owned of [fixture, approver].filter(Boolean))
          try {
            await owned.cleanup();
          } catch (error) {
            errors.push(error);
          }
        try {
          fs.rmSync(directory, { recursive: true, force: true });
        } catch (error) {
          errors.push(error);
        }
        if (errors.length)
          throw new AggregateError(
            errors,
            "Owned retirement approval cleanup failed",
          );
      };
      try {
        if (ready) {
          await gate.scenario(scenarios.at(-1), cleanup);
          await gate.finish({ requiredScenarios: scenarios });
        } else await cleanup();
      } catch (error) {
        failure = failure
          ? new AggregateError(
              [failure, error],
              "Retirement approval and cleanup failed",
            )
          : error;
      }
      if (failure) throw failure;
    }
  },
);
