/**
 * Qualification notes: Automatic renewal after identity retirement
 * The trusted manual `certops-scheduler-capacity-qualification.yml` workflow runs
 * `certops-retired-scheduler-e2e.test.js` sequentially after the existing capacity and toggle fixtures
 * have removed their resources. It requires an exclusive API/PostgreSQL database, OpenSSL and
 * `CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1`.
 *
 * Expected refusal: `CERTOPS_CERTIFICATE_NOT_RENEWABLE`.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/** Exclusive real API/PostgreSQL scheduler retirement qualification.
 * Imports real short-lived certificates, provisions explicit complete local
 * execution profiles, then uses public management/retirement routes. Owned row
 * locks force cache lag without changing data. No CA execution or time rewriting.
 * Run with CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1 on an empty disposable stack. */
"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture"),
  scheduler = require("../../apps/api/services/certops/renewalScheduler"),
  { createCertificateJob } = require("../../apps/api/services/certops/jobs"),
  {
    buildRenewalJobPayload,
  } = require("../../apps/api/services/certops/renewalProfile");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = [
  "retired-scheduler-active-positive",
  "retired-scheduler-real-retirement-cache-lag",
  "retired-scheduler-authoritative-scan",
  "retired-scheduler-final-admission",
  "retired-scheduler-owned-cleanup",
];
module.exports = { scenarios };
test(
  "automatic renewal cannot revive an authoritative retired identity behind a stale source",
  { timeout: 120000 },
  async (t) => {
    if (
      !process.env.CERTOPS_CSR_API_URL &&
      process.env.CERTOPS_E2E_REQUIRED !== "1"
    ) {
      // skip-reason: no-host - requires exclusive disposable authenticated API PostgreSQL and OpenSSL fixture
      t.skip("Exclusive disposable scheduler stack required");
      return;
    }
    assert.equal(process.env.CERTOPS_SCHEDULER_EXCLUSIVE_STACK, "1");
    const fixture = await createApiFixture(process.env.CERTOPS_CSR_API_URL),
      directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "certops-retired-scheduler-"),
      ),
      items = [];
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
      source = "tests/e2e/certops-retired-scheduler-e2e.test.js";
    const gate = createHostGate({
      suite: "retired-identity-scheduler-api",
      strict: true,
      evidenceLevel: "integration",
      reportPath: process.env.CERTOPS_RETIRED_SCHEDULER_REPORT,
      fixtureSource: {
        file: source,
        sha256: crypto
          .createHash("sha256")
          .update(fs.readFileSync(__filename))
          .digest("hex"),
      },
      requiredCapabilities: ["api", "postgres", "openssl", "exclusiveStack"],
      probeCapabilities: () => ({
        api: { available: true },
        postgres: { available: true },
        openssl: { available: spawnSync("openssl", ["version"]).status === 0 },
        exclusiveStack: {
          available: process.env.CERTOPS_SCHEDULER_EXCLUSIVE_STACK === "1",
        },
      }),
    });
    gate.report.fixtureSources = [
      "tests/e2e/helpers/certops-api-fixture.js",
      "apps/api/services/certops/renewalScheduler.js",
      "apps/api/services/certops/jobs.js",
    ].map((file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
        .digest("hex"),
    }));
    gate.report.fixturePrerequisite =
      "Complete linked local profile/key mode SQL prerequisites only; real public import, management binding, retirement and actual SQL NOW scheduler; no seeded jobs, timestamps or native execution";
    const jobs = async () =>
      (
        await fixture.pool.query(
          "SELECT id,source,status,subject_id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows;
    const sweep = () =>
      scheduler.runRenewalSchedulerSweep({
        dbPool: fixture.pool,
        env: process.env,
        batchSize: 20,
      });
    let ready = false,
      failure;
    try {
      await gate.preflight();
      ready = true;
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT COUNT(*)::int AS n FROM certops_management_periods WHERE workspace_id<>$1 AND ended_at IS NULL AND automation_enabled=TRUE",
            [fixture.workspaceId],
          )
        ).rows[0].n,
        0,
        "Global sweep requires an exclusive stack",
      );
      assert.equal(
        (
          await fixture.request(`${prefix}/settings`, "PUT", {
            certOpsRequireApprovalAlways: true,
            reason: "Owned retirement scheduler qualification",
          })
        ).status,
        200,
      );
      for (let i = 0; i < 3; i++) {
        const host = `retired-scheduler-${i}.example.test`;
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
              `${i}.key`,
              "-out",
              `${i}.crt`,
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
        const pem = fs.readFileSync(path.join(directory, `${i}.crt`), "utf8"),
          fingerprint = new crypto.X509Certificate(pem).fingerprint256
            .replace(/:/g, "")
            .toLowerCase();
        const imported = await fixture.request(
          `${prefix}/certificates`,
          "POST",
          { certificatePem: pem },
        );
        assert.equal(imported.status, 201);
        const id = imported.body.items[0].id;
        const target = {
            type: "domain",
            reference: host,
            certPath: path.join(directory, `${i}-deployed.pem`),
          },
          profile = {
            schemaVersion: 1,
            profileId: null,
            profileName: `Retired scheduler ${i}`,
            sanPolicy: { mode: "exact", sans: [host], allowWildcards: false },
            keyAlgorithm: "rsa",
            keySize: 2048,
            keyRotationPolicy: { rotateOnRenew: true },
            preferredChain: null,
            ca: {
              endpoint: "https://retired-scheduler.invalid/directory",
              accountRef: null,
              eabRef: null,
            },
            acme: { kind: "certbot", commandRef: "owned.retired" },
            dns: { provider: "cloudflare", zone: "example.test" },
            target,
            deploymentTargets: [target],
            verification: { host, port: 443, requireMatch: true },
          };
        const profileId = (
          await fixture.pool.query(
            "INSERT INTO certificate_profiles(workspace_id,name,key_mode,public_metadata,created_by) VALUES($1,$2,'agent-local',$3,$4) RETURNING id",
            [
              fixture.workspaceId,
              `Retired scheduler ${i}`,
              JSON.stringify({ renewalProfile: profile }),
              fixture.userId,
            ],
          )
        ).rows[0].id;
        await fixture.pool.query(
          "UPDATE managed_certificates SET key_mode='agent-local',profile_id=$3 WHERE workspace_id=$1 AND id=$2",
          [fixture.workspaceId, id, profileId],
        );
        const period = (
          await fixture.pool.query(
            "SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
            [fixture.workspaceId, id],
          )
        ).rows[0];
        assert.ok(period);
        // Only the first active control is scheduled yet. Other sources are enabled
        // publicly immediately before retirement, so no old idempotency row can hide admission.
        if (i === 0)
          assert.equal(
            (
              await fixture.request(
                `${prefix}/sources/${id}/replace-management`,
                "POST",
                {
                  periodId: period.id,
                  renewalProfileId: profileId,
                  automationEnabled: true,
                },
              )
            ).status,
            201,
          );
        const identity = (
          await fixture.pool.query(
            "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
            [fixture.workspaceId, fingerprint],
          )
        ).rows[0];
        if (i > 0)
          assert.equal(
            (
              await fixture.request(
                `${prefix}/profiles/${profileId}`,
                "PATCH",
                { autoRenewEnabled: false },
              )
            ).status,
            200,
          );
        items.push({
          id,
          identityId: identity.id,
          fingerprint,
          status: i === 2 ? "decommissioned" : "revoked",
          profileId,
        });
      }
      await gate.scenario(scenarios[0], async () => {
        const result = await sweep();
        assert.equal(result.errors.length, 0);
        assert.equal(result.created, 1);
        assert.equal(result.scanned, 1);
        const rows = await jobs();
        assert.equal(rows.length, 1);
        assert.equal(rows[0].subject_id, items[0].id);
        assert.equal(rows[0].source, "automation");
        assert.equal(rows[0].status, "pending_approval");
        assert.equal(
          (
            await fixture.request(
              `${prefix}/jobs/${rows[0].id}/reject`,
              "POST",
              { reason: "Owned active automatic admission observed" },
            )
          ).status,
          200,
        );
        assert.equal(
          (
            await fixture.request(
              `${prefix}/certificate-identities/${items[0].identityId}/retire`,
              "POST",
              {
                status: "revoked",
                expectedFingerprintSha256: items[0].fingerprint,
                reason: "Owned active control retired",
                acknowledgeUncertainty: true,
              },
            )
          ).status,
          200,
        );
      });
      await gate.scenario(scenarios[1], async () => {
        for (const item of items.slice(1)) {
          assert.equal(
            (
              await fixture.request(
                `${prefix}/profiles/${item.profileId}`,
                "PATCH",
                { autoRenewEnabled: true },
              )
            ).status,
            200,
          );
          const period = (
            await fixture.pool.query(
              "SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
              [fixture.workspaceId, item.id],
            )
          ).rows[0];
          assert.equal(
            (
              await fixture.request(
                `${prefix}/sources/${item.id}/replace-management`,
                "POST",
                {
                  periodId: period.id,
                  renewalProfileId: item.profileId,
                  automationEnabled: true,
                },
              )
            ).status,
            201,
          );
          const scanned = await scheduler.findCertificatesDueForRenewal({
            db: fixture.pool,
            thresholdDays: 30,
            batchSize: 20,
            terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES,
          });
          item.scanned = scanned.find((row) => row.id === item.id);
          assert.ok(item.scanned);
        }
        const lock = await fixture.pool.connect();
        try {
          await lock.query("BEGIN");
          assert.equal(
            (
              await lock.query(
                "SELECT id FROM managed_certificates WHERE workspace_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR NO KEY UPDATE",
                [fixture.workspaceId, items.slice(1).map((x) => x.id)],
              )
            ).rows.length,
            2,
          );
          for (const item of items.slice(1))
            assert.equal(
              (
                await fixture.request(
                  `${prefix}/certificate-identities/${item.identityId}/retire`,
                  "POST",
                  {
                    status: item.status,
                    expectedFingerprintSha256: item.fingerprint,
                    reason: "Owned source cache lag",
                    acknowledgeUncertainty: true,
                  },
                )
              ).status,
              200,
            );
        } finally {
          try {
            await lock.query("ROLLBACK");
          } finally {
            lock.release();
          }
        }
        for (const item of items.slice(1)) {
          const row = (
            await fixture.pool.query(
              "SELECT mc.status,ci.lifecycle_status FROM managed_certificates mc JOIN certops_certificate_identities ci ON ci.workspace_id=mc.workspace_id AND ci.fingerprint_sha256=certops_normalize_fingerprint(mc.fingerprint_sha256) WHERE mc.workspace_id=$1 AND mc.id=$2",
              [fixture.workspaceId, item.id],
            )
          ).rows[0];
          assert.equal(row.lifecycle_status, item.status);
          assert.ok(!["revoked", "decommissioned"].includes(row.status));
        }
        assert.equal((await jobs()).length, 1);
      });
      await gate.scenario(scenarios[2], async () => {
        const before = await jobs();
        const result = await sweep();
        assert.equal(result.errors.length, 0);
        assert.equal(result.created, 0);
        assert.equal(result.scanned, 0);
        assert.deepEqual(await jobs(), before);
        for (const item of items.slice(1))
          assert.equal(
            (
              await fixture.request(
                `${prefix}/profiles/${item.profileId}`,
                "PATCH",
                { autoRenewEnabled: false },
              )
            ).status,
            200,
          );
        const disabled = await sweep();
        assert.equal(disabled.errors.length, 0);
        assert.equal(
          disabled.skippedAutoRenewDisabled,
          0,
          "Retired identities are not disabled-renewal candidates",
        );
        assert.equal(disabled.created, 0);
        for (const item of items.slice(1))
          assert.equal(
            (
              await fixture.request(
                `${prefix}/profiles/${item.profileId}`,
                "PATCH",
                { autoRenewEnabled: true },
              )
            ).status,
            200,
          );
        assert.deepEqual(await jobs(), before);
      });
      await gate.scenario(scenarios[3], async () => {
        const before = await jobs();
        for (const item of items.slice(1))
          for (const source of ["api", "automation"]) {
            const payload = buildRenewalJobPayload({
              certificate: item.scanned,
            });
            const client = await fixture.pool.connect();
            try {
              await client.query("BEGIN");
              await assert.rejects(
                createCertificateJob({
                  client,
                  workspaceId: fixture.workspaceId,
                  operation: "renew",
                  source,
                  subjectType: "managed_certificate",
                  subjectId: item.id,
                  idempotencyKey: crypto.randomUUID(),
                  payload,
                  env: process.env,
                }),
                { code: "CERTOPS_CERTIFICATE_NOT_RENEWABLE" },
              );
            } finally {
              try {
                await client.query("ROLLBACK");
              } finally {
                client.release();
              }
            }
          }
        assert.deepEqual(await jobs(), before);
      });
    } catch (error) {
      failure = error;
    } finally {
      const cleanup = async () => {
        try {
          await fixture.cleanup();
        } finally {
          fs.rmSync(directory, { recursive: true, force: true });
        }
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
              "Retired scheduler and cleanup failed",
            )
          : error;
      }
      if (failure) throw failure;
    }
  },
);
