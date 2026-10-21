/**
 * Qualification notes: Terminal certificate renewal admission
 * `terminal-renewal-admission-api` verifies that public manual and bulk renewal cannot revive an
 * operator-retired identity. Seven mandatory scenarios use real authenticated API requests,
 * PostgreSQL, public certificate imports and independently trusted loopback TLS. Complete linked
 * agent-local renewal profiles/key mode are explicit SQL prerequisites. No jobs, certificate expiry or
 * observations are seeded.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Public renewal admission for terminal identities with complete stored profiles.
 * Uses real public imports/retirement/TLS rediscovery and PostgreSQL oracles. Complete
 * linked agent-local profiles/key mode are explicitly seeded prerequisites; no job,
 * certificate expiry or observation is seeded and no CA/native installation is claimed.
 * Run against an explicitly disposable API using CERTOPS_TERMINAL_RENEWAL_REPORT.
 */
"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  https = require("node:https"),
  tls = require("node:tls"),
  { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture"),
  { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = [
  "terminal-renewal-complete-profile-imports",
  "terminal-renewal-active-positive-control",
  "terminal-renewal-public-retirement",
  "terminal-renewal-authoritative-retirement-refusal",
  "terminal-renewal-trusted-tls-rediscovery",
  "terminal-renewal-manual-and-bulk-refusal",
  "terminal-renewal-owned-cleanup",
];
module.exports = { scenarios };
test(
  "public renew cannot revive retired fully profiled certificates after real rediscovery",
  { timeout: 120000 },
  async (t) => {
    if (
      !process.env.CERTOPS_CSR_API_URL &&
      process.env.CERTOPS_E2E_REQUIRED !== "1"
    ) {
      // skip-reason: no-host - requires disposable authenticated API PostgreSQL and OpenSSL TLS fixture
      t.skip("Disposable API fixture required");
      return;
    }
    assert.ok(process.env.CERTOPS_CSR_API_URL);
    const fixture = await createApiFixture(process.env.CERTOPS_CSR_API_URL),
      directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "certops-terminal-renew-"),
      ),
      items = [],
      servers = [];
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
      source = "tests/e2e/certops-terminal-renewal-e2e.test.js";
    const gate = createHostGate({
      suite: "terminal-renewal-admission-api",
      strict: true,
      evidenceLevel: "integration",
      reportPath: process.env.CERTOPS_TERMINAL_RENEWAL_REPORT,
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
      "apps/api/services/certops/jobs.js",
      "apps/api/routes/certops.js",
      "apps/api/services/certops/certificateIdentity.js",
    ].map((file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
        .digest("hex"),
    }));
    gate.report.fixturePrerequisite =
      "Complete linked agent-local renewal profile/key mode SQL prerequisites and an explicit owned source-row lock during public retirement; public active renew positive control, actual public retirement and independently trusted served TLS; no seeded jobs/observations/expiry or native CA execution";
    const jobs = async () =>
      (
        await fixture.pool.query(
          "SELECT to_jsonb(j) AS row FROM certificate_jobs j WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows;
    const state = async () => ({
      jobs: await jobs(),
      managedCertificates: (
        await fixture.pool.query(
          "SELECT to_jsonb(mc) AS row FROM managed_certificates mc WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows,
      profiles: (
        await fixture.pool.query(
          "SELECT to_jsonb(cp) AS row FROM certificate_profiles cp WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows,
      outbox: (
        await fixture.pool.query(
          "SELECT to_jsonb(o) AS row FROM certops_outbox o WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows,
      identities: (
        await fixture.pool.query(
          "SELECT id,fingerprint_sha256,lifecycle_status,lifecycle_reason,retired_at FROM certops_certificate_identities WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows,
      tokens: (
        await fixture.pool.query(
          "SELECT id,cert_lifecycle_status,expiration FROM tokens WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows,
      audits: (
        await fixture.pool.query(
          "SELECT id,action,metadata FROM audit_events WHERE workspace_id=$1 ORDER BY id",
          [fixture.workspaceId],
        )
      ).rows,
    });
    const assertRenewalRefused = async () => {
      const before = await state();
      for (const item of items) {
        const response = await fixture.request(`${prefix}/jobs`, "POST", {
          operation: "renew",
          subjectId: item.certificateId,
          idempotencyKey: crypto.randomUUID(),
        });
        assert.equal(response.status, 409);
        assert.equal(response.body.code, "CERTOPS_CERTIFICATE_NOT_RENEWABLE");
        const bulk = await fixture.request(
          `${prefix}/jobs/bulk-renew`,
          "POST",
          {
            certificateIds: [item.certificateId],
            idempotencyKey: crypto.randomUUID(),
          },
        );
        assert.equal(bulk.status, 200);
        assert.equal(bulk.body.results[0].ok, false);
        assert.equal(
          bulk.body.results[0].errorCode,
          "CERTOPS_CERTIFICATE_NOT_RENEWABLE",
        );
        assert.deepEqual(await state(), before);
      }
    };
    let ready = false,
      failure;
    try {
      await gate.preflight();
      ready = true;
      assert.equal(
        (
          await fixture.request(`${prefix}/settings`, "PUT", {
            certOpsRequireApprovalAlways: true,
            reason: "Owned terminal admission fixture",
          })
        ).status,
        200,
      );
      await gate.scenario(scenarios[0], async () => {
        for (const status of ["revoked", "decommissioned"]) {
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
                `${status}.key`,
                "-out",
                `${status}.crt`,
                "-days",
                "2",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
              ],
              { cwd: directory, stdio: "ignore", timeout: 20000 },
            ).status,
            0,
          );
          const pem = fs.readFileSync(path.join(directory, `${status}.crt`)),
            fingerprint = new crypto.X509Certificate(pem).fingerprint256
              .replace(/:/g, "")
              .toLowerCase();
          const response = await fixture.request(
            `${prefix}/certificates`,
            "POST",
            { certificatePem: pem.toString() },
          );
          assert.equal(response.status, 201);
          const certificate = response.body.items[0];
          const identity = (
            await fixture.pool.query(
              "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
              [fixture.workspaceId, fingerprint],
            )
          ).rows[0];
          assert.ok(identity);
          const target = {
              type: "domain",
              reference: "localhost",
              certPath: path.join(directory, `${status}-deployed.crt`),
            },
            profile = {
              schemaVersion: 1,
              profileId: null,
              profileName: `Terminal ${status}`,
              sanPolicy: {
                mode: "exact",
                sans: ["localhost", "127.0.0.1"],
                allowWildcards: false,
              },
              keyAlgorithm: "rsa",
              keySize: 2048,
              keyRotationPolicy: { rotateOnRenew: true },
              preferredChain: null,
              ca: {
                endpoint: "https://terminal-renew.invalid/directory",
                accountRef: null,
                eabRef: null,
              },
              acme: { kind: "certbot", commandRef: "owned.terminal" },
              dns: { provider: "cloudflare", zone: "example.test" },
              deploymentTargets: [target],
              target,
              verification: {
                host: "localhost",
                port: 443,
                requireMatch: true,
              },
            };
          const profileId = (
            await fixture.pool.query(
              "INSERT INTO certificate_profiles(workspace_id,name,key_mode,public_metadata,created_by) VALUES($1,$2,'agent-local',$3,$4) RETURNING id",
              [
                fixture.workspaceId,
                `Terminal ${status}`,
                JSON.stringify({ renewalProfile: profile }),
                fixture.userId,
              ],
            )
          ).rows[0].id;
          await fixture.pool.query(
            "UPDATE managed_certificates SET key_mode='agent-local',profile_id=$3 WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, certificate.id, profileId],
          );
          items.push({
            status,
            pem,
            fingerprint,
            certificateId: certificate.id,
            identityId: identity.id,
            tokenId: certificate.tokenId,
          });
        }
      });
      await gate.scenario(scenarios[1], async () => {
        for (const item of items) {
          const response = await fixture.request(`${prefix}/jobs`, "POST", {
            operation: "renew",
            subjectId: item.certificateId,
            idempotencyKey: crypto.randomUUID(),
          });
          assert.equal(response.status, 201);
          const job = (await jobs()).find(
            (row) => row.row.id === response.body.job.id,
          ).row;
          assert.equal(job.status, "pending_approval");
          assert.equal(job.payload.commandRef, "owned.terminal");
          assert.equal(
            (
              await fixture.request(`${prefix}/jobs/${job.id}/reject`, "POST", {
                reason: "Owned active admission positive control completed",
              })
            ).status,
            200,
          );
        }
      });
      await gate.scenario(scenarios[2], async () => {
        // A concurrent source writer may hold a managed-certificate row while
        // retirement deliberately skips that cache. The identity is authoritative.
        // Holding this owned lock changes no data and forces that supported path.
        const lock = await fixture.pool.connect();
        try {
          await lock.query("BEGIN");
          const held = await lock.query(
            "SELECT id FROM managed_certificates WHERE workspace_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR NO KEY UPDATE",
            [fixture.workspaceId, items.map((item) => item.certificateId)],
          );
          assert.equal(held.rows.length, items.length);
          for (const item of items) {
            const response = await fixture.request(
              `${prefix}/certificate-identities/${item.identityId}/retire`,
              "POST",
              {
                status: item.status,
                expectedFingerprintSha256: item.fingerprint,
                reason: "Owned terminal admission",
                acknowledgeUncertainty: true,
              },
            );
            assert.equal(response.status, 200);
          }
        } finally {
          try {
            await lock.query("ROLLBACK");
          } finally {
            lock.release();
          }
        }
      });
      await gate.scenario(scenarios[3], async () => {
        for (const item of items) {
          const row = (
            await fixture.pool.query(
              "SELECT mc.status,ci.lifecycle_status FROM managed_certificates mc JOIN certops_certificate_identities ci ON ci.workspace_id=mc.workspace_id AND ci.fingerprint_sha256=certops_normalize_fingerprint(mc.fingerprint_sha256) WHERE mc.workspace_id=$1 AND mc.id=$2",
              [fixture.workspaceId, item.certificateId],
            )
          ).rows[0];
          assert.equal(row.lifecycle_status, item.status);
          assert.ok(
            !["revoked", "decommissioned"].includes(row.status),
            "The fixture must exercise the intentionally stale source cache",
          );
          item.cachedStatus = row.status;
        }
        await assertRenewalRefused();
      });
      await gate.scenario(scenarios[4], async () => {
        for (const item of items) {
          const server = https.createServer(
            {
              key: fs.readFileSync(path.join(directory, `${item.status}.key`)),
              cert: item.pem,
            },
            (_request, response) => response.end("Owned terminal certificate"),
          );
          servers.push(server);
          await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(0, "127.0.0.1", resolve);
          });
          await new Promise((resolve, reject) => {
            const socket = tls.connect(
              {
                host: "127.0.0.1",
                port: server.address().port,
                servername: "localhost",
                ca: item.pem,
                rejectUnauthorized: true,
              },
              () => {
                try {
                  assert.equal(socket.authorized, true);
                  assert.equal(
                    socket
                      .getPeerCertificate()
                      .fingerprint256.replace(/:/g, "")
                      .toLowerCase(),
                    item.fingerprint,
                  );
                  resolve();
                } catch (error) {
                  reject(error);
                } finally {
                  socket.destroy();
                }
              },
            );
            socket.once("error", reject);
            socket.setTimeout(10000, () =>
              socket.destroy(new Error("Owned TLS oracle timeout")),
            );
          });
          const observed = await fixture.request(
            `/api/v1/workspaces/${fixture.workspaceId}/domains`,
            "POST",
            {
              url: `https://127.0.0.1:${server.address().port}`,
              health_check_enabled: false,
              check_interval: "1min",
            },
          );
          assert.equal(observed.status, 201);
          const detail = await fixture.request(
            `${prefix}/certificate-identities/${item.identityId}`,
          );
          assert.equal(detail.status, 200);
          assert.equal(detail.body.certificate.stillObserved, true);
          assert.equal(detail.body.certificate.lifecycleStatus, item.status);
          assert.equal(
            (
              await fixture.pool.query(
                "SELECT status FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
                [fixture.workspaceId, item.certificateId],
              )
            ).rows[0].status,
            item.cachedStatus,
          );
        }
      });
      await gate.scenario(scenarios[5], assertRenewalRefused);
    } catch (error) {
      failure = error;
    } finally {
      const cleanup = async () => {
        const errors = [];
        for (const server of servers)
          try {
            await new Promise((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve())),
            );
          } catch (error) {
            errors.push(error);
          }
        try {
          await fixture.cleanup();
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
            "Owned terminal renewal cleanup failed",
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
              "Terminal renewal and cleanup failed",
            )
          : error;
      }
      if (failure) throw failure;
    }
  },
);
