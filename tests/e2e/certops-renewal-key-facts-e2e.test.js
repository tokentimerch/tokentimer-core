/**
 * Qualification notes: Renewal public-key metadata correctness
 * The `renewal-key-facts-api` suite exercises seven mandatory named scenarios against a disposable
 * authenticated API/PostgreSQL fixture and actual OpenSSL RSA/EC public certificates. Signed agent
 * claims, evidence and result requests exercise the production renewal completion path. Complete
 * execution-profile and key-mode rows are explicit fixture prerequisites.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/** Real API/PostgreSQL renewal evidence cannot retain predecessor public-key facts.
 * Uses actual OpenSSL certificates and registered signed-claim/evidence/result
 * requests; complete local execution profile/key mode are explicit SQL prerequisites.
 * No installed agent, native issuance/custody, observation, expiry or job is fabricated. */
"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture"),
  { createRegisteredAgent } = require("./helpers/certops-registered-agent"),
  { createHostGate } = require("../../packages/agent/scripts/host-gate"),
  { verifyJobSignature } = require("../../packages/agent/src/signing");
const scenarios = [
  "renewal-key-facts-parsed-control",
  "renewal-key-facts-same-fingerprint-preserved",
  "renewal-key-facts-rotation-clears-predecessor",
  "renewal-key-facts-client-spki-not-authoritative",
  "renewal-key-facts-public-leaf-restores",
  "renewal-key-facts-result-replay-preserves",
  "renewal-key-facts-owned-cleanup",
];
const requiredSources = [
  "tests/e2e/certops-renewal-key-facts-e2e.test.js",
  "tests/e2e/helpers/certops-api-fixture.js",
  "tests/e2e/helpers/certops-registered-agent.js",
  "apps/api/services/certops/agentDispatch.js",
  "apps/api/services/certops/inventory.js",
  "apps/api/services/certops/parser.js",
];
module.exports = { scenarios, requiredSources };
test(
  "renewal certificate changes invalidate unproven predecessor key facts",
  { timeout: 150000 },
  async (t) => {
    const base = process.env.CERTOPS_CSR_API_URL;
    if (!base && process.env.CERTOPS_E2E_REQUIRED !== "1") {
      // skip-reason: no-host - requires disposable authenticated API PostgreSQL OpenSSL and signed agent claims
      t.skip("Disposable certificate API required");
      return;
    }
    assert.ok(base);
    const fixture = await createApiFixture(base);
    let directory;
    try {
      directory = fs.mkdtempSync(path.join(os.tmpdir(), "renewal-key-facts-"));
    } catch (error) {
      try {
        await fixture.cleanup();
      } catch (cleanup) {
        throw new AggregateError(
          [error, cleanup],
          "Fixture setup and cleanup failed",
        );
      }
      throw error;
    }
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
      host = "renewal-facts.example.test";
    const hash = (file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
        .digest("hex"),
    });
    const gate = createHostGate({
      suite: "renewal-key-facts-api",
      strict: true,
      evidenceLevel: "integration",
      reportPath: process.env.CERTOPS_RENEWAL_KEY_FACTS_REPORT,
      fixtureSource: hash(requiredSources[0]),
      requiredCapabilities: ["api", "postgres", "openssl"],
      probeCapabilities: () => ({
        api: { available: true },
        postgres: { available: true },
        openssl: { available: spawnSync("openssl", ["version"]).status === 0 },
      }),
    });
    gate.report.fixtureSources = requiredSources.map(hash);
    gate.report.fixturePrerequisite =
      "Complete linked local profile/key mode plus legacy fingerprint spelling only; protocol-reported completion, no native issuance or custody claim";
    let ready = false,
      primary,
      certificateId,
      agent,
      oldLeaf,
      newLeaf,
      lastResult;
    const facts = async () =>
      (
        await fixture.pool.query(
          "SELECT fingerprint_sha256,certificate_pem,spki_fingerprint_sha256,public_key_algorithm,public_key_size,signature_algorithm,serial_number,not_after,subject,public_metadata FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
          [fixture.workspaceId, certificateId],
        )
      ).rows[0];
    const make = (label, kind) => {
      const key = path.join(directory, label + ".key"),
        cert = path.join(directory, label + ".crt");
      assert.equal(
        spawnSync(
          "openssl",
          [
            "req",
            "-x509",
            "-newkey",
            kind,
            ...(kind === "ec"
              ? ["-pkeyopt", "ec_paramgen_curve:prime256v1"]
              : []),
            "-nodes",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "2",
            "-subj",
            `/CN=${host}`,
            "-addext",
            `subjectAltName=DNS:${host}`,
          ],
          { stdio: "ignore", timeout: 20000 },
        ).status,
        0,
      );
      const pem = fs.readFileSync(cert, "utf8"),
        parsed = new crypto.X509Certificate(pem),
        spki = crypto
          .createHash("sha256")
          .update(parsed.publicKey.export({ type: "spki", format: "der" }))
          .digest("hex");
      return {
        pem,
        parsed,
        spki,
        fingerprint: parsed.fingerprint256.replace(/:/g, "").toLowerCase(),
      };
    };
    const upload = (leaf) =>
      fixture.request(`${prefix}/certificates`, "POST", {
        certificatePem: leaf.pem,
        sourceRef: "Owned renewal metadata fixture",
      });
    const assertKnown = (value, leaf) => {
      assert.equal(value.fingerprint_sha256, leaf.fingerprint);
      assert.equal(
        new crypto.X509Certificate(value.certificate_pem).fingerprint256,
        leaf.parsed.fingerprint256,
      );
      assert.equal(value.spki_fingerprint_sha256, leaf.spki);
      assert.equal(
        value.public_key_algorithm,
        leaf.parsed.publicKey.asymmetricKeyType,
      );
      assert.equal(
        value.public_key_size,
        leaf.parsed.publicKey.asymmetricKeyDetails.modulusLength || null,
      );
      assert.equal(
        value.signature_algorithm,
        leaf.parsed.signatureAlgorithm || null,
      );
      const details = leaf.parsed.publicKey.asymmetricKeyDetails;
      if (details.namedCurve)
        assert.equal(
          value.public_metadata.publicKeyMetadata.namedCurve,
          details.namedCurve,
        );
      if (details.modulusLength)
        assert.equal(
          value.public_metadata.publicKeyMetadata.modulusLength,
          details.modulusLength,
        );
    };
    async function complete(leaf, extra = [], legacyRepresentation = false) {
      const created = await fixture.request(`${prefix}/jobs`, "POST", {
        operation: "renew",
        subjectId: certificateId,
        idempotencyKey: crypto.randomUUID(),
      });
      assert.equal(created.status, 201);
      const claimed = await agent.machine("jobs/claim", "claim", {
        maxJobs: 1,
        supportedActions: ["renew"],
        supportedDnsProviders: ["cloudflare"],
      });
      assert.equal(claimed.status, 200);
      const job = claimed.body.jobs.find(
        (row) => row.jobId === created.body.job.id,
      );
      assert.ok(job);
      assert.deepEqual(
        verifyJobSignature({
          job,
          publicKeyPem: agent.signingPublicKeyPem,
          pinnedSigningKeyId: agent.signingKeyId,
        }),
        { allowed: true },
      );
      if (legacyRepresentation) {
        await fixture.pool.query(
          "UPDATE managed_certificates SET fingerprint_sha256=$3 WHERE workspace_id=$1 AND id=$2",
          [
            fixture.workspaceId,
            certificateId,
            leaf.fingerprint.toUpperCase().match(/../g).join(":"),
          ],
        );
      }
      const body = {
        jobId: job.jobId,
        claimId: job.claimId,
        evidenceItems: [
          {
            evidenceId: crypto.randomUUID(),
            eventType: "validation.passed",
            observedAt: new Date().toISOString(),
            fingerprintSha256: leaf.fingerprint,
            metadata: [
              { name: "step", value: "verify" },
              { name: "serialNumber", value: leaf.parsed.serialNumber },
              {
                name: "validTo",
                value: new Date(leaf.parsed.validTo).toISOString(),
              },
              {
                name: "validFrom",
                value: new Date(leaf.parsed.validFrom).toISOString(),
              },
              { name: "subject", value: leaf.parsed.subject },
              { name: "issuer", value: leaf.parsed.issuer },
              { name: "subjectAltNames", value: host },
              ...extra.filter((item) => item.name !== "certificatePem"),
            ],
          },
        ],
      };
      if (extra.some((item) => item.name === "certificatePem")) {
        const before = await facts(),
          invalid = structuredClone(body);
        invalid.evidenceItems[0].metadata.push({
          name: "certificatePem",
          value: "not-a-public-leaf",
        });
        const rejected = await agent.machine(
          "jobs/results",
          "evidence",
          invalid,
        );
        assert.equal(rejected.status, 422);
        assert.deepEqual(await facts(), before);
      }
      const evidence = await agent.machine("jobs/results", "evidence", body);
      assert.equal(evidence.status, 200);
      lastResult = {
        jobId: job.jobId,
        attemptId: job.attemptId,
        nonce: job.nonce,
        status: "succeeded",
        keyRotated: leaf === newLeaf,
      };
      assert.equal(
        (await agent.machine("jobs/results", "result", lastResult)).status,
        200,
      );
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT status FROM certificate_jobs WHERE id=$1",
            [job.jobId],
          )
        ).rows[0].status,
        "succeeded",
      );
    }
    try {
      await gate.preflight();
      ready = true;
      await gate.scenario(scenarios[0], async () => {
        oldLeaf = make("old", "rsa:2048");
        newLeaf = make("new", "ec");
        assert.notEqual(oldLeaf.spki, newLeaf.spki);
        const imported = await upload(oldLeaf);
        assert.equal(imported.status, 201);
        certificateId = imported.body.items[0].id;
        assertKnown(await facts(), oldLeaf);
        const target = {
            type: "domain",
            reference: host,
            certPath: path.join(directory, "deployed.crt"),
          },
          profile = {
            schemaVersion: 1,
            profileId: null,
            profileName: "Owned renewal facts",
            sanPolicy: { mode: "exact", sans: [host], allowWildcards: false },
            keyAlgorithm: "rsa",
            keySize: 2048,
            keyRotationPolicy: { rotateOnRenew: true },
            preferredChain: null,
            ca: {
              endpoint: "https://renewal-facts.invalid/directory",
              accountRef: null,
              eabRef: null,
            },
            acme: { kind: "certbot", commandRef: "owned.facts" },
            dns: { provider: "cloudflare", zone: "example.test" },
            deploymentTargets: [target],
            target,
            verification: { host, port: 443, requireMatch: true },
          };
        const profileId = (
          await fixture.pool.query(
            "INSERT INTO certificate_profiles(workspace_id,name,key_mode,public_metadata,created_by) VALUES($1,'Owned renewal facts','agent-local',$2,$3) RETURNING id",
            [
              fixture.workspaceId,
              JSON.stringify({ renewalProfile: profile }),
              fixture.userId,
            ],
          )
        ).rows[0].id;
        await fixture.pool.query(
          "UPDATE managed_certificates SET key_mode='agent-local',profile_id=$3,public_metadata=public_metadata||$4::jsonb WHERE workspace_id=$1 AND id=$2",
          [
            fixture.workspaceId,
            certificateId,
            profileId,
            JSON.stringify({ qualificationUnrelatedMetadata: "preserved" }),
          ],
        );
        agent = await createRegisteredAgent(
          fixture,
          base,
          ["evidence-claim-binding-v1"],
          {
            declaredCommandProfileNames: ["owned.facts"],
            declaredTargetSelectors: [host],
            supportedDnsProviders: ["cloudflare"],
          },
        );
      });
      await gate.scenario(scenarios[1], async () => {
        const before = await facts();
        await complete(oldLeaf, [], true);
        const after = await facts();
        assertKnown(after, oldLeaf);
        for (const key of [
          "certificate_pem",
          "spki_fingerprint_sha256",
          "public_key_algorithm",
          "public_key_size",
          "signature_algorithm",
          "public_metadata",
        ])
          assert.deepEqual(after[key], before[key]);
      });
      await gate.scenario(scenarios[2], async () => {
        await complete(newLeaf, [
          { name: "spkiFingerprintSha256", value: oldLeaf.spki },
          { name: "publicKeyAlgorithm", value: "rsa" },
          { name: "publicKeySize", value: 4096 },
          { name: "signatureAlgorithm", value: "arbitrary-client-signature" },
          { name: "certificatePem", value: "not-a-public-leaf" },
        ]);
        const value = await facts();
        assert.equal(value.fingerprint_sha256, newLeaf.fingerprint);
        for (const field of [
          "certificate_pem",
          "spki_fingerprint_sha256",
          "public_key_algorithm",
          "public_key_size",
          "signature_algorithm",
        ])
          assert.equal(value[field], null);
        for (const field of [
          "parser",
          "chainIndex",
          "subject",
          "subjectAltName",
          "fingerprint512",
          "publicKeyMetadata",
          "signatureAlgorithmOid",
        ])
          assert.equal(Object.hasOwn(value.public_metadata, field), false);
        assert.equal(
          value.public_metadata.qualificationUnrelatedMetadata,
          "preserved",
        );
        const publicRow = await fixture.request(
          `${prefix}/certificates/${certificateId}`,
        );
        assert.equal(publicRow.status, 200);
        assert.equal(publicRow.body.certificate.spkiFingerprintSha256, null);
        assert.equal(publicRow.body.certificate.certificatePem, null);
        assert.equal(value.serial_number, newLeaf.parsed.serialNumber);
        assert.equal(
          new Date(value.not_after).getTime(),
          Date.parse(newLeaf.parsed.validTo),
        );
      });
      await gate.scenario(scenarios[3], async () => {
        await complete(newLeaf, [
          { name: "spkiFingerprintSha256", value: newLeaf.spki },
        ]);
        const value = await facts();
        assert.equal(value.spki_fingerprint_sha256, null);
        assert.equal(value.certificate_pem, null);
      });
      await gate.scenario(scenarios[4], async () => {
        const response = await upload(newLeaf);
        assert.ok([200, 201].includes(response.status));
        assert.equal(response.body.items[0].id, certificateId);
        assertKnown(await facts(), newLeaf);
        const publicRow = await fixture.request(
          `${prefix}/certificates/${certificateId}`,
        );
        assert.equal(publicRow.status, 200);
        assert.equal(
          publicRow.body.certificate.spkiFingerprintSha256,
          newLeaf.spki,
        );
        assert.equal(
          publicRow.body.certificate.publicKeyAlgorithm,
          newLeaf.parsed.publicKey.asymmetricKeyType,
        );
      });
      await gate.scenario(scenarios[5], async () => {
        const before = await facts();
        const replay = await agent.machine(
          "jobs/results",
          "result",
          lastResult,
        );
        assert.equal(replay.status, 200);
        assert.equal(replay.body.duplicate, true);
        assert.deepEqual(await facts(), before);
      });
    } catch (error) {
      primary = error;
    } finally {
      const cleanup = async () => {
        const errors = [];
        try {
          await fixture.cleanup();
        } catch (error) {
          errors.push(error);
        }
        try {
          const owned = path.resolve(directory);
          assert.equal(path.dirname(owned), path.resolve(os.tmpdir()));
          assert.match(
            path.basename(owned),
            /^renewal-key-facts-[A-Za-z0-9]{6}$/,
          );
          assert.equal(fs.lstatSync(owned).isSymbolicLink(), false);
          fs.rmSync(owned, { recursive: true, force: true });
        } catch (error) {
          errors.push(error);
        }
        if (errors.length)
          throw new AggregateError(
            errors,
            "Owned renewal facts cleanup failed",
          );
      };
      try {
        if (ready) {
          await gate.scenario(scenarios.at(-1), cleanup);
          await gate.finish({ requiredScenarios: scenarios });
        } else await cleanup();
      } catch (error) {
        primary = primary
          ? new AggregateError(
              [primary, error],
              "Renewal facts and cleanup failed",
            )
          : error;
      }
    }
    if (primary) throw primary;
  },
);
