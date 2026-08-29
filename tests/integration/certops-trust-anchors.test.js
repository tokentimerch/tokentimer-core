"use strict";

const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  validateSignedJob,
} = require("../../packages/contracts/certops/validate-signed-job.cjs");

const {
  createTrustAnchor,
  listTrustAnchors,
  retireTrustAnchor,
  createTrustJob,
  onTrustJobTerminalTransition,
  revalidateTrustJobForDispatch,
  ingestTrustJobResult,
  sweepOverdueTrustInstallations,
  TRUST_JOB_TERMINAL_NEGATIVE_STATUSES,
  CERTOPS_TRUST_ANCHOR_NOT_ACTIVE,
  CERTOPS_TRUST_RESULT_MISMATCH,
  CERTOPS_TRUST_RESULT_STALE_GENERATION,
  CERTOPS_TRUST_RESULT_INVALID,
  CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
  CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
} = require("../../apps/api/services/certops/trustAnchors");

// Ten distinct self-signed CA certificates (Basic Constraints CA:TRUE),
// generated once via openssl so each test that needs its own independent
// trust-anchor identity (a distinct fingerprint) can have one without
// colliding on certops_trust_anchors' (workspace_id, fingerprint_sha256)
// unique index.
const CA_CERTS = [
  `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUb2xuYhUxgIF1BFLOgY06NLIEaLAwDQYJKoZIhvcNAQEL
BQAwPzEjMCEGA1UEAwwaVG9rZW5UaW1lciBUZXN0IFRydXN0IENBIDExGDAWBgNV
BAoMD1Rva2VuVGltZXIgVGVzdDAeFw0yNjA4MjQxMTM3MzBaFw0zNjA4MjExMTM3
MzBaMD8xIzAhBgNVBAMMGlRva2VuVGltZXIgVGVzdCBUcnVzdCBDQSAxMRgwFgYD
VQQKDA9Ub2tlblRpbWVyIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQChoDDh1wRQ01OOy/7d70gzvQjgczI4PYNVT4agNQw6s3aRcEiG0xUxWzA9
Dic9i/Rcn3i2Y5g/DIlIYenoF/+jsIQop0BAfWPrwbnda5n9AooCsPuvlwHc5Is/
On5YvVLRynqNdHuipnZXZ40Ps+FEh96tvkCDQZzmCEaiOkaavHAySUAb5CH3/HeF
4RK+5VhulX46w23yjmdB8mXd41U+Bptdq66Wp1i7nAwfC8nuVNIhIi1PeEzyWNgP
UayPp03ojHZyKV+4X4UeVJDtCsvmfo01RTZBCcOzLb7zNQZ8uAIzEvMPzDOU29Gb
1qzoyVGz+/Q19huL1CPehEbYUatDAgMBAAGjUzBRMB0GA1UdDgQWBBTCHUxs562a
RqSldDc4dGmprfhu2jAfBgNVHSMEGDAWgBTCHUxs562aRqSldDc4dGmprfhu2jAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCEN2IoqNtA4KBYKq8i
MRCta41xfBKUajxTb+qoM86tMH6Xip3UyQnB/yIwrISDaHTQVqvLnagGuWPCbk/v
pqEQF0dge2oGgLTzCSPoVNQ4Ia51XmK8oOM6CME0Ye6eKKugAONpPefbtb7cbE4d
YGve8Uy+Pu9C/fYTi+EBWiHMWQFM78xSuPaSODdMmFBkfCI7tMOVPDydylpxKdA0
6YgVt5CGCGzeTvqnfc+ZrXArNDe6iiGccnJg7NYmTp8FSM9hS3n+3wNDWVcJ+gxI
a7sguuh7bnvonuxyF+fHeFsi7jxHTcRUI9VNpwlnIxOvY+MwprzOlA4dYH/5FnpZ
U9D6
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUMzFqrxKhqXp98zAp2dD0/0V/PbAwDQYJKoZIhvcNAQEL
BQAwPzEjMCEGA1UEAwwaVG9rZW5UaW1lciBUZXN0IFRydXN0IENBIDIxGDAWBgNV
BAoMD1Rva2VuVGltZXIgVGVzdDAeFw0yNjA4MjQxMTM3MzBaFw0zNjA4MjExMTM3
MzBaMD8xIzAhBgNVBAMMGlRva2VuVGltZXIgVGVzdCBUcnVzdCBDQSAyMRgwFgYD
VQQKDA9Ub2tlblRpbWVyIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtbYS5LmD59UBHR2Ldfk2SxicmX/HmsCu6p+eK2Yv/emOtJ6wxp4BOpn1p
vr3EL+0tpOr5VYubxmqNVKlJn1Z+feNDmoaKu1eEBmW5GtKEesPWdZfv6vHqf7tZ
dzT4NoT4g836qzzBE/bfDcZF9evwdp/reX/Uyb+YjT+WaGErrbYeHnt0tl0i+Syd
zARZoHQAIPOM62WkZlsrT2HXNkqGL5m+Ov0ErpqlaxiOzwR8W4LCr8MlIpGKOc7i
T2hNW7GcOp26K7/2FgwvESxuyUOf1Plze+AmX9sXj6qodm5jMq7055FiiuFBxzg2
fV8kT0wQW+aODjmMGBibvsuxsvKJAgMBAAGjUzBRMB0GA1UdDgQWBBQKNOpZG55k
5q+YV/SgqtawI/zZRzAfBgNVHSMEGDAWgBQKNOpZG55k5q+YV/SgqtawI/zZRzAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB2gVeVTYvRbkt60sOY
wpUAwVvRzc0NriXSAFHjhlcpmQcZJwq0WZR9rGbKVnOwFufHARiRBIc3AuPO2uMf
nwrXgo6MMqXouYvYXSPYCsdsdGaI9KxXvw79ZdBrTRv8DUDRFYpAEWGDYxYaU4br
qnpj2cmuPw45tF74XueFi6nLxvUfON2snnm3CswLeixelumhhyoDfD1GkDMGc2Wi
vCd2irkAtrGPgLqahAzysTW2lZuvmNg9a6FxpA8INhkzcqZQnwFoG6uQ8admNEHF
Cig04A1VDOLLxLPyLiT6mqP3tDyr0ePCqefvJGgyAAhGeGy38zgP5VqfKRdzS0eq
XJ1l
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUaXBqN1EXV1by13iibTpiIlQWsxowDQYJKoZIhvcNAQEL
BQAwPzEjMCEGA1UEAwwaVG9rZW5UaW1lciBUZXN0IFRydXN0IENBIDMxGDAWBgNV
BAoMD1Rva2VuVGltZXIgVGVzdDAeFw0yNjA4MjQxMTM3MzBaFw0zNjA4MjExMTM3
MzBaMD8xIzAhBgNVBAMMGlRva2VuVGltZXIgVGVzdCBUcnVzdCBDQSAzMRgwFgYD
VQQKDA9Ub2tlblRpbWVyIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDXeMvpROMAAFjBhv5T7ubsR/62xYq+WStKwyQolZBXJ+UdNfWXBCXkMpBX
9WeARoREshkGGMFG7ftSfPX6aV+n37gKTsPV9S8Za/STbhpfg3bvNWXuD+I2nV36
R9JP19VLbZdDUgvu5KdUyS3uS9IY7LngACasVw+JzvhI+0FR850QmfoTPVm1CIx8
sAC2krRZb+029gUZORyXODsSR1f3l2wdvcpGUF2jfrgtae65ZLxANgy/xSIdC8L1
lFfblUG4oFDKswzxtFZYjyM08UjVrYCt5xFXGSEBtc6f6LjhK1kWqkMCG9hvWH63
fS1CI+JghEvxyN+8ViVlejKjv3WTAgMBAAGjUzBRMB0GA1UdDgQWBBQZEfnijkfq
dUpsuqsEGU8Ln1EMkjAfBgNVHSMEGDAWgBQZEfnijkfqdUpsuqsEGU8Ln1EMkjAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC+wRQ+0RzYMQejYn/P
ccyR9ea0gGtYDSZQtfSWb/mJUjWc7XxNwOJCpK1R4jKivkdowiap7Xrr5bUsPB4E
hTTyOZcVinvK3kTqffsQprK0RZff32dOCng3vXN1PSyH5No1puAjHsakDkbs4fBG
9EM4Nz4KLBlgxdpyb6bzB+9q9MTQJ2qW87kTgOQ/9RINARu/a3orQpT3Iy7AW6GW
ITWNepwv0A1TEFz+D/w38+8jxxPhSSUT8583ZuXBDC6HabAr60UYD0xPwlW76mbT
cxms5UlCJTjBo+JJ0qswTLrq7D4u4ZvtMa/H2LYlVvAqPs6G2neSQHxH042Q6wcn
KwI9
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIURHEj4uS4Z+v63uM3CRfEvIHPUYcwDQYJKoZIhvcNAQEL
BQAwPzEjMCEGA1UEAwwaVG9rZW5UaW1lciBUZXN0IFRydXN0IENBIDQxGDAWBgNV
BAoMD1Rva2VuVGltZXIgVGVzdDAeFw0yNjA4MjQxMTM3MzBaFw0zNjA4MjExMTM3
MzBaMD8xIzAhBgNVBAMMGlRva2VuVGltZXIgVGVzdCBUcnVzdCBDQSA0MRgwFgYD
VQQKDA9Ub2tlblRpbWVyIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCz2LYjrmjMhEDKf+yrHKfaccbWq8LdXOUY3exOHAWF6d9PImFantbqZfgf
1xj0WTHdS1l/yQ4V9zBPHAJm1zAGD5ObzCA/hj5AVllE6FdcxTnnwNmvs14gSrf7
OBpt4MrB9jg94wcUlLl78cChAuwqjtmrDhRmfA01f6e0fHDnorB6o4B0nF/vsrGF
RD509GPw5ARFf1HeQSwzdMP5zO1UVrfCi9nOP6iIE/h6bV6UWx+A91ZNZUb2gckD
NMMa4UTUTFklgaoZj2HYFLZKu/ObuPJsqRwrbHryutSw0SfOaIPSF+V8d1QjRtCi
+4ZHm1iC7gHZ8x6frr8l0DNje++zAgMBAAGjUzBRMB0GA1UdDgQWBBRLJ0MLFygM
IpaMlDOmhhYp35V6bjAfBgNVHSMEGDAWgBRLJ0MLFygMIpaMlDOmhhYp35V6bjAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBDc4mTrCg6Z8MskanB
Eo4vnVi/deDzjM8tvQWGXO2mYhPg5wy6BCi5tBuAb6/++wnKB2yb1QiMO60ZIdgt
5g6NGxyjJWSKE/U8SmEaHYsWEkFbXC13aaSmNB0eHuryEzLE0QuizY+q2Y72cJnV
SSTBGv3fHcoeKqYcKd0iUGEDGF3KRt6/2QJUxNKuL4yCZg2NCebT/5Pgm0PSM0cT
D1jNyzQwcnmYbhE1DI5tS8AQGeCzEA6u6neTLH0y0MqJh9XaLeiqWRnbX0lE8Svt
ylZfNxSeIpeOwGpX1NGqFf06nlbrUOSW5woUgdmxZ5jur1JQDGFAB+U1/J1cjPkc
VtvP
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUPEIsK7qR7TqwNwxQ62GkWptUuW0wDQYJKoZIhvcNAQEL
BQAwPzEjMCEGA1UEAwwaVG9rZW5UaW1lciBUZXN0IFRydXN0IENBIDUxGDAWBgNV
BAoMD1Rva2VuVGltZXIgVGVzdDAeFw0yNjA4MjQxMTM3MzFaFw0zNjA4MjExMTM3
MzFaMD8xIzAhBgNVBAMMGlRva2VuVGltZXIgVGVzdCBUcnVzdCBDQSA1MRgwFgYD
VQQKDA9Ub2tlblRpbWVyIFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC4OGiZquQ56gOumhKyFAbZ0Zml9uljhxujI1IFN+zGY3hNDN/ji91aKtVR
4bSDsxNPjpMWAQYgRb6y5dyRw2Fv2zMl6cWyN5DNk5GpvLU6Ygmuwdw26MEsDEC4
PYheiarfgciyrQJa5k1miXH5ULBvf1t5RkPx4Tx2ct8YGGYgGFUTooJVFGH6LBzV
pitVrnPuDND7vIkPZxRe3Tw3ldkPdnL5imFUpJtZkDYA+veAJeHDKarMKFOh1jRS
kz09FG6aVzrOPetN9OnqcBp0fh/VqDSYy9wVZLYBwo1GFnKFA714dwbokMphtZ+m
l0r0jrxHo49IbJo4SjCYRPhCfqDlAgMBAAGjUzBRMB0GA1UdDgQWBBS3DWkQPWum
msqiqQeKDW8B78NhkjAfBgNVHSMEGDAWgBS3DWkQPWummsqiqQeKDW8B78NhkjAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBhG+2NBcob5tvcS79F
MD8BvL2JaNdEvCZkDZHPeYGAqmiZvJdXxJP+YXxh4B15lGbpGC1SV4b2P18fzdrK
wlPM2loyc25xZKp5nTHQXiTQKF3jLpcxZLlogDbqoPlJSKD56DL0NjYoWd6QZa74
nU4er610Wmq7bd2Zr2vM+IoDSG7klXS4QPtCQSSDVxufvGP8kM4wp9D/5Fb4ypUN
/NXPxdQy59TgLKoa1nJwlK/N+CJSx8v76a+OQBCyLaWhKbV6Lp/boHyCj49LeSee
eifXxWEm9UN6NamKwnNBHxMRx0ccY+1ezWGDpchUl+nEpd6Tu3rcT7NdoeVNnqdX
tG/Y
-----END CERTIFICATE-----`,
];

function trustAnchorPemFor(index) {
  return CA_CERTS[index % CA_CERTS.length];
}

function quotedIdentifier(identifier) {
  return `"${String(identifier).replace(/"/g, '""')}"`;
}

/**
 * The trust-anchor orchestration service's own row-level-locking discipline
 * (SELECT ... FOR UPDATE inside one transaction, ADR-0012 decision 20h) can
 * only be genuinely exercised against real PostgreSQL: a mocked client would
 * let two "concurrent" calls both observe the pre-lock state. Every test
 * below therefore runs against the real test database, mirroring
 * tests/integration/certops-issuance-concurrency.test.js's own rationale.
 */
describe("CertOps trust-anchor orchestration (real database, ADR-0012 decision 20)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;
  let anchorCounter = 0;

  before(async () => {
    await runMigrations();

    const email = `trust-anchor-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Trust Anchor Test', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;

    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Trust Anchor Test WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [
        workspaceId,
      ]);
    }
    if (ownerId) {
      // Deleting the user would otherwise NULL out actor_user_id/
      // subject_user_id on the audit rows these tests wrote, and audit_events
      // is update-immutable by trigger. Remove those rows first, the same way
      // worker-claim-lease.test.js does.
      await TestUtils.execQuery(
        `DELETE FROM audit_events
          WHERE actor_user_id = $1 OR subject_user_id = $1`,
        [ownerId],
      );
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  // --- Helpers -------------------------------------------------------------

  async function createAgent(overrides = {}) {
    const agentId = `agent-${crypto.randomUUID()}`;
    const capabilities = overrides.capabilities || ["trust-anchor-deploy-v1"];
    const capabilitiesUpdatedAt =
      overrides.capabilitiesUpdatedAt === undefined
        ? new Date()
        : overrides.capabilitiesUpdatedAt;
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, declared_capabilities,
         capabilities_updated_at, last_seen_at
       )
       VALUES ($1, $2, 'trust-agent', '0.13.0', '1.0.0', $3, $4, 'active',
               $5::jsonb, $6, NOW())
       RETURNING id`,
      [
        workspaceId,
        agentId,
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
        JSON.stringify(capabilities),
        capabilitiesUpdatedAt,
      ],
    );
    return { id: inserted.rows[0].id, agentId, workspaceId };
  }

  // A fresh trust anchor identity per call (own CA fingerprint), always
  // left 'active' by createTrustAnchor regardless of any prior state -- see
  // createTrustAnchor's own re-approval-reactivates doc comment.
  async function createFreshAnchor(overrides = {}) {
    const pem = trustAnchorPemFor(anchorCounter++);
    return createTrustAnchor({
      workspaceId,
      name: overrides.name || `Test Trust Anchor ${anchorCounter}`,
      anchorType: overrides.anchorType || "root",
      pem,
      createdByUserId: ownerId,
    });
  }

  async function getJobRow(jobId) {
    const result = await TestUtils.execQuery(
      `SELECT * FROM certificate_jobs WHERE id = $1`,
      [jobId],
    );
    return result.rows[0];
  }

  async function getInstallationById(installationId) {
    const result = await TestUtils.execQuery(
      `SELECT * FROM certops_trust_anchor_installations WHERE id = $1`,
      [installationId],
    );
    return result.rows[0];
  }

  async function getInstallationByLastJob(jobId) {
    const result = await TestUtils.execQuery(
      `SELECT * FROM certops_trust_anchor_installations WHERE last_job_id = $1`,
      [jobId],
    );
    return result.rows[0];
  }

  async function withTx(fn) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_rollbackError) {
        // Original error is more useful.
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async function expectServiceError(promise, code) {
    let threw = false;
    try {
      await promise;
    } catch (error) {
      threw = true;
      expect(error.code).to.equal(code);
    }
    expect(threw, `expected rejection with code ${code}`).to.equal(true);
  }

  function distributeOptions({ anchor, agent, store, owner, idempotencyKey }) {
    return {
      workspaceId,
      operation: "distribute-trust",
      trustAnchorId: anchor.id,
      agentId: agent.id,
      store: store || "Root",
      owner: owner || "workspace-policy",
      idempotencyKey,
      requestedByUserId: ownerId,
    };
  }

  function revokeOptions({ anchor, agent, store, owner, idempotencyKey }) {
    return {
      workspaceId,
      operation: "revoke-trust",
      trustAnchorId: anchor.id,
      agentId: agent.id,
      store: store || "Root",
      owner: owner || "workspace-policy",
      idempotencyKey,
      requestedByUserId: ownerId,
    };
  }

  // Builds a trust-result-contract.schema.json-shaped result for the given
  // job/installation pair. installationRow must be the CURRENT row (i.e.
  // read back after the job that will be answered), since transitionGeneration
  // must match decision 20f's stale-generation check.
  function buildResult({
    job,
    installationRow,
    outcome,
    agentIdOverride,
    storeOverride,
    generationOverride,
    trustAnchorIdOverride,
    fingerprintOverride,
    failureCategoryOverride,
  }) {
    const mutationAttempted = outcome === "installed" || outcome === "removed";
    const isRemovalOutcome =
      outcome === "removed" || outcome === "already_absent";
    return {
      schemaVersion: 1,
      jobId: String(job.id),
      workspaceId: String(job.workspace_id),
      agentId: agentIdOverride ?? String(installationRow.agent_id),
      trustAnchorId:
        trustAnchorIdOverride ?? String(job.payload.trustAnchorId),
      action: job.operation,
      transitionGeneration:
        generationOverride ?? installationRow.transition_generation,
      store: storeOverride ?? installationRow.store,
      outcome,
      mutationAttempted,
      mutationPerformed: mutationAttempted,
      observedFingerprintBefore: isRemovalOutcome
        ? (fingerprintOverride ?? installationRow.fingerprint_sha256)
        : null,
      observedFingerprintAfter: isRemovalOutcome
        ? null
        : (fingerprintOverride ?? installationRow.fingerprint_sha256),
      receipt: { id: "receipt-1", state: "finalized" },
      observedAt: new Date().toISOString(),
      ...(failureCategoryOverride ? { failureCategory: failureCategoryOverride } : {}),
    };
  }

  // --- Idempotent creation (decision 20a/20c) ------------------------------

  it("creates a distribute-trust job and advances the installation row to pending_install", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const key = `dist-${crypto.randomUUID()}`;

    const outcome = await createTrustJob(
      distributeOptions({ anchor, agent, idempotencyKey: key }),
    );

    expect(outcome.created).to.equal(true);
    expect(outcome.installation.transitionState).to.equal("pending_install");
    expect(outcome.transitionGeneration).to.equal(2);

    const job = await getJobRow(outcome.job.id);
    expect(job.subject_type).to.equal("trust_anchor");
    expect(job.subject_id).to.equal(anchor.id);
    expect(job.assigned_agent_id).to.equal(agent.id);

    const installation = await getInstallationById(outcome.installation.id);
    expect(installation.transition_state).to.equal("pending_install");
    expect(installation.transition_generation).to.equal(2);
    expect(String(installation.last_job_id)).to.equal(String(job.id));
  });

  it("replays the same idempotencyKey and returns the same job and generation", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const key = `replay-${crypto.randomUUID()}`;

    const first = await createTrustJob(
      distributeOptions({ anchor, agent, idempotencyKey: key }),
    );
    const second = await createTrustJob(
      distributeOptions({ anchor, agent, idempotencyKey: key }),
    );

    expect(first.created).to.equal(true);
    expect(second.created).to.equal(false);
    expect(String(second.job.id)).to.equal(String(first.job.id));
    expect(second.transitionGeneration).to.equal(first.transitionGeneration);

    const installation = await getInstallationById(first.installation.id);
    expect(installation.transition_generation).to.equal(
      first.transitionGeneration,
    );
  });

  it("replaying the same idempotencyKey does not touch last_attempt_at or last_error", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const key = `replay-side-effects-${crypto.randomUUID()}`;

    const first = await createTrustJob(
      distributeOptions({ anchor, agent, idempotencyKey: key }),
    );
    const staleAttemptAt = new Date("2020-01-01T00:00:00.000Z");
    await TestUtils.execQuery(
      `UPDATE certops_trust_anchor_installations
          SET last_attempt_at = $2,
              last_error = $3
        WHERE id = $1`,
      [first.installation.id, staleAttemptAt, "prior failure"],
    );

    const beforeReplay = await getInstallationById(first.installation.id);
    expect(beforeReplay.last_attempt_at.toISOString()).to.equal(
      staleAttemptAt.toISOString(),
    );
    expect(beforeReplay.last_error).to.equal("prior failure");

    const second = await createTrustJob(
      distributeOptions({ anchor, agent, idempotencyKey: key }),
    );
    expect(second.created).to.equal(false);

    const afterReplay = await getInstallationById(first.installation.id);
    expect(afterReplay.last_attempt_at.toISOString()).to.equal(
      staleAttemptAt.toISOString(),
    );
    expect(afterReplay.last_error).to.equal("prior failure");
  });

  it("re-approving the same fingerprint updates anchor_type when the caller submits a different type", async () => {
    const pem = trustAnchorPemFor(0);
    const first = await createTrustAnchor({
      workspaceId,
      name: "Root CA",
      anchorType: "root",
      pem,
      createdByUserId: ownerId,
    });
    const second = await createTrustAnchor({
      workspaceId,
      name: "Same cert, intermediate type",
      anchorType: "intermediate",
      pem,
      createdByUserId: ownerId,
    });

    expect(second.id).to.equal(first.id);
    expect(second.anchorType).to.equal("intermediate");
  });

  it("requires idempotencyKey (rejects, does not merely accept omission)", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();

    await expectServiceError(
      createTrustJob(distributeOptions({ anchor, agent, idempotencyKey: "" })),
      CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
    );
  });

  it("rejects distribute-trust against a retired anchor", async () => {
    const anchor = await createFreshAnchor();
    await retireTrustAnchor({ workspaceId, anchorId: anchor.id });
    const agent = await createAgent();

    await expectServiceError(
      createTrustJob(
        distributeOptions({
          anchor,
          agent,
          idempotencyKey: `retired-${crypto.randomUUID()}`,
        }),
      ),
      CERTOPS_TRUST_ANCHOR_NOT_ACTIVE,
    );
  });

  it("rejects revoke-trust when no installation is tracked, without leaving a phantom row", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();

    await expectServiceError(
      createTrustJob(
        revokeOptions({
          anchor,
          agent,
          idempotencyKey: `revoke-untracked-${crypto.randomUUID()}`,
        }),
      ),
      CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
    );

    const rows = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS n FROM certops_trust_anchor_installations
        WHERE workspace_id = $1 AND agent_id = $2 AND trust_anchor_id = $3`,
      [workspaceId, agent.id, anchor.id],
    );
    expect(rows.rows[0].n).to.equal(0);
  });

  // --- Concurrency / row-level locking (decision 20h) -----------------------
  //
  // Each createTrustJob call opens and commits its own transaction (via
  // trustAnchors.js's internal withTransaction), so calling it twice
  // concurrently via Promise.all genuinely races two real connections
  // against the installation row's SELECT ... FOR UPDATE lock -- the same
  // "real overlapping transactions" rationale as
  // certops-issuance-concurrency.test.js.

  it("serializes two concurrent distribute-trust requests on the same installation without a lost update", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";
    const owner = "workspace-policy";

    const [first, second] = await Promise.all([
      createTrustJob(
        distributeOptions({
          anchor,
          agent,
          store,
          owner,
          idempotencyKey: `race-a-${crypto.randomUUID()}`,
        }),
      ),
      createTrustJob(
        distributeOptions({
          anchor,
          agent,
          store,
          owner,
          idempotencyKey: `race-b-${crypto.randomUUID()}`,
        }),
      ),
    ]);

    // Two distinct requests (different idempotency keys) both legitimately
    // advance the same row; row-level locking must serialize them so the
    // final generation reflects both bumps, never a lost update where one
    // overwrites the other's starting point.
    expect(String(first.installation.id)).to.equal(String(second.installation.id));
    const generations = [first.transitionGeneration, second.transitionGeneration].sort(
      (a, b) => a - b,
    );
    expect(generations).to.deep.equal([2, 3]);

    const installation = await getInstallationById(first.installation.id);
    expect(installation.transition_generation).to.equal(3);

    const jobIds = new Set([String(first.job.id), String(second.job.id)]);
    expect(jobIds.size).to.equal(2, "two distinct requests get two distinct jobs");
  });

  it("serializes two concurrent replays of the same idempotencyKey to exactly one job", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const key = `race-replay-${crypto.randomUUID()}`;

    const [first, second] = await Promise.all([
      createTrustJob(distributeOptions({ anchor, agent, idempotencyKey: key })),
      createTrustJob(distributeOptions({ anchor, agent, idempotencyKey: key })),
    ]);

    expect(String(first.job.id)).to.equal(String(second.job.id));
    expect(first.transitionGeneration).to.equal(second.transitionGeneration);
    const createdFlags = [first.created, second.created].filter(
      (value) => value === true,
    );
    expect(createdFlags.length).to.equal(
      1,
      "exactly one of the two concurrent replays is the creator",
    );

    const jobs = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS n FROM certificate_jobs
        WHERE workspace_id = $1 AND idempotency_key = $2`,
      [workspaceId, key],
    );
    expect(jobs.rows[0].n).to.equal(1);
  });

  // --- Terminal-state unwinding (decision 20b) ------------------------------

  for (const status of TRUST_JOB_TERMINAL_NEGATIVE_STATUSES) {
    it(`deletes a pending_install row when its job reaches terminal status '${status}'`, async () => {
      const anchor = await createFreshAnchor();
      const agent = await createAgent();
      const outcome = await createTrustJob(
        distributeOptions({
          anchor,
          agent,
          idempotencyKey: `unwind-install-${status}-${crypto.randomUUID()}`,
        }),
      );

      await withTx((client) =>
        onTrustJobTerminalTransition({
          client,
          job: {
            id: outcome.job.id,
            operation: "distribute-trust",
            status,
            workspace_id: workspaceId,
          },
        }),
      );

      const installation = await getInstallationById(outcome.installation.id);
      expect(installation).to.equal(undefined, "pending_install row must be deleted");
    });

    it(`reverts a pending_remove row to 'installed' when its job reaches terminal status '${status}'`, async () => {
      const anchor = await createFreshAnchor();
      const agent = await createAgent();
      const store = "Root";
      const owner = "workspace-policy";

      // First install for real (a successful result), then start a revoke
      // and unwind it -- the anchor was never actually removed, so the row
      // must come back to 'installed', not be deleted.
      const distributeOutcome = await createTrustJob(
        distributeOptions({
          anchor,
          agent,
          store,
          owner,
          idempotencyKey: `unwind-remove-setup-${status}-${crypto.randomUUID()}`,
        }),
      );
      const distributeJob = await getJobRow(distributeOutcome.job.id);
      const distributeInstallationRow = await getInstallationById(
        distributeOutcome.installation.id,
      );
      await withTx((client) =>
        ingestTrustJobResult({
          client,
          job: distributeJob,
          result: buildResult({
            job: distributeJob,
            installationRow: distributeInstallationRow,
            outcome: "installed",
          }),
        }),
      );

      const revokeOutcome = await createTrustJob(
        revokeOptions({
          anchor,
          agent,
          store,
          owner,
          idempotencyKey: `unwind-remove-${status}-${crypto.randomUUID()}`,
        }),
      );
      const installedBeforeUnwind = await getInstallationById(
        revokeOutcome.installation.id,
      );
      expect(installedBeforeUnwind.transition_state).to.equal("pending_remove");

      await withTx((client) =>
        onTrustJobTerminalTransition({
          client,
          job: {
            id: revokeOutcome.job.id,
            operation: "revoke-trust",
            status,
            workspace_id: workspaceId,
          },
        }),
      );

      const installation = await getInstallationById(revokeOutcome.installation.id);
      expect(installation.transition_state).to.equal("installed");
    });
  }

  it("does not unwind a superseded (older-generation) job's terminal outcome", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";
    const owner = "workspace-policy";

    const firstOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `superseded-a-${crypto.randomUUID()}`,
      }),
    );
    // A second distribute-trust request for the same tuple advances the row
    // to a NEWER generation and a NEW last_job_id, superseding the first.
    const secondOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `superseded-b-${crypto.randomUUID()}`,
      }),
    );
    expect(secondOutcome.transitionGeneration).to.be.greaterThan(
      firstOutcome.transitionGeneration,
    );

    // The first job's own eventual terminal-negative outcome must not touch
    // a row that a newer transition already owns (its last_job_id no longer
    // points at the first job at all).
    await withTx((client) =>
      onTrustJobTerminalTransition({
        client,
        job: {
          id: firstOutcome.job.id,
          operation: "distribute-trust",
          status: "failed",
          workspace_id: workspaceId,
        },
      }),
    );

    const installation = await getInstallationById(secondOutcome.installation.id);
    expect(installation.transition_state).to.equal("pending_install");
    expect(installation.transition_generation).to.equal(
      secondOutcome.transitionGeneration,
    );
  });

  // --- Dispatch-time revalidation (decision 20i) ----------------------------

  it("unwinds a pending_install when the anchor is retired between approval and dispatch", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `dispatch-retire-${crypto.randomUUID()}`,
      }),
    );

    // The anchor is retired AFTER the job already exists (approval-then-
    // retire race), so revalidation -- not creation -- is what must catch it.
    await retireTrustAnchor({ workspaceId, anchorId: anchor.id });

    const jobRow = await getJobRow(outcome.job.id);
    const revalidation = await withTx((client) =>
      revalidateTrustJobForDispatch({ client, job: jobRow }),
    );

    expect(revalidation.allow).to.equal(false);
    expect(revalidation.reason).to.equal("trust_anchor_retired");

    const installation = await getInstallationById(outcome.installation.id);
    expect(installation).to.equal(undefined, "pending_install must be unwound");
  });

  it("always permits revoke-trust dispatch regardless of anchor status", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";
    const owner = "workspace-policy";

    const distributeOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `dispatch-revoke-setup-${crypto.randomUUID()}`,
      }),
    );
    const distributeJob = await getJobRow(distributeOutcome.job.id);
    const distributeInstallationRow = await getInstallationById(
      distributeOutcome.installation.id,
    );
    await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: distributeJob,
        result: buildResult({
          job: distributeJob,
          installationRow: distributeInstallationRow,
          outcome: "installed",
        }),
      }),
    );

    // revoke-trust may still be created and dispatched against a retired
    // anchor (decision 20g: retirement blocks new installs, not removal of
    // material that already exists).
    await retireTrustAnchor({ workspaceId, anchorId: anchor.id });
    const revokeOutcome = await createTrustJob(
      revokeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `dispatch-revoke-${crypto.randomUUID()}`,
      }),
    );

    const revokeJob = await getJobRow(revokeOutcome.job.id);
    const revalidation = await withTx((client) =>
      revalidateTrustJobForDispatch({ client, job: revokeJob }),
    );
    expect(revalidation.allow).to.equal(true);

    const installation = await getInstallationById(revokeOutcome.installation.id);
    expect(installation.transition_state).to.equal("pending_remove");
  });

  it("revoke-trust for one owner never touches the OS while another owner's reference is still live", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";

    // Two independent owners install the same anchor to the same
    // (agent, store, fingerprint) tuple.
    const ownerAOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner: "owner-a",
        idempotencyKey: `ref-count-dist-a-${crypto.randomUUID()}`,
      }),
    );
    const ownerBOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner: "owner-b",
        idempotencyKey: `ref-count-dist-b-${crypto.randomUUID()}`,
      }),
    );
    for (const outcome of [ownerAOutcome, ownerBOutcome]) {
      const job = await getJobRow(outcome.job.id);
      const installationRow = await getInstallationById(outcome.installation.id);
      await withTx((client) =>
        ingestTrustJobResult({
          client,
          job,
          result: buildResult({ job, installationRow, outcome: "installed" }),
        }),
      );
    }

    // Releasing owner A's reference must not create a real revoke-trust job
    // (no OS mutation) while owner B's reference is still installed.
    const releaseOutcome = await createTrustJob(
      revokeOptions({
        anchor,
        agent,
        store,
        owner: "owner-a",
        idempotencyKey: `ref-count-revoke-a-${crypto.randomUUID()}`,
      }),
    );
    expect(releaseOutcome.job).to.equal(null);
    expect(releaseOutcome.skippedOsMutation).to.equal(true);

    const ownerARow = await getInstallationById(ownerAOutcome.installation.id);
    expect(ownerARow.transition_state).to.equal("removed");

    // Owner B's reference must be completely untouched.
    const ownerBRow = await getInstallationById(ownerBOutcome.installation.id);
    expect(ownerBRow.transition_state).to.equal("installed");
    expect(ownerBRow.transition_generation).to.equal(
      ownerBOutcome.transitionGeneration,
    );

    // Once B also releases, that IS the last reference, so it goes through
    // the normal pending_remove -> real job path.
    const finalReleaseOutcome = await createTrustJob(
      revokeOptions({
        anchor,
        agent,
        store,
        owner: "owner-b",
        idempotencyKey: `ref-count-revoke-b-${crypto.randomUUID()}`,
      }),
    );
    expect(finalReleaseOutcome.job).to.not.equal(null);
    expect(finalReleaseOutcome.skippedOsMutation).to.not.equal(true);
    const finalOwnerBRow = await getInstallationById(
      ownerBOutcome.installation.id,
    );
    expect(finalOwnerBRow.transition_state).to.equal("pending_remove");
  });

  it("revoke-trust for a preexisting installation releases the reference without dispatching an agent job", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();

    const distributeOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `preexisting-revoke-dist-${crypto.randomUUID()}`,
      }),
    );
    const distributeJob = await getJobRow(distributeOutcome.job.id);
    const distributeInstallation = await getInstallationById(
      distributeOutcome.installation.id,
    );
    await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: distributeJob,
        result: buildResult({
          job: distributeJob,
          installationRow: distributeInstallation,
          outcome: "preexisting",
        }),
      }),
    );

    const installedRow = await getInstallationById(distributeOutcome.installation.id);
    expect(installedRow.transition_state).to.equal("installed");
    expect(installedRow.provenance).to.equal("preexisting");

    const revokeOutcome = await createTrustJob(
      revokeOptions({
        anchor,
        agent,
        idempotencyKey: `preexisting-revoke-${crypto.randomUUID()}`,
      }),
    );

    expect(revokeOutcome.skippedOsMutation).to.equal(true);
    expect(revokeOutcome.job).to.equal(null);

    const removedRow = await getInstallationById(distributeOutcome.installation.id);
    expect(removedRow.transition_state).to.equal("removed");
  });

  it("does not short-circuit (and does not orphan a certificate) when the only other reference is still pending_install (D1 fix)", async () => {
    // Regression for the orphaned-certificate leak found in the 0.14.0
    // consistency-check pass: countOtherLiveReferences must not credit an
    // unconfirmed pending_install row as a live reference, because that row
    // can still be deleted outright (never a real reference) by
    // onTrustJobTerminalTransition if its own job later fails. Crediting it
    // let owner A's revoke skip the real OS removal on the strength of a
    // reference that could vanish without a trace, permanently orphaning the
    // certificate on the host.
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";

    const ownerAOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner: "owner-a",
        idempotencyKey: `d1-dist-a-${crypto.randomUUID()}`,
      }),
    );
    const ownerAJob = await getJobRow(ownerAOutcome.job.id);
    const ownerAInstallationRow = await getInstallationById(ownerAOutcome.installation.id);
    await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: ownerAJob,
        result: buildResult({ job: ownerAJob, installationRow: ownerAInstallationRow, outcome: "installed" }),
      }),
    );

    // Owner B's install is dispatched but never resolved - it stays
    // pending_install, exactly the state a crashed/still-in-flight job would
    // be in when owner A's revoke request runs.
    const ownerBOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner: "owner-b",
        idempotencyKey: `d1-dist-b-${crypto.randomUUID()}`,
      }),
    );
    const ownerBPendingRow = await getInstallationById(ownerBOutcome.installation.id);
    expect(ownerBPendingRow.transition_state).to.equal("pending_install");

    // Owner A revokes while B is still pending_install: this must proceed
    // as a REAL job (not short-circuit), since B's reference is unconfirmed.
    const releaseOutcome = await createTrustJob(
      revokeOptions({
        anchor,
        agent,
        store,
        owner: "owner-a",
        idempotencyKey: `d1-revoke-a-${crypto.randomUUID()}`,
      }),
    );
    expect(releaseOutcome.skippedOsMutation).to.not.equal(true);
    expect(releaseOutcome.job).to.not.equal(null);

    const ownerARow = await getInstallationById(ownerAOutcome.installation.id);
    expect(ownerARow.transition_state).to.equal("pending_remove");

    // Now B's install job fails - the exact interleaving that used to leak.
    // Even though B's row is deleted outright, nothing was ever skipped on
    // A's side, so there is no dangling OS material left unaccounted for.
    await withTx((client) =>
      onTrustJobTerminalTransition({
        client,
        job: {
          id: ownerBOutcome.job.id,
          operation: "distribute-trust",
          status: "failed",
          workspace_id: workspaceId,
        },
      }),
    );
    const ownerBRowAfterFailure = await getInstallationById(ownerBOutcome.installation.id);
    expect(ownerBRowAfterFailure).to.equal(undefined, "B's pending_install row must be deleted");

    // A's own revoke job still completes normally against the real job it
    // was given, proving the certificate was never orphaned.
    const releaseJob = await getJobRow(releaseOutcome.job.id);
    const releaseInstallationRow = await getInstallationById(ownerAOutcome.installation.id);
    await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: releaseJob,
        result: buildResult({ job: releaseJob, installationRow: releaseInstallationRow, outcome: "removed" }),
      }),
    );
    const finalOwnerARow = await getInstallationById(ownerAOutcome.installation.id);
    expect(finalOwnerARow.transition_state).to.equal("removed");
  });

  it("fails closed on a signed pem/anchorType/fingerprint mismatch (defense-in-depth)", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `dispatch-mismatch-${crypto.randomUUID()}`,
      }),
    );

    const jobRow = await getJobRow(outcome.job.id);
    jobRow.payload = { ...jobRow.payload, fingerprintSha256: "0".repeat(64) };

    const revalidation = await withTx((client) =>
      revalidateTrustJobForDispatch({ client, job: jobRow }),
    );
    expect(revalidation.allow).to.equal(false);
    expect(revalidation.reason).to.equal("trust_anchor_payload_mismatch");
  });

  it("supplies the generation that result ingestion will demand, and the wire payload validates", async () => {
    // Regression guard: the stored payload deliberately omits
    // transitionGeneration (it is hashed for idempotency), so dispatch must
    // resolve it from the installation row. If it did not, the agent would
    // report a generation the server rejects as stale and every real trust
    // job would fail ingestion.
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `dispatch-generation-${crypto.randomUUID()}`,
      }),
    );

    const jobRow = await getJobRow(outcome.job.id);
    const revalidation = await withTx((client) =>
      revalidateTrustJobForDispatch({ client, job: jobRow }),
    );

    expect(revalidation.allow).to.equal(true);
    const installationRow = await getInstallationById(outcome.installation.id);
    expect(revalidation.transitionGeneration).to.equal(
      installationRow.transition_generation,
    );

    const wirePayload = {
      schemaVersion: 1,
      jobId: String(jobRow.id),
      workspaceId,
      agentId: agent.agentId,
      trustAnchorId: jobRow.payload.trustAnchorId,
      action: jobRow.operation,
      anchorType: jobRow.payload.anchorType,
      fingerprintSha256: jobRow.payload.fingerprintSha256,
      transitionGeneration: revalidation.transitionGeneration,
      pem: revalidation.pem,
      mode: jobRow.mode || "real",
      requestedAt: new Date(jobRow.created_at).toISOString(),
    };
    const validation = validateSignedJob(wirePayload);
    expect(validation.valid, JSON.stringify(validation.errors)).to.equal(true);

    // The generation the agent would echo back is accepted, not stale.
    const ingested = await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: jobRow,
        result: buildResult({
          job: jobRow,
          installationRow,
          outcome: "installed",
          generationOverride: revalidation.transitionGeneration,
        }),
      }),
    );
    expect(ingested.transitionState).to.equal("installed");
  });

  // --- Result ingestion (decision 20e/20f) ----------------------------------

  it("rejects a result for a job whose assigned agent does not match the installation's agent", async () => {
    // Regression guard: the agent-identity leg of this check compares
    // job.assigned_agent_id (certops_agents.id, a UUID) against
    // installationRow.agent_id (the same UUID space), never
    // result.agentId (the agent's wire-format identity string, e.g.
    // "candidate-<host>-<pid>", a different identifier space that is never
    // persisted on the installation row). A previous version of this check
    // compared result.agentId to installationRow.agent_id directly, which
    // could never match for any real agent and made every live
    // distribute-trust/revoke-trust result ingestion fail.
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-agent-mismatch-${crypto.randomUUID()}`,
      }),
    );
    const job = await getJobRow(outcome.job.id);
    job.assigned_agent_id = crypto.randomUUID();
    const installationRow = await getInstallationById(outcome.installation.id);

    await expectServiceError(
      withTx((client) =>
        ingestTrustJobResult({
          client,
          job,
          result: buildResult({
            job,
            installationRow,
            outcome: "installed",
          }),
        }),
      ),
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  });

  it("rejects a result whose store does not match the signed job", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store: "Root",
        idempotencyKey: `result-store-mismatch-${crypto.randomUUID()}`,
      }),
    );
    const job = await getJobRow(outcome.job.id);
    const installationRow = await getInstallationById(outcome.installation.id);

    await expectServiceError(
      withTx((client) =>
        ingestTrustJobResult({
          client,
          job,
          result: buildResult({
            job,
            installationRow,
            outcome: "installed",
            storeOverride: "CA",
          }),
        }),
      ),
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  });

  it("rejects a result whose observed fingerprint does not match the signed job's installation row", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-fingerprint-mismatch-${crypto.randomUUID()}`,
      }),
    );
    const job = await getJobRow(outcome.job.id);
    const installationRow = await getInstallationById(outcome.installation.id);

    await expectServiceError(
      withTx((client) =>
        ingestTrustJobResult({
          client,
          job,
          result: buildResult({
            job,
            installationRow,
            outcome: "installed",
            fingerprintOverride: crypto
              .createHash("sha256")
              .update(crypto.randomUUID())
              .digest("hex"),
          }),
        }),
      ),
      CERTOPS_TRUST_RESULT_MISMATCH,
    );
  });

  it("rejects a result whose transitionGeneration is stale", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-stale-${crypto.randomUUID()}`,
      }),
    );
    const job = await getJobRow(outcome.job.id);
    const installationRow = await getInstallationById(outcome.installation.id);

    // The signed job and its installation row are still the CURRENT ones
    // (last_job_id matches); only the reported generation itself is wrong
    // -- e.g. the agent held on to a stale copy of the number. This must be
    // rejected purely on the generation mismatch, independent of any
    // superseding transition.
    await expectServiceError(
      withTx((client) =>
        ingestTrustJobResult({
          client,
          job,
          result: buildResult({
            job,
            installationRow,
            outcome: "installed",
            generationOverride: installationRow.transition_generation - 1,
          }),
        }),
      ),
      CERTOPS_TRUST_RESULT_STALE_GENERATION,
    );

    const installation = await getInstallationById(outcome.installation.id);
    expect(installation.transition_state).to.equal(
      "pending_install",
      "a rejected stale-generation result must not advance the row",
    );
  });

  it("rejects a result that reports a non-null failureCategory (self-contradictory: only ingested via the succeeded-job path)", async () => {
    // Hardens the outcome/mutationPerformed schema tie (installed/removed
    // now require mutationPerformed: true) with a service-layer check for
    // the one combination the schema alone cannot express: this function is
    // only ever called for a job the caller has already classified as
    // succeeded, and the reference agent never reports status "succeeded"
    // with a non-null failureCategory - so a result that does is rejected
    // outright rather than silently accepted as a shape-valid success.
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-contradictory-failure-${crypto.randomUUID()}`,
      }),
    );
    const job = await getJobRow(outcome.job.id);
    const installationRow = await getInstallationById(outcome.installation.id);

    await expectServiceError(
      withTx((client) =>
        ingestTrustJobResult({
          client,
          job,
          result: buildResult({
            job,
            installationRow,
            outcome: "installed",
            failureCategoryOverride: "os_mutation_failed",
          }),
        }),
      ),
      CERTOPS_TRUST_RESULT_INVALID,
    );

    const installation = await getInstallationById(outcome.installation.id);
    expect(installation.transition_state).to.equal(
      "pending_install",
      "a rejected self-contradictory result must not advance the row",
    );
  });

  it("advances installed->installed with provenance tokentimer_installed on a successful distribute", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-installed-${crypto.randomUUID()}`,
      }),
    );
    const job = await getJobRow(outcome.job.id);
    const installationRow = await getInstallationById(outcome.installation.id);

    const updated = await withTx((client) =>
      ingestTrustJobResult({
        client,
        job,
        result: buildResult({ job, installationRow, outcome: "installed" }),
      }),
    );

    expect(updated.transitionState).to.equal("installed");
    expect(updated.provenance).to.equal("tokentimer_installed");
  });

  it("a fresh installation's first-ever result starts provenance at preexisting, not tokentimer_installed", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-fresh-provenance-${crypto.randomUUID()}`,
      }),
    );
    const installationRow = await getInstallationById(outcome.installation.id);
    // Before any result is ingested, nothing has actually been installed by
    // TokenTimer yet - defaulting to tokentimer_installed here would let an
    // outcome:"preexisting" result (agent found the cert already there, no
    // mutation performed) keep a provenance TokenTimer never earned.
    expect(installationRow.provenance).to.equal("preexisting");
  });

  it("preexisting never loosens an already-tokentimer_installed provenance", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();

    const firstOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-preexisting-first-${crypto.randomUUID()}`,
      }),
    );
    const firstJob = await getJobRow(firstOutcome.job.id);
    const firstInstallationRow = await getInstallationById(
      firstOutcome.installation.id,
    );
    const afterInstall = await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: firstJob,
        result: buildResult({
          job: firstJob,
          installationRow: firstInstallationRow,
          outcome: "installed",
        }),
      }),
    );
    expect(afterInstall.provenance).to.equal("tokentimer_installed");

    const secondOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `result-preexisting-second-${crypto.randomUUID()}`,
      }),
    );
    const secondJob = await getJobRow(secondOutcome.job.id);
    const secondInstallationRow = await getInstallationById(
      secondOutcome.installation.id,
    );

    const updated = await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: secondJob,
        result: buildResult({
          job: secondJob,
          installationRow: secondInstallationRow,
          outcome: "preexisting",
        }),
      }),
    );

    expect(updated.transitionState).to.equal("installed");
    // preexisting must never loosen an already-tokentimer_installed
    // provenance -- the agent reporting "found it already there" this time
    // does not retroactively erase who really put it there originally.
    expect(updated.provenance).to.equal("tokentimer_installed");
  });

  it("advances removed/already_absent outcomes to transition_state 'removed'", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";
    const owner = "workspace-policy";

    const distributeOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `result-removed-setup-${crypto.randomUUID()}`,
      }),
    );
    const distributeJob = await getJobRow(distributeOutcome.job.id);
    const distributeInstallationRow = await getInstallationById(
      distributeOutcome.installation.id,
    );
    await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: distributeJob,
        result: buildResult({
          job: distributeJob,
          installationRow: distributeInstallationRow,
          outcome: "installed",
        }),
      }),
    );

    const revokeOutcome = await createTrustJob(
      revokeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `result-removed-${crypto.randomUUID()}`,
      }),
    );
    const revokeJob = await getJobRow(revokeOutcome.job.id);
    const revokeInstallationRow = await getInstallationById(
      revokeOutcome.installation.id,
    );

    const updated = await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: revokeJob,
        result: buildResult({
          job: revokeJob,
          installationRow: revokeInstallationRow,
          outcome: "removed",
        }),
      }),
    );
    expect(updated.transitionState).to.equal("removed");
  });

  // --- Reconciliation sweep (decision 20b/20f/20h) --------------------------

  it("marks an overdue pending row stale once it exceeds the max reconcile age", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `sweep-stale-${crypto.randomUUID()}`,
      }),
    );

    // Force the row overdue: next_reconcile_at in the past.
    await TestUtils.execQuery(
      `UPDATE certops_trust_anchor_installations
          SET next_reconcile_at = NOW() - INTERVAL '1 hour',
              last_attempt_at = NOW() - INTERVAL '10 hours'
        WHERE id = $1`,
      [outcome.installation.id],
    );

    const summary = await sweepOverdueTrustInstallations({
      dbPool: pool,
      maxAgeMs: 60 * 60 * 1000,
    });
    expect(summary.markedStale).to.be.greaterThanOrEqual(1);

    const installation = await getInstallationById(outcome.installation.id);
    expect(installation.next_reconcile_at).to.equal(null);
    // The row does have a last_job_id, and that job is still pending, so the
    // recorded reason names the status that failed to resolve. The
    // "_no_job" variant is reserved for the (unreachable) no-job case.
    expect(installation.last_error).to.equal(
      "reconciliation_stale_job_pending",
    );
  });

  it("reschedules an overdue row that is still within its max age budget", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `sweep-reschedule-${crypto.randomUUID()}`,
      }),
    );

    await TestUtils.execQuery(
      `UPDATE certops_trust_anchor_installations
          SET next_reconcile_at = NOW() - INTERVAL '1 minute'
        WHERE id = $1`,
      [outcome.installation.id],
    );

    const before = await getInstallationById(outcome.installation.id);
    const summary = await sweepOverdueTrustInstallations({
      dbPool: pool,
      maxAgeMs: 6 * 60 * 60 * 1000,
      reconcileDelayMs: 15 * 60 * 1000,
    });
    expect(summary.rescheduled).to.be.greaterThanOrEqual(1);

    const after = await getInstallationById(outcome.installation.id);
    expect(after.next_reconcile_at).to.not.equal(null);
    expect(new Date(after.next_reconcile_at).getTime()).to.be.greaterThan(
      new Date(before.next_reconcile_at).getTime(),
    );
  });

  it("unwinds (rather than redispatches) an overdue row whose job already reached a terminal-negative status", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const outcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        idempotencyKey: `sweep-unwind-${crypto.randomUUID()}`,
      }),
    );

    // Simulate the terminal-negative hook having been missed: the job row
    // itself reached 'failed' but nothing unwound the installation row.
    await TestUtils.execQuery(
      `UPDATE certificate_jobs SET status = 'failed' WHERE id = $1`,
      [outcome.job.id],
    );
    await TestUtils.execQuery(
      `UPDATE certops_trust_anchor_installations
          SET next_reconcile_at = NOW() - INTERVAL '1 minute'
        WHERE id = $1`,
      [outcome.installation.id],
    );

    const summary = await sweepOverdueTrustInstallations({ dbPool: pool });
    expect(summary.unwound).to.be.greaterThanOrEqual(1);

    const installation = await getInstallationById(outcome.installation.id);
    expect(installation).to.equal(undefined, "pending_install must be unwound, not redispatched");
  });

  // --- Anchor-level retire (decision 20g) ------------------------------------

  it("retire never fans out removal jobs against existing installations", async () => {
    const anchor = await createFreshAnchor();
    const agent = await createAgent();
    const store = "Root";
    const owner = "workspace-policy";

    const distributeOutcome = await createTrustJob(
      distributeOptions({
        anchor,
        agent,
        store,
        owner,
        idempotencyKey: `retire-no-fanout-${crypto.randomUUID()}`,
      }),
    );
    const distributeJob = await getJobRow(distributeOutcome.job.id);
    const distributeInstallationRow = await getInstallationById(
      distributeOutcome.installation.id,
    );
    await withTx((client) =>
      ingestTrustJobResult({
        client,
        job: distributeJob,
        result: buildResult({
          job: distributeJob,
          installationRow: distributeInstallationRow,
          outcome: "installed",
        }),
      }),
    );

    const jobCountBefore = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS n FROM certificate_jobs
        WHERE workspace_id = $1 AND subject_id = $2`,
      [workspaceId, anchor.id],
    );

    await retireTrustAnchor({ workspaceId, anchorId: anchor.id });

    const jobCountAfter = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS n FROM certificate_jobs
        WHERE workspace_id = $1 AND subject_id = $2`,
      [workspaceId, anchor.id],
    );
    expect(jobCountAfter.rows[0].n).to.equal(jobCountBefore.rows[0].n);

    const installation = await getInstallationById(distributeOutcome.installation.id);
    expect(installation.transition_state).to.equal(
      "installed",
      "retiring the anchor must not touch existing installation rows",
    );
  });

  it("is idempotent: retiring an already-retired anchor is a no-op success", async () => {
    const anchor = await createFreshAnchor();
    const first = await retireTrustAnchor({ workspaceId, anchorId: anchor.id });
    const second = await retireTrustAnchor({ workspaceId, anchorId: anchor.id });

    expect(first.retiredNow).to.equal(true);
    expect(second.retiredNow).to.equal(false);
    // The underlying column is still literally 'revoked' (decision 6's
    // enum is unchanged); only the user/audit-facing verb is "retire"
    // (decision 20g). See retireTrustAnchor's own doc comment for the
    // terminology resolution this asserts.
    expect(second.anchor.status).to.equal("revoked");
  });

  it("lists anchors and reflects their current status", async () => {
    const anchor = await createFreshAnchor();
    await retireTrustAnchor({ workspaceId, anchorId: anchor.id });

    const activeOnly = await listTrustAnchors({ workspaceId, status: "active" });
    expect(activeOnly.find((entry) => entry.id === anchor.id)).to.equal(undefined);

    const revokedOnly = await listTrustAnchors({ workspaceId, status: "revoked" });
    expect(revokedOnly.find((entry) => entry.id === anchor.id)?.status).to.equal(
      "revoked",
    );
  });
});
