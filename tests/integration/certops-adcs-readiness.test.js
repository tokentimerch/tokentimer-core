const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  CERTOPS_ADCS_AGENT_NOT_PREPARED,
  createAutomaticAdcsRenewal,
} = require("../../apps/api/services/certops/renewalScheduler");

// Realistic values: the CA config and template are plain text, and the
// readiness gate compares them as text.
const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const OTHER_TEMPLATE = "LegacyWebServer";
const KEY = "ab".repeat(32);
const OTHER_KEY = "cd".repeat(32);
const REFERENCE = "app.example.com";

describe("AD CS automatic renewal readiness (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();
    const email = `adcs-ready-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'AD CS Readiness', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;
    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'AD CS Readiness WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    await TestUtils.execQuery(
      `DELETE FROM audit_events
        WHERE workspace_id = $1
           OR subject_user_id = $2
           OR actor_user_id = $2`,
      [workspaceId, ownerId],
    );
    await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
  });

  // Each scenario gets its own issuer and agent so earlier evidence cannot
  // change which preflight is the latest one.
  async function scenario(template = TEMPLATE) {
    const issuer = await TestUtils.execQuery(
      `INSERT INTO certificate_issuers (workspace_id, kind, name, current_version, revalidation_required)
       VALUES ($1, 'adcs', $2, 1, false)
       RETURNING id`,
      [workspaceId, `Issuing CA ${crypto.randomUUID()}`],
    );
    const issuerId = issuer.rows[0].id;
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 1, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, template, KEY],
    );
    const agent = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, declared_target_selectors
       ) VALUES ($1, $2, 'adcs-agent', '0.1.0', '1.0.0', $3, $4, 'active', $5::jsonb)
       RETURNING id`,
      [
        workspaceId,
        `agent-${crypto.randomUUID()}`,
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
        JSON.stringify([REFERENCE]),
      ],
    );
    return { issuerId, agentId: agent.rows[0].id };
  }

  async function addPreflight({ issuerId, agentId, verdict, hoursAgo = 0 }) {
    await TestUtils.execQuery(
      `INSERT INTO certificate_jobs (
         workspace_id, operation, status, executor_kind, mode, subject_type,
         subject_id, payload, requested_by_user_id, assigned_agent_id, result_metadata,
         created_at
       ) VALUES ($1, 'adcs-preflight', 'succeeded', 'agent', 'real', 'external',
         $2, '{}'::jsonb, $3, $4, $5::jsonb,
         NOW() - make_interval(hours => $6::int))`,
      [
        workspaceId,
        issuerId,
        ownerId,
        agentId,
        JSON.stringify({ preflightVerdict: verdict }),
        hoursAgo,
      ],
    );
  }

  // Moves confirmation back so an older preflight can still be after it.
  async function backdateConfirmation(issuerId, hoursAgo) {
    await TestUtils.execQuery(
      `UPDATE certificate_issuer_versions
          SET confirmed_at = NOW() - make_interval(hours => $3::int)
        WHERE workspace_id = $1 AND issuer_id = $2 AND version = 1`,
      [workspaceId, issuerId, hoursAgo],
    );
  }

  // Shape written by the agent-result path: the verdict fields the gate reads.
  function verdict({ template = TEMPLATE, keySha256 = KEY } = {}) {
    return {
      templateCheck: "safe",
      caCheck: "safe",
      caConfig: CA,
      template,
      caKeySha256s: [keySha256],
    };
  }

  // Runs the real gate against the database and reports the scheduler outcome.
  async function runGate(issuerId) {
    const certificate = {
      id: crypto.randomUUID(),
      workspace_id: workspaceId,
      profile_id: null,
      profile_issuer_id: issuerId,
      common_name: "app.example.com",
      not_after: "2027-12-01T00:00:00Z",
      profile_public_metadata: {
        renewalProfile: {
          target: {
            type: "windows-iis",
            reference: REFERENCE,
            store: "WebHosting",
            binding: { site: "Shop", port: 443 },
          },
          sanPolicy: { sans: ["app.example.com"] },
          keyAlgorithm: "rsa",
          keySize: 2048,
        },
      },
    };
    const error = await createAutomaticAdcsRenewal({
      dbPool: pool,
      certificate,
      mode: "real",
      env: {},
      auditWriter: async () => {},
    }).catch((caught) => caught);
    return { error };
  }

  it("qualifies an agent whose safe preflight matches the confirmed CA, template, and key", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({ issuerId, agentId, verdict: verdict() });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.not.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("does not qualify a preflight older than the 24-hour freshness bound", async () => {
    const { issuerId, agentId } = await scenario();
    await backdateConfirmation(issuerId, 48);
    await addPreflight({ issuerId, agentId, verdict: verdict(), hoursAgo: 25 });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("qualifies a preflight 23 hours old, inside the freshness bound", async () => {
    const { issuerId, agentId } = await scenario();
    await backdateConfirmation(issuerId, 48);
    await addPreflight({ issuerId, agentId, verdict: verdict(), hoursAgo: 23 });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.not.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("does not qualify a preflight that checked a different template", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({
      issuerId,
      agentId,
      verdict: verdict({ template: OTHER_TEMPLATE }),
    });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("does not qualify a preflight that pinned a different CA key", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({
      issuerId,
      agentId,
      verdict: verdict({ keySha256: OTHER_KEY }),
    });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("stops qualifying evidence once the issuer is re-confirmed with a different template", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({ issuerId, agentId, verdict: verdict() });
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 2, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, OTHER_TEMPLATE, KEY],
    );
    await TestUtils.execQuery(
      "UPDATE certificate_issuers SET current_version = 2 WHERE id = $1",
      [issuerId],
    );
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("requires a new preflight job created after re-confirmation even when nothing changed", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({ issuerId, agentId, verdict: verdict() });
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 2, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, TEMPLATE, KEY],
    );
    await TestUtils.execQuery(
      "UPDATE certificate_issuers SET current_version = 2 WHERE id = $1",
      [issuerId],
    );
    const before = await runGate(issuerId);
    expect(before.error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);

    await addPreflight({ issuerId, agentId, verdict: verdict() });
    const after = await runGate(issuerId);
    expect(after.error?.code).to.not.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });
});
