"use strict";

const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const {
  RENEWAL_PATH_STATES,
  RENEWAL_PATH_REASONS,
  resolveRenewalPathForCertificate,
  resolveRenewalPathsForWorkspace,
  listCertificatesDependentOnAgent,
  countCertificatesDependentPerAgent,
} = require("../../apps/api/services/certops/renewalPathHealth.js");
const {
  generateAgentCredential,
} = require("../../apps/api/services/certops/agentCredentials");
const { pool } = require("../../apps/api/db/database");

/**
 * Real renewal-path resolution for every topology case (renewalPathHealth.js
 * module doc: PINNED, OPEN-CLAIM redundant/degraded/all-down, no-target,
 * pinned-but-retired, plus the "not applicable" short-circuits) against a
 * real Postgres workspace.
 *
 * Unlike tests/unit/certops-renewal-path-health.test.js (which stubs every
 * db.query call with a fake object that pattern-matches SQL prefixes), this
 * test creates real managed_certificates/certificate_profiles/certops_agents
 * rows and calls the real exported resolvers against them, so the actual
 * SQL (the JOIN to certificate_profiles, the JSONB path extraction for
 * discovery_agent_id, the target-selector array containment check) is
 * exercised for real, not merely pattern-matched by a fixture.
 */
describe("CertOps renewal-path health - real topology resolution against a real Postgres workspace", function () {
  this.timeout(120000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();

    const email = `renewal-path-health-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Renewal Path Health Test Owner', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;

    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Renewal Path Health Test WS', $2, 'pro')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    }
    if (ownerId) {
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  function executableRenewalProfile(targetReference) {
    return {
      schemaVersion: 1,
      profileId: `renewal-path-profile-${crypto.randomUUID()}`,
      profileName: "renewal-path-test",
      sanPolicy: {
        mode: "exact",
        sans: ["app.example.com"],
        allowWildcards: false,
      },
      keyAlgorithm: "rsa",
      keySize: 2048,
      keyRotationPolicy: { rotateOnRenew: true },
      preferredChain: null,
      ca: {
        endpoint: "https://acme.example.test/directory",
        accountRef: null,
        eabRef: null,
      },
      acme: { kind: "certbot", commandRef: "renew.web" },
      dns: { provider: "cloudflare", zone: "example.com" },
      deploymentTargets: [
        {
          type: "endpoint",
          reference: targetReference,
          certPath: "/etc/ssl/app.pem",
        },
      ],
      target: {
        type: "endpoint",
        reference: targetReference,
        certPath: "/etc/ssl/app.pem",
      },
      verification: { host: null, port: null, requireMatch: false },
    };
  }

  async function createAgent({
    status = "active",
    lastSeenAt = "NOW()",
    targetSelectors = [],
  } = {}) {
    const agentId = `renewal-path-test-agent-${crypto.randomUUID()}`;
    const credential = generateAgentCredential();
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, declared_target_selectors,
         supported_operations, supported_dns_providers, declared_command_profile_names,
         last_seen_at
       )
       VALUES (
         $1, $2, 'renewal-path-test-fleet-agent', '1.0.0', '1.0.0', $3, $4, $5, $6::jsonb,
         $7::jsonb, $8::jsonb, $9::jsonb, ${lastSeenAt}
       )
       RETURNING id`,
      [
        workspaceId,
        agentId,
        credential.credentialPrefix,
        credential.credentialHash,
        status,
        JSON.stringify(targetSelectors),
        JSON.stringify(["renew"]),
        JSON.stringify(["cloudflare"]),
        JSON.stringify(["renew.web"]),
      ],
    );
    return { id: String(inserted.rows[0].id), agentId };
  }

  async function createProfile({ status = "active", targetReference = null } = {}) {
    // Incomplete profiles stay incomplete so the topology_unknown path is
    // exercised. Executable topology cases must pass a targetReference.
    const publicMetadata = targetReference
      ? { renewalProfile: executableRenewalProfile(targetReference) }
      : { renewalProfile: {} };
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certificate_profiles (workspace_id, name, status, public_metadata)
       VALUES ($1, $2, $3, $4::jsonb)
       RETURNING id`,
      [workspaceId, `renewal-path-test-profile-${crypto.randomUUID()}`, status, JSON.stringify(publicMetadata)],
    );
    return String(inserted.rows[0].id);
  }

  async function createCertificate({
    source = "manual",
    keyMode = "agent-local",
    status = "active",
    profileId = null,
    discoveryAgentId = null,
  } = {}) {
    const publicMetadata = discoveryAgentId
      ? { controllerObservation: { agentId: discoveryAgentId } }
      : {};
    const inserted = await TestUtils.execQuery(
      `INSERT INTO managed_certificates (workspace_id, common_name, source, key_mode, status, profile_id, public_metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id`,
      [
        workspaceId,
        `renewal-path-test-${crypto.randomUUID()}.example`,
        source,
        keyMode,
        status,
        profileId,
        JSON.stringify(publicMetadata),
      ],
    );
    return String(inserted.rows[0].id);
  }

  it("Case A (PINNED): agent_filesystem source whose discovery_agent_id resolves to a real online agent is Healthy with exactly one required dependency", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    const agent = await createAgent({ targetSelectors: [targetRef] });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({
      source: "agent_filesystem",
      profileId,
      discoveryAgentId: agent.agentId,
    });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.HEALTHY);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
    expect(result.dependencies).to.have.length(1);
    expect(result.dependencies[0].agentRowId).to.equal(agent.id);
    expect(result.dependencies[0].required).to.equal(true);
    expect(result.dependencies[0].online).to.equal(true);
  });

  it("Case A (PINNED, offline): the pinned agent is real but offline -> Unavailable/agent_offline, not open-claim fallback", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    const agent = await createAgent({
      targetSelectors: [targetRef],
      lastSeenAt: "NOW() - INTERVAL '1 hour'",
    });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({
      source: "agent_filesystem",
      profileId,
      discoveryAgentId: agent.agentId,
    });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.UNAVAILABLE);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.AGENT_OFFLINE);
    expect(result.dependencies).to.have.length(1);
    expect(result.dependencies[0].online).to.equal(false);
  });

  it("Case A (PINNED, retired): the pinned agent has been retired -> permanent Unavailable/assigned_agent_retired, never falls through to open-claim", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    const agent = await createAgent({ targetSelectors: [targetRef] });
    await TestUtils.execQuery(
      `UPDATE certops_agents SET status = 'retired', retired_at = NOW() WHERE id = $1`,
      [agent.id],
    );
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({
      source: "agent_filesystem",
      profileId,
      discoveryAgentId: agent.agentId,
    });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.UNAVAILABLE);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.ASSIGNED_AGENT_RETIRED);
    expect(result.dependencies).to.have.length(0);
  });

  it("Case B (OPEN-CLAIM, single agent online): a non-agent_filesystem certificate with one matching declared selector is Healthy", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    const agent = await createAgent({ targetSelectors: [targetRef] });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.HEALTHY);
    expect(result.dependencies).to.have.length(1);
    expect(result.dependencies[0].required).to.equal(true);
  });

  it("Case B (OPEN-CLAIM, redundant, all online): two agents declaring the same selector -> Healthy, neither individually required", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    const agentOne = await createAgent({ targetSelectors: [targetRef] });
    const agentTwo = await createAgent({ targetSelectors: [targetRef] });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.HEALTHY);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
    expect(result.dependencies).to.have.length(2);
    expect(result.dependencies.every((d) => d.required === false)).to.equal(true);
    expect(result.dependencies.map((d) => d.agentRowId).sort()).to.deep.equal(
      [agentOne.id, agentTwo.id].sort(),
    );
  });

  it("Case B->Degraded (OPEN-CLAIM, redundant, partial outage): one of two declaring agents offline -> Degraded/partial_location_outage", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    await createAgent({ targetSelectors: [targetRef] });
    await createAgent({ targetSelectors: [targetRef], lastSeenAt: "NOW() - INTERVAL '1 hour'" });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.DEGRADED);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.PARTIAL_LOCATION_OUTAGE);
    expect(result.dependencies).to.have.length(2);
  });

  it("Case C (OPEN-CLAIM, all executors down): both declaring agents offline -> Unavailable/all_executors_offline", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    await createAgent({ targetSelectors: [targetRef], lastSeenAt: "NOW() - INTERVAL '1 hour'" });
    await createAgent({ targetSelectors: [targetRef], lastSeenAt: "NOW() - INTERVAL '1 hour'" });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.UNAVAILABLE);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.ALL_EXECUTORS_OFFLINE);
  });

  it("no agent declares the configured target selector -> Unavailable/no_execution_target", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    // A real agent exists in the workspace, but declares an unrelated selector.
    await createAgent({ targetSelectors: [`${targetRef}-unrelated`] });
    const profileId = await createProfile({ targetReference: targetRef });
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.UNAVAILABLE);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.NO_EXECUTION_TARGET);
    expect(result.dependencies).to.have.length(0);
  });

  it("no target reference at all on an otherwise-real profile -> Unknown/topology_unknown", async () => {
    const profileId = await createProfile();
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(RENEWAL_PATH_STATES.UNKNOWN);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.TOPOLOGY_UNKNOWN);
  });

  it("key_mode not agent-deployable -> renewalPathState is null with not_agent_deployable, never a fabricated Unavailable", async () => {
    const profileId = await createProfile();
    const certId = await createCertificate({ source: "manual", profileId, keyMode: "external-unknown" });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(null);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.NOT_AGENT_DEPLOYABLE);
  });

  it("no profile linked at all -> renewalPathState is null with no_profile", async () => {
    const certId = await createCertificate({ source: "manual", profileId: null });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(null);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.NO_PROFILE);
  });

  it("a real disabled certificate_profiles row -> renewalPathState is null with auto_renew_disabled, not a fabricated dependency failure", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    await createAgent({ targetSelectors: [targetRef] });
    const profileId = await createProfile({ status: "disabled", targetReference: targetRef });
    const certId = await createCertificate({ source: "manual", profileId });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(null);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.AUTO_RENEW_DISABLED);
  });

  it("a real revoked managed_certificates row -> renewalPathState is null with certificate_retired", async () => {
    const profileId = await createProfile();
    const certId = await createCertificate({ source: "manual", profileId, status: "revoked" });

    const result = await resolveRenewalPathForCertificate({ db: pool, workspaceId, certificateId: certId });
    expect(result.renewalPathState).to.equal(null);
    expect(result.renewalPathReason).to.equal(RENEWAL_PATH_REASONS.CERTIFICATE_RETIRED);
  });

  it("resolveRenewalPathsForWorkspace excludes revoked/decommissioned rows entirely (they never even appear in the batch)", async () => {
    const profileId = await createProfile();
    const revokedId = await createCertificate({ source: "manual", profileId, status: "revoked" });
    const activeId = await createCertificate({ source: "manual", profileId, keyMode: "external-unknown" });

    const all = await resolveRenewalPathsForWorkspace({ db: pool, workspaceId });
    const ids = all.map((entry) => entry.certificateId);
    expect(ids).to.not.include(revokedId);
    expect(ids).to.include(activeId);
  });

  it("listCertificatesDependentOnAgent and countCertificatesDependentPerAgent report a real agent's real dependents, including redundant (non-required) ones", async () => {
    const targetRef = `renewal-path-test-target-${crypto.randomUUID()}`;
    const agentOne = await createAgent({ targetSelectors: [targetRef] });
    const agentTwo = await createAgent({ targetSelectors: [targetRef] });
    const unrelatedAgent = await createAgent({ targetSelectors: [`${targetRef}-other`] });
    const profileId = await createProfile({ targetReference: targetRef });
    await createCertificate({ source: "manual", profileId });
    await createCertificate({ source: "manual", profileId });

    const dependentOnOne = await listCertificatesDependentOnAgent({
      db: pool,
      workspaceId,
      agentRowId: agentOne.id,
    });
    expect(dependentOnOne.length).to.be.at.least(2);

    const counts = await countCertificatesDependentPerAgent({ db: pool, workspaceId });
    expect(counts.get(agentOne.id)).to.be.at.least(2);
    expect(counts.get(agentTwo.id)).to.be.at.least(2);
    expect(counts.get(unrelatedAgent.id) || 0).to.equal(0);
  });
});
