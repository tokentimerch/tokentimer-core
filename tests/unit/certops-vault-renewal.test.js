"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  deriveRenewalProfileFromIssuedCertificate,
} = require("../../apps/api/services/certops/renewalProfileDerivation");
const {
  isAgentDeployableKeyMode,
  isAgentRenewableKeyMode,
  manualRenewalJobCreator,
} = require("../../apps/api/services/certops/jobs");
const {
  classifyRenewalBlock,
  RENEWAL_BLOCKED_NO_PROFILE,
} = require("../../apps/api/services/certops/renewalProfileAdmin");
const { deriveCertificateRenewalState } =
  require("../../apps/api/routes/certops")._test;
const { createManualCertificateJobHandler } =
  require("../../apps/api/routes/certops")._test;
const {
  resolveDistributionJobDefaults,
} = require("../../apps/api/services/certops/materialDistribution");
const {
  repairPublicationRenewalProfile,
} = require("../../apps/api/services/certops/publicationRenewalRepair");

const W = "11111111-1111-4111-8111-111111111111";
const C = "22222222-2222-4222-8222-222222222222";
const G = "33333333-3333-4333-8333-333333333333";
const P = "44444444-4444-4444-8444-444444444444";
const A = "55555555-5555-4555-8555-555555555555";

test("manual renewal returns the publication conflict instead of an internal error", async () => {
  const handler = createManualCertificateJobHandler({
    manualJobCreator: async () => {
      throw Object.assign(new Error("CERTOPS_PUBLICATION_UNRESOLVED"), {
        code: "CERTOPS_PUBLICATION_UNRESOLVED",
        statusCode: 409,
      });
    },
  });
  const response = {
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
  await handler({ workspace: { id: W }, body: { operation: "renew", subjectId: C } }, response);
  assert.equal(response.statusCode, 409);
  assert.equal(response.body.code, "CERTOPS_PUBLICATION_UNRESOLVED");
});
const publication = {
  type: "vault-kv2",
  groupId: G,
  managementPeriodId: P,
  materialVersionId: "66666666-6666-5666-8666-666666666666",
  materialStoreRef: "customer",
  issuanceProfileRef: "wildcard",
  profileRevision: 1,
};
const payload = {
  target: { type: "domain", reference: "*.example.com" },
  sans: ["*.example.com", "example.com"],
  caEndpoint: "https://acme.example.com/directory",
  commandRef: "certbot",
  dnsProvider: "cloudflare",
  dnsZone: "example.com",
  keyAlgorithm: "ecdsa",
  keySize: 256,
  publication,
};
const profile = deriveRenewalProfileFromIssuedCertificate({
  payload,
  certificate: { commonName: null, subjectAltNames: payload.sans },
});
const row = {
  id: C,
  workspace_id: W,
  status: "active",
  key_mode: "vault-managed",
  key_reference: "vault:customer/group",
  not_after: "2027-01-01T00:00:00.000Z",
  common_name: "*.example.com",
  subject_alt_names: payload.sans,
  profile_id: P,
  profile_public_metadata: { renewalProfile: profile },
};

test("SAN-only Vault profile enables renewal, never generic local deployment", () => {
  assert.deepEqual(profile.sanPolicy.sans, payload.sans);
  assert.deepEqual(profile.deploymentTargets, []);
  assert.equal(isAgentRenewableKeyMode(row), true);
  assert.equal(isAgentDeployableKeyMode(row), false);
  assert.equal(classifyRenewalBlock(row), null);
  assert.equal(deriveCertificateRenewalState(row).state, "auto");
  const incomplete = {
    ...row,
    profile_public_metadata: {
      renewalProfile: { ...profile, publicationDestination: undefined },
    },
  };
  assert.equal(isAgentRenewableKeyMode(incomplete), false);
  const missing = { ...row, profile_id: null };
  assert.equal(classifyRenewalBlock(missing), RENEWAL_BLOCKED_NO_PROFILE);
  assert.equal(deriveCertificateRenewalState(missing).state, "not-configured");
  assert.match(deriveCertificateRenewalState(missing).detail, /Repair it/);
});

test("transferred Vault inventory does not advertise repair from another workspace's publication", () => {
  const transferred = { ...row, profile_id: null, key_reference: null };
  const renewal = deriveCertificateRenewalState(transferred);
  assert.equal(renewal.state, "not-configured");
  assert.match(renewal.detail, /distribution is not configured in this workspace/);
  assert.doesNotMatch(renewal.detail, /repair/i);
});

test("manual renewal versions differ across requests and remain stable on replay", async () => {
  const creator = manualRenewalJobCreator({
    certificateId: C,
    loadCertificate: async () => row,
    createJob: async (options) => options.payload,
  });
  const run = (key) =>
    creator({ client: {}, workspaceId: W, idempotencyKey: key, payload: {} });
  const first = await run("rejected"),
    corrected = await run("corrected"),
    replay = await run("corrected");
  assert.notEqual(
    first.publication.materialVersionId,
    corrected.publication.materialVersionId,
  );
  assert.deepEqual(corrected, replay);
  assert.equal(corrected.publication.groupId, G);
  assert.equal(corrected.certPath, undefined);
});

test("publication renewal defaults to its issuer and rejects another executor", async () => {
  const client = {
    query: async () => ({
      rows: [
        {
          id: G,
          state: "active",
          ended_at: null,
          managed_certificate_id: C,
          issuer_agent_id: A,
          material_store_ref: "customer",
          issuance_profile_ref: "wildcard",
          profile_revision: 1,
          management_period_id: P,
        },
      ],
    }),
  };
  const options = {
    client,
    workspaceId: W,
    operation: "renew",
    subjectId: C,
    payload: { publication },
  };
  assert.deepEqual(await resolveDistributionJobDefaults(options), {
    autoAssignedAgentId: A,
  });
  await assert.rejects(
    resolveDistributionJobDefaults({ ...options, assignedAgentId: P }),
    { code: "CERTOPS_PUBLICATION_INTENT_MISMATCH" },
  );
});

test("repair fails closed without accepted publication evidence or a live issuer", async () => {
  for (const retired of [false, true]) {
    const queries = [];
    const client = {
      release() {},
      async query(sql) {
        queries.push(sql);
        if (/FROM workspaces/.test(sql))
          return { rows: [{ id: W, certops_paused: false }] };
        if (/SELECT g.id/.test(sql)) return { rows: [{ id: G }] };
        if (/SELECT g\.\*/.test(sql))
          return {
            rows: [
              { id: G, state: "active", ended_at: null, issuer_agent_id: A },
            ],
          };
        if (/FROM managed_certificates/.test(sql))
          return {
            rows: [
              {
                id: C,
                key_mode: "vault-managed",
                status: "active",
                profile_id: null,
              },
            ],
          };
        if (/FROM certops_agents/.test(sql))
          return { rowCount: retired ? 0 : 1, rows: [] };
        return { rows: [], rowCount: 0 };
      },
    };
    const oldEnabled = process.env.CERTOPS_ENABLED;
    process.env.CERTOPS_ENABLED = "true";
    try {
      await assert.rejects(
        repairPublicationRenewalProfile({
          workspaceId: W,
          certificateId: C,
          actorUserId: 1,
          dbPool: { connect: async () => client },
        }),
        {
          code: retired
            ? "CERTOPS_PUBLICATION_REPAIR_INELIGIBLE"
            : "CERTOPS_PUBLICATION_REPAIR_EVIDENCE_REQUIRED",
        },
      );
      assert.ok(queries.includes("ROLLBACK"));
      assert.ok(
        !queries.some((sql) =>
          /INSERT INTO certificate_profiles|UPDATE managed_certificates/.test(
            sql,
          ),
        ),
      );
    } finally {
      if (oldEnabled === undefined) delete process.env.CERTOPS_ENABLED;
      else process.env.CERTOPS_ENABLED = oldEnabled;
    }
  }
});
