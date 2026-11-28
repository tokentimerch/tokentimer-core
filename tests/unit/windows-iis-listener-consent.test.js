"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  enableWindowsIisConsumer,
  snapshotWindowsIisConsumers,
  authorizeWindowsIisConsumer,
  assertIndependentIisTarget,
} = require("../../apps/api/services/certops/windowsIisConsent");
const {
  formatBindingSelector,
} = require("../../packages/agent/src/windows-iis");
const now = new Date(),
  fp = "a".repeat(64);
function fixture(address, sni = null, priorSelector = null, sourceRef = null) {
  let stored = priorSelector;
  const owner = {
    period_id: "period",
    managed_certificate_id: "cert",
    current_identity_id: "identity",
    renewal_profile_id: "profile",
    fingerprint_sha256: fp,
    deployed_agent_id: "agent",
    certificate_status: "active",
    agent_public_id: "public",
    agent_status: "active",
    last_seen_at: now,
    created_at: now,
    profile_metadata: {
      renewalProfile: { target: { type: "windows-cert-store", store: "My" } },
    },
    declared_capabilities: ["windows-store-iis-consumers-v1"],
    capabilities_updated_at: now,
  };
  const target = {
    id: "target",
    source_ref: sourceRef,
    windows_store: "My",
    windows_site: "Site",
    windows_port: 443,
    windows_sni_host: sni,
    public_metadata: { agentId: "public", boundAddress: address },
    observed_fingerprint_sha256: fp,
    presence_state: "confirmed_present",
    captured_at: now,
    profile_conflict: false,
  };
  const client = {
    async query(sql, args) {
      if (sql.includes("FOR UPDATE OF p,mc")) return { rows: [owner] };
      if (sql.includes("SELECT DISTINCT p.id AS period_id"))
        return { rows: [] };
      if (sql.includes("FOR UPDATE OF ct,ci")) return { rows: [target] };
      if (
        sql.includes("FROM certificate_jobs WHERE") ||
        sql.includes("UPDATE certops_windows_iis_renewal_consumers c SET")
      )
        return { rows: [] };
      if (sql.includes("INSERT INTO certops_windows_store_renewal_owners"))
        return { rows: [{ id: "owner" }] };
      if (
        sql.includes("SELECT id,target_id,selector_key,authorization_revision")
      )
        return { rows: [] };
      if (sql.includes("INSERT INTO certops_windows_iis_renewal_consumers")) {
        stored = args[4];
        return { rows: [{ id: "consumer", authorization_revision: 1 }] };
      }
      if (sql.includes("FROM managed_certificates predecessor"))
        return { rows: [] };
      if (sql.includes("SELECT c.id AS consumer_id"))
        return {
          rows: [
            {
              ...target,
              consumer_id: "consumer",
              authorization_revision: 1,
              selector_key: stored,
              owner_id: "owner",
              management_period_id: "period",
              fingerprint_sha256: fp,
              certificate_status: "active",
              agent_status: "active",
              last_seen_at: now,
              created_at: now,
              agent_public_id: "public",
              target_id: "target",
            },
          ],
        };
      if (sql.includes("SELECT c.selector_key,"))
        return {
          rows: [
            {
              selector_key: stored,
              source_ref: sourceRef,
              windows_port: 443,
              windows_sni_host: sni,
              public_metadata: target.public_metadata,
            },
          ],
        };
      throw Error("Unexpected query");
    },
  };
  return {
    client,
    get selector() {
      return stored;
    },
  };
}
const snapshot = (f) =>
  snapshotWindowsIisConsumers({
    client: f.client,
    workspaceId: "workspace",
    certificateId: "cert",
    agentId: "agent",
  });
const authorize = (f) =>
  authorizeWindowsIisConsumer({
    client: f.client,
    agent: { id: "agent", workspaceId: "workspace" },
    jobId: "job",
    claimId: "claim",
    consumerId: "consumer",
    authorizationRevision: 1,
  });
test("IIS consent, snapshot and claim retain exact listener selector", async () => {
  for (const [address, sni, key, netsh] of [
    ["192.0.2.10", null, "ipport:192.0.2.10:443", "ipport=192.0.2.10:443"],
    ["::1", null, "ipport:[::1]:443", "ipport=[::1]:443"],
    ["::", null, "ipport:[::]:443", "ipport=[::]:443"],
    ["0.0.0.0", null, "ipport:0.0.0.0:443", "ipport=0.0.0.0:443"],
    [undefined, null, "ipport:0.0.0.0:443", "ipport=0.0.0.0:443"],
    [
      "0.0.0.0",
      "www.example.test",
      "hostnameport:www.example.test:443",
      "hostnameport=www.example.test:443",
    ],
  ]) {
    const f = fixture(address, sni);
    await enableWindowsIisConsumer({
      client: f.client,
      workspaceId: "workspace",
      periodId: "period",
      targetId: "target",
      actorUserId: 1,
      audit: async () => {},
    });
    assert.equal(f.selector, key);
    const x = await snapshot(f);
    assert.equal(x.length, 1);
    assert.equal(formatBindingSelector(x[0].binding), netsh);
    assert.equal(await authorize(f), true);
  }
});
test("historical wildcard consent cannot authorize a concrete observed IP", async () => {
  for (const address of ["192.0.2.10", "::1"]) {
    const f = fixture(address, null, "ipport:0.0.0.0:443");
    assert.deepEqual(await snapshot(f), []);
    assert.equal(await authorize(f), false);
  }
});
test("invalid or incompatible observed addresses fail closed", async () => {
  for (const [address, sni] of [
    ["not-ip", null],
    ["192.0.2.10", "www.example.test"],
    ["::1", "www.example.test"],
    ["::", "www.example.test"],
  ]) {
    const f = fixture(address, sni, "ipport:0.0.0.0:443");
    await assert.rejects(
      enableWindowsIisConsumer({
        client: f.client,
        workspaceId: "workspace",
        periodId: "period",
        targetId: "target",
        actorUserId: 1,
        audit: async () => {},
      }),
      { code: "CERTOPS_WINDOWS_CONSENT_REFUSED" },
    );
    assert.deepEqual(await snapshot(f), []);
    assert.equal(await authorize(f), false);
  }
});
test("independent IIS renewal rejects an overlapping observed listener", async () => {
  let compared;
  const client = {
    async query(sql, args) {
      if (sql.includes("SELECT c.id FROM")) {
        compared = args[2];
        return { rows: [] };
      }
      if (sql.includes("AS bound_address"))
        return {
          rows: [
            {
              windows_port: 443,
              windows_sni_host: null,
              bound_address: "192.0.2.10",
            },
          ],
        };
      throw Error("Unexpected query");
    },
  };
  await assert.rejects(
    assertIndependentIisTarget({
      client,
      workspaceId: "workspace",
      agentId: "agent",
      target: {
        type: "windows-iis",
        binding: { site: "Site", port: 443, address: "192.0.2.10" },
      },
    }),
    { code: "CERTOPS_WINDOWS_CONSENT_REFUSED" },
  );
  assert.equal(compared, "ipport:192.0.2.10:443");
});
test("explicit source with missing address metadata never becomes wildcard", async () => {
  const f = fixture(
    undefined,
    null,
    "ipport:0.0.0.0:443",
    "agent/host/iis_binding/Site:443@192.0.2.10",
  );
  await assert.rejects(
    enableWindowsIisConsumer({
      client: f.client,
      workspaceId: "workspace",
      periodId: "period",
      targetId: "target",
      actorUserId: 1,
      audit: async () => {},
    }),
    { code: "CERTOPS_WINDOWS_CONSENT_REFUSED" },
  );
  assert.deepEqual(await snapshot(f), []);
  assert.equal(await authorize(f), false);
});
