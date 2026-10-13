const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  UNKNOWN_CA_BUCKET,
  adcsCaBucket,
  assertRenewalPerCaCapacityAvailable,
  normalizeCaBucket,
} = require("../../apps/api/services/certops/renewalCapacity");
const {
  certificateCaBucket,
} = require("../../apps/api/services/certops/renewalScheduler");

const TERMINAL = ["succeeded", "failed", "cancelled"];

function capacityClient(bucketRows) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (sql.includes("pg_advisory_xact_lock")) return { rows: [] };
      return { rows: bucketRows.map((ca_bucket) => ({ ca_bucket })) };
    },
  };
}

describe("AD CS capacity bucket", () => {
  it("keys AD CS by issuer identity, not by a CA URL", () => {
    assert.equal(adcsCaBucket("Issuer-ABC"), "adcs-issuer:issuer-abc");
    assert.equal(
      normalizeCaBucket(adcsCaBucket("issuer-abc")),
      adcsCaBucket("issuer-abc"),
    );
  });

  it("buckets an AD CS certificate by its issuer even when metadata names a URL", () => {
    const bucket = certificateCaBucket({
      profile_issuer_kind: "adcs",
      profile_issuer_id: "issuer-1",
      certificate_ca_endpoint: "https://acme.example.com/directory",
      profile_ca_endpoint: null,
    });
    assert.equal(bucket, adcsCaBucket("issuer-1"));
  });

  it("keeps ACME certificates bucketed by their normalized CA endpoint", () => {
    const bucket = certificateCaBucket({
      profile_issuer_kind: "acme",
      profile_issuer_id: "issuer-2",
      certificate_ca_endpoint: "HTTPS://CA.example.com/dir/",
      profile_ca_endpoint: null,
    });
    assert.equal(bucket, normalizeCaBucket("https://ca.example.com/dir"));
    assert.equal(
      certificateCaBucket({ profile_issuer_kind: null, profile_ca_endpoint: null }),
      UNKNOWN_CA_BUCKET,
    );
  });

  it("counts in-flight AD CS jobs against their own issuer, not the shared unknown bucket", async () => {
    const client = capacityClient(
      Array.from({ length: 5 }, () => adcsCaBucket("issuer-1")),
    );
    await assert.rejects(
      assertRenewalPerCaCapacityAvailable({
        client,
        workspaceId: "ws-1",
        payload: {},
        terminalStatuses: TERMINAL,
        perCaCap: 5,
        capacityBucket: adcsCaBucket("issuer-1"),
      }),
      { code: CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED },
    );
  });

  it("does not let other issuers' in-flight jobs use up this issuer's slots", async () => {
    const client = capacityClient([
      adcsCaBucket("issuer-2"),
      adcsCaBucket("issuer-2"),
      adcsCaBucket("issuer-2"),
      UNKNOWN_CA_BUCKET,
    ]);
    const result = await assertRenewalPerCaCapacityAvailable({
      client,
      workspaceId: "ws-1",
      payload: {},
      terminalStatuses: TERMINAL,
      perCaCap: 3,
      capacityBucket: adcsCaBucket("issuer-1"),
    });
    assert.equal(result.inFlight, 0);
    assert.equal(result.caBucket, adcsCaBucket("issuer-1"));
  });

  it("locks and counts through the enrollment link for AD CS jobs", async () => {
    const client = capacityClient([]);
    await assertRenewalPerCaCapacityAvailable({
      client,
      workspaceId: "ws-1",
      payload: {},
      terminalStatuses: TERMINAL,
      perCaCap: 5,
      capacityBucket: adcsCaBucket("issuer-1"),
    });
    const count = client.calls.find((call) => call.sql.includes("FOR UPDATE OF cj"));
    assert.ok(count, "in-flight count query runs");
    assert.match(count.sql, /certificate_enrollments e/);
    assert.match(count.sql, /e\.current_job_id = cj\.id/);
    assert.match(count.sql, /'adcs-issuer:' \|\| e\.issuer_id::text/);
  });
});
