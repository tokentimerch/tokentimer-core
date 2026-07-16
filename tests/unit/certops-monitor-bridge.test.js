"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  PRIVATE_KEY_MATERIAL_REJECTED,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/parser.js"),
);
const {
  bridgeEndpointCertificateObservation,
  certificateFromObservation,
  CERTOPS_UNSAFE_IDENTITY,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/monitorBridge.js"),
);
const {
  upsertManagedCertificateByMonitorSource,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);

const FAKE_PRIVATE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const fakePem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_PRIVATE_BODY}\n-----END ${label}-----`;

const PRIVATE_KEY_PEM = fakePem("RSA PRIVATE KEY");
const NONCANONICAL_PRIVATE_KEY_PEM = `-----begin rsa private key-----\n${FAKE_PRIVATE_BODY}\n-----end rsa private key-----`;

const WORKSPACE_ID = "550e8400-e29b-41d4-a716-446655440000";
const MONITOR_A = "660e8400-e29b-41d4-a716-446655440001";
const MONITOR_B = "660e8400-e29b-41d4-a716-446655440002";
const SHARED_FINGERPRINT = "a".repeat(64);
const ROTATED_FINGERPRINT = "b".repeat(64);

function assertPrivateKeyRejected(fn) {
  assert.throws(fn, (error) => {
    assert.equal(error.code, PRIVATE_KEY_MATERIAL_REJECTED);
    assert.equal(error.status, 422);
    assert.match(error.message, /private key material/i);
    assert.doesNotMatch(error.message, /RSA PRIVATE KEY/i);
    assert.doesNotMatch(error.message, new RegExp(FAKE_PRIVATE_BODY));
    return true;
  });
}

function createIdentityStore() {
  const managed = new Map();
  const targets = new Map();
  const instances = new Map();
  let seq = 0;

  function managedKey(workspaceId, source, sourceRef) {
    return `${workspaceId}|${source}|${sourceRef}`;
  }

  function nextId(prefix) {
    seq += 1;
    return `${prefix}-${seq}`;
  }

  function rowFromInsertParams(params) {
    const now = new Date().toISOString();
    return {
      id: nextId("mc"),
      workspace_id: params[0],
      token_id: params[1],
      status: params[2],
      source: params[3],
      source_ref: params[4],
      name: params[5],
      common_name: params[6],
      subject_alt_names: params[7] || [],
      issuer: params[8],
      subject: params[9],
      serial_number: params[10],
      certificate_pem: params[11],
      fingerprint_sha256: params[12],
      spki_fingerprint_sha256: params[13],
      public_key_algorithm: params[14],
      public_key_size: params[15],
      signature_algorithm: params[16],
      not_before: params[17],
      not_after: params[18],
      key_mode: params[19],
      key_reference: params[20],
      public_metadata:
        typeof params[21] === "string" ? JSON.parse(params[21]) : params[21] || {},
      created_by: params[22],
      created_at: now,
      updated_at: now,
    };
  }

  function isRetiredStatus(status) {
    return status === "revoked" || status === "decommissioned";
  }

  // Emulate the D7 status CASE only when the query text actually contains it,
  // so tests exercise the production SQL rather than mock behavior.
  function sqlPreservesRetiredStatus(normalizedSql) {
    return /status = CASE\s+WHEN managed_certificates\.status IN \('revoked', 'decommissioned'\)\s+THEN managed_certificates\.status\s+ELSE .+? END/.test(
      normalizedSql,
    );
  }

  function nextStatusFor(normalizedSql, currentStatus, requestedStatus) {
    if (
      sqlPreservesRetiredStatus(normalizedSql) &&
      isRetiredStatus(currentStatus)
    ) {
      return currentStatus;
    }
    return requestedStatus;
  }

  return {
    managed,
    async query(sql, params = []) {
      const normalized = sql.replace(/\s+/g, " ").trim();

      if (normalized === "BEGIN" || normalized === "COMMIT" || normalized === "ROLLBACK") {
        return { rows: [] };
      }

      if (
        normalized.includes("FROM managed_certificates") &&
        normalized.includes("source = $2") &&
        normalized.includes("source_ref = $3")
      ) {
        const key = managedKey(params[0], params[1], params[2]);
        const row = managed.get(key);
        return { rows: row ? [row] : [] };
      }

      if (
        normalized.includes("INSERT INTO managed_certificates") &&
        normalized.includes("ON CONFLICT (workspace_id, source, source_ref)")
      ) {
        const key = managedKey(params[0], params[3], params[4]);
        const existing = managed.get(key);
        if (existing) {
          Object.assign(existing, {
            token_id: params[1] ?? existing.token_id,
            status: nextStatusFor(normalized, existing.status, params[2]),
            name: params[5] ?? existing.name,
            common_name: params[6],
            subject_alt_names: params[7] || [],
            issuer: params[8],
            subject: params[9],
            serial_number: params[10],
            certificate_pem: params[11],
            fingerprint_sha256: params[12],
            spki_fingerprint_sha256: params[13],
            public_key_algorithm: params[14],
            public_key_size: params[15],
            signature_algorithm: params[16],
            not_before: params[17],
            not_after: params[18],
            key_mode: params[19] ?? existing.key_mode,
            key_reference: params[20] ?? existing.key_reference,
            public_metadata:
              typeof params[21] === "string"
                ? JSON.parse(params[21])
                : params[21] || {},
            updated_at: new Date().toISOString(),
          });
          return { rows: [existing] };
        }
        const created = rowFromInsertParams(params);
        managed.set(key, created);
        return { rows: [created] };
      }

      if (
        normalized.includes("UPDATE managed_certificates") &&
        normalized.includes("fingerprint_sha256 = COALESCE")
      ) {
        const row = [...managed.values()].find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        assert.ok(row, "expected managed certificate for observation update");
        Object.assign(row, {
          status: nextStatusFor(normalized, row.status, params[2]),
          token_id: params[3] ?? row.token_id,
          name: params[4] ?? row.name,
          common_name: params[5] ?? row.common_name,
          issuer: params[6] ?? row.issuer,
          subject: params[7] ?? row.subject,
          serial_number: params[8] ?? row.serial_number,
          certificate_pem: params[9] ?? row.certificate_pem,
          fingerprint_sha256: params[10] ?? row.fingerprint_sha256,
          spki_fingerprint_sha256: params[11] ?? row.spki_fingerprint_sha256,
          not_before: params[12] ?? row.not_before,
          not_after: params[13] ?? row.not_after,
          updated_at: new Date().toISOString(),
        });
        return { rows: [row] };
      }

      if (
        normalized.includes("UPDATE managed_certificates") &&
        normalized.includes("SET token_id = $1")
      ) {
        const row = [...managed.values()].find(
          (item) => item.workspace_id === params[1] && item.id === params[2],
        );
        assert.ok(row, "expected managed certificate for token update");
        row.token_id = params[0];
        row.updated_at = new Date().toISOString();
        return { rows: [row] };
      }

      if (
        normalized.includes("FROM certificate_targets") &&
        normalized.includes("domain_monitor_id = $2")
      ) {
        const key = `${params[0]}|${params[1]}`;
        const row = targets.get(key);
        return { rows: row ? [row] : [] };
      }

      if (normalized.includes("INSERT INTO certificate_targets")) {
        const now = new Date().toISOString();
        const row = {
          id: nextId("target"),
          workspace_id: params[0],
          domain_monitor_id: params[1],
          token_id: params[2],
          name: params[3],
          target_type: params[4],
          status: "active",
          source: params[5],
          source_ref: params[6],
          hostname: params[7],
          url: params[8],
          deployment_reference: params[9],
          public_metadata:
            typeof params[10] === "string" ? JSON.parse(params[10]) : {},
          created_by: params[11],
          created_at: now,
          updated_at: now,
        };
        targets.set(`${params[0]}|${params[1]}`, row);
        return { rows: [row] };
      }

      if (normalized.includes("UPDATE certificate_targets")) {
        const row = [...targets.values()].find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        assert.ok(row, "expected certificate target");
        Object.assign(row, {
          token_id: params[2] ?? row.token_id,
          name: params[3] ?? row.name,
          target_type: params[4],
          status: "active",
          source: params[5],
          source_ref: params[6] ?? row.source_ref,
          hostname: params[7] ?? row.hostname,
          url: params[8] ?? row.url,
          deployment_reference: params[9] ?? row.deployment_reference,
          updated_at: new Date().toISOString(),
        });
        return { rows: [row] };
      }

      if (normalized.includes("INSERT INTO certificate_instances")) {
        const key = `${params[0]}|${params[2]}|${params[1]}|${params[8]}`;
        const existing = instances.get(key);
        const now = new Date().toISOString();
        if (existing) {
          Object.assign(existing, {
            domain_monitor_id: params[3],
            token_id: params[4] ?? existing.token_id,
            status: params[5],
            source: params[6],
            source_ref: params[7] ?? existing.source_ref,
            observed_serial_number: params[9],
            observed_subject: params[10],
            observed_issuer: params[11],
            observed_not_before: params[12],
            observed_not_after: params[13],
            deployment_reference: params[14],
            observed_at: params[15],
            updated_at: now,
          });
          return { rows: [existing] };
        }
        const row = {
          id: nextId("instance"),
          workspace_id: params[0],
          managed_certificate_id: params[1],
          target_id: params[2],
          domain_monitor_id: params[3],
          token_id: params[4],
          status: params[5],
          source: params[6],
          source_ref: params[7],
          observed_fingerprint_sha256: params[8],
          observed_serial_number: params[9],
          observed_subject: params[10],
          observed_issuer: params[11],
          observed_not_before: params[12],
          observed_not_after: params[13],
          deployment_reference: params[14],
          observed_at: params[15],
          public_metadata:
            typeof params[16] === "string" ? JSON.parse(params[16]) : {},
          created_by: params[17],
          created_at: now,
          updated_at: now,
        };
        instances.set(key, row);
        return { rows: [row] };
      }

      throw new Error(`Unexpected query: ${normalized}`);
    },
  };
}

function bridgeClient(store) {
  return {
    async connect() {
      return {
        query: (...args) => store.query(...args),
        release() {},
      };
    },
  };
}

async function bridgeObservation(store, overrides = {}) {
  return bridgeEndpointCertificateObservation({
    dbPool: bridgeClient(store),
    env: { CERTOPS_ENABLED: "true" },
    workspaceId: WORKSPACE_ID,
    tokenId: 42,
    hostname: "www.example.com",
    ...overrides,
  });
}

describe("CertOps monitor bridge zero-custody", () => {
  it("rejects private key material in certificate.certificatePem", () => {
    assertPrivateKeyRejected(() =>
      certificateFromObservation({
        certificate: { certificatePem: PRIVATE_KEY_PEM },
      }),
    );
  });

  it("rejects noncanonical private key PEM in observation metadata fields", () => {
    assertPrivateKeyRejected(() =>
      certificateFromObservation({
        certificate: {
          issuer: "Probe CA",
          subject: NONCANONICAL_PRIVATE_KEY_PEM,
        },
      }),
    );
  });

  it("rejects private key material anywhere in bridge options before feature gating", async () => {
    await assert.rejects(
      () =>
        bridgeEndpointCertificateObservation({
          env: { CERTOPS_ENABLED: "false" },
          workspaceId: WORKSPACE_ID,
          domainMonitorId: MONITOR_A,
          deploymentReference: PRIVATE_KEY_PEM,
          certificate: {
            issuer: "Probe CA",
            subject: "CN=probe.example.com",
            fingerprintSha256: "a".repeat(64),
            notAfter: "2099-01-01",
          },
        }),
      (error) => {
        assert.equal(error.code, PRIVATE_KEY_MATERIAL_REJECTED);
        assert.doesNotMatch(String(error.message), /RSA PRIVATE KEY/i);
        assert.doesNotMatch(String(error.message), new RegExp(FAKE_PRIVATE_BODY));
        return true;
      },
    );
  });

  it("does not false-positive-reject on deeply nested infra handles (dbPool/client/env)", async () => {
    function deeplyNested(depth) {
      let node = { leaf: true };
      for (let index = 0; index < depth; index += 1) {
        node = { child: node };
      }
      return node;
    }
    const fakeDbPool = {
      connect: async () => ({
        query: async () => ({ rows: [] }),
        release: () => {},
      }),
      deep: deeplyNested(30),
    };

    const result = await bridgeEndpointCertificateObservation({
      dbPool: fakeDbPool,
      env: { CERTOPS_ENABLED: "false" },
      workspaceId: WORKSPACE_ID,
      domainMonitorId: MONITOR_A,
      certificate: {
        issuer: "Probe CA",
        subject: "CN=probe.example.com",
        fingerprintSha256: "a".repeat(64),
        notAfter: "2099-01-01",
      },
    });
    assert.equal(result.skipped, true);
    assert.equal(result.reason, "certops_disabled");
  });

  it("does not emit private-key-looking fields from certificateFromObservation", () => {
    const certificate = certificateFromObservation({
      hostname: "www.example.com",
      certificate: {
        issuer: "Example CA",
        subject: "CN=www.example.com",
        serialNumber: "01",
        fingerprintSha256: "b".repeat(64),
        notAfter: "2099-01-01",
      },
    });

    for (const key of Object.keys(certificate)) {
      assert.doesNotMatch(
        key,
        /private/i,
        `${key} looks like a private-key custody field`,
      );
    }
    assert.equal(certificate.certificatePem, null);
  });

  it("rejects unsafe hostname identities before persisting", async () => {
    const store = createIdentityStore();
    await assert.rejects(
      () =>
        bridgeObservation(store, {
          domainMonitorId: MONITOR_A,
          hostname: "exаmple.com",
          certificate: {
            issuer: "Probe CA",
            subject: "CN=probe.example.com",
            fingerprintSha256: SHARED_FINGERPRINT,
            notAfter: "2099-01-01",
          },
        }),
      (error) => {
        assert.equal(error.code, CERTOPS_UNSAFE_IDENTITY);
        return true;
      },
    );
    assert.equal(store.managed.size, 0);
  });
});

describe("CertOps monitor bridge identity (D8)", () => {
  it("exports upsertManagedCertificateByMonitorSource", () => {
    assert.equal(typeof upsertManagedCertificateByMonitorSource, "function");
  });

  it("keeps two monitors with the same fingerprint as separate rows", async () => {
    const store = createIdentityStore();
    const cert = {
      issuer: "Probe CA",
      subject: "CN=www.example.com",
      fingerprintSha256: SHARED_FINGERPRINT,
      notAfter: "2099-01-01",
    };

    const first = await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      hostname: "a.example.com",
      certificate: cert,
    });
    const second = await bridgeObservation(store, {
      domainMonitorId: MONITOR_B,
      hostname: "b.example.com",
      certificate: cert,
    });

    assert.equal(first.skipped, false);
    assert.equal(second.skipped, false);
    assert.notEqual(first.managedCertificate.id, second.managedCertificate.id);
    assert.equal(first.managedCertificate.sourceRef, MONITOR_A);
    assert.equal(second.managedCertificate.sourceRef, MONITOR_B);
    assert.equal(first.managedCertificate.fingerprintSha256, SHARED_FINGERPRINT);
    assert.equal(second.managedCertificate.fingerprintSha256, SHARED_FINGERPRINT);
    assert.equal(store.managed.size, 2);
  });

  it("updates the same row on repeated observation for one monitor", async () => {
    const store = createIdentityStore();
    const cert = {
      issuer: "Probe CA",
      subject: "CN=www.example.com",
      fingerprintSha256: SHARED_FINGERPRINT,
      serialNumber: "01",
      notAfter: "2099-01-01",
    };

    const first = await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      certificate: cert,
    });
    const second = await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      certificate: { ...cert, serialNumber: "02" },
    });

    assert.equal(first.managedCertificate.id, second.managedCertificate.id);
    assert.equal(store.managed.size, 1);
    assert.equal(second.managedCertificate.serialNumber, "02");
  });

  it("rotates fingerprint on one monitor without changing the other", async () => {
    const store = createIdentityStore();
    const shared = {
      issuer: "Probe CA",
      subject: "CN=www.example.com",
      fingerprintSha256: SHARED_FINGERPRINT,
      notAfter: "2099-01-01",
    };

    const monitorA = await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      hostname: "a.example.com",
      certificate: shared,
    });
    const monitorB = await bridgeObservation(store, {
      domainMonitorId: MONITOR_B,
      hostname: "b.example.com",
      certificate: shared,
    });

    const rotated = await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      hostname: "a.example.com",
      certificate: {
        ...shared,
        fingerprintSha256: ROTATED_FINGERPRINT,
        serialNumber: "rot-1",
      },
    });

    assert.equal(rotated.managedCertificate.id, monitorA.managedCertificate.id);
    assert.equal(rotated.managedCertificate.fingerprintSha256, ROTATED_FINGERPRINT);
    assert.equal(store.managed.size, 2);

    const monitorBRow = [...store.managed.values()].find(
      (row) => row.source_ref === MONITOR_B,
    );
    assert.equal(monitorBRow.id, monitorB.managedCertificate.id);
    assert.equal(monitorBRow.fingerprint_sha256, SHARED_FINGERPRINT);
  });
});

describe("CertOps monitor bridge retire-first lifecycle (D7)", () => {
  for (const retiredStatus of ["revoked", "decommissioned"]) {
    it(`keeps a ${retiredStatus} certificate ${retiredStatus} on re-observation while updating observation fields`, async () => {
      const store = createIdentityStore();
      const cert = {
        issuer: "Probe CA",
        subject: "CN=www.example.com",
        fingerprintSha256: SHARED_FINGERPRINT,
        serialNumber: "01",
        notAfter: "2099-01-01",
      };

      const first = await bridgeObservation(store, {
        domainMonitorId: MONITOR_A,
        certificate: cert,
      });
      assert.equal(first.skipped, false);
      assert.equal(first.managedCertificate.status, "discovered");

      const managedRow = [...store.managed.values()].find(
        (row) => row.source_ref === MONITOR_A,
      );
      managedRow.status = retiredStatus;

      const second = await bridgeObservation(store, {
        domainMonitorId: MONITOR_A,
        certificate: {
          ...cert,
          fingerprintSha256: ROTATED_FINGERPRINT,
          serialNumber: "02",
        },
      });

      assert.equal(second.skipped, false);
      assert.equal(second.managedCertificate.id, first.managedCertificate.id);
      assert.equal(
        second.managedCertificate.status,
        retiredStatus,
        "monitor observation must not resurrect a retired certificate",
      );
      assert.equal(second.managedCertificate.serialNumber, "02");
      assert.equal(
        second.managedCertificate.fingerprintSha256,
        ROTATED_FINGERPRINT,
      );
      assert.equal(store.managed.size, 1);
      assert.equal(managedRow.status, retiredStatus);
    });
  }

  it("still applies the requested status when the existing row is not retired", async () => {
    const store = createIdentityStore();
    const cert = {
      issuer: "Probe CA",
      subject: "CN=www.example.com",
      fingerprintSha256: SHARED_FINGERPRINT,
      notAfter: "2099-01-01",
    };

    await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      certificate: cert,
    });
    const managedRow = [...store.managed.values()].find(
      (row) => row.source_ref === MONITOR_A,
    );
    managedRow.status = "expiring";

    const second = await bridgeObservation(store, {
      domainMonitorId: MONITOR_A,
      status: "active",
      certificate: cert,
    });

    assert.equal(second.managedCertificate.status, "active");
  });
});
