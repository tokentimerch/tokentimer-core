const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  acquireManagedCertificateImportLock,
  countActiveManagedCertificatesWithClient,
  countQuotaConsumingNewFingerprints,
  fingerprintsFromCertificates,
  importPublicCertificates,
} = require("../../apps/api/services/certops/inventory");
const { parsePublicCertificateMaterial } = require(
  "../../apps/api/services/certops/parser",
);

const PUBLIC_LEAF_CERT = `
-----BEGIN CERTIFICATE-----
MIIDgjCCAmqgAwIBAgIUKJShixxx/7TH81hKwHE3UsvIFMkwDQYJKoZIhvcNAQEL
BQAwNDEYMBYGA1UEAwwPY2VydG9wcy5leGFtcGxlMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwHhcNMjYwNjI2MDA0MDU5WhcNMjcwNjI2MDA0MDU5WjA0MRgwFgYD
VQQDDA9jZXJ0b3BzLmV4YW1wbGUxGDAWBgNVBAoMD1Rva2VuVGltZXIgVGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoaAIgElNelqNg6TsY++HnK
rFeOgn7csJYu9AbFfQRAoFO592aVI9QdyejoGesSy+tDN06vJl411Ntz6caB2+fd
+qkllZ+c39IZEbp++PDp7dD+4aEC68tGoZ9F/9dOGRaZ4xSFp0W0+5hd8E5q4E9U
MSdc4cUjQKuZX+jwBQqy+SRxhhNh6GPVWg3Cr6W0F53yFxWlb8q+4cwOZg0AP7sK
2u8UvordGO3o4eiPsVtmRh87YeRnUDRuzPb4Mi/Fo9Cr+1Fq3Q3xdWH9LhP0DSmD
89Ho84nvn+DfM+Dbnb7PsmNgqOVictn/LxHMOrl1F04BkvY9rNuBkh7wHC7TOR8C
AwEAAaOBizCBiDAdBgNVHQ4EFgQUoOXgW3/xFso+3GDIpFqimZ2K2TUwHwYDVR0j
BBgwFoAUoOXgW3/xFso+3GDIpFqimZ2K2TUwDwYDVR0TAQH/BAUwAwEB/zA1BgNV
HREELjAsgg9jZXJ0b3BzLmV4YW1wbGWCE2FwaS5jZXJ0b3BzLmV4YW1wbGWHBH8A
AAEwDQYJKoZIhvcNAQELBQADggEBAGi4XAScskH5bdxNbXwtEqlep2eDyseUyulF
g2yILrkiA22+WveOZrmReuxHx+umHVAO4O6JtHwD1figZyKgCrMzrREqmRwGj6pb
jgaW6Eeck+zFh1cKTH6ZUYlN6yOHOhKR0nBnseSuoh/gEangQVLRug3SqCCi6GQI
aOAUKMHYsxTyfjtE2k7URQYy7fbfLW/k+68l+xI/ktwFlS+MncmrS+Lx+dWwxVCn
EucPyYnACaKyw2oY6kCVaW9OReglxzoFzLxZvqxyrA1LpWjzgJiR7nIpZCappsi9
gB1JS6DPep8dhLORucnHS/Opy2xOB0lB3kmNoh5bierJUVeReSc=
-----END CERTIFICATE-----
`;

const PUBLIC_CA_CERT = `
-----BEGIN CERTIFICATE-----
MIIDaDCCAlCgAwIBAgIUdCT2l9wFjDoFlfsF97QP3v7uq5IwDQYJKoZIhvcNAQEL
BQAwNDEYMBYGA1UEAwwPQ2VydE9wcyBUZXN0IENBMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwHhcNMjYwNjI2MDA0MTA3WhcNMjgwNjI1MDA0MTA3WjA0MRgwFgYD
VQQDDA9DZXJ0T3BzIFRlc3QgQ0ExGDAWBgNVBAoMD1Rva2VuVGltZXIgVGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANupE0mTV+O2+WJOXL/nj/Cw
JzVE6KVygV/W8MZWg3yN+FFzO/o+AcCxJlRgnDdkF9P8CWmhsDZ4GfVZtTfjuQeT
lu2Y5LG3fDGN3cxJovrbGjA1TbIRIODE7C5jAPJMvwmXE9PJO0nJnuhE15xKU7IZ
2zk6fO/TwG7FfCqS9NBccbtHKB9sV/4dBf2GZ1eT8VMWLeUPrKFbAitQ7tgFb6h2
MLKfMjfqbW+IYchp53YSPS8k/alXJRi84Ev6tDASrZoaYTjRO0Ps1QFa9tVBAQLg
fa/4IpcXZmItiTYZlVAHN90WhbxZOiY5GiirZWWLkcUv9pSOHv07awzDolek/MkC
AwEAAaNyMHAwHQYDVR0OBBYEFMET4X2O2V7eGtpu6k8TjKLtf6AxMB8GA1UdIwQY
MBaAFMET4X2O2V7eGtpu6k8TjKLtf6AxMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0R
BBYwFIISY2EuY2VydG9wcy5leGFtcGxlMA0GCSqGSIb3DQEBCwUAA4IBAQBUjILj
UB9s79qPbzSVE4uZ+zMatfiOxG4PnF46iNJg1iRJJ1w3FOcjlj1FxO19RsRlqyOf
2rICSmyiSGundtu7u7cFVK0OFhNr8Da9ugm0tqiHh5ZtwGCfbDirLDIwPuL2nelR
8bk/cUepTFC1NAmRRa8cX3HgaEzY8YFThZ/JR1ps0/iWOMxC1MWdSNPgSrgX2DQ1
Wyd4gytVWmsBFmV4Xvc2wshwjy56jm60KaaNAWN/N6xSL5ay5+ImaBm1g2rapCMU
WXYC1Jw/NQfgLOwRIlX/AmpCib6udusu0XruVpYvBu9E2RxbaRto34iLQdUtrNN/
o9wtTp83p6p21Okl
-----END CERTIFICATE-----
`;

async function createWorkspace(label) {
  const ownerEmail = `${label}-${Date.now()}-${crypto.randomUUID()}@example.com`;
  const owner = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [
      ownerEmail.toLowerCase(),
      ownerEmail,
      label,
      "not-used-in-import-helper-test",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceId = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss')`,
    [workspaceId, label, ownerId],
  );

  return { ownerId, workspaceId };
}

async function cleanupWorkspace(ownerId, workspaceId) {
  await TestUtils.execQuery(
    "DELETE FROM managed_certificates WHERE workspace_id = $1",
    [workspaceId],
  );
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

async function seedManagedCertificate(workspaceId, fingerprint, status = "active") {
  await TestUtils.execQuery(
    `INSERT INTO managed_certificates (
       workspace_id, status, source, name, fingerprint_sha256
     ) VALUES ($1, $2, 'import', $3, $4)`,
    [workspaceId, status, `seed-${fingerprint.slice(0, 8)}`, fingerprint],
  );
}

async function countWorkspaceTokens(workspaceId) {
  const result = await TestUtils.execQuery(
    "SELECT COUNT(*)::int AS c FROM tokens WHERE workspace_id = $1",
    [workspaceId],
  );
  return result.rows[0].c;
}

async function countWorkspaceManagedCertificates(workspaceId) {
  const result = await TestUtils.execQuery(
    "SELECT COUNT(*)::int AS c FROM managed_certificates WHERE workspace_id = $1",
    [workspaceId],
  );
  return result.rows[0].c;
}

describe("CertOps inventory import transaction helpers", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;
  let leafFingerprint;
  let caFingerprint;
  let retiredFingerprint;
  let revokedFingerprint;

  before(async () => {
    await runMigrations();
    const workspace = await createWorkspace("CertOps import helpers");
    ownerId = workspace.ownerId;
    workspaceId = workspace.workspaceId;

    const certificates = parsePublicCertificateMaterial(
      `${PUBLIC_LEAF_CERT}\n${PUBLIC_CA_CERT}`,
    );
    [leafFingerprint, caFingerprint] = fingerprintsFromCertificates(certificates);
    retiredFingerprint = `${"b".repeat(64)}`;
    revokedFingerprint = `${"c".repeat(64)}`;

    await seedManagedCertificate(workspaceId, leafFingerprint, "active");
    await seedManagedCertificate(workspaceId, retiredFingerprint, "decommissioned");
    await seedManagedCertificate(workspaceId, revokedFingerprint, "revoked");
  });

  after(async () => {
    if (ownerId && workspaceId) {
      await cleanupWorkspace(ownerId, workspaceId);
    }
  });

  it("imports multiple certificates in one caller-managed transaction", async () => {
    const isolated = await createWorkspace("CertOps import tx");
    const client = await pool.connect();

    try {
      await client.query("BEGIN");
      let validateCalled = false;
      const items = await importPublicCertificates({
        client,
        workspaceId: isolated.workspaceId,
        createdBy: isolated.ownerId,
        certificatePem: `${PUBLIC_LEAF_CERT}\n${PUBLIC_CA_CERT}`,
        validateImport: async (txClient, certificates) => {
          validateCalled = true;
          expect(txClient).to.equal(client);
          expect(certificates).to.have.length(2);
          expect(fingerprintsFromCertificates(certificates)).to.have.length(2);
        },
      });

      expect(validateCalled).to.equal(true);
      expect(items).to.have.length(2);
      expect(items.map((item) => item.commonName)).to.include.members([
        "certops.example",
        "CertOps Test CA",
      ]);

      const activeCount = await countActiveManagedCertificatesWithClient(
        client,
        isolated.workspaceId,
      );
      expect(activeCount).to.equal(2);

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
      await cleanupWorkspace(isolated.ownerId, isolated.workspaceId);
    }
  });

  it("countActiveManagedCertificatesWithClient excludes retired certificates", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const activeCount = await countActiveManagedCertificatesWithClient(
        client,
        workspaceId,
      );
      expect(activeCount).to.equal(1);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("countQuotaConsumingNewFingerprints treats active fingerprints as idempotent", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const consuming = await countQuotaConsumingNewFingerprints(
        client,
        workspaceId,
        [leafFingerprint],
      );
      expect(consuming).to.equal(0);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("countQuotaConsumingNewFingerprints treats decommissioned fingerprints as idempotent", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const consuming = await countQuotaConsumingNewFingerprints(
        client,
        workspaceId,
        [retiredFingerprint],
      );
      expect(consuming).to.equal(0);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("countQuotaConsumingNewFingerprints treats revoked fingerprints as idempotent", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const consuming = await countQuotaConsumingNewFingerprints(
        client,
        workspaceId,
        [revokedFingerprint],
      );
      expect(consuming).to.equal(0);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("countQuotaConsumingNewFingerprints counts unseen fingerprints", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const consuming = await countQuotaConsumingNewFingerprints(
        client,
        workspaceId,
        [caFingerprint],
      );
      expect(consuming).to.equal(1);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("countQuotaConsumingNewFingerprints classifies mixed fingerprint sets", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const consuming = await countQuotaConsumingNewFingerprints(
        client,
        workspaceId,
        [leafFingerprint, retiredFingerprint, revokedFingerprint, caFingerprint],
      );
      expect(consuming).to.equal(1);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });

  it("acquireManagedCertificateImportLock serializes concurrent transactions", async () => {
    const client1 = await pool.connect();
    const client2 = await pool.connect();

    try {
      await client1.query("BEGIN");
      await client2.query("BEGIN");

      await acquireManagedCertificateImportLock(client1, workspaceId);

      const lockPromise = acquireManagedCertificateImportLock(client2, workspaceId);
      const raced = await Promise.race([
        lockPromise.then(() => "acquired"),
        new Promise((resolve) => setTimeout(() => resolve("waiting"), 250)),
      ]);
      expect(raced).to.equal("waiting");

      await client1.query("COMMIT");
      await lockPromise;
      await client2.query("COMMIT");
    } catch (error) {
      await client1.query("ROLLBACK").catch(() => {});
      await client2.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client1.release();
      client2.release();
    }
  });

  it("rolls back import when validateImport throws and creates no rows", async () => {
    const isolated = await createWorkspace("CertOps import validation rollback");
    const tokensBefore = await countWorkspaceTokens(isolated.workspaceId);
    const managedBefore = await countWorkspaceManagedCertificates(
      isolated.workspaceId,
    );

    let validateCalled = false;
    try {
      await importPublicCertificates({
        workspaceId: isolated.workspaceId,
        createdBy: isolated.ownerId,
        certificatePem: PUBLIC_LEAF_CERT,
        validateImport: async () => {
          validateCalled = true;
          const err = new Error("Import validation failed");
          err.code = "CERTOPS_IMPORT_VALIDATION_FAILED";
          throw err;
        },
      });
      throw new Error("expected importPublicCertificates to reject");
    } catch (error) {
      expect(validateCalled).to.equal(true);
      expect(error.code).to.equal("CERTOPS_IMPORT_VALIDATION_FAILED");
    }

    expect(await countWorkspaceTokens(isolated.workspaceId)).to.equal(tokensBefore);
    expect(await countWorkspaceManagedCertificates(isolated.workspaceId)).to.equal(
      managedBefore,
    );

    await cleanupWorkspace(isolated.ownerId, isolated.workspaceId);
  });

  it("leaves active managed certificate count unchanged on idempotent re-import", async () => {
    const isolated = await createWorkspace("CertOps import idempotent");
    await seedManagedCertificate(isolated.workspaceId, leafFingerprint, "active");

    const items = await importPublicCertificates({
      workspaceId: isolated.workspaceId,
      createdBy: isolated.ownerId,
      certificatePem: PUBLIC_LEAF_CERT,
      validateImport: async (client, certificates) => {
        const consuming = await countQuotaConsumingNewFingerprints(
          client,
          isolated.workspaceId,
          fingerprintsFromCertificates(certificates),
        );
        expect(consuming).to.equal(0);
      },
    });

    expect(items).to.have.length(1);
    const activeCount = await countActiveManagedCertificatesWithClient(
      pool,
      isolated.workspaceId,
    );
    expect(activeCount).to.equal(1);

    await cleanupWorkspace(isolated.ownerId, isolated.workspaceId);
  });

  it("keeps a decommissioned certificate retired on re-import without consuming quota", async () => {
    const isolated = await createWorkspace("CertOps import retired re-import");
    await seedManagedCertificate(
      isolated.workspaceId,
      leafFingerprint,
      "decommissioned",
    );

    const items = await importPublicCertificates({
      workspaceId: isolated.workspaceId,
      createdBy: isolated.ownerId,
      certificatePem: PUBLIC_LEAF_CERT,
      validateImport: async (client, certificates) => {
        expect(
          await countQuotaConsumingNewFingerprints(
            client,
            isolated.workspaceId,
            fingerprintsFromCertificates(certificates),
          ),
        ).to.equal(0);
      },
    });

    expect(items).to.have.length(1);
    const persisted = await TestUtils.execQuery(
      `SELECT status FROM managed_certificates
       WHERE workspace_id = $1 AND fingerprint_sha256 = $2`,
      [isolated.workspaceId, leafFingerprint],
    );
    expect(persisted.rows[0].status).to.equal("decommissioned");
    await cleanupWorkspace(isolated.ownerId, isolated.workspaceId);
  });
});
