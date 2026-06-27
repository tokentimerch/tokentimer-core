const path = require("path");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, request, TestUtils } = require("./setup");
const { runMigrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

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

const PRIVATE_KEY_PEM = `
-----BEGIN RSA PRIVATE KEY-----
RkFLRS1OT1QtQS1SRUFMLUtFWQ==
-----END RSA PRIVATE KEY-----
`;

async function primaryWorkspaceId(session) {
  const response = await request(BASE)
    .get("/api/v1/workspaces?limit=50&offset=0")
    .set("Cookie", session.cookie)
    .expect(200);
  return response.body.items[0].id;
}

function walkKeys(value, visit) {
  if (Array.isArray(value)) {
    for (const item of value) walkKeys(item, visit);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    visit(key);
    walkKeys(item, visit);
  }
}

function expectNoPrivateKeyFields(value) {
  const forbiddenFragments = [
    "private",
    "pkcs12",
    "pfx",
    "key_material",
    "key_pem",
    "key_der",
    "raw_key",
    "backup",
    "secret",
    "credential",
    "password",
  ];

  walkKeys(value, (key) => {
    for (const fragment of forbiddenFragments) {
      expect(
        key.toLowerCase().includes(fragment),
        `${key} looks like private-key custody`,
      ).to.equal(false);
    }
  });
  expect(JSON.stringify(value)).to.not.include("PRIVATE KEY");
}

describe("CertOps inventory routes", function () {
  this.timeout(90000);

  let ownerUser;
  let ownerSession;
  let managerUser;
  let managerSession;
  let viewerUser;
  let viewerSession;
  let outsiderUser;
  let outsiderSession;
  let workspaceId;
  let outsiderWorkspaceId;
  let leafCertificate;

  before(async () => {
    await runMigrations();

    ownerUser = await TestUtils.createVerifiedTestUser();
    ownerSession = await TestUtils.loginTestUser(
      ownerUser.email,
      "SecureTest123!@#",
    );
    workspaceId = await primaryWorkspaceId(ownerSession);

    managerUser = await TestUtils.createVerifiedTestUser();
    managerSession = await TestUtils.loginTestUser(
      managerUser.email,
      "SecureTest123!@#",
    );
    viewerUser = await TestUtils.createVerifiedTestUser();
    viewerSession = await TestUtils.loginTestUser(
      viewerUser.email,
      "SecureTest123!@#",
    );
    outsiderUser = await TestUtils.createVerifiedTestUser();
    outsiderSession = await TestUtils.loginTestUser(
      outsiderUser.email,
      "SecureTest123!@#",
    );
    outsiderWorkspaceId = await primaryWorkspaceId(outsiderSession);

    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'workspace_manager', $3), ($4, $2, 'viewer', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
      [managerUser.id, workspaceId, ownerUser.id, viewerUser.id],
    );
  });

  after(async () => {
    for (const [user, session] of [
      [ownerUser, ownerSession],
      [managerUser, managerSession],
      [viewerUser, viewerSession],
      [outsiderUser, outsiderSession],
    ]) {
      if (user?.email && session?.cookie) {
        await TestUtils.cleanupTestUser(user.email, session.cookie);
      }
    }
  });

  it("imports a public certificate and returns normalized inventory data", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({
        certificatePem: `\n\n${PUBLIC_LEAF_CERT}\n`,
        keyMode: "external-unknown",
        keyReference: "  vault://pki/web/example  ",
      })
      .expect(202);

    expect(response.body.count).to.equal(1);
    leafCertificate = response.body.items[0];
    expect(leafCertificate.schemaVersion).to.equal(1);
    expect(leafCertificate.workspaceId).to.equal(workspaceId);
    expect(leafCertificate.source).to.equal("import");
    expect(leafCertificate.commonName).to.equal("certops.example");
    expect(leafCertificate.subjectAltNames).to.include("api.certops.example");
    expect(leafCertificate.fingerprintSha256).to.match(/^[a-f0-9]{64}$/);
    expect(leafCertificate.spkiFingerprintSha256).to.match(/^[a-f0-9]{64}$/);
    expect(leafCertificate.notBefore).to.match(/^\d{4}-\d{2}-\d{2}T/);
    expect(leafCertificate.notAfter).to.match(/^\d{4}-\d{2}-\d{2}T/);
    expect(leafCertificate.keyMode).to.equal("external-unknown");
    expect(leafCertificate.keyReference).to.equal("vault://pki/web/example");
    expect(leafCertificate.certificatePem).to.include("BEGIN CERTIFICATE");
    expectNoPrivateKeyFields(leafCertificate);
  });

  it("normalizes an empty key reference to null", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({ certificatePem: PUBLIC_CA_CERT, keyReference: "   " })
      .expect(202);

    expect(response.body.count).to.equal(1);
    expect(response.body.items[0].keyReference).to.equal(null);
  });

  it("deduplicates by workspace and SHA-256 fingerprint", async () => {
    const duplicate = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/certificates`)
      .set("Cookie", ownerSession.cookie)
      .send({ certificatePem: PUBLIC_LEAF_CERT })
      .expect(201);

    expect(duplicate.body.count).to.equal(1);
    expect(duplicate.body.items[0].id).to.equal(leafCertificate.id);

    const list = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/certops/certificates`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    const matching = list.body.items.filter(
      (item) => item.fingerprintSha256 === leafCertificate.fingerprintSha256,
    );
    expect(matching).to.have.length(1);
  });

  it("allows a workspace manager to import a public certificate chain", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", managerSession.cookie)
      .send({ certificatePem: `${PUBLIC_LEAF_CERT}\n${PUBLIC_CA_CERT}` })
      .expect(202);

    expect(response.body.count).to.equal(2);
    expect(response.body.items.map((item) => item.commonName)).to.include(
      "CertOps Test CA",
    );
  });

  it("allows viewers to list and fetch certificates in their workspace", async () => {
    const list = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/certops/certificates`)
      .set("Cookie", viewerSession.cookie)
      .expect(200);

    expect(list.body.items.map((item) => item.id)).to.include(
      leafCertificate.id,
    );

    const detail = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceId}/certops/certificates/${leafCertificate.id}`,
      )
      .set("Cookie", viewerSession.cookie)
      .expect(200);

    expect(detail.body.certificate.id).to.equal(leafCertificate.id);
    expect(detail.body.certificate.workspaceId).to.equal(workspaceId);
    expectNoPrivateKeyFields(detail.body.certificate);
  });

  it("denies viewer writes", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", viewerSession.cookie)
      .send({ certificatePem: PUBLIC_CA_CERT });

    expect(response.status).to.equal(403);
    expect(response.body.code).to.equal("INSUFFICIENT_ROLE");
  });

  it("keeps certificate detail and list access isolated by workspace", async () => {
    const crossWorkspaceDetail = await request(BASE)
      .get(
        `/api/v1/workspaces/${outsiderWorkspaceId}/certops/certificates/${leafCertificate.id}`,
      )
      .set("Cookie", outsiderSession.cookie);

    expect(crossWorkspaceDetail.status).to.equal(404);
    expect(crossWorkspaceDetail.body.code).to.equal(
      "CERTOPS_CERTIFICATE_NOT_FOUND",
    );

    const outsiderList = await request(BASE)
      .get(`/api/v1/workspaces/${outsiderWorkspaceId}/certops/certificates`)
      .set("Cookie", outsiderSession.cookie)
      .expect(200);
    expect(outsiderList.body.items).to.deep.equal([]);
  });

  it("rejects private key material without echoing raw input", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({ certificatePem: `${PUBLIC_LEAF_CERT}\n${PRIVATE_KEY_PEM}` });

    expect(response.status).to.equal(422);
    expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expect(response.text).to.not.include("RSA PRIVATE KEY");
    expect(response.text).to.not.include("RkFLRS1OT1QtQS1SRUFMLUtFWQ");
  });

  it("rejects an overlong key reference without echoing it", async () => {
    const keyReference = `hsm://${"a".repeat(260)}`;
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({ certificatePem: PUBLIC_LEAF_CERT, keyReference });

    expect(response.status).to.equal(400);
    expect(response.body.code).to.equal("CERTOPS_KEY_REFERENCE_INVALID");
    expect(response.text).to.not.include(keyReference);
  });

  it("rejects obvious secret-like key references without echoing them", async () => {
    const keyReference = "external-unknown://legacy-ref?password=swordfish";
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({ certificatePem: PUBLIC_LEAF_CERT, keyReference });

    expect(response.status).to.equal(400);
    expect(response.body.code).to.equal("CERTOPS_KEY_REFERENCE_INVALID");
    expect(response.text).to.not.include(keyReference);
  });

  it("rejects private key material in keyReference at the request boundary", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({
        certificatePem: PUBLIC_LEAF_CERT,
        keyReference: PRIVATE_KEY_PEM,
      });

    expect(response.status).to.equal(422);
    expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expect(response.text).to.not.include("RSA PRIVATE KEY");
  });

  it("rejects malformed certificate input with a stable code", async () => {
    const malformed = "not a public certificate";
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/certops/imports`)
      .set("Cookie", ownerSession.cookie)
      .send({ certificatePem: malformed });

    expect(response.status).to.equal(400);
    expect(response.body.code).to.equal("CERTOPS_CERTIFICATE_PARSE_FAILED");
    expect(response.text).to.not.include(malformed);
  });
});
