const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

/**
 * Integration base URLs must not turn the server into a proxy for internal
 * networks. The test API stack sets INTEGRATION_ENFORCE_PRIVATE_IP_CHECK=true
 * so the guard runs despite NODE_ENV=test. The INTEGRATION_ALLOW_PRIVATE_IPS
 * opt-in is process-level env, so it is covered in
 * tests/unit/integration-address-guard.test.js.
 */
describe("Integration base URL private-address guard", function () {
  this.timeout(30000);

  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    const user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  const cases = [
    {
      name: "GitLab scan",
      path: "/api/v1/integrations/gitlab/scan",
      body: (url) => ({ baseUrl: url, token: "glpat-x" }),
    },
    {
      name: "GitHub scan",
      path: "/api/v1/integrations/github/scan",
      body: (url) => ({ baseUrl: url, token: "ghp_x" }),
    },
    {
      name: "Vault scan",
      path: "/api/v1/integrations/vault/scan",
      body: (url) => ({ address: url, token: "hvs.x" }),
    },
    {
      name: "Vault mounts",
      path: "/api/v1/integrations/vault/mounts",
      body: (url) => ({ address: url, token: "hvs.x" }),
    },
    {
      name: "Azure Key Vault scan",
      path: "/api/v1/integrations/azure/scan",
      body: (url) => ({ vaultUrl: url, token: "x" }),
    },
  ];

  for (const c of cases) {
    for (const url of [
      "http://127.0.0.1:8080",
      "http://192.168.10.20",
      "http://169.254.169.254",
      "http://localhost:8200",
    ]) {
      it(`${c.name} refuses ${url} in plain words`, async () => {
        const res = await request(BASE)
          .post(c.path)
          .set("Cookie", cookie)
          .send({ ...c.body(url), workspace_id: workspaceId });
        expect(res.status, JSON.stringify(res.body)).to.equal(400);
        expect(res.body.code).to.equal("INTEGRATION_PRIVATE_ADDRESS_BLOCKED");
        expect(res.body.error).to.match(/private or internal network/);
        expect(res.body.error).to.include("INTEGRATION_ALLOW_PRIVATE_IPS");
      });
    }
  }
});
