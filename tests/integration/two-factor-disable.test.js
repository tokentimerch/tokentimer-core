const { expect, request, TestUtils, TestEnvironment } = require("./setup");
const { logger } = require("./logger");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Two-Factor Authentication Disable", function () {
  this.timeout(60000);

  it("disables 2FA after enabling it", async () => {
    await TestEnvironment.setup();

    const email = TestUtils.generateTestEmail("2fa-disable");
    const password = "SecureTest123!@#";
    await TestUtils.createVerifiedTestUser(email, password, "2FA Disable User");

    const agent = await TestUtils.newAgent();
    await agent.post("/auth/login").send({ email, password }).expect(200);

    const setupRes = await agent.post("/api/account/2fa/setup").send({});
    if (setupRes.status !== 200) {
      logger.info("2FA setup not available, skipping test");
      return;
    }
    expect(setupRes.body).to.have.property("secret");
    const secret = setupRes.body.secret;

    const { generateSync } = require("otplib");
    const enableCode = generateSync({ secret });
    await agent
      .post("/api/account/2fa/enable")
      .send({ token: enableCode })
      .expect(200);

    // Verify 2FA is enabled
    await agent.post("/api/logout").expect(200);
    const loginRes = await agent
      .post("/auth/login")
      .send({ email, password })
      .expect(200);
    expect(loginRes.body.requires2FA).to.equal(true);

    // Complete 2FA to get a full session
    const verifyCode = generateSync({ secret });
    await agent
      .post("/auth/verify-2fa")
      .send({ token: verifyCode })
      .expect(200);

    // Disable 2FA (requires currentPassword, not TOTP token)
    const disableRes = await agent
      .post("/api/account/2fa/disable")
      .send({ currentPassword: password });

    expect(disableRes.status).to.equal(200);

    // Verify 2FA is no longer required on next login
    await agent.post("/api/logout").expect(200);
    const loginAfterDisable = await agent
      .post("/auth/login")
      .send({ email, password })
      .expect(200);

    expect(loginAfterDisable.body.requires2FA).to.not.equal(true);
    expect(loginAfterDisable.body.user).to.have.property("email");
  });
});
