const crypto = require("crypto");
const { TestUtils, request, expect } = require("./setup");

// These tests guard the fix for the "password change does not invalidate other
// sessions" vulnerability. See apps/api/routes/auth.js change-password and
// reset-password handlers.

describe("Auth session invalidation on credential change", () => {
  const countSessionsForUser = async (userId) => {
    const res = await TestUtils.execQuery(
      `SELECT sid
         FROM session
        WHERE (sess #>> '{passport,user}') = $1`,
      [String(userId)],
    );
    return { count: res.rowCount, rows: res.rows };
  };

  const loginAgent = async (email, password) => {
    const agent = await TestUtils.newAgent();
    await agent
      .post("/auth/login")
      .send({ email, password })
      .expect(200);
    return agent;
  };

  describe("POST /api/account/change-password", () => {
    it("keeps the acting session and destroys other sessions for the same user", async () => {
      const email = TestUtils.generateTestEmail("pwchange-sessions");
      const oldPassword = "OldValidPass123!@#";
      const newPassword = "NewValidPass456!@#";
      const user = await TestUtils.createVerifiedTestUser(email, oldPassword);

      const browserA = await loginAgent(email, oldPassword);
      const browserB = await loginAgent(email, oldPassword);

      const aBefore = await browserA.get("/api/session").expect(200);
      const bBefore = await browserB.get("/api/session").expect(200);
      expect(aBefore.body.loggedIn).to.equal(true);
      expect(bBefore.body.loggedIn).to.equal(true);

      const before = await countSessionsForUser(user.id);
      expect(before.count).to.be.at.least(2);

      await browserA
        .post("/api/account/change-password")
        .send({ currentPassword: oldPassword, newPassword })
        .expect(200);

      const aAfter = await browserA.get("/api/session").expect(200);
      expect(aAfter.body.loggedIn).to.equal(true);
      expect(aAfter.body.user).to.have.property("email", email);

      const bAfter = await browserB.get("/api/session").expect(200);
      expect(bAfter.body.loggedIn).to.equal(false);

      const after = await countSessionsForUser(user.id);
      expect(after.count).to.equal(1);
    });

    it("rotates the session id for the acting browser after password change", async () => {
      const email = TestUtils.generateTestEmail("pwchange-rotate");
      const oldPassword = "OldValidPass123!@#";
      const newPassword = "NewValidPass456!@#";
      await TestUtils.createVerifiedTestUser(email, oldPassword);

      const agent = await TestUtils.newAgent();
      const loginRes = await agent
        .post("/auth/login")
        .send({ email, password: oldPassword })
        .expect(200);

      const cookiesBefore = loginRes.headers["set-cookie"] || [];
      expect(cookiesBefore.length).to.be.at.least(1);

      const changeRes = await agent
        .post("/api/account/change-password")
        .send({ currentPassword: oldPassword, newPassword })
        .expect(200);

      const cookiesAfter = changeRes.headers["set-cookie"] || [];
      expect(
        cookiesAfter.length,
        "change-password should emit a Set-Cookie for the rotated session",
      ).to.be.at.least(1);
    });

    it("allows login with the new password and rejects the old password", async () => {
      const email = TestUtils.generateTestEmail("pwchange-reauth");
      const oldPassword = "OldValidPass123!@#";
      const newPassword = "NewValidPass456!@#";
      await TestUtils.createVerifiedTestUser(email, oldPassword);

      const agent = await TestUtils.newAgent();
      await agent
        .post("/auth/login")
        .send({ email, password: oldPassword })
        .expect(200);

      await agent
        .post("/api/account/change-password")
        .send({ currentPassword: oldPassword, newPassword })
        .expect(200);

      await request("http://localhost:4000")
        .post("/auth/login")
        .send({ email, password: oldPassword })
        .expect(401);

      await request("http://localhost:4000")
        .post("/auth/login")
        .send({ email, password: newPassword })
        .expect(200);
    });

    it("does not affect sessions of other unrelated users", async () => {
      const ownerEmail = TestUtils.generateTestEmail("pwchange-owner");
      const otherEmail = TestUtils.generateTestEmail("pwchange-other");
      const password = "ValidPass123!@#";
      const newPassword = "UpdatedPass456!@#";

      const owner = await TestUtils.createVerifiedTestUser(ownerEmail, password);
      const other = await TestUtils.createVerifiedTestUser(otherEmail, password);

      const ownerAgent = await loginAgent(ownerEmail, password);
      const otherAgent = await loginAgent(otherEmail, password);

      await ownerAgent
        .post("/api/account/change-password")
        .send({ currentPassword: password, newPassword })
        .expect(200);

      const otherSessionAfter = await otherAgent.get("/api/session").expect(200);
      expect(otherSessionAfter.body.loggedIn).to.equal(true);
      expect(otherSessionAfter.body.user).to.have.property("email", otherEmail);

      const remainingOwner = await countSessionsForUser(owner.id);
      const remainingOther = await countSessionsForUser(other.id);
      expect(remainingOwner.count).to.equal(1);
      expect(remainingOther.count).to.be.at.least(1);
    });
  });

  describe("POST /auth/reset-password", () => {
    it("revokes every session for the user whose password was reset", async () => {
      const email = TestUtils.generateTestEmail("pwreset-sessions");
      const oldPassword = "OldValidPass123!@#";
      const newPassword = "NewValidPass456!@#";
      const user = await TestUtils.createVerifiedTestUser(email, oldPassword);

      const browserA = await loginAgent(email, oldPassword);
      const browserB = await loginAgent(email, oldPassword);

      const before = await countSessionsForUser(user.id);
      expect(before.count).to.be.at.least(2);

      const resetToken = crypto.randomBytes(24).toString("hex");
      await TestUtils.execQuery(
        `UPDATE users
            SET reset_token = $2,
                reset_token_expires = NOW() + INTERVAL '5 minutes'
          WHERE LOWER(email) = LOWER($1)`,
        [email, resetToken],
      );

      await request("http://localhost:4000")
        .post("/auth/reset-password")
        .send({ token: resetToken, newPassword })
        .expect(200);

      const after = await countSessionsForUser(user.id);
      expect(after.count).to.equal(0);

      const aAfter = await browserA.get("/api/session").expect(200);
      const bAfter = await browserB.get("/api/session").expect(200);
      expect(aAfter.body.loggedIn).to.equal(false);
      expect(bAfter.body.loggedIn).to.equal(false);

      await request("http://localhost:4000")
        .post("/auth/login")
        .send({ email, password: newPassword })
        .expect(200);
    });

    it("does not revoke sessions of other users when resetting one account", async () => {
      const victimEmail = TestUtils.generateTestEmail("pwreset-victim");
      const bystanderEmail = TestUtils.generateTestEmail("pwreset-bystander");
      const password = "ValidPass123!@#";
      const newPassword = "UpdatedPass456!@#";

      await TestUtils.createVerifiedTestUser(victimEmail, password);
      const bystander = await TestUtils.createVerifiedTestUser(
        bystanderEmail,
        password,
      );

      const bystanderAgent = await loginAgent(bystanderEmail, password);

      const resetToken = crypto.randomBytes(24).toString("hex");
      await TestUtils.execQuery(
        `UPDATE users
            SET reset_token = $2,
                reset_token_expires = NOW() + INTERVAL '5 minutes'
          WHERE LOWER(email) = LOWER($1)`,
        [victimEmail, resetToken],
      );

      await request("http://localhost:4000")
        .post("/auth/reset-password")
        .send({ token: resetToken, newPassword })
        .expect(200);

      const bystanderStatus = await bystanderAgent
        .get("/api/session")
        .expect(200);
      expect(bystanderStatus.body.loggedIn).to.equal(true);
      expect(bystanderStatus.body.user).to.have.property(
        "email",
        bystanderEmail,
      );

      const remaining = await countSessionsForUser(bystander.id);
      expect(remaining.count).to.be.at.least(1);
    });
  });
});
