const crypto = require("crypto");
const { TestUtils, request, expect } = require("./setup");

describe("Invite Registration and Reset Password Integration", () => {
  const createInvitation = async ({ email, role = "viewer" } = {}) => {
    const inviter = await TestUtils.createVerifiedTestUser();
    const workspaceRes = await TestUtils.execQuery(
      `SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1`,
      [inviter.id],
    );
    expect(workspaceRes.rowCount).to.equal(1);

    const invitedEmail = email || TestUtils.generateTestEmail("invitee");
    const inviteToken = crypto.randomBytes(24).toString("hex");
    await TestUtils.execQuery(
      `INSERT INTO workspace_invitations (id, workspace_id, email, role, invited_by, token)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        crypto.randomUUID(),
        workspaceRes.rows[0].id,
        invitedEmail.toLowerCase(),
        role,
        inviter.id,
        inviteToken,
      ],
    );

    return { invitedEmail, inviteToken };
  };

  describe("POST /auth/register (invite-only)", () => {
    it("creates a user when invitation token and email match", async () => {
      const { invitedEmail, inviteToken } = await createInvitation();

      const response = await request("http://localhost:4000")
        .post("/auth/register")
        .send({
          token: inviteToken,
          email: invitedEmail,
          first_name: "Invite",
          last_name: "User",
          password: "ValidPass123!@#",
        })
        .expect(201);

      expect(response.body.success).to.equal(true);
      expect(response.body.user).to.have.property("email", invitedEmail);
      expect(response.body.user).to.have.property("id");
    });

    it("rejects registration with invalid invitation token", async () => {
      const invitedEmail = TestUtils.generateTestEmail("invitee");
      const response = await request("http://localhost:4000")
        .post("/auth/register")
        .send({
          token: "invalid-token",
          email: invitedEmail,
          first_name: "Invite",
          last_name: "User",
          password: "ValidPass123!@#",
        })
        .expect(400);

      expect(response.body).to.have.property("code", "INVITE_TOKEN_INVALID");
    });
  });

  describe("GET /auth/verify-email/:token", () => {
    it("verifies email, redirects to dashboard, and creates an authenticated session", async () => {
      const { invitedEmail, inviteToken } = await createInvitation();

      await request("http://localhost:4000")
        .post("/auth/register")
        .send({
          token: inviteToken,
          email: invitedEmail,
          first_name: "Verify",
          last_name: "Flow",
          password: "ValidPass123!@#",
        })
        .expect(201);

      const tokenRes = await TestUtils.execQuery(
        `SELECT verification_token
           FROM users
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1`,
        [invitedEmail],
      );
      expect(tokenRes.rowCount).to.equal(1);
      const verificationToken = tokenRes.rows[0].verification_token;
      expect(verificationToken).to.be.a("string").and.not.equal("");

      const agent = request.agent("http://localhost:4000");
      const verifyRes = await agent
        .get(`/auth/verify-email/${verificationToken}`)
        .expect(302);

      expect(verifyRes.headers.location).to.include("/dashboard");
      expect(verifyRes.headers.location).to.include("first_login=true");

      const sessionRes = await agent.get("/api/session").expect(200);
      expect(sessionRes.body.loggedIn).to.equal(true);
      expect(sessionRes.body.user).to.have.property("email", invitedEmail);
      expect(sessionRes.body.user).to.have.property("emailVerified", true);
    });
  });

  describe("POST /auth/reset-password", () => {
    it("rejects unknown reset token", async () => {
      const response = await request("http://localhost:4000")
        .post("/auth/reset-password")
        .send({
          token: "unknown-reset-token",
          newPassword: "NewValidPass123!@#",
        })
        .expect(400);

      expect(response.body.error).to.include("Invalid or expired");
    });

    it("resets password with valid token and allows login with new password", async () => {
      const email = TestUtils.generateTestEmail("reset");
      const oldPassword = "OldValidPass123!@#";
      const newPassword = "NewValidPass123!@#";
      const resetToken = crypto.randomBytes(24).toString("hex");

      await TestUtils.createVerifiedTestUser(email, oldPassword);
      await TestUtils.execQuery(
        `UPDATE users
            SET reset_token = $2,
                reset_token_expires = NOW() + INTERVAL '5 minutes'
          WHERE LOWER(email) = LOWER($1)`,
        [email, resetToken],
      );

      await request("http://localhost:4000")
        .post("/auth/reset-password")
        .send({
          token: resetToken,
          newPassword,
        })
        .expect(200);

      await request("http://localhost:4000")
        .post("/auth/login")
        .send({
          email,
          password: oldPassword,
        })
        .expect(401);

      await request("http://localhost:4000")
        .post("/auth/login")
        .send({
          email,
          password: newPassword,
        })
        .expect(200);
    });
  });
});
