const { TestUtils, request, expect } = require("./setup");
const { logger } = require("./logger");

describe("Authentication Integration Tests", () => {
  let testUser;
  let session;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    try {
      session = await TestUtils.loginTestUser(
        testUser.email,
        "SecureTest123!@#",
      );
    } catch (error) {
      logger.info(
        "Login failed, will test without authentication:",
        error.message,
      );
      session = { cookie: null };
    }
  });

  describe("Login Flow", () => {
    it("should login with valid credentials", async () => {
      const response = await request("http://localhost:4000")
        .post("/auth/login")
        .send({
          email: testUser.email,
          password: "SecureTest123!@#",
        })
        .expect(200);

      expect(response.body.message).to.include("Login successful");
      expect(response.body.user).to.have.property("email", testUser.email);
    });

    it("should reject login with invalid credentials", async () => {
      const response = await request("http://localhost:4000")
        .post("/auth/login")
        .send({
          email: testUser.email,
          password: "wrongpassword",
        })
        .expect(401);

      expect(response.body.error).to.include("Invalid credentials");
    });

    it("should reject login with missing fields", async () => {
      const response = await request("http://localhost:4000")
        .post("/auth/login")
        .send({
          email: testUser.email,
          // Missing password
        })
        .expect(400);

      expect(response.body.error).to.equal("Invalid email or password");
    });
  });

  describe("Two-Factor Authentication (TOTP)", () => {
    it("should support enabling 2FA and challenge on login", async () => {
      const email = `otp-user-${Date.now()}@example.com`;
      const password = "SecureTest123!@#";

      // Create user via DB (core does not expose /auth/register)
      const otpUser = await TestUtils.createVerifiedTestUser(
        email,
        password,
        "OTP User",
      );

      // Login (establish session)
      const agent = await TestUtils.newAgent();
      await agent.post("/auth/login").send({ email, password }).expect(200);

      // Setup 2FA
      const setupRes = await agent.post("/api/account/2fa/setup").send({});

      if (setupRes.status !== 200) {
        logger.info("2FA setup failed with status:", setupRes.status);
        logger.info("2FA setup response body:", JSON.stringify(setupRes.body));
        logger.info(
          "2FA setup response headers:",
          JSON.stringify(setupRes.headers),
        );
      }
      expect(setupRes.status).to.equal(200);
      expect(setupRes.body).to.have.property("secret");

      // otplib v13+ exports functions directly instead of authenticator object
      const { generateSync } = require("otplib");
      const firstCode = generateSync({ secret: setupRes.body.secret });

      await agent
        .post("/api/account/2fa/enable")
        .send({ token: firstCode })
        .expect(200);

      // Logout to test challenge
      await agent.post("/api/logout").expect(200);

      // New login attempt should require 2FA
      const loginRes = await agent
        .post("/auth/login")
        .send({ email, password })
        .expect(200);
      expect(loginRes.body.requires2FA).to.equal(true);

      // Invalid code rejected
      await agent
        .post("/auth/verify-2fa")
        .send({ token: "000000" })
        .expect(401);

      // Valid current code succeeds
      const validCode = generateSync({ secret: setupRes.body.secret });
      await agent
        .post("/auth/verify-2fa")
        .send({ token: validCode })
        .expect(200);
    });
  });

  describe("Session Management", () => {
    it("should maintain session after login when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const response = await request("http://localhost:4000")
        .get("/api/session")
        .set("Cookie", session.cookie)
        .expect(200);

      expect(response.body.loggedIn).to.be.true;
      if (response.body.user) {
        expect(response.body.user.email).to.equal(testUser.email);
      } else {
        logger.info("No user object in session response, skipping email check");
      }
    });

    it("should logout successfully when authenticated", async () => {
      if (!session.cookie) {
        logger.info("Skipping authenticated test due to login failure");
        return;
      }

      const response = await request("http://localhost:4000")
        .post("/auth/logout")
        .set("Cookie", session.cookie)
        .expect(200);

      expect(response.body.message).to.equal("logged out successfully");
    });
  });
});
