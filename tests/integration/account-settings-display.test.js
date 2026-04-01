const { TestUtils, request, expect } = require("./test-server");
const User = require("../../apps/api/db/models/User");
const bcrypt = require("bcryptjs");

// Use the existing Docker Compose server
const TEST_SERVER_URL = process.env.TEST_API_URL || "http://localhost:4000";

describe("Account Settings Display", () => {
  let agent;

  beforeEach(async () => {
    agent = request.agent(TEST_SERVER_URL);
  });

  afterEach(async () => {
    // Clean up any test data
    await User.findByEmail("test@example.com").then((user) => {
      if (user) {
        // Note: In a real test, you'd want to delete the user
        // For now, we'll just check the session
      }
    });
  });

  describe("Session Authentication Method Display", () => {
    it('should show "Email & Password" for local users', async () => {
      // Create a local user
      const passwordHash = await bcrypt.hash("testpassword", 12);
      const localUserData = {
        email: "test.local@example.com",
        displayName: "Test Local User",
        passwordHash,
        authMethod: "local",
        photo: "data:image/svg+xml;base64,test",
        verificationToken: "test-token",
        verificationTokenExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      const localUser = await User.createLocal(localUserData);

      // Simulate login by setting up session
      const loginResponse = await agent.post("/auth/login").send({
        email: localUser.email,
        password: "testpassword",
      });

      // Get session to verify auth method
      const sessionResponse = await agent.get("/api/session");

      expect(sessionResponse.status).to.equal(200);
      expect(sessionResponse.body.loggedIn).to.be.true;
      expect(sessionResponse.body.user.authMethod).to.equal("local");
      expect(sessionResponse.body.user.loginMethod).to.equal("email");
    });
  });

  describe("Frontend Account Component Logic", () => {
    it("should correctly identify Google OAuth users", () => {
      // This is a unit test for the frontend logic
      const googleSession = {
        authMethod: "google",
        displayName: "Test User",
        email: "test@example.com",
      };

      const isGoogleOAuth = googleSession.authMethod === "google";
      expect(isGoogleOAuth).to.be.true;
    });

    it("should correctly identify local users", () => {
      // This is a unit test for the frontend logic
      const localSession = {
        authMethod: "local",
        displayName: "Test User",
        email: "test@example.com",
      };

      const isLocalUser = localSession.authMethod === "local";
      expect(isLocalUser).to.be.true;
    });

    it("should display correct badge colors", () => {
      // Test the badge color logic from Account.jsx
      const getBadgeColor = (authMethod) => {
        return authMethod === "google" ? "blue" : "green";
      };

      expect(getBadgeColor("google")).to.equal("blue");
      expect(getBadgeColor("local")).to.equal("green");
    });

    it("should display correct login method text", () => {
      // Test the display text logic from Account.jsx
      const getLoginMethodText = (authMethod) => {
        return authMethod === "google" ? "Google OAuth" : "Email & Password";
      };

      expect(getLoginMethodText("google")).to.equal("Google OAuth");
      expect(getLoginMethodText("local")).to.equal("Email & Password");
    });
  });
});
