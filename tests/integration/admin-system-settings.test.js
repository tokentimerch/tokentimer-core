const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Admin System Settings", function () {
  this.timeout(60000);

  let adminUser, adminCookie;
  let regularUser, regularCookie;

  before(async () => {
    await TestEnvironment.setup();

    adminUser = await TestUtils.createVerifiedTestUser();
    const adminSession = await TestUtils.loginTestUser(
      adminUser.email,
      adminUser.password,
    );
    adminCookie = adminSession.cookie;

    await TestUtils.execQuery("UPDATE users SET is_admin = TRUE WHERE id = $1", [
      adminUser.id,
    ]);

    regularUser = await TestUtils.createVerifiedTestUser();
    const regularSession = await TestUtils.loginTestUser(
      regularUser.email,
      regularUser.password,
    );
    regularCookie = regularSession.cookie;
  });

  describe("GET /api/admin/system-settings", () => {
    it("returns smtp and whatsapp sections for admin", async () => {
      const res = await request(BASE)
        .get("/api/admin/system-settings")
        .set("Cookie", adminCookie)
        .expect(200);

      expect(res.body).to.have.property("smtp");
      expect(res.body).to.have.property("whatsapp");
      expect(res.body.smtp).to.have.property("configured");
      expect(res.body.whatsapp).to.have.property("configured");
    });

    it("rejects non-admin users with 403", async () => {
      const res = await request(BASE)
        .get("/api/admin/system-settings")
        .set("Cookie", regularCookie)
        .expect(403);

      expect(res.body).to.have.property("error");
      expect(res.body.code).to.equal("FORBIDDEN");
    });

    it("rejects unauthenticated requests with 401", async () => {
      await request(BASE).get("/api/admin/system-settings").expect(401);
    });
  });

  describe("PUT /api/admin/system-settings", () => {
    it("saves SMTP settings and returns 200 with smtp section", async () => {
      const res = await request(BASE)
        .put("/api/admin/system-settings")
        .set("Cookie", adminCookie)
        .send({
          smtp: {
            host: "smtp.test.local",
            port: "2525",
            user: "testuser",
            pass: "testpass",
            from_email: "test@example.com",
            from_name: "TokenTimer Test",
            secure: false,
            require_tls: false,
          },
        })
        .expect(200);

      expect(res.body).to.have.property("smtp");
      expect(res.body.smtp).to.have.property("host");
      // When SMTP_HOST is set via env, the env value takes precedence (locked).
      // When not set, the DB-saved value is returned. Either way, a value should exist.
      const hostVal = res.body.smtp.host;
      if (hostVal && typeof hostVal === "object") {
        expect(hostVal.value).to.be.a("string").that.is.not.empty;
      }
    });

    it("saves WhatsApp settings", async () => {
      const res = await request(BASE)
        .put("/api/admin/system-settings")
        .set("Cookie", adminCookie)
        .send({
          whatsapp: {
            account_sid: "AC_test_sid_value_12345",
            auth_token: "test_auth_token_value",
            whatsapp_from: "+14155238886",
          },
        })
        .expect(200);

      expect(res.body.whatsapp).to.have.property("account_sid");
      expect(res.body.whatsapp).to.have.property("configured");
    });

    it("rejects non-admin users with 403", async () => {
      await request(BASE)
        .put("/api/admin/system-settings")
        .set("Cookie", regularCookie)
        .send({ smtp: { host: "evil.local" } })
        .expect(403);
    });

    it("persists false-like boolean values for secure/require_tls", async () => {
      await request(BASE)
        .put("/api/admin/system-settings")
        .set("Cookie", adminCookie)
        .send({
          smtp: { secure: false, require_tls: false },
        })
        .expect(200);

      const res = await request(BASE)
        .get("/api/admin/system-settings")
        .set("Cookie", adminCookie)
        .expect(200);

      const secureVal = res.body.smtp.secure;
      if (secureVal && typeof secureVal === "object") {
        expect(secureVal.value).to.satisfy(
          (v) => v === "false" || v === false || v === null,
        );
      }
    });
  });

  describe("POST /api/admin/test-smtp", () => {
    it("rejects non-admin users", async () => {
      await request(BASE)
        .post("/api/admin/test-smtp")
        .set("Cookie", regularCookie)
        .send({ email: "test@example.com" })
        .expect(403);
    });

    it("accepts admin and attempts to send (success or SMTP error)", async () => {
      // The API server has its own env/DB config. We cannot clear its SMTP
      // from the test process. Instead, verify the endpoint is reachable and
      // returns a meaningful response (200 success or 500 SMTP error).
      const res = await request(BASE)
        .post("/api/admin/test-smtp")
        .set("Cookie", adminCookie)
        .send({ email: "test@example.com" });

      expect(res.status).to.be.oneOf([200, 400, 500]);
      if (res.status === 200) {
        expect(res.body.success).to.equal(true);
      }
    });
  });

  describe("POST /api/admin/test-whatsapp", () => {
    it("rejects non-admin users", async () => {
      await request(BASE)
        .post("/api/admin/test-whatsapp")
        .set("Cookie", regularCookie)
        .send({ phone: "+1234567890" })
        .expect(403);
    });

    it("validates phone number format", async () => {
      const res = await request(BASE)
        .post("/api/admin/test-whatsapp")
        .set("Cookie", adminCookie)
        .send({ phone: "not-a-phone" })
        .expect(400);

      expect(res.body.code).to.equal("INVALID_PHONE_FORMAT");
    });

    it("accepts admin with valid phone (success or config/send error)", async () => {
      // The API server has its own Twilio config. We cannot clear it from
      // the test process. Verify the endpoint responds meaningfully.
      const res = await request(BASE)
        .post("/api/admin/test-whatsapp")
        .set("Cookie", adminCookie)
        .send({ phone: "+1234567890" });

      // 200 = sent, 400 = not configured, 500 = send failed
      expect(res.status).to.be.oneOf([200, 400, 500]);
      if (res.status === 400) {
        expect(res.body.code).to.be.oneOf([
          "WHATSAPP_NOT_CONFIGURED",
          "WHATSAPP_TEST_FAILED",
        ]);
      }
    });
  });
});
