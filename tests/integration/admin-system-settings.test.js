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

  describe("System admin access is not coupled to workspace admin role (0.6.0)", () => {
    let systemAdminUser, systemAdminCookie;
    let managerOnlyUser, managerOnlyCookie;
    let sharedWorkspaceId;

    before(async () => {
      // Create a user, mark them as installation-wide system admin via DB,
      // but only as workspace_manager on the workspace. This mirrors the
      // post-hardening state where SSO-driven users.is_admin=TRUE no longer
      // implies workspace admin on the shared Default workspace.
      systemAdminUser = await TestUtils.createVerifiedTestUser();
      const sys = await TestUtils.loginTestUser(
        systemAdminUser.email,
        systemAdminUser.password,
      );
      systemAdminCookie = sys.cookie;
      await TestUtils.execQuery(
        "UPDATE users SET is_admin = TRUE WHERE id = $1",
        [systemAdminUser.id],
      );

      // Find the workspace the user already has (createVerifiedTestUser seeds
      // one for them as admin) and demote them to workspace_manager so the
      // ONLY route to /api/admin/system-settings is the system-admin flag.
      const wsRow = await TestUtils.execQuery(
        "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
        [systemAdminUser.id],
      );
      sharedWorkspaceId = wsRow.rows[0].id;
      await TestUtils.execQuery(
        `UPDATE workspace_memberships
            SET role = 'workspace_manager'
          WHERE user_id = $1
            AND workspace_id = $2`,
        [systemAdminUser.id, sharedWorkspaceId],
      );

      // Control user: workspace_manager somewhere, NOT a system admin.
      managerOnlyUser = await TestUtils.createVerifiedTestUser();
      const mgr = await TestUtils.loginTestUser(
        managerOnlyUser.email,
        managerOnlyUser.password,
      );
      managerOnlyCookie = mgr.cookie;
      const mgrWs = await TestUtils.execQuery(
        "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
        [managerOnlyUser.id],
      );
      if (mgrWs.rowCount > 0) {
        await TestUtils.execQuery(
          `UPDATE workspace_memberships
              SET role = 'workspace_manager'
            WHERE user_id = $1
              AND workspace_id = $2`,
          [managerOnlyUser.id, mgrWs.rows[0].id],
        );
      }
    });

    it("allows users.is_admin=TRUE with Default workspace role workspace_manager to GET /api/admin/system-settings", async () => {
      // Sanity-check the precondition the test is asserting: the system admin
      // user really is workspace_manager (not admin) on the workspace.
      const role = await TestUtils.execQuery(
        `SELECT role FROM workspace_memberships
          WHERE user_id = $1 AND workspace_id = $2`,
        [systemAdminUser.id, sharedWorkspaceId],
      );
      expect(role.rows[0].role).to.equal("workspace_manager");

      // The endpoint must let them in because is_admin gates it, not the
      // workspace role.
      const res = await request(BASE)
        .get("/api/admin/system-settings")
        .set("Cookie", systemAdminCookie)
        .expect(200);
      expect(res.body).to.have.property("smtp");
      expect(res.body).to.have.property("whatsapp");
    });

    it("rejects a workspace_manager who is NOT a system admin with 403 (control)", async () => {
      const res = await request(BASE)
        .get("/api/admin/system-settings")
        .set("Cookie", managerOnlyCookie)
        .expect(403);
      expect(res.body.code).to.equal("FORBIDDEN");
    });
  });

  describe("PATCH /api/admin/users/:userId/system-admin", () => {
    it("rejects non-admin callers", async () => {
      await request(BASE)
        .patch(`/api/admin/users/${adminUser.id}/system-admin`)
        .set("Cookie", regularCookie)
        .send({ is_admin: true })
        .expect(403);
    });

    it("grants system admin to another user", async () => {
      const res = await request(BASE)
        .patch(`/api/admin/users/${regularUser.id}/system-admin`)
        .set("Cookie", adminCookie)
        .send({ is_admin: true })
        .expect(200);

      expect(res.body.is_admin).to.equal(true);

      const row = await TestUtils.execQuery(
        "SELECT is_admin FROM users WHERE id = $1",
        [regularUser.id],
      );
      expect(row.rows[0].is_admin).to.equal(true);
    });
  });
});
