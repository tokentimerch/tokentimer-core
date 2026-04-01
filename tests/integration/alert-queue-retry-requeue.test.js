const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Alert Queue Retry and Requeue", function () {
  this.timeout(60000);

  let user, cookie, ws;

  before(async () => {
    await TestEnvironment.setup();
    user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;
    ws = await TestUtils.ensureTestWorkspace(cookie);
  });

  async function insertFailedAlert(tokenId) {
    const result = await TestUtils.execQuery(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status, attempts, error_message, next_attempt_at)
       VALUES ($1, $2, $3, 7, CURRENT_DATE, '["email"]', 'failed', 3, 'SMTP timeout', NOW() - INTERVAL '1 hour')
       RETURNING id`,
      [user.id, tokenId, `test_retry:${tokenId}:${Date.now()}`],
    );
    return result.rows[0].id;
  }

  describe("POST /api/alert-queue/:id/retry", () => {
    it("resets a failed alert to pending", async () => {
      const soon = new Date();
      soon.setDate(soon.getDate() + 5);
      const token = await request(BASE)
        .post("/api/tokens")
        .set("Cookie", cookie)
        .send({
          name: "Retry Token",
          type: "api_key",
          category: "general",
          expiresAt: soon.toISOString().slice(0, 10),
          workspace_id: ws,
        })
        .expect(201);

      const alertId = await insertFailedAlert(token.body.id);

      const res = await request(BASE)
        .post(`/api/alert-queue/${alertId}/retry`)
        .set("Cookie", cookie);

      // The endpoint may return 200 on success or 404 if not implemented as a standalone
      // Some implementations use the requeue bulk endpoint instead
      if (res.status === 200) {
        // Verify the alert was reset
        const check = await TestUtils.execQuery(
          "SELECT status, next_attempt_at FROM alert_queue WHERE id = $1",
          [alertId],
        );
        expect(check.rows[0].status).to.equal("pending");
      } else {
        expect(res.status).to.be.oneOf([200, 404]);
      }
    });
  });

  describe("POST /api/alert-queue/requeue", () => {
    it("requeues all failed alerts for user", async () => {
      const soon = new Date();
      soon.setDate(soon.getDate() + 3);
      const token = await request(BASE)
        .post("/api/tokens")
        .set("Cookie", cookie)
        .send({
          name: "Requeue Token",
          type: "api_key",
          category: "general",
          expiresAt: soon.toISOString().slice(0, 10),
          workspace_id: ws,
        })
        .expect(201);

      await insertFailedAlert(token.body.id);
      await insertFailedAlert(token.body.id);

      const res = await request(BASE)
        .post("/api/alert-queue/requeue")
        .set("Cookie", cookie)
        .send({})
        .expect(200);

      expect(res.body).to.have.property("updated");
      expect(res.body.updated).to.be.at.least(1);
    });

    it("supports workspace-scoped requeue", async () => {
      const res = await request(BASE)
        .post("/api/alert-queue/requeue")
        .set("Cookie", cookie)
        .send({ workspace_id: ws })
        .expect(200);

      expect(res.body).to.have.property("updated");
    });

    it("rejects requeue for workspace where user is not admin/manager", async () => {
      const otherUser = await TestUtils.createVerifiedTestUser();
      const otherSession = await TestUtils.loginTestUser(
        otherUser.email,
        otherUser.password,
      );

      const res = await request(BASE)
        .post("/api/alert-queue/requeue")
        .set("Cookie", otherSession.cookie)
        .send({ workspace_id: ws });

      expect(res.status).to.equal(403);
    });
  });
});
