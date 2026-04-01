const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Delivery Window Deferral", function () {
  this.timeout(120000);

  let user, cookie, ws;

  before(async () => {
    await TestEnvironment.setup();
    user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;
    ws = await TestUtils.ensureTestWorkspace(cookie);
  });

  it("defers alert delivery when outside the delivery window", async () => {
    // Create a contact so we can set up a contact group with an email recipient
    const contact = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "Deferral",
        last_name: "Test",
        details: { email: user.email },
      })
      .expect(201);

    // Set a delivery window that is guaranteed to exclude the current time.
    const now = new Date();
    const utcHour = now.getUTCHours();
    const pastHour = (utcHour + 21) % 24; // 3 hours behind
    const windowStart = `${String(pastHour).padStart(2, "0")}:00`;
    const windowEnd = `${String(pastHour).padStart(2, "0")}:01`;

    await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({
        delivery_window_start: windowStart,
        delivery_window_end: windowEnd,
        delivery_window_tz: "UTC",
        email_alerts_enabled: true,
        alert_thresholds: [30, 14, 7, 1, 0],
        contact_groups: [
          {
            id: "deferral-grp",
            name: "Deferral Group",
            email_contact_ids: [contact.body.id],
          },
        ],
        default_contact_group_id: "deferral-grp",
      })
      .expect(200);

    const soon = new Date();
    soon.setDate(soon.getDate() + 6);

    const token = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Deferral Token",
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: ws,
        contact_group_id: "deferral-grp",
      })
      .expect(201);

    // Run discovery to queue the alert
    await TestUtils.runNode("node", ["src/queue-manager.js"], "apps/worker");

    // Verify alert is queued
    const queued = await TestUtils.execQuery(
      "SELECT id, status FROM alert_queue WHERE token_id = $1 AND status = 'pending'",
      [token.body.id],
    );
    expect(queued.rows.length).to.be.at.least(
      1,
      "Expected at least one queued alert",
    );

    const alertId = queued.rows[0].id;

    // Run delivery worker - alert should be deferred (not sent) because outside window
    await TestUtils.runNode(
      "node",
      ["src/delivery-worker.js"],
      "apps/worker",
      { DELIVERY_WINDOW_DEFERRAL_MS: "5000" },
    );

    // The alert should NOT have status 'sent'.
    const after = await TestUtils.execQuery(
      "SELECT status, next_attempt_at FROM alert_queue WHERE id = $1",
      [alertId],
    );

    const status = after.rows[0]?.status;
    expect(status).to.not.equal("sent");
  });
});
