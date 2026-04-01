const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const crypto = require("crypto");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

const hasTwilio = !!process.env.TWILIO_AUTH_TOKEN;
const describeIf = hasTwilio ? describe : describe.skip;

describeIf("Twilio WhatsApp Status Webhook", function () {
  this.timeout(60000);

  let user;
  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    user = u.user || u;
    cookie = u.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  function signTwilioWebhook(url, body, authToken) {
    // Twilio signature: Base64(HMAC-SHA1(authToken, url + concatenatedParams))
    const params = Array.from(new URLSearchParams(body).entries()).sort(
      (a, b) => a[0].localeCompare(b[0]),
    );
    let data = url;
    for (const [key, value] of params) data += key + value;
    const hmac = crypto.createHmac("sha1", authToken);
    hmac.update(Buffer.from(data, "utf-8"));
    return hmac.digest("base64");
  }

  it("accepts valid signature and updates delivery log metadata", async () => {
    // Seed a delivery log row with a messageSid to update
    const { Client } = require("pg");
    const client = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    await client.connect();

    // Create a token to attribute the row
    const tok = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [
        user.id,
        workspaceId,
        "WA Webhook Token",
        new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
      ],
    );
    const tokenId = tok.rows[0].id;

    const messageSid = `SM${Math.random().toString(36).slice(2, 12)}`;
    await client.query(
      `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, sent_at, metadata)
       VALUES (NULL, $1, $2, $3, 'whatsapp', 'success', NOW(), $4::jsonb)`,
      [user.id, tokenId, workspaceId, JSON.stringify({ messageSid })],
    );

    // Build webhook payload like Twilio would send
    const payload = {
      MessageSid: messageSid,
      MessageStatus: "delivered",
      ErrorCode: null,
      ChannelToAddress: "+14155550100",
      EventType: "DELIVERED",
      ChannelPrefix: "whatsapp",
    };
    const body = new URLSearchParams(payload).toString();
    const url = `${BASE}/webhooks/twilio/whatsapp/status`;

    const authToken = process.env.TWILIO_AUTH_TOKEN || "test_auth_token";
    const signature = signTwilioWebhook(url, body, authToken);

    const res = await request(BASE)
      .post("/webhooks/twilio/whatsapp/status")
      .set("X-Twilio-Signature", signature)
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send(body)
      .expect(200);

    // Verify metadata updated
    const check = await client.query(
      `SELECT metadata FROM alert_delivery_log WHERE user_id=$1 AND channel='whatsapp' AND (metadata->>'messageSid')=$2 ORDER BY sent_at DESC LIMIT 1`,
      [user.id, messageSid],
    );
    expect(check.rowCount).to.equal(1);
    const meta = check.rows[0].metadata || {};
    expect(meta.MessageStatus || meta.messageStatus || meta.status).to.be.oneOf(
      ["delivered", "DELIVERED"],
    );

    await client.end();
  });

  it("rejects invalid signature with 403", async () => {
    const body = new URLSearchParams({ MessageSid: "SM_invalid" }).toString();
    await request(BASE)
      .post("/webhooks/twilio/whatsapp/status")
      .set("X-Twilio-Signature", "invalid-signature")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send(body)
      .expect(403);
  });
});
