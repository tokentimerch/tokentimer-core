const { TestUtils, expect } = require("./setup");

function getWeekStartDateUtc() {
  const now = new Date();
  const day = now.getUTCDay();
  const diff = day === 0 ? 6 : day - 1;
  const monday = new Date(now);
  monday.setUTCDate(now.getUTCDate() - diff);
  monday.setUTCHours(0, 0, 0, 0);
  return monday.toISOString().slice(0, 10);
}

describe("Weekly digest worker integration", function () {
  this.timeout(120000);

  let testUser;
  let workspaceId;
  let contactGroupId;
  let contactId;

  before(async () => {
    testUser = await TestUtils.createVerifiedTestUser();
    const ws = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [testUser.id],
    );
    workspaceId = ws.rows[0].id;
    contactGroupId = "digest-main";

    const contact = await TestUtils.execQuery(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, details, created_by)
       VALUES ($1, 'Digest', 'Recipient', $2::jsonb, $3)
       RETURNING id`,
      [workspaceId, JSON.stringify({ email: testUser.email }), testUser.id],
    );
    contactId = contact.rows[0]?.id;
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery(
        "DELETE FROM weekly_digest_log WHERE workspace_id = $1",
        [workspaceId],
      );
      await TestUtils.execQuery("DELETE FROM tokens WHERE workspace_id = $1", [
        workspaceId,
      ]);
    }
  });

  it("selects digest candidates and records one digest per week", async () => {
    await TestUtils.execQuery(
      `INSERT INTO workspace_settings (
         workspace_id,
         contact_groups,
         default_contact_group_id,
         alert_thresholds,
         delivery_window_start,
         delivery_window_end,
         delivery_window_tz
       )
       VALUES ($1, $2::jsonb, $3, $4::jsonb, '00:00', '23:59', 'UTC')
       ON CONFLICT (workspace_id) DO UPDATE SET
         contact_groups = EXCLUDED.contact_groups,
         default_contact_group_id = EXCLUDED.default_contact_group_id,
         alert_thresholds = EXCLUDED.alert_thresholds,
         delivery_window_start = EXCLUDED.delivery_window_start,
         delivery_window_end = EXCLUDED.delivery_window_end,
         delivery_window_tz = EXCLUDED.delivery_window_tz`,
      [
        workspaceId,
        JSON.stringify([
          {
            id: contactGroupId,
            name: "Digest Team",
            email_contact_ids: [contactId],
            weekly_digest_email: true,
          },
        ]),
        contactGroupId,
        JSON.stringify([7, 30]),
      ],
    );

    await TestUtils.execQuery(
      `INSERT INTO tokens
        (workspace_id, name, expiration, type, category, contact_group_id)
       VALUES
        ($1, 'digest-soon', CURRENT_DATE + INTERVAL '5 day', 'api_key', 'key_secret', $2),
        ($1, 'digest-later', CURRENT_DATE + INTERVAL '20 day', 'ssl_cert', 'cert', $2),
        ($1, 'digest-ignore', CURRENT_DATE + INTERVAL '120 day', 'other', 'general', $2)`,
      [workspaceId, contactGroupId],
    );

    await TestUtils.runNode(
      "node",
      ["src/weekly-digest-runner.js"],
      "apps/worker",
      {
        ...process.env,
        NODE_ENV: "test",
      },
    );

    const weekStart = getWeekStartDateUtc();
    const firstRun = await TestUtils.execQuery(
      `SELECT tokens_count
       FROM weekly_digest_log
       WHERE workspace_id = $1 AND contact_group_id = $2 AND week_start_date = $3`,
      [workspaceId, contactGroupId, weekStart],
    );
    expect(firstRun.rows).to.have.length(1);
    expect(Number(firstRun.rows[0].tokens_count)).to.be.greaterThan(0);

    // Idempotency and skip behavior: second run in same week does not duplicate log
    await TestUtils.runNode(
      "node",
      ["src/weekly-digest-runner.js"],
      "apps/worker",
      {
        ...process.env,
        NODE_ENV: "test",
      },
    );

    const secondRun = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS c
       FROM weekly_digest_log
       WHERE workspace_id = $1 AND contact_group_id = $2 AND week_start_date = $3`,
      [workspaceId, contactGroupId, weekStart],
    );
    expect(secondRun.rows[0].c).to.equal(1);
  });
});
