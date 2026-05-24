const { TestUtils, request, expect } = require("./test-server");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const BOOTSTRAP_ADMIN_EMAIL =
  process.env.ADMIN_EMAIL || "admin@localhost.local";

describe("Account deletion vs last system admin", () => {
  after(async () => {
    await TestUtils.execQuery(
      "UPDATE users SET is_admin = TRUE WHERE LOWER(email) = LOWER($1)",
      [BOOTSTRAP_ADMIN_EMAIL],
    );
  });

  it("blocks deletion when user is the last active system admin", async () => {
    const soleAdmin = await TestUtils.createVerifiedTestUser();
    // Fresh installs bootstrap a system admin; demote everyone else so this
    // user is genuinely the last active system admin for the assertion.
    await TestUtils.execQuery("UPDATE users SET is_admin = FALSE WHERE id <> $1", [
      soleAdmin.id,
    ]);
    await TestUtils.execQuery("UPDATE users SET is_admin = TRUE WHERE id = $1", [
      soleAdmin.id,
    ]);

    const session = await TestUtils.loginTestUser(
      soleAdmin.email,
      "SecureTest123!@#",
    );

    const res = await request(BASE)
      .delete("/api/account")
      .set("Cookie", session.cookie)
      .expect(409);

    expect(res.body.code).to.equal("LAST_SYSTEM_ADMIN");
  });

  it("clears is_admin when a system admin deletes their account and another admin exists", async () => {
    const adminA = await TestUtils.createVerifiedTestUser();
    const adminB = await TestUtils.createVerifiedTestUser();
    await TestUtils.execQuery(
      "UPDATE users SET is_admin = TRUE WHERE id = ANY($1::int[])",
      [[adminA.id, adminB.id]],
    );

    const sessionA = await TestUtils.loginTestUser(
      adminA.email,
      "SecureTest123!@#",
    );

    const res = await request(BASE)
      .delete("/api/account")
      .set("Cookie", sessionA.cookie)
      .expect(200);

    expect(res.body.message).to.include("deleted");

    const row = await TestUtils.execQuery(
      "SELECT is_admin, email, display_name FROM users WHERE id = $1",
      [adminA.id],
    );
    expect(row.rows[0].is_admin).to.equal(false);
    expect(String(row.rows[0].email)).to.match(/@example\.invalid$/);
    expect(row.rows[0].display_name).to.equal("Deleted Account");
  });
});
