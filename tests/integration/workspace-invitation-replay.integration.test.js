const crypto = require("crypto");
const { request, expect, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const PASSWORD = "SecureTest123!@#";

describe("Workspace invitation replay on login", function () {
  this.timeout(90000);

  let ownerUser;
  let ownerSession;
  let workspaceId;
  const inviteeUsers = [];
  const inviteeSessions = [];

  async function seedInvitation({ email, role, acceptedAt = null }) {
    const id = crypto.randomUUID();
    const token = crypto.randomBytes(24).toString("hex");
    await TestUtils.execQuery(
      `INSERT INTO workspace_invitations
         (id, workspace_id, email, role, invited_by, token, accepted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        id,
        workspaceId,
        email.toLowerCase(),
        role,
        ownerUser.id,
        token,
        acceptedAt,
      ],
    );
    return id;
  }

  async function membershipRole(userId) {
    const res = await TestUtils.execQuery(
      `SELECT role FROM workspace_memberships
        WHERE user_id = $1 AND workspace_id = $2`,
      [userId, workspaceId],
    );
    return res.rows[0]?.role || null;
  }

  function plusAlias(email, tag = "rejoin") {
    const [local, domain] = String(email).split("@");
    return `${local}+${tag}@${domain}`;
  }

  before(async () => {
    ownerUser = await TestUtils.createVerifiedTestUser();
    ownerSession = await TestUtils.loginTestUser(ownerUser.email, PASSWORD);

    const wsRes = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    workspaceId = wsRes?.body?.items?.[0]?.id;
    expect(workspaceId, "owner workspace id").to.exist;
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery(
        "DELETE FROM workspace_invitations WHERE workspace_id = $1",
        [workspaceId],
      );
    }
    for (const session of inviteeSessions) {
      if (session?.cookie) {
        await TestUtils.cleanupTestUser(session.email, session.cookie);
      }
    }
    for (const user of inviteeUsers) {
      if (user?.email && !inviteeSessions.some((s) => s?.email === user.email)) {
        try {
          await TestUtils.cleanupTestUser(user.email);
        } catch (_err) {
          /* best-effort */
        }
      }
    }
    if (ownerSession?.cookie) {
      await TestUtils.cleanupTestUser(ownerUser.email, ownerSession.cookie);
    }
  });

  it("does not restore a removed member from an already-accepted plus-alias invitation", async () => {
    const invitee = await TestUtils.createVerifiedTestUser();
    inviteeUsers.push(invitee);
    await seedInvitation({
      email: plusAlias(invitee.email),
      role: "workspace_manager",
    });

    const firstLogin = await TestUtils.loginTestUser(invitee.email, PASSWORD);
    inviteeSessions.push({ email: invitee.email, cookie: firstLogin.cookie });
    expect(await membershipRole(invitee.id)).to.equal("workspace_manager");

    await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/members/${invitee.id}`)
      .set("Cookie", ownerSession.cookie)
      .expect(204);
    expect(await membershipRole(invitee.id)).to.equal(null);

    await TestUtils.loginTestUser(invitee.email, PASSWORD);
    expect(await membershipRole(invitee.id)).to.equal(null);
  });

  it("does not re-elevate a downgraded role from a leftover accepted invitation", async () => {
    const invitee = await TestUtils.createVerifiedTestUser();
    inviteeUsers.push(invitee);
    await seedInvitation({
      email: plusAlias(invitee.email, "manager"),
      role: "workspace_manager",
    });

    const firstLogin = await TestUtils.loginTestUser(invitee.email, PASSWORD);
    inviteeSessions.push({ email: invitee.email, cookie: firstLogin.cookie });
    expect(await membershipRole(invitee.id)).to.equal("workspace_manager");

    await request(BASE)
      .patch(`/api/v1/workspaces/${workspaceId}/members/${invitee.id}`)
      .set("Cookie", ownerSession.cookie)
      .send({ role: "viewer" })
      .expect(200);
    expect(await membershipRole(invitee.id)).to.equal("viewer");

    await TestUtils.loginTestUser(invitee.email, PASSWORD);
    expect(await membershipRole(invitee.id)).to.equal("viewer");
  });

  it("matches a Gmail canonical alias invitation on login", async () => {
    const stamp = `${Date.now()}${Math.random().toString(36).slice(2, 8)}`;
    const gmailEmail = `replaygmail${stamp}@gmail.com`;
    const gmailAlias = `replay.gmail${stamp}+invite@googlemail.com`;
    const invitee = await TestUtils.createVerifiedTestUser(gmailEmail);
    inviteeUsers.push(invitee);

    await seedInvitation({
      email: gmailAlias,
      role: "viewer",
    });

    const session = await TestUtils.loginTestUser(invitee.email, PASSWORD);
    inviteeSessions.push({ email: invitee.email, cookie: session.cookie });
    expect(await membershipRole(invitee.id)).to.equal("viewer");
  });

  it("ignores already-accepted invitations on a later login", async () => {
    const invitee = await TestUtils.createVerifiedTestUser();
    inviteeUsers.push(invitee);
    await seedInvitation({
      email: plusAlias(invitee.email, "stale"),
      role: "workspace_manager",
      acceptedAt: new Date().toISOString(),
    });

    const session = await TestUtils.loginTestUser(invitee.email, PASSWORD);
    inviteeSessions.push({ email: invitee.email, cookie: session.cookie });
    expect(await membershipRole(invitee.id)).to.equal(null);
  });
});
