const { TestUtils, request, expect } = require("./test-server");
const { testDataManager } = require("./test-data-manager");

// Create and edit must share one type/category rule set.
describe("Token type and category consistency", () => {
  let session;
  let userId;

  const future = () =>
    new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];

  const create = (type, category, extra = {}) =>
    request("http://localhost:4000")
      .post("/api/tokens")
      .set("Cookie", session.cookie)
      .send({
        name: `Consistency ${type} ${Math.random().toString(36).slice(2, 8)}`,
        type,
        category,
        expiresAt: future(),
        workspace_id: session.workspaceId,
        ...extra,
      });

  const update = (id, body) =>
    request("http://localhost:4000")
      .put(`/api/tokens/${id}`)
      .set("Cookie", session.cookie)
      .send(body);

  before(async () => {
    const user = await TestUtils.createVerifiedTestUser();
    userId = user.id;
    session = await TestUtils.loginTestUser(user.email, "SecureTest123!@#");
    session.workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);
  });

  after(async () => {
    await testDataManager.cleanupAll();
  });

  describe("every dashboard type/category pair", () => {
    const pairs = [
      ["ssl_cert", "cert"],
      ["tls_cert", "cert"],
      ["code_signing", "cert"],
      ["client_cert", "cert"],
      ["api_key", "key_secret"],
      ["secret", "key_secret"],
      ["password", "key_secret"],
      ["encryption_key", "key_secret"],
      ["ssh_key", "key_secret"],
      ["software_license", "license"],
      ["service_subscription", "license"],
      ["domain_registration", "license"],
      ["other", "general"],
      ["document", "general"],
      ["membership", "general"],
    ];

    for (const [type, category] of pairs) {
      it(`creates and re-saves ${type} under ${category}`, async () => {
        const created = await create(type, category).expect(201);
        const res = await update(created.body.id, { type, category });
        expect(res.status, JSON.stringify(res.body)).to.equal(200);
        expect(res.body.type).to.equal(type);
        expect(res.body.category).to.equal(category);
      });
    }
  });

  describe("create rejects what edit rejects", () => {
    it("rejects an api_key under the cert category", async () => {
      const res = await create("api_key", "cert").expect(400);
      expect(res.body.details.join(" ")).to.include(
        "Invalid token type for selected category",
      );
    });

    it("rejects an api_key under the general category", async () => {
      await create("api_key", "general").expect(400);
    });

    it("rejects a general type under the license category", async () => {
      await create("document", "license").expect(400);
    });
  });

  describe("types the database cannot store", () => {
    for (const type of ["oauth_token", "jwt_token"]) {
      it(`rejects ${type} with a validation error on create`, async () => {
        const res = await create(type, "key_secret");
        expect(res.status).to.equal(400);
        expect(res.body.details.join(" ")).to.include("Invalid token type");
      });
    }

    it("rejects an unknown type on edit instead of failing in the database", async () => {
      const created = await create("secret", "key_secret").expect(201);
      const res = await update(created.body.id, { type: "bogus" });
      expect(res.status).to.equal(400);
      expect(res.body.details.join(" ")).to.include("Invalid token type");
    });
  });

  describe("edit checks the effective pair", () => {
    it("rejects changing only the type to one outside the stored category", async () => {
      const created = await create("secret", "key_secret").expect(201);
      const res = await update(created.body.id, { type: "ssl_cert" });
      expect(res.status).to.equal(400);
      expect(res.body.details.join(" ")).to.include(
        "Invalid token type for selected category",
      );
    });

    it("rejects changing only the category away from the stored type", async () => {
      const created = await create("secret", "key_secret").expect(201);
      const res = await update(created.body.id, { category: "cert" });
      expect(res.status).to.equal(400);
    });

    it("accepts moving to another valid pair", async () => {
      const created = await create("secret", "key_secret").expect(201);
      const res = await update(created.body.id, {
        type: "software_license",
        category: "license",
      });
      expect(res.status, JSON.stringify(res.body)).to.equal(200);
    });
  });

  describe("legacy rows with a mismatched pair stay editable", () => {
    let legacyId;

    before(async () => {
      const ws = await TestUtils.execQuery(
        `SELECT workspace_id FROM workspace_memberships WHERE user_id = $1 LIMIT 1`,
        [userId],
      );
      const inserted = await TestUtils.execQuery(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, 'Legacy mismatched pair', $3, 'api_key', 'general')
         RETURNING id`,
        [userId, ws.rows[0].workspace_id, future()],
      );
      legacyId = inserted.rows[0].id;
    });

    it("accepts a save that sends the stored pair unchanged", async () => {
      const res = await update(legacyId, {
        name: "Legacy mismatched pair renamed",
        type: "api_key",
        category: "general",
      });
      expect(res.status, JSON.stringify(res.body)).to.equal(200);
    });

    it("accepts a save that omits type and category", async () => {
      await update(legacyId, { notes: "still editable" }).expect(200);
    });

    it("still rejects moving it to a different mismatched pair", async () => {
      await update(legacyId, { type: "ssl_cert", category: "license" }).expect(
        400,
      );
    });
  });
});
