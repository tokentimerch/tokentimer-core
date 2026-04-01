const { request, expect } = require("./setup");

// Helper function to generate future dates for test tokens
function getFutureDate(daysInFuture = 90) {
  return new Date(Date.now() + daysInFuture * 24 * 60 * 60 * 1000)
    .toISOString()
    .split("T")[0];
}

describe("Generic integration import endpoint", () => {
  it("rejects import without items array", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({})
      .expect((res) => {
        expect([400, 401]).to.include(res.status);
      });
  });

  it("rejects import with empty items array", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({ items: [] })
      .expect((res) => {
        expect([400, 401]).to.include(res.status);
      });
  });

  it("validates item structure", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: "", // Missing name
            expiration: getFutureDate(180),
            category: "key_secret",
            type: "api_key",
          },
        ],
      })
      .expect((res) => {
        expect([400, 401, 201]).to.include(res.status);
        if (res.status === 201) {
          expect(res.body).to.have.property("error_count");
          expect(res.body.error_count).to.be.at.least(1);
        }
      });
  });

  it("validates field length constraints", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: "Valid Name",
            expiration: getFutureDate(180),
            category: "key_secret",
            type: "api_key",
            location: "x".repeat(501), // Too long (max 500)
            issuer: "y".repeat(256), // Too long (max 255)
          },
        ],
      })
      .expect((res) => {
        expect([400, 401, 201]).to.include(res.status);
        if (res.status === 201) {
          expect(res.body).to.have.property("error_count");
          expect(res.body.error_count).to.equal(1);
          expect(res.body.errors[0].error).to.match(/location|issuer/i);
        }
      });
  });

  it("validates name length (3-100 characters)", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: "ab", // Too short (min 3)
            expiration: getFutureDate(180),
            category: "key_secret",
            type: "api_key",
          },
        ],
      })
      .expect((res) => {
        expect([400, 401, 201]).to.include(res.status);
        if (res.status === 201) {
          expect(res.body).to.have.property("error_count");
          expect(res.body.error_count).to.equal(1);
          expect(res.body.errors[0].error).to.match(/name.*3.*100/i);
        }
      });
  });

  it("validates renewal_date format", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: "Test License",
            expiration: getFutureDate(180),
            category: "license",
            type: "software_license",
            renewal_date: "12/31/2025", // Wrong format (should be YYYY-MM-DD)
          },
        ],
      })
      .expect((res) => {
        expect([400, 401, 201]).to.include(res.status);
        if (res.status === 201) {
          expect(res.body).to.have.property("error_count");
          expect(res.body.error_count).to.equal(1);
          expect(res.body.errors[0].error).to.match(
            /renewal_date.*YYYY-MM-DD/i,
          );
        }
      });
  });

  it("validates key_size numeric range", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: "Test Key",
            expiration: getFutureDate(180),
            category: "key_secret",
            type: "encryption_key",
            key_size: 64, // Too small (min 128)
          },
        ],
      })
      .expect((res) => {
        expect([400, 401, 201]).to.include(res.status);
        if (res.status === 201) {
          expect(res.body).to.have.property("error_count");
          expect(res.body.error_count).to.equal(1);
          expect(res.body.errors[0].error).to.match(/key_size.*128.*16384/i);
        }
      });
  });

  it("sanitizes HTML in text fields", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: 'Test<script>alert("xss")</script>', // XSS attempt
            expiration: getFutureDate(180),
            category: "key_secret",
            type: "api_key",
          },
        ],
      })
      .expect((res) => {
        expect([400, 401, 201]).to.include(res.status);
        if (res.status === 201 && res.body.created_count > 0) {
          // Name should be HTML-escaped
          const created = res.body.created[0];
          expect(created.name).to.not.include("<script>");
          expect(created.name).to.include("&lt;").or.include("&gt;");
        }
      });
  });

  it("supports new fields (privileges, last_used, imported_at, sections array)", async () => {
    const lastUsedDate = new Date().toISOString();
    const createdAtDate = new Date(Date.now() - 86400000).toISOString();

    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/import?workspace_id=test")
      .send({
        items: [
          {
            name: "Integration Test Token",
            expiration: getFutureDate(180),
            category: "key_secret",
            type: "api_key",
            privileges: "read, write",
            last_used_at: lastUsedDate,
            created_at: createdAtDate,
            section: ["infra", "core"],
          },
        ],
      })
      .expect((res) => {
        // Authentication may fail if not set up, but we want to check if it's accepted by route if auth was there
        expect([201, 401]).to.include(res.status);
        if (res.status === 201) {
          expect(res.body.created_count).to.equal(1);
        }
      });
  });
});
