import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import request from "supertest";

const api = createRequire(new URL("../../apps/api/package.json", import.meta.url));
const { pool } = api("./db/database");
const { setProviderRuntimeStatus, removeProviderRuntimeStatus } = api("./sso/sso-runtime-status");
const { isContactGroupPluralWritesEnabled } = api("./src/shared/contactGroupPluralWrites");
const app = api("express")();
app.use(api("./routes/health"));

describe("Runtime extension auth feature defaults", () => {
  it("advertises neither SSO protocol on an unconfigured installation", async (t) => {
    t.mock.method(pool, "query", async () => ({ rows: [] }));
    const { body } = await request(app).get("/api/auth/features")
      .expect("Cache-Control", "no-store").expect(200);
    assert.deepEqual(body.providers, { oidc: [], saml: [] });
    assert.equal(body.oidc, false);
    assert.equal(body.saml, false);
    assert.equal(body.contactGroupPluralWrites, isContactGroupPluralWritesEnabled());
  });

  for (const type of ["oidc", "saml"]) {
    it(`advertises ${type} only after the selected provider is ready`, async (t) => {
      const row = { id: 1, type, slug: "example", enabled: true, display_name: "Example", config: {} };
      t.mock.method(pool, "query", async (sql) => ({
        rows: /FROM sso_providers\b/.test(sql) ? [row] : [],
      }));
      t.after(() => removeProviderRuntimeStatus(row.slug));
      for (const signInReady of [false, true]) {
        setProviderRuntimeStatus(row.slug, { registered: signInReady, signInReady });
        const { body } = await request(app).get("/api/auth/features").expect(200);
        assert.equal(body[type], signInReady);
        assert.equal(body[type === "oidc" ? "saml" : "oidc"], false);
        assert.equal(body.providers[type][0].slug, row.slug);
        assert.equal(body.providers[type][0].signInReady, signInReady);
      }
    });
  }
});
