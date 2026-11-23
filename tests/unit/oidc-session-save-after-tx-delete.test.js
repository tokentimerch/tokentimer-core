"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const oidcProvider = require("../../apps/api/auth/oidc");

describe("oidc session save after tx delete", () => {
  it("deleteOidcTxAndSave removes tx then calls session.save before caller continues", async () => {
    const order = [];
    const req = {
      session: {
        oidcAuth: {
          "state-1": { providerSlug: "azure-ad", state: "state-1" },
        },
        save(cb) {
          order.push("save");
          cb();
        },
      },
    };

    await oidcProvider._deleteOidcTxAndSave(req, "state-1");
    order.push("after-save");

    assert.deepStrictEqual(order, ["save", "after-save"]);
    assert.strictEqual(req.session.oidcAuth, undefined);
  });

  it("failRedirect pattern saves before redirect (simulated)", async () => {
    const order = [];
    const req = {
      session: {
        oidcAuth: { st: { providerSlug: "a" } },
        save(cb) {
          order.push("save");
          cb();
        },
      },
    };
    const redirect = () => order.push("redirect");

    await oidcProvider._deleteOidcTxAndSave(req, "st");
    redirect();

    assert.deepStrictEqual(order, ["save", "redirect"]);
  });
});
