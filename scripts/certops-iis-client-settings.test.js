"use strict";
// These are adversarial report controls, not native execution evidence.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const helper = require("../packages/agent/scripts/host/iis-client-settings-fixture");
function fixture() { return { scope: helper.SCOPE, clientAuthHandshakeQualified: false, cases: helper.CASES.map(item => ({ id: item.id, checkMode: item.checkMode, freshness: item.freshness, retrievalTimeout: item.retrievalTimeout, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) })) }; }
test("both native HTTP.sys policy profiles and every independent outcome are mandatory", () => {
  assert.equal(helper.verifyProof(fixture()), true);
  for (let index = 0; index < 2; index++) {
    for (const flag of helper.FLAGS) {
      for (const wrong of [false, 1, null, "true"]) { const value = fixture(); value.cases[index][flag] = wrong; assert.throws(() => helper.verifyProof(value)); }
      const value = fixture(); delete value.cases[index][flag]; assert.throws(() => helper.verifyProof(value));
    }
    for (const key of ["id", "checkMode", "freshness", "retrievalTimeout"]) { const value = fixture(); value.cases[index][key] = "incorrect"; assert.throws(() => helper.verifyProof(value)); }
  }
});
test("policy preservation cannot promote client-auth or fabricated/default timer scope", () => {
  for (const change of [{ scope: "client-auth-handshake" }, { clientAuthHandshakeQualified: true }, { privateKey: "forbidden" }, { cases: fixture().cases.slice(0, 1) }, { cases: [fixture().cases[0], fixture().cases[0]] }]) assert.throws(() => helper.verifyProof({ ...fixture(), ...change }));
  for (const key of ["checkMode", "freshness", "retrievalTimeout"]) for (const wrong of [0, -1, 0x100000000, true, null]) { const value = fixture(); value.cases[0][key] = wrong; assert.throws(() => helper.verifyProof(value)); }
});
