"use strict";

// Credential families must never be interchangeable (ADR-0015 section 2).
// Executor API tokens, agent bootstrap tokens, agent runtime credentials and
// operator connection credentials each have their own prefix and their own
// routes. None of these checks needs a database: a credential of the wrong
// family is refused before any lookup.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const primitives = require(
  path.resolve(__dirname, "../../apps/api/services/credentials/primitives.js"),
);
const apiTokens = require(
  path.resolve(__dirname, "../../apps/api/services/certops/apiTokens.js"),
);
const agentCredentials = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentCredentials.js"),
);
const connections = require(
  path.resolve(__dirname, "../../apps/api/services/operator/connections.js"),
);

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const ID = "0123456789abcdef";
const SECRET = "a".repeat(64);

const RAW = {
  executor: `ttx_${ID}_${SECRET}`,
  bootstrap: `ttboot_${ID}_${SECRET}`,
  agent: `ttagent_${ID}_${SECRET}`,
  operator: `ttopc_${ID}_${SECRET}`,
};

describe("credential primitives", () => {
  it("hashes deterministically and compares in constant time", () => {
    const hash = primitives.sha256Hex("value");
    assert.match(hash, /^[a-f0-9]{64}$/);
    assert.equal(primitives.sha256Hex("value"), hash);
    assert.equal(primitives.safeCompareSha256Hex(hash, hash), true);
    assert.equal(primitives.safeCompareSha256Hex(hash, primitives.sha256Hex("other")), false);
  });

  it("refuses malformed hashes on either side without throwing", () => {
    const hash = primitives.sha256Hex("value");
    assert.equal(primitives.safeCompareSha256Hex("not-a-hash", hash), false);
    assert.equal(primitives.safeCompareSha256Hex(hash, "not-a-hash"), false);
    assert.equal(primitives.safeCompareSha256Hex(hash, undefined), false);
    assert.equal(primitives.safeCompareSha256Hex("", ""), false);
  });

  it("generates credentials that parse back to their own lookup prefix", () => {
    const family = primitives.defineCredentialFamily({ prefix: "ttxx_" });
    const raw = family.generate();
    assert.equal(raw.length, family.rawLength);
    const parsed = family.parse(raw);
    assert.equal(parsed.lookupPrefix, `ttxx_${parsed.idHex}`);
    assert.notEqual(family.generate(), raw);
  });

  it("rejects wrong length, case, charset and non-strings when parsing", () => {
    const family = connections.CONNECTION_CREDENTIAL;
    assert.ok(family.parse(RAW.operator));
    assert.equal(family.parse(`${RAW.operator}0`), null);
    assert.equal(family.parse(RAW.operator.toUpperCase()), null);
    assert.equal(family.parse(`ttopc_${"g".repeat(16)}_${SECRET}`), null);
    assert.equal(family.parse(undefined), null);
    assert.equal(family.parse(42), null);
    assert.equal(family.parse(` ${RAW.operator}`), null);
  });

  it("refuses prefixes that are not a lowercase word ending in an underscore", () => {
    for (const prefix of ["", "TT_", "tt", "tt-", "tt_x_"]) {
      assert.throws(() => primitives.defineCredentialFamily({ prefix }), /prefix/i, prefix);
    }
  });

  it("detects an embedded credential anywhere in free text", () => {
    const family = connections.CONNECTION_CREDENTIAL;
    assert.equal(family.containsEmbedded(`note ${RAW.operator} end`), true);
    assert.equal(family.containsEmbedded(RAW.operator.toUpperCase()), true);
    assert.equal(family.containsEmbedded("ordinary name"), false);
    assert.equal(family.containsEmbedded(null), false);
  });
});

describe("credential families are not interchangeable", () => {
  it("uses four distinct prefixes", () => {
    const prefixes = [
      apiTokens.TOKEN_PREFIX,
      "ttboot_",
      "ttagent_",
      connections.CONNECTION_CREDENTIAL.prefix,
    ];
    assert.equal(new Set(prefixes).size, prefixes.length);
    for (const a of prefixes) {
      for (const b of prefixes) {
        if (a !== b) assert.ok(!a.startsWith(b), `${a} must not start with ${b}`);
      }
    }
  });

  it("operator parsing accepts only the operator family", () => {
    const parse = connections.CONNECTION_CREDENTIAL.parse;
    assert.ok(parse(RAW.operator));
    for (const family of ["executor", "bootstrap", "agent"]) {
      assert.equal(parse(RAW[family]), null, `${family} credential must not parse as operator`);
    }
  });

  it("the executor token validator refuses an operator credential before any lookup", async () => {
    const outcome = await apiTokens.validateApiToken({
      client: {
        query() {
          throw new Error("database must not be consulted");
        },
      },
      rawToken: RAW.operator,
      workspaceId: WORKSPACE,
      requiredScopes: ["certops:read"],
    });
    assert.equal(outcome.valid, false);
    assert.equal(outcome.code, apiTokens.CERTOPS_API_TOKEN_MALFORMED);
  });

  it("the agent validators refuse an operator credential before any lookup", async () => {
    const explode = {
      query() {
        throw new Error("database must not be consulted");
      },
    };
    const bootstrap = await agentCredentials.validateBootstrapToken({
      client: explode,
      rawToken: RAW.operator,
      workspaceId: WORKSPACE,
    });
    assert.equal(bootstrap.valid, false);

    const runtime = await agentCredentials.validateAgentCredential({
      client: explode,
      rawCredential: RAW.operator,
      workspaceId: WORKSPACE,
    });
    assert.equal(runtime.valid, false);
  });

  it("controls: each validator does reach the database for its own family", async () => {
    const reached = [];
    const spy = {
      async query() {
        reached.push(true);
        return { rows: [] };
      },
    };
    await apiTokens.validateApiToken({
      client: spy,
      rawToken: RAW.executor,
      workspaceId: WORKSPACE,
      requiredScopes: ["certops:read"],
    });
    await agentCredentials.validateBootstrapToken({
      client: spy,
      rawToken: RAW.bootstrap,
      workspaceId: WORKSPACE,
    });
    await agentCredentials.validateAgentCredential({
      client: spy,
      rawCredential: RAW.agent,
      workspaceId: WORKSPACE,
    });
    await connections.authenticateCredential({ client: spy, rawCredential: RAW.operator });
    assert.equal(
      reached.length,
      4,
      "every validator must consult the database for a credential of its own family",
    );
  });

  it("the operator authenticator refuses every other family before any lookup", async () => {
    const explode = {
      query() {
        throw new Error("database must not be consulted");
      },
    };
    for (const family of ["executor", "bootstrap", "agent"]) {
      const outcome = await connections.authenticateCredential({
        client: explode,
        rawCredential: RAW[family],
      });
      assert.equal(outcome.valid, false, `${family} credential must not authenticate as operator`);
    }
    for (const bad of [undefined, null, "", "Bearer x", 7]) {
      const outcome = await connections.authenticateCredential({ client: explode, rawCredential: bad });
      assert.equal(outcome.valid, false);
    }
  });
});
