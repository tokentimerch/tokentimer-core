"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");

const {
  buildAuthorizationRequest,
  buildEndSessionUrl,
  createOidcClient,
  exchangeAuthorizationCode,
  validateUserinfoSubject,
  buildPassportStyleProfiles,
  resolveIdpHttpTimeoutMs,
  createOpenIdHttpOptionsProvider,
} = require("../../apps/api/auth/oidc-flow.js");

function makeMockClient() {
  const authParamsCaptured = [];
  const callbackChecks = [];
  const client = {
    authorizationUrl: (params) => {
      authParamsCaptured.push(params);
      return "https://idp.test/authorize?ok=1";
    },
    callback: async (_redirectUri, _params, checks) => {
      callbackChecks.push(checks);
      return {
        claims: () => ({
          sub: "id-token-sub",
          email: "user@example.com",
          email_verified: true,
        }),
        access_token: "access-1",
      };
    },
    userinfo: async () => ({
      sub: "id-token-sub",
      email: "user@example.com",
    }),
  };
  return { client, authParamsCaptured, callbackChecks };
}

function makeMockOpenIdClientModule() {
  class Client {
    authorizationUrl() {
      return "https://idp.test/auth";
    }
    callback() {
      return { claims: () => ({ sub: "sub-1" }) };
    }
  }
  class Issuer {
    constructor(metadata) {
      this.metadata = metadata;
    }
  }
  Issuer.prototype.Client = Client;
  return {
    Issuer,
    custom: { clock_tolerance: Symbol("clock_tolerance") },
    generators: {
      state: () => "state-fixed",
      nonce: () => "nonce-fixed",
      codeVerifier: () => "verifier-fixed",
      codeChallenge: (v) => `challenge-for-${v}`,
    },
  };
}

const strategyConfig = {
  issuer: "https://idp.test",
  clientID: "client-1",
  clientSecret: "secret",
  callbackURL: "http://localhost:4000/auth/oidc/test-oidc/callback",
  authorizationURL: "https://idp.test/authorize",
  tokenURL: "https://idp.test/token",
  userInfoURL: "https://idp.test/userinfo",
  scope: ["openid", "profile", "email"],
  acceptedClockSkewMs: 0,
};

describe("resolveIdpHttpTimeoutMs", () => {
  const envBackup = { ...process.env };

  afterEach(() => {
    process.env = { ...envBackup };
  });

  it("defaults to 20 seconds", () => {
    delete process.env.SSO_IDP_HTTP_TIMEOUT_MS;
    assert.strictEqual(resolveIdpHttpTimeoutMs(), 20_000);
  });

  it("honours SSO_IDP_HTTP_TIMEOUT_MS within bounds", () => {
    process.env.SSO_IDP_HTTP_TIMEOUT_MS = "45000";
    assert.strictEqual(resolveIdpHttpTimeoutMs(), 45_000);
    process.env.SSO_IDP_HTTP_TIMEOUT_MS = "1000";
    assert.strictEqual(resolveIdpHttpTimeoutMs(), 5_000);
  });

  it("createOpenIdHttpOptionsProvider exposes only openid-client allowed options", () => {
    const provider = createOpenIdHttpOptionsProvider(20_000);
    const opts = provider(new URL("https://auth.example.com/token"));
    assert.strictEqual(opts.timeout, 20_000);
    assert.strictEqual(opts.lookup, undefined);
    assert.strictEqual(opts.servername, undefined);
  });

  it("applies the shared outbound policy to each OIDC request", () => {
    process.env.OUTBOUND_ALLOWLIST = "allowed-idp.example";
    process.env.NO_PROXY = "allowed-idp.example";
    process.env.no_proxy = process.env.NO_PROXY;
    const options = createOpenIdHttpOptionsProvider(20_000);
    assert.throws(() => options(new URL("https://blocked-idp.example/token")),
      { code: "OUTBOUND_POLICY_DENIED" });
    assert.deepStrictEqual(options(new URL("https://allowed-idp.example/token")),
      { timeout: 20_000 });
  });
});

describe("OIDC flow (openid-client)", () => {
  describe("buildAuthorizationRequest", () => {
    it("includes code_challenge and code_challenge_method=S256 when PKCE is enabled", () => {
      const { client, authParamsCaptured } = makeMockClient();
      const openIdClient = makeMockOpenIdClientModule();
      const auth = buildAuthorizationRequest(strategyConfig, client, openIdClient, {
        pkceEnabled: true,
      });
      assert.strictEqual(auth.codeVerifier, "verifier-fixed");
      assert.ok(authParamsCaptured[0].code_challenge);
      assert.strictEqual(
        authParamsCaptured[0].code_challenge_method,
        "S256",
      );
      assert.match(
        authParamsCaptured[0].code_challenge,
        /^challenge-for-verifier-fixed$/,
      );
    });

    it("omits PKCE parameters when PKCE is disabled", () => {
      const { client, authParamsCaptured } = makeMockClient();
      const openIdClient = makeMockOpenIdClientModule();
      buildAuthorizationRequest(strategyConfig, client, openIdClient, {
        pkceEnabled: false,
      });
      assert.strictEqual(authParamsCaptured[0].code_challenge, undefined);
      assert.strictEqual(
        authParamsCaptured[0].code_challenge_method,
        undefined,
      );
    });
  });

  describe("exchangeAuthorizationCode", () => {
    it("passes code_verifier to the token exchange when PKCE is enabled", async () => {
      const { client, callbackChecks } = makeMockClient();
      await exchangeAuthorizationCode({
        client,
        strategyConfig,
        callbackParams: { code: "auth-code", state: "state-fixed" },
        sessionAuth: {
          state: "state-fixed",
          nonce: "nonce-fixed",
          codeVerifier: "verifier-fixed",
        },
        pkceEnabled: true,
      });
      assert.strictEqual(
        callbackChecks[0].code_verifier,
        "verifier-fixed",
      );
    });

    it("rejects when openid-client callback fails (nonce mismatch)", async () => {
      const { client } = makeMockClient();
      client.callback = async () => {
        throw new Error("nonce mismatch");
      };
      await assert.rejects(
        exchangeAuthorizationCode({
          client,
          strategyConfig,
          callbackParams: { code: "auth-code", state: "state-fixed" },
          sessionAuth: {
            state: "state-fixed",
            nonce: "nonce-fixed",
            codeVerifier: "verifier-fixed",
          },
          pkceEnabled: true,
        }),
        /nonce mismatch/,
      );
    });
  });

  describe("validateUserinfoSubject", () => {
    it("rejects UserInfo sub mismatch", () => {
      const result = validateUserinfoSubject("id-sub", { sub: "other-sub" });
      assert.strictEqual(result.trusted, false);
      assert.strictEqual(result.reason, "userinfo_sub_mismatch");
    });

    it("discards UserInfo when sub is missing", () => {
      const result = validateUserinfoSubject("id-sub", { email: "a@b.com" });
      assert.strictEqual(result.trusted, false);
      assert.strictEqual(result.reason, "userinfo_missing_sub");
    });
  });

  describe("buildPassportStyleProfiles", () => {
    it("uses ID Token sub as profile.id for auth binding", () => {
      const { profile } = buildPassportStyleProfiles(
        { sub: "id-token-sub", email: "a@b.com" },
        { sub: "id-token-sub", email: "a@b.com" },
        true,
      );
      assert.strictEqual(profile.id, "id-token-sub");
    });
  });

});

describe("OIDC flow using the installed library", () => {
  it("creates an authorization-code request with state, nonce and S256 PKCE", () => {
    const { client, openidClient } = createOidcClient(strategyConfig);
    const auth = buildAuthorizationRequest(strategyConfig, client, openidClient);
    const url = new URL(auth.authorizationUrl);

    assert.strictEqual(url.searchParams.get("response_type"), "code");
    assert.strictEqual(url.searchParams.get("state"), auth.state);
    assert.strictEqual(url.searchParams.get("nonce"), auth.nonce);
    assert.strictEqual(url.searchParams.get("code_challenge_method"), "S256");
    assert.strictEqual(
      url.searchParams.get("code_challenge"),
      openidClient.generators.codeChallenge(auth.codeVerifier),
    );
    assert.ok(auth.state && auth.nonce && auth.codeVerifier);
  });

  it("uses the ID token hint without adding a client ID at logout", () => {
    const config = { ...strategyConfig, endSessionURL: "https://idp.test/logout" };
    const url = new URL(buildEndSessionUrl(config, { idToken: "id-token" }));

    assert.strictEqual(url.searchParams.get("id_token_hint"), "id-token");
    assert.strictEqual(url.searchParams.has("client_id"), false);
  });
});
