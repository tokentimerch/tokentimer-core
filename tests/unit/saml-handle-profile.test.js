"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");

const entraPath = require.resolve("../../apps/api/sso/entra-identity-normalize");
const samlPath = require.resolve("../../apps/api/auth/saml");

function clearModuleCache() {
  for (const key of Object.keys(require.cache)) {
    if (
      key === samlPath ||
      key === entraPath ||
      key === samlPath
    ) {
      delete require.cache[key];
    }
  }
}

function makeSamlLoginPool(seedUsers = []) {
  const users = [...seedUsers];
  const links = [];
  let nextUserId = 1;
  let nextLinkId = 1;
  let insertedDisplayName = null;
  let hasMembership = false;

  const matchRegex = (sql, regex) => regex.test(sql.replace(/\s+/g, " "));

  const handle = async (sql, params = []) => {
    const flat = sql.replace(/\s+/g, " ").trim();

    if (/^BEGIN$/i.test(flat)) return { rows: [], rowCount: 0 };
    if (/^COMMIT$/i.test(flat)) return { rows: [], rowCount: 0 };
    if (/^ROLLBACK$/i.test(flat)) return { rows: [], rowCount: 0 };

    if (/^SELECT 1 FROM sso_providers WHERE slug = \$1 AND enabled FOR SHARE/i.test(flat)) {
      return { rows: [{ "?column?": 1 }] };
    }
    if (/^SELECT type, config FROM sso_providers WHERE slug = \$1 AND enabled FOR SHARE/i.test(flat)) {
      return { rows: [{ type: "saml" }], rowCount: 1 };
    }
    if (/^UPDATE users SET auth_method/i.test(flat)) {
      const user = users.find((entry) => entry.id === params[0]);
      if (!user || (user.auth_method === "local" && flat.includes("AND auth_method <> 'local'"))) {
        return { rows: [], rowCount: 0 };
      }
      user.auth_method = "sso";
      user.email_verified = true;
      return { rows: [], rowCount: 1 };
    }
    if (/^UPDATE users SET recipient_verified_email/i.test(flat)) {
      const user = users.find((u) => u.id === params[0]);
      if (user) {
        user.recipient_verified_email = params[2] === true &&
          user.email_original.trim().toLowerCase() === params[1].trim().toLowerCase()
          ? params[1].trim().toLowerCase() : null;
      }
      return { rows: [], rowCount: user ? 1 : 0 };
    }

    if (
      matchRegex(
        flat,
        /FROM external_identities ei JOIN users u ON u\.id = ei\.user_id WHERE ei\.provider_slug = \$1 AND ei\.subject_id = \$2/i,
      )
    ) {
      const link = links.find((l) => l.provider_slug === params[0] && l.subject_id === params[1]);
      const user = link && users.find((u) => u.id === link.user_id);
      return user
        ? { rows: [{ ...user, link_id: link.id, auth_method_before: user.auth_method }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    }

    if (
      matchRegex(
        flat,
        /^SELECT \* FROM users WHERE LOWER\(email\) = LOWER\(\$1\) LIMIT 1/i,
      )
    ) {
      const user = users.find((u) => u.email.toLowerCase() === params[0].toLowerCase());
      return user ? { rows: [{ ...user }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    if (
      matchRegex(
        flat,
        /^SELECT subject_id FROM external_identities WHERE user_id = \$1 AND provider_slug = \$2 LIMIT 1/i,
      )
    ) {
      return { rows: [], rowCount: 0 };
    }

    if (
      matchRegex(
        flat,
        /^INSERT INTO users \(email, email_original, display_name, auth_method, email_verified, password_hash, is_admin\) VALUES/i,
      )
    ) {
      const [email, , displayName] = params;
      insertedDisplayName = displayName;
      const row = {
        id: nextUserId++,
        email,
        email_original: params[1],
        display_name: displayName,
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      };
      users.push(row);
      return { rowCount: 1, rows: [row] };
    }

    if (
      matchRegex(
        flat,
        /^INSERT INTO external_identities \(user_id, provider_slug, protocol, subject_id, email_at_link, display_name_at_link, last_seen_at\) VALUES/i,
      )
    ) {
      const [userId, providerSlug, protocol, subjectId, emailAtLink, displayAtLink] =
        params;
      links.push({
        id: nextLinkId++,
        user_id: userId,
        provider_slug: providerSlug,
        protocol,
        subject_id: subjectId,
        email_at_link: emailAtLink,
        display_name_at_link: displayAtLink,
      });
      return { rowCount: 1, rows: [{ user_id: userId }] };
    }

    if (/^SELECT 1 FROM workspace_memberships WHERE user_id/i.test(flat)) {
      return hasMembership ? { rowCount: 1, rows: [{}] } : { rowCount: 0, rows: [] };
    }
    if (matchRegex(flat, /^SELECT \* FROM users WHERE id = \$1/i)) {
      const [userId] = params;
      const user = users.find((u) => u.id === userId);
      return user ? { rowCount: 1, rows: [user] } : { rows: [], rowCount: 0 };
    }

    return { rows: [], rowCount: 0 };
  };

  const client = {
    query: handle,
    release: () => {},
  };

  return {
    connect: async () => client,
    query: handle,
    getInsertedDisplayName: () => insertedDisplayName,
    getUsers: () => users,
    grantWorkspaceMembership: () => { hasMembership = true; },
  };
}

function setupSamlRuntime(pool, samlProvider, securityConfig = {}, provisioning = null) {
  samlProvider._resetSamlRuntimeForTests();
  samlProvider._setSamlRuntimeForTests("azure-ad", {
    providerSlug: "azure-ad",
    enabled: true,
    claimConfig: {
      saml: {
        email: "email",
        displayName: "displayName",
        groups: "groups",
        subject: "nameID",
      },
    },
    securityConfig: {
      allowAutoLinkLocalAccounts: false,
      strictMembershipSync: false,
      ...securityConfig,
    },
    bootstrapAdminGroups: [],
    pool,
    deps: {
      canonicalizeEmail: (email) => String(email || "").trim().toLowerCase(),
      logger: { warn: () => {} },
      ensureInitialWorkspaceForUser: provisioning,
    },
  });
}

async function loginViaSamlProfile(samlProvider, profile, slug = "azure-ad") {
  const req = { params: { provider: slug }, session: {} };
  return new Promise((resolve, reject) => {
    samlProvider.handleSamlProfile(req, profile, (err, user) => {
      if (err) reject(err);
      else resolve(user);
    });
  });
}

describe("handleSamlProfile displayName fallback", () => {
  afterEach(() => {
    clearModuleCache();
  });

  it("records failures for disabled numeric provider slugs in audit metadata", async () => {
    const slug = "2147483648";
    const events = [];
    const samlProvider = require(samlPath);
    await samlProvider.setupSamlStrategy({}, makeSamlLoginPool(), null, {
      writeAudit: async (event) => events.push(event),
      logger: { info() {}, warn() {}, error() {} },
    });

    await assert.rejects(loginViaSamlProfile(samlProvider, {}, slug), /provider_disabled/);
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].action, "LOGIN_FAILED");
    assert.strictEqual(events[0].targetId, null);
    assert.deepStrictEqual(events[0].metadata, {
      method: "saml", provider_slug: slug, reason: "provider_disabled",
    });
  });

  it("completes login when SAML sends email but no display name claim", async () => {
    const pool = makeSamlLoginPool();
    const samlProvider = require(samlPath);
    setupSamlRuntime(pool, samlProvider);

    const result = await loginViaSamlProfile(samlProvider, {
      email: "alice@example.com",
      nameID: "subject-1",
    });

    assert.strictEqual(result.email, "alice@example.com");
    assert.strictEqual(pool.getInsertedDisplayName(), "alice");
    assert.strictEqual(result.display_name, "alice");
  });

  it("does not hit emailForLogin temporal dead zone when normalized displayName is empty", async () => {
    clearModuleCache();
    const entra = require(entraPath);
    const savedNormalize = entra.normalizeEntraIdentityClaims;
    entra.normalizeEntraIdentityClaims = () => ({
      email: "alice@example.com",
      displayName: "",
    });

    try {
      const pool = makeSamlLoginPool();
      const samlProvider = require(samlPath);
      setupSamlRuntime(pool, samlProvider);

      const result = await loginViaSamlProfile(samlProvider, {
        email: "alice@example.com",
        nameID: "subject-2",
      });

      assert.strictEqual(result.email, "alice@example.com");
      assert.strictEqual(pool.getInsertedDisplayName(), "alice");
    } finally {
      entra.normalizeEntraIdentityClaims = savedNormalize;
      clearModuleCache();
    }
  });
});

describe("handleSamlProfile recipient mailbox proof", () => {
  afterEach(() => {
    require(samlPath)._resetSamlRuntimeForTests();
    clearModuleCache();
  });

  for (const claim of [undefined, false, "false", true, "true", "TRUE", 1, "1"]) {
    it(`persists only explicit true proof for email_verified=${String(claim)}`, async () => {
      const pool = makeSamlLoginPool();
      const samlProvider = require(samlPath);
      setupSamlRuntime(pool, samlProvider);
      const profile = { email: "alice@example.com", nameID: "subject-proof" };
      await loginViaSamlProfile(samlProvider, { ...profile, email_verified: true });
      assert.strictEqual(pool.getUsers()[0].recipient_verified_email, profile.email);

      const user = await loginViaSamlProfile(samlProvider, {
        ...profile,
        ...(claim === undefined ? {} : { email_verified: claim }),
      });
      assert.strictEqual(user.id, pool.getUsers()[0].id);
      assert.strictEqual(pool.getUsers().length, 1);
      assert.strictEqual(pool.getUsers()[0].recipient_verified_email,
        claim === true || claim === "true" ? profile.email : null);
    });
  }

  for (const claim of [undefined, false, true]) {
    it(`preserves local account auto-link policy with email_verified=${String(claim)}`, async () => {
      const samlProvider = require(samlPath);
      const localUser = {
        id: 42, email: "alice@example.com", email_original: "alice@example.com",
        display_name: "Alice", auth_method: "local", email_verified: true,
      };
      const profile = { email: localUser.email, nameID: "subject-local",
        ...(claim === undefined ? {} : { email_verified: claim }) };
      const deniedPool = makeSamlLoginPool([{ ...localUser }]);
      setupSamlRuntime(deniedPool, samlProvider);
      await assert.rejects(loginViaSamlProfile(samlProvider, profile), /Enable allow auto-link/);

      const provisioned = [];
      const pool = makeSamlLoginPool([{ ...localUser }]);
      setupSamlRuntime(pool, samlProvider, { allowAutoLinkLocalAccounts: true },
        (...args) => provisioned.push(args));
      const user = await loginViaSamlProfile(samlProvider, profile);
      assert.strictEqual(user.id, localUser.id);
      assert.strictEqual(pool.getUsers().length, 1);
      assert.strictEqual(user.auth_method, "local");
      assert.strictEqual((await loginViaSamlProfile(samlProvider, profile)).auth_method, "local");
      const verifiedEmail = claim === true ? localUser.email : null;
      assert.strictEqual(pool.getUsers()[0].recipient_verified_email, verifiedEmail);
      assert.deepStrictEqual(provisioned.map((args) => args[3]), [
        { sso: true, verifiedEmail },
        { sso: true, verifiedEmail },
      ]);
    });
  }

  it("does not transfer a guest UPN verification to its reconstructed mailbox", async () => {
    const pool = makeSamlLoginPool();
    const samlProvider = require(samlPath);
    setupSamlRuntime(pool, samlProvider);
    const user = await loginViaSamlProfile(samlProvider, {
      email: "alice_example.com#EXT#@tenant.onmicrosoft.com",
      nameID: "subject-guest", email_verified: true,
    });
    assert.strictEqual(user.email, "alice@example.com");
    assert.strictEqual(pool.getUsers()[0].recipient_verified_email, null);
  });

  it("requires explicit trust before relinking an orphan with only its signed email", async () => {
    const orphan = {
      id: 42, email: "member@example.test", email_original: "member@example.test",
      display_name: "Member", auth_method: "sso", email_verified: true,
    };
    const pool = makeSamlLoginPool([orphan]);
    const samlProvider = require(samlPath);
    const profile = { email: orphan.email, nameID: "member-subject" };
    setupSamlRuntime(pool, samlProvider);
    await assert.rejects(loginViaSamlProfile(samlProvider, profile), /requires a verified email/);
    setupSamlRuntime(pool, samlProvider, { allowAutoLinkLocalAccounts: true });
    const user = await loginViaSamlProfile(samlProvider, profile);
    assert.strictEqual(user.id, orphan.id);
    assert.strictEqual(orphan.recipient_verified_email, null);
  });

  for (const verifiedEmail of [false, true]) {
    it(`strict SAML admission can redeem only an invitation for a verified mailbox (proof=${verifiedEmail})`, async () => {
      const pool = makeSamlLoginPool();
      const samlProvider = require(samlPath);
      const profile = { email: "sso-member@example.test", nameID: "invited-subject", email_verified: verifiedEmail };
      const provisioned = [];
      setupSamlRuntime(pool, samlProvider, { strictMembershipSync: true },
        async (_id, _email, _displayName, options) => {
          provisioned.push(options);
          if (options.invitationsOnly && options.verifiedEmail === profile.email) {
            pool.grantWorkspaceMembership();
          }
        });
      if (verifiedEmail) {
        const user = await loginViaSamlProfile(samlProvider, profile);
        assert.strictEqual(user.email, profile.email);
        assert.deepStrictEqual(provisioned, [
          { sso: true, verifiedEmail: profile.email, invitationsOnly: true },
          { sso: true, verifiedEmail: profile.email },
        ]);
      } else {
        await assert.rejects(loginViaSamlProfile(samlProvider, profile), /strict membership sync/);
        assert.deepStrictEqual(provisioned, []);
      }
    });
  }
});
