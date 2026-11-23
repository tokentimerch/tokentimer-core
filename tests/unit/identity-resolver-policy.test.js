"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const { resolveUser } = require("../../apps/api/sso/identity-resolver");

// Database double for the resolver's lookup, link and mailbox policy.
function makeMockPool(initialUsers = []) {
  const users = [...initialUsers];
  const links = [];
  const providers = new Map();
  const issuer = "https://idp.example.test";

  const matchRegex = (sql, regex) => regex.test(sql.replace(/\s+/g, " "));

  const handle = async (sql, params) => {
    const flat = sql.replace(/\s+/g, " ").trim();

    if (/^BEGIN$/i.test(flat)) return { rows: [], rowCount: 0 };
    if (/^COMMIT$/i.test(flat)) return { rows: [], rowCount: 0 };
    if (/^ROLLBACK$/i.test(flat)) return { rows: [], rowCount: 0 };
    if (/^SELECT type, config FROM sso_providers WHERE slug = \$1 AND enabled FOR SHARE/i.test(flat)) {
      return { rows: [providers.get(params[0])], rowCount: 1 };
    }
    if (/^UPDATE users SET recipient_verified_email/i.test(flat)) {
      const user = users.find(row => row.id === params[0]);
      if (user) user.recipient_verified_email = params[2] === true
        && String(user.email_original || "").trim().toLowerCase() === String(params[1]).trim().toLowerCase()
        ? String(params[1]).trim().toLowerCase() : null;
      return { rows: [], rowCount: user ? 1 : 0 };
    }

    if (
      matchRegex(
        flat,
        /FROM external_identities ei JOIN users u ON u\.id = ei\.user_id WHERE ei\.provider_slug = \$1 AND ei\.subject_id = \$2/i,
      )
    ) {
      const [providerSlug, subjectId] = params;
      const hit = links.find(
        (l) => l.provider_slug === providerSlug && l.subject_id === subjectId,
      );
      if (!hit) return { rows: [], rowCount: 0 };
      const user = users.find((u) => u.id === hit.user_id);
      return {
        rowCount: 1,
        rows: [
          {
            link_id: hit.id,
            ...user,
            auth_method_before: user.auth_method,
          },
        ],
      };
    }

    if (
      matchRegex(
        flat,
        /^SELECT \* FROM users WHERE LOWER\(email\) = LOWER\(\$1\) LIMIT 1/i,
      )
    ) {
      const [email] = params;
      const u = users.find(
        (u) => u.email.toLowerCase() === String(email).toLowerCase(),
      );
      return u ? { rowCount: 1, rows: [u] } : { rowCount: 0, rows: [] };
    }

    if (
      matchRegex(
        flat,
        /^SELECT subject_id FROM external_identities WHERE user_id = \$1 AND provider_slug = \$2 LIMIT 1/i,
      )
    ) {
      const [userId, providerSlug] = params;
      const hit = links.find(
        (l) => l.user_id === userId && l.provider_slug === providerSlug,
      );
      return hit
        ? { rowCount: 1, rows: [{ subject_id: hit.subject_id }] }
        : { rowCount: 0, rows: [] };
    }

    if (
      matchRegex(
        flat,
        /^SELECT 1 FROM external_identities WHERE user_id = \$1 LIMIT 1/i,
      )
    ) {
      const [userId] = params;
      const hit = links.find((l) => l.user_id === userId);
      return hit ? { rowCount: 1, rows: [{}] } : { rowCount: 0, rows: [] };
    }

    if (matchRegex(flat, /^UPDATE external_identities SET last_seen_at = NOW\(\) WHERE id = \$1/i)) {
      const [id] = params;
      const link = links.find((l) => l.id === id);
      if (link) link.last_seen_at = new Date();
      return { rowCount: 1, rows: [] };
    }

    if (matchRegex(flat, /^DELETE FROM external_identities WHERE id = \$1/i)) {
      const [id] = params;
      const idx = links.findIndex((l) => l.id === id);
      if (idx >= 0) links.splice(idx, 1);
      return { rowCount: 1, rows: [] };
    }

    if (
      matchRegex(
        flat,
        /^INSERT INTO external_identities \(user_id, provider_slug, protocol, subject_id, email_at_link, display_name_at_link, last_seen_at\) VALUES/i,
      )
    ) {
      const [userId, providerSlug, protocol, subjectId, emailAtLink, displayAtLink] =
        params;
      const existing = links.find(
        (l) =>
          l.provider_slug === providerSlug && l.subject_id === subjectId,
      );
      if (existing) {
        if (existing.user_id !== userId) return { rowCount: 0, rows: [] };
        existing.last_seen_at = new Date();
        return { rowCount: 1, rows: [{ user_id: userId }] };
      }
      links.push({
        id: `link-${links.length + 1}`,
        user_id: userId,
        provider_slug: providerSlug,
        protocol,
        subject_id: subjectId,
        email_at_link: emailAtLink,
        display_name_at_link: displayAtLink,
        last_seen_at: new Date(),
      });
      return { rowCount: 1, rows: [{ user_id: userId }] };
    }

    if (
      matchRegex(
        flat,
        /^UPDATE external_identities SET last_seen_at = NOW\(\) WHERE user_id = \$1/i,
      )
    ) {
      const [userId] = params;
      links
        .filter((l) => l.user_id === userId)
        .forEach((l) => (l.last_seen_at = new Date()));
      return { rowCount: 1, rows: [] };
    }

    if (
      matchRegex(
        flat,
        /^INSERT INTO users \(email, email_original, display_name, auth_method, email_verified, password_hash, is_admin\) VALUES \(\$1, \$2, \$3, 'sso', TRUE, 'SSO_NO_PASSWORD', FALSE\) RETURNING \*/i,
      )
    ) {
      const [email, emailOriginal, displayName] = params;
      const row = {
        id: `user-${users.length + 1}`,
        email,
        email_original: emailOriginal,
        display_name: displayName,
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      };
      users.push(row);
      return { rowCount: 1, rows: [row] };
    }

    throw new Error(`makeMockPool: unexpected SQL: ${flat}`);
  };

  const pendingLocks = new Map();
  function connect() {
    const unlock = [];
    return {
      async query(sql, params = []) {
        if (sql.includes("pg_advisory_xact_lock")) {
          const key = JSON.stringify(params);
          const previous = pendingLocks.get(key);
          let release;
          const pending = new Promise((resolve) => { release = resolve; });
          pendingLocks.set(key, pending);
          await previous;
          unlock.push(() => {
            if (pendingLocks.get(key) === pending) pendingLocks.delete(key);
            release();
          });
          return { rows: [], rowCount: 1 };
        }
        const result = await handle(sql, params);
        if (sql === "COMMIT" || sql === "ROLLBACK") {
          for (const release of unlock.splice(0)) release();
        }
        return result;
      },
      release: () => {},
    };
  }

  return {
    connect,
    _providers: providers,
    _issuer: issuer,
    _users: () => users,
    _links: () => links,
  };
}

function resolveWithProvider(args) {
  if (!args.pool._providers.has(args.providerSlug)) {
    args.pool._providers.set(args.providerSlug, {
      type: args.protocol,
      config: { issuer: args.pool._issuer },
    });
  }
  return resolveUser({ issuer: args.pool._issuer, ...args });
}

describe("identity-resolver email-fallback policy", () => {
  it("refreshes exact recipient mailbox proof only from a verified provider assertion", async () => {
    const pool = makeMockPool();
    const args = {
      pool, providerSlug: "test-idp", protocol: "oidc", subjectId: "stable-subject",
      email: "Member@Example.Test", displayName: "Member", allowAutoLink: false,
      canonicalizeEmail: email => email.toLowerCase(),
    };
    await resolveWithProvider({ ...args, verifiedEmail: null });
    assert.strictEqual(pool._users()[0].recipient_verified_email, null);
    await resolveWithProvider({ ...args, verifiedEmail: args.email });
    assert.strictEqual(pool._users()[0].recipient_verified_email, "member@example.test");
    await resolveWithProvider({ ...args, verifiedEmail: "different@example.test" });
    assert.strictEqual(pool._users()[0].recipient_verified_email, null);
    await resolveWithProvider({ ...args, verifiedEmail: args.email });
    assert.strictEqual(pool._users()[0].recipient_verified_email, "member@example.test");
    await resolveWithProvider({ ...args, verifiedEmail: null });
    assert.strictEqual(pool._users()[0].recipient_verified_email, null);
    await resolveWithProvider({ ...args, email: "other@example.test", verifiedEmail: "other@example.test" });
    assert.strictEqual(pool._users()[0].recipient_verified_email, null);
  });

  it("a previously bound subject signs in without email auto-link or mailbox proof", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "alice@example.com",
        email_original: "alice@example.com",
        display_name: "Alice",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    // Pre-seed an existing link so the subject lookup hits.
    pool._links().push({
      id: "link-existing",
      user_id: "u-1",
      provider_slug: "oidc",
      subject_id: "subject-stable",
      email_at_link: "alice@example.com",
      display_name_at_link: "Alice",
      last_seen_at: new Date(0),
    });
    const r = await resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      subjectId: "subject-stable",
      email: "alice@example.com",
      displayName: "Alice",
      allowAutoLink: false,
      verifiedEmail: null,
    });
    assert.strictEqual(r.user.id, "u-1");
    assert.strictEqual(r.reason, null);
    assert.strictEqual(r.isNewUser, false);
    assert.strictEqual(r.isNewLink, false);
  });

  it("blocks email fallback to local accounts when allowAutoLink=false", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "bob@example.com",
        email_original: "bob@example.com",
        display_name: "Bob",
        auth_method: "local",
        email_verified: true,
        password_hash: "hash",
        is_admin: false,
      },
    ]);
    const r = await resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      subjectId: "new-subject",
      email: "bob@example.com",
      displayName: "Bob",
      allowAutoLink: false,
      verifiedEmail: "bob@example.com",
    });
    assert.strictEqual(r.user, null);
    assert.strictEqual(r.reason, "local_account_exists_auto_link_disabled");
  });

  it("blocks cross-provider email fallback when allowAutoLink=false", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "merge-blocked@example.com",
        email_original: "merge-blocked@example.com",
        display_name: "Multi-IdP",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    pool._links().push({
      id: "link-saml",
      user_id: "u-1",
      provider_slug: "test-saml",
      subject_id: "saml-sub-1",
      email_at_link: "merge-blocked@example.com",
      display_name_at_link: "Multi-IdP",
      last_seen_at: new Date(0),
    });
    const r = await resolveWithProvider({
      pool,
      providerSlug: "test-oidc",
      protocol: "oidc",
      subjectId: "oidc-sub-1",
      email: "merge-blocked@example.com",
      displayName: "Multi-IdP",
      allowAutoLink: false,
      verifiedEmail: "merge-blocked@example.com",
    });
    assert.strictEqual(r.user, null);
    assert.strictEqual(r.reason, "cross_provider_auto_link_disabled");
  });

  it("relinks orphaned SSO accounts when allowAutoLink=false and provider link was removed", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "carol@example.com",
        email_original: "carol@example.com",
        display_name: "Carol",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    const r = await resolveWithProvider({
      pool,
      providerSlug: "entra",
      protocol: "saml",
      subjectId: "carol-subject-after-recreate",
      email: "carol@example.com",
      displayName: "Carol",
      allowAutoLink: false,
      verifiedEmail: "carol@example.com",
    });
    assert.strictEqual(r.user.id, "u-1");
    assert.strictEqual(r.isNewLink, true);
    assert.strictEqual(r.reason, null);
  });

  it("blocks email fallback when SSO user already linked under a different subject", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "carol@example.com",
        email_original: "carol@example.com",
        display_name: "Carol",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    pool._links().push({
      id: "link-existing",
      user_id: "u-1",
      provider_slug: "oidc",
      subject_id: "carol-stable-subject",
      email_at_link: "carol@example.com",
      display_name_at_link: "Carol",
      last_seen_at: new Date(0),
    });
    const r = await resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      subjectId: "fresh-attacker-subject",
      email: "carol@example.com",
      displayName: "Carol",
      allowAutoLink: false,
      verifiedEmail: "carol@example.com",
    });
    assert.strictEqual(r.user, null);
    assert.strictEqual(r.reason, "sso_account_exists_subject_mismatch");
  });

  it("blocks email fallback when the IdP did not verify the selected mailbox", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "dan@example.com",
        email_original: "dan@example.com",
        display_name: "Dan",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    const r = await resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      subjectId: "fresh-subject",
      email: "dan@example.com",
      displayName: "Dan",
      allowAutoLink: true,
      verifiedEmail: null,
    });
    assert.strictEqual(r.user, null);
    assert.strictEqual(r.reason, "email_not_verified_for_link");
  });

  it("blocks email fallback when the existing user is already linked to a different subject on the same provider", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "eve@example.com",
        email_original: "eve@example.com",
        display_name: "Eve",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    pool._links().push({
      id: "link-1",
      user_id: "u-1",
      provider_slug: "oidc",
      subject_id: "original-subject",
      email_at_link: "eve@example.com",
      display_name_at_link: "Eve",
      last_seen_at: new Date(0),
    });
    const r = await resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      subjectId: "different-subject",
      email: "eve@example.com",
      displayName: "Eve",
      allowAutoLink: true,
      verifiedEmail: "eve@example.com",
    });
    assert.strictEqual(r.user, null);
    assert.strictEqual(r.reason, "sso_account_exists_subject_mismatch");
    // The original link must be untouched.
    const stillThere = pool
      ._links()
      .find((l) => l.subject_id === "original-subject");
    assert.ok(stillThere);
  });

  it("links cross-provider when auto-link is opted in AND email is verified", async () => {
    const pool = makeMockPool([
      {
        id: "u-1",
        email: "frank@example.com",
        email_original: "frank@example.com",
        display_name: "Frank",
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      },
    ]);
    pool._links().push({
      id: "link-saml",
      user_id: "u-1",
      provider_slug: "saml",
      subject_id: "saml-sub",
      email_at_link: "frank@example.com",
      display_name_at_link: "Frank",
      last_seen_at: new Date(0),
    });
    const r = await resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      subjectId: "oidc-sub",
      email: "frank@example.com",
      displayName: "Frank",
      allowAutoLink: true,
      verifiedEmail: "frank@example.com",
    });
    assert.strictEqual(r.user.id, "u-1");
    assert.strictEqual(r.isNewLink, true);
    const newLink = pool._links().find((l) => l.subject_id === "oidc-sub");
    assert.ok(newLink, "new oidc link must exist");
    assert.strictEqual(newLink.provider_slug, "oidc");
  });

  it("returns missing_subject when subjectId is absent", async () => {
    const pool = makeMockPool([]);
    const r = await resolveWithProvider({
      pool,
      providerSlug: "saml",
      protocol: "saml",
      subjectId: "",
      email: "no-subject@example.com",
      displayName: "No Subject",
      allowAutoLink: true,
      verifiedEmail: "no-subject@example.com",
    });
    assert.strictEqual(r.user, null);
    assert.strictEqual(r.reason, "missing_subject");
  });

  it("creates a new user when neither subject nor email matches (step 3 unchanged)", async () => {
    const pool = makeMockPool([]);
    const r = await resolveWithProvider({
      pool,
      providerSlug: "saml",
      protocol: "saml",
      subjectId: "saml-sub",
      email: "grace@example.com",
      displayName: "Grace",
      allowAutoLink: false,
      verifiedEmail: "grace@example.com",
    });
    assert.strictEqual(r.isNewUser, true);
    assert.strictEqual(r.isNewLink, true);
    assert.strictEqual(r.user.email, "grace@example.com");
    assert.strictEqual(pool._users().length, 1);
    assert.strictEqual(pool._links().length, 1);
  });

  it("still JIT-creates an SSO user when DISABLE_MANUAL_INVITES is true", async () => {
    process.env.DISABLE_MANUAL_INVITES = "true";
    try {
      const pool = makeMockPool([]);
      const r = await resolveWithProvider({
        pool,
        providerSlug: "saml",
        protocol: "saml",
        subjectId: "saml-sub-flag",
        email: "flag-jit@example.com",
        displayName: "Flag JIT",
        allowAutoLink: false,
        verifiedEmail: "flag-jit@example.com",
      });
      assert.strictEqual(r.isNewUser, true);
      assert.strictEqual(r.user.email, "flag-jit@example.com");
    } finally {
      delete process.env.DISABLE_MANUAL_INVITES;
    }
  });

  it("creates a fresh SSO user when subject still links to a deleted account", async () => {
    const pool = makeMockPool([
      {
        id: "u-deleted",
        email: "deleted+u-deleted@example.invalid",
        email_original: null,
        display_name: "Deleted Account",
        auth_method: "local",
        email_verified: false,
        password_hash: "hashed",
        is_admin: false,
      },
    ]);
    pool._links().push({
      id: "link-deleted",
      user_id: "u-deleted",
      provider_slug: "entra",
      subject_id: "entra-subject-1",
      email_at_link: "user@example.com",
      display_name_at_link: "User",
      last_seen_at: new Date(0),
    });

    const r = await resolveWithProvider({
      pool,
      providerSlug: "entra",
      protocol: "saml",
      subjectId: "entra-subject-1",
      email: "user@example.com",
      displayName: "User Name",
      allowAutoLink: false,
      verifiedEmail: "user@example.com",
    });

    assert.strictEqual(r.isNewUser, true);
    assert.strictEqual(r.user.id, "user-2");
    assert.strictEqual(r.user.display_name, "User Name");
    assert.strictEqual(r.user.email, "user@example.com");
    assert.strictEqual(pool._links().length, 1);
    assert.strictEqual(pool._links()[0].user_id, "user-2");
    assert.strictEqual(pool._links()[0].subject_id, "entra-subject-1");
  });

  it("rejects an authenticated issuer that no longer matches the persisted provider", async () => {
    const pool = makeMockPool();
    await assert.rejects(resolveWithProvider({
      pool,
      providerSlug: "oidc",
      protocol: "oidc",
      issuer: "https://old-idp.example.test",
      subjectId: "member-subject",
      email: "member@example.test",
    }), /provider configuration changed/);
    assert.deepStrictEqual(pool._users(), []);
    assert.deepStrictEqual(pool._links(), []);
  });

  it("returns one committed user for concurrent first logins of the same subject", async () => {
    const pool = makeMockPool();
    const args = { pool, providerSlug: "test-oidc", protocol: "oidc", subjectId: "member-subject" };
    const logins = await Promise.all([
      resolveWithProvider({ ...args, email: "old@example.test" }),
      resolveWithProvider({ ...args, email: "new@example.test" }),
    ]);
    assert.strictEqual(pool._users().length, 1);
    assert.strictEqual(pool._links().length, 1);
    const [link] = pool._links();
    for (const login of logins) assert.strictEqual(login.user.id, link.user_id);
  });

  it("keeps one binding when concurrent subjects resolve to the same account under one provider", async () => {
    const pool = makeMockPool();
    const email = "member@example.test";
    const args = { pool, providerSlug: "test-oidc", protocol: "oidc", email,
      allowAutoLink: true, verifiedEmail: email };
    const results = await Promise.all([
      resolveWithProvider({ ...args, subjectId: "first-subject" }),
      resolveWithProvider({ ...args, subjectId: "second-subject" }),
    ]);
    const successes = results.filter((result) => result.user);
    const denials = results.filter((result) => !result.user);
    assert.strictEqual(successes.length, 1);
    assert.strictEqual(denials[0].reason, "sso_account_exists_subject_mismatch");
    assert.strictEqual(pool._users().length, 1);
    assert.strictEqual(pool._links().length, 1);
    assert.strictEqual(successes[0].user.id, pool._links()[0].user_id);
  });
});
