"use strict";

/**
 * Resolve an SSO user to a TokenTimer `users` row using `external_identities`.
 */

const { isValidEmail } = require("../utils/emailAddress");

function isStr(v) {
  return typeof v === "string" && v.trim().length > 0;
}

function isTombstonedUser(user) {
  if (!user) return false;
  if (String(user.display_name || "").trim() === "Deleted Account") return true;
  return /@example\.invalid$/i.test(String(user.email || "").trim());
}

async function withinTx(pool, run) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await run(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {
      // ignore rollback errors
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * @param {object} args
 * @param {object} args.pool
 * @param {string} args.providerSlug
 * @param {'oidc'|'saml'} args.protocol
 * @param {string} [args.issuer] - Issuer of the authenticated OIDC token
 * @param {string} args.subjectId
 * @param {string} args.email
 * @param {string} args.displayName
 * @param {boolean} args.allowAutoLink
 * @param {string|null} [args.verifiedEmail] - Exact mailbox verified by the IdP
 * @param {string|null} [args.trustedSamlEmail] - Mailbox in the signed SAML assertion
 * @param {Function} [args.canonicalizeEmail]
 */
async function resolveUser({
  pool,
  providerSlug,
  protocol,
  issuer,
  subjectId,
  email,
  displayName,
  allowAutoLink,
  verifiedEmail,
  trustedSamlEmail,
  canonicalizeEmail,
}) {
  if (!providerSlug || !isStr(providerSlug)) {
    throw new Error("identity-resolver: providerSlug is required");
  }
  if (!protocol || !["oidc", "saml"].includes(protocol)) {
    throw new Error(`identity-resolver: invalid protocol ${protocol}`);
  }
  if (!isStr(subjectId)) {
    return {
      user: null,
      isNewUser: false,
      isNewLink: false,
      authMethodBefore: null,
      reason: "missing_subject",
    };
  }
  if (!isStr(email)) {
    return {
      user: null,
      isNewUser: false,
      isNewLink: false,
      authMethodBefore: null,
      reason: "missing_email",
    };
  }

  const canonical =
    typeof canonicalizeEmail === "function"
      ? canonicalizeEmail(email || "")
      : String(email || "").trim().toLowerCase();
  const rawEmail = String(email || "").trim();
  const safeDisplayName = isStr(displayName) ? displayName.trim() : rawEmail;

  const mailbox = rawEmail.toLowerCase();
  const matchesMailbox = (value) =>
    isValidEmail(value) && value.trim().toLowerCase() === mailbox;
  const hasVerifiedEmail = matchesMailbox(verifiedEmail);
  const canLinkByEmail =
    hasVerifiedEmail ||
    (protocol === "saml" &&
      allowAutoLink === true &&
      matchesMailbox(trustedSamlEmail));

  return withinTx(pool, async (client) => {
    // Coordinate with provider updates before binding an authenticated subject.
    const providerResult = await client.query(
      "SELECT type, config FROM sso_providers WHERE slug = $1 AND enabled FOR SHARE",
      [providerSlug],
    );
    const provider = providerResult.rows[0];
    const configuredIssuer = provider?.config?.issuer;
    if (
      provider?.type !== protocol ||
      (protocol === "oidc" &&
        (typeof configuredIssuer !== "string" ||
          configuredIssuer.trim() === "" ||
          configuredIssuer.trim() !== issuer))
    ) {
      throw new Error("SSO provider configuration changed during sign-in");
    }

    // The unique index alone cannot serialize a subject lookup that finds no row.
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtext('sso-identity:' || $1::text), hashtext($2))",
      [providerSlug, subjectId],
    );

    async function attachIdentity(user) {
      const attached = await client.query(
        `INSERT INTO external_identities
             (user_id, provider_slug, protocol, subject_id, email_at_link, display_name_at_link, last_seen_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())
           ON CONFLICT (provider_slug, subject_id) DO UPDATE SET last_seen_at = NOW()
             WHERE external_identities.user_id = EXCLUDED.user_id
           RETURNING user_id`,
        [user.id, providerSlug, protocol, subjectId, rawEmail, safeDisplayName],
      );
      if (attached.rows[0]?.user_id !== user.id) {
        throw new Error("identity-resolver: identity owner changed");
      }
    }

    async function refreshRecipientProof(user) {
      await client.query(
        `UPDATE users SET recipient_verified_email =
           CASE WHEN $3::boolean AND lower(btrim(email_original)) = lower(btrim($2))
             THEN lower(btrim($2)) ELSE NULL END
         WHERE id = $1`,
        [user.id, rawEmail, hasVerifiedEmail],
      );
    }
    const linkRow = await client.query(
      `SELECT ei.id AS link_id,
              u.*,
              u.auth_method AS auth_method_before
         FROM external_identities ei
         JOIN users u ON u.id = ei.user_id
        WHERE ei.provider_slug = $1 AND ei.subject_id = $2
        LIMIT 1 FOR UPDATE OF u`,
      [providerSlug, subjectId],
    );
    if (linkRow.rowCount > 0) {
      const row = linkRow.rows[0];
      if (isTombstonedUser(row)) {
        await client.query("DELETE FROM external_identities WHERE id = $1", [
          row.link_id,
        ]);
      } else {
        await client.query(
          "UPDATE external_identities SET last_seen_at = NOW() WHERE id = $1",
          [row.link_id],
        );
        delete row.link_id;
        const authMethodBefore = row.auth_method_before || null;
        delete row.auth_method_before;
        await refreshRecipientProof(row);
        return {
          user: row,
          isNewUser: false,
          isNewLink: false,
          authMethodBefore,
          reason: null,
        };
      }
    }

    if (isStr(canonical)) {
      // Serialize provisioning when the canonical address has no user row yet.
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtext('sso-user-email'), hashtext(lower($1)))",
        [canonical],
      );
      const emailRow = await client.query(
        "SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1 FOR UPDATE",
        [canonical],
      );
      const user = emailRow.rows[0];
      if (user && !isTombstonedUser(user)) {
        const authMethodBefore = user.auth_method || null;

        const existingLink = await client.query(
          `SELECT subject_id FROM external_identities
              WHERE user_id = $1 AND provider_slug = $2
              LIMIT 1`,
          [user.id, providerSlug],
        );
        const linkedSubject =
          existingLink.rowCount > 0 ? existingLink.rows[0].subject_id : null;
        if (linkedSubject && linkedSubject !== subjectId) {
          return {
            user: null,
            isNewUser: false,
            isNewLink: false,
            authMethodBefore,
            reason: "sso_account_exists_subject_mismatch",
          };
        }

        const isLocalAccount = user.auth_method === "local";
        const anyIdentityLink = await client.query(
          `SELECT 1 FROM external_identities WHERE user_id = $1 LIMIT 1`,
          [user.id],
        );
        const hasAnyIdentityLink = anyIdentityLink.rowCount > 0;
        // Orphaned = SSO user whose provider links were removed (e.g. provider
        // delete CASCADE). Cross-provider merge still requires allowAutoLink.
        const isOrphanedSsoAccount =
          !isLocalAccount &&
          !linkedSubject &&
          !hasAnyIdentityLink &&
          ["sso", "saml", "oidc"].includes(String(user.auth_method || ""));

        if (!allowAutoLink && isLocalAccount) {
          return {
            user: null,
            isNewUser: false,
            isNewLink: false,
            authMethodBefore,
            reason: "local_account_exists_auto_link_disabled",
          };
        }
        if (!allowAutoLink && !isOrphanedSsoAccount) {
          const reason =
            hasAnyIdentityLink && !linkedSubject
              ? "cross_provider_auto_link_disabled"
              : "sso_account_exists_subject_mismatch";
          return {
            user: null,
            isNewUser: false,
            isNewLink: false,
            authMethodBefore,
            reason,
          };
        }
        if (!canLinkByEmail) {
          return {
            user: null,
            isNewUser: false,
            isNewLink: false,
            authMethodBefore,
            reason: "email_not_verified_for_link",
          };
        }
        await attachIdentity(user);
        await refreshRecipientProof(user);
        return {
          user,
          isNewUser: false,
          isNewLink: true,
          authMethodBefore,
          reason: null,
        };
      }
    }

    const inserted = await client.query(
      `INSERT INTO users (email, email_original, display_name, auth_method, email_verified, password_hash, is_admin)
       VALUES ($1, $2, $3, 'sso', TRUE, 'SSO_NO_PASSWORD', FALSE)
       RETURNING *`,
      [canonical, rawEmail || canonical, safeDisplayName],
    );
    const user = inserted.rows[0];
    await attachIdentity(user);
    await refreshRecipientProof(user);
    return {
      user,
      isNewUser: true,
      isNewLink: true,
      authMethodBefore: null,
      reason: null,
    };
  });
}

module.exports = {
  resolveUser,
  isTombstonedUser,
};
