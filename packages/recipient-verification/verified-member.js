"use strict";

async function findVerifiedMemberEmails({ client, workspaceId, recipients }) {
  if (!workspaceId || !Array.isArray(recipients) || !recipients.length) return [];
  const candidates = recipients.filter(row => row.contactId && row.destination && row.fingerprint);
  if (!candidates.length) return [];
  const result = await client.query(
    `-- RV_VERIFIED_MEMBER_EMAILS
     WITH requested AS (
       SELECT * FROM unnest($2::uuid[], $3::text[], $4::text[])
         AS r(contact_id, destination_normalized, destination_fingerprint)
     )
     SELECT r.contact_id, r.destination_normalized
       FROM requested r
       JOIN workspace_contacts c ON c.id = r.contact_id AND c.workspace_id = $1
      WHERE lower(btrim(COALESCE(c.details->>'email', ''))) = r.destination_normalized
        AND EXISTS (
          SELECT 1 FROM workspace_memberships m JOIN users u ON u.id = m.user_id
           WHERE m.workspace_id = c.workspace_id AND u.email_verified = TRUE
             AND lower(btrim(u.email_original)) = r.destination_normalized
             AND (u.auth_method = 'local'
               OR lower(btrim(u.recipient_verified_email)) = r.destination_normalized)
        )
        AND NOT EXISTS (
          SELECT 1 FROM contact_channel_verifications v
           WHERE v.workspace_id = c.workspace_id AND v.contact_id = c.id
             AND v.channel = 'email' AND v.destination_normalized = r.destination_normalized
             AND v.status IN ('opted_out', 'revoked')
        )
        AND NOT EXISTS (
          SELECT 1 FROM notification_suppressions s
           WHERE s.channel = 'email' AND s.destination_fingerprint = r.destination_fingerprint
             AND (s.expires_at IS NULL OR s.expires_at > NOW())
             AND (s.scope = 'global' OR (s.scope = 'workspace' AND s.workspace_id = c.workspace_id))
        )`,
    [workspaceId, candidates.map(row => row.contactId), candidates.map(row => row.destination),
      candidates.map(row => row.fingerprint)],
  );
  return result.rows;
}

module.exports = { findVerifiedMemberEmails };
