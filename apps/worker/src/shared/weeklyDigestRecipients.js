import { dedupeNormalizedDestinations } from "./contactGroups.js";

const CLAIM_SQL = `INSERT INTO weekly_digest_recipient_log (
  workspace_id, week_start_date, channel, recipient_key, status, attempt_count, lease_expires_at, tokens_count, updated_at
) VALUES ($1,$2,$3,$4,'pending',1, NOW() + ($5::int * interval '1 millisecond'), $6, NOW())
ON CONFLICT (workspace_id, week_start_date, channel, recipient_key)
DO UPDATE SET
  status = 'pending',
  attempt_count = weekly_digest_recipient_log.attempt_count + 1,
  lease_expires_at = NOW() + ($5::int * interval '1 millisecond'),
  tokens_count = EXCLUDED.tokens_count,
  updated_at = NOW()
WHERE weekly_digest_recipient_log.status <> 'sent'
  AND (
    weekly_digest_recipient_log.lease_expires_at IS NULL
    OR weekly_digest_recipient_log.lease_expires_at < NOW()
  )
RETURNING *`;

function digestFlagOn(group, flag) {
  const value = group && group[flag];
  return value === true || value === "true";
}

function tokenId(token) {
  if (!token || typeof token !== "object") return null;
  if (token.id != null) return String(token.id);
  if (token.token_id != null) return String(token.token_id);
  return null;
}

function unionTokens(existing, incoming) {
  const out = Array.isArray(existing) ? existing.slice() : [];
  const seen = new Set(out.map(tokenId).filter(Boolean));
  for (const token of Array.isArray(incoming) ? incoming : []) {
    const id = tokenId(token);
    if (id) {
      if (seen.has(id)) continue;
      seen.add(id);
    }
    out.push(token);
  }
  return out;
}

function lookupTokens(tokensByGroupId, groupId) {
  if (groupId == null) return [];
  if (tokensByGroupId instanceof Map) {
    return (
      tokensByGroupId.get(groupId) ||
      tokensByGroupId.get(String(groupId)) ||
      []
    );
  }
  if (!tokensByGroupId || typeof tokensByGroupId !== "object") return [];
  return tokensByGroupId[groupId] || tokensByGroupId[String(groupId)] || [];
}

function invertDigestCandidates({ groupCandidates }) {
  const buckets = new Map();

  const add = (channel, recipientKey, tokens, groupId) => {
    const mapKey = `${channel}\0${recipientKey}`;
    let entry = buckets.get(mapKey);
    if (!entry) {
      entry = {
        channel,
        recipientKey,
        tokens: [],
        contributingGroupIds: [],
      };
      buckets.set(mapKey, entry);
    }
    entry.tokens = unionTokens(entry.tokens, tokens);
    if (groupId != null && !entry.contributingGroupIds.includes(groupId)) {
      entry.contributingGroupIds.push(groupId);
    }
  };

  for (const candidate of Array.isArray(groupCandidates)
    ? groupCandidates
    : []) {
    if (!candidate) continue;
    const group = candidate.group || {};
    const tokens = Array.isArray(candidate.tokens) ? candidate.tokens : [];
    const groupId = group.id != null ? String(group.id) : null;

    if (digestFlagOn(group, "weekly_digest_email")) {
      for (const email of dedupeNormalizedDestinations(
        candidate.emails,
        "email",
      )) {
        add("email", email, tokens, groupId);
      }
    }
    if (digestFlagOn(group, "weekly_digest_whatsapp")) {
      for (const phone of dedupeNormalizedDestinations(
        candidate.phones,
        "phone",
      )) {
        add("whatsapp", phone, tokens, groupId);
      }
    }
    if (digestFlagOn(group, "weekly_digest_webhooks")) {
      for (const url of dedupeNormalizedDestinations(
        candidate.webhookUrls || candidate.webhook_urls,
        "webhook",
      )) {
        add("webhook", url, tokens, groupId);
      }
    }
  }

  const rows = [...buckets.values()];
  for (const row of rows) {
    row.contributingGroupIds.sort();
  }
  return rows;
}

function aggregateDigestRecipients({ groups, tokensByGroupId }) {
  const groupCandidates = (Array.isArray(groups) ? groups : []).map((group) => ({
    group,
    tokens: lookupTokens(tokensByGroupId, group && group.id),
    emails: group && (group.emails || group.email_addresses),
    phones: group && (group.phones || group.phone_numbers),
    webhookUrls: group && (group.webhookUrls || group.webhook_urls),
  }));
  return invertDigestCandidates({ groupCandidates });
}

async function claimWeeklyDigestRecipient(
  client,
  { workspaceId, weekStartDate, channel, recipientKey, tokensCount, leaseMs },
) {
  const res = await client.query(CLAIM_SQL, [
    workspaceId,
    weekStartDate,
    channel,
    recipientKey,
    leaseMs,
    tokensCount,
  ]);
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function markWeeklyDigestRecipientSent(
  client,
  { workspaceId, weekStartDate, channel, recipientKey },
) {
  const res = await client.query(
    `UPDATE weekly_digest_recipient_log
        SET status = 'sent',
            lease_expires_at = NULL,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND week_start_date = $2
        AND channel = $3
        AND recipient_key = $4
        AND status = 'pending'
      RETURNING *`,
    [workspaceId, weekStartDate, channel, recipientKey],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

function weeklyDigestWhatsAppIdempotencyKey({
  workspaceId,
  weekStartDate,
  phone,
}) {
  return `weekly-digest:${workspaceId}:${weekStartDate}:whatsapp:${phone}`;
}

export {
  aggregateDigestRecipients,
  invertDigestCandidates,
  claimWeeklyDigestRecipient,
  markWeeklyDigestRecipientSent,
  weeklyDigestWhatsAppIdempotencyKey,
};
