import { dedupeNormalizedDestinations } from "./contactGroups.js";
import crypto from "node:crypto";

const CLAIM_SQL = `INSERT INTO weekly_digest_recipient_log (
  workspace_id, week_start_date, channel, recipient_key, status, attempt_count, lease_expires_at, tokens_count, claim_token, updated_at
) VALUES ($1,$2,$3,$4,'pending',1, NOW() + ($5::int * interval '1 millisecond'), $6, $7, NOW())
ON CONFLICT (workspace_id, week_start_date, channel, recipient_key)
DO UPDATE SET
  status = 'pending',
  attempt_count = weekly_digest_recipient_log.attempt_count + 1,
  lease_expires_at = CASE
    WHEN weekly_digest_recipient_log.provider_accepted_at IS NULL
      AND weekly_digest_recipient_log.delivery_state = 'in_progress'
      THEN NOW() + ($8::int * interval '1 second')
    ELSE NOW() + ($5::int * interval '1 millisecond')
  END,
  tokens_count = EXCLUDED.tokens_count,
  claim_token = EXCLUDED.claim_token,
  delivery_state = CASE
    WHEN weekly_digest_recipient_log.provider_accepted_at IS NOT NULL THEN 'accepted'
    WHEN weekly_digest_recipient_log.delivery_state = 'in_progress' THEN 'uncertain'
    ELSE NULL
  END,
  retry_after = CASE
    WHEN weekly_digest_recipient_log.provider_accepted_at IS NULL
      AND weekly_digest_recipient_log.delivery_state = 'in_progress'
      THEN NOW() + ($8::int * interval '1 second')
    ELSE NULL
  END,
  updated_at = NOW()
WHERE weekly_digest_recipient_log.status <> 'sent'
  AND (
    (
      COALESCE(weekly_digest_recipient_log.delivery_state, 'idle') IN ('idle', 'rejected')
      AND (
        weekly_digest_recipient_log.lease_expires_at IS NULL
        OR weekly_digest_recipient_log.lease_expires_at < NOW()
      )
    )
    OR (
      weekly_digest_recipient_log.provider_accepted_at IS NOT NULL
      AND (
        weekly_digest_recipient_log.lease_expires_at IS NULL
        OR weekly_digest_recipient_log.lease_expires_at < NOW()
      )
    )
    OR (
      weekly_digest_recipient_log.delivery_state = 'uncertain'
      AND weekly_digest_recipient_log.retry_after IS NOT NULL
      AND weekly_digest_recipient_log.retry_after <= NOW()
      AND (
        weekly_digest_recipient_log.lease_expires_at IS NULL
        OR weekly_digest_recipient_log.lease_expires_at < NOW()
      )
    )
    OR (
      weekly_digest_recipient_log.delivery_state = 'in_progress'
      AND weekly_digest_recipient_log.provider_accepted_at IS NULL
      AND weekly_digest_recipient_log.lease_expires_at < NOW()
    )
  )
RETURNING *`;

function isUncertainProviderFailure(value) {
  if (!value) return false;
  if (value.uncertain === true) return true;
  const text = `${value.code || ""} ${value.message || ""} ${value.error || ""}`;
  return /timeout|ECONNRESET|ECONNABORTED|EAI_AGAIN|ESOCKET|EPIPE/i.test(text);
}

function digestUncertainRetrySeconds(value) {
  const raw = Number(value);
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  const fromEnv = Number(process.env.WEEKLY_DIGEST_UNCERTAIN_RETRY_SECONDS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return Math.floor(fromEnv);
  return 900;
}

function digestRecipientHmacSecret() {
  const dedicated = String(process.env.WEEKLY_DIGEST_RECIPIENT_KEY || "").trim();
  if (dedicated) return dedicated;
  const session = String(process.env.SESSION_SECRET || "").trim();
  if (session) return session;
  if (process.env.NODE_ENV === "test") {
    return "tokentimer-test-digest-recipient-key";
  }
  throw new Error(
    "WEEKLY_DIGEST_RECIPIENT_KEY or SESSION_SECRET is required to claim digest recipients",
  );
}

function hashDigestRecipientKey(destination) {
  return crypto
    .createHmac("sha256", digestRecipientHmacSecret())
    .update(String(destination ?? ""), "utf8")
    .digest("hex");
}

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

function claimParams(input) {
  return [
    input.workspaceId,
    input.weekStartDate,
    input.channel,
    hashDigestRecipientKey(input.recipientKey),
    input.leaseMs,
    input.tokensCount,
    crypto.randomUUID(),
    digestUncertainRetrySeconds(input.uncertainRetrySeconds),
  ];
}

async function claimWeeklyDigestRecipient(client, input) {
  const res = await client.query(CLAIM_SQL, claimParams(input));
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

function ownedPendingSql(setClause) {
  return `UPDATE weekly_digest_recipient_log
      SET ${setClause},
          updated_at = NOW()
    WHERE workspace_id = $1
      AND week_start_date = $2
      AND channel = $3
      AND recipient_key = $4
      AND status = 'pending'
      AND claim_token = $5`;
}

async function beginWeeklyDigestDelivery(client, input) {
  const res = await client.query(
    `${ownedPendingSql(`delivery_state = 'in_progress',
          retry_after = NULL,
          lease_expires_at = NOW() + ($6::int * interval '1 millisecond')`)}
      AND provider_accepted_at IS NULL
      AND COALESCE(delivery_state, 'idle') IN ('idle', 'rejected')
    RETURNING *`,
    [
      input.workspaceId,
      input.weekStartDate,
      input.channel,
      hashDigestRecipientKey(input.recipientKey),
      input.claimToken || null,
      input.leaseMs,
    ],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function renewWeeklyDigestClaimLease(client, input) {
  const res = await client.query(
    `${ownedPendingSql(`lease_expires_at = NOW() + ($6::int * interval '1 millisecond')`)}
      AND delivery_state = 'in_progress'
      AND provider_accepted_at IS NULL
    RETURNING claim_token, lease_expires_at`,
    [
      input.workspaceId,
      input.weekStartDate,
      input.channel,
      hashDigestRecipientKey(input.recipientKey),
      input.claimToken || null,
      input.leaseMs,
    ],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function releaseWeeklyDigestRecipientClaim(
  client,
  { workspaceId, weekStartDate, channel, recipientKey, claimToken },
) {
  const res = await client.query(
    `DELETE FROM weekly_digest_recipient_log
      WHERE workspace_id = $1
        AND week_start_date = $2
        AND channel = $3
        AND recipient_key = $4
        AND status = 'pending'
        AND claim_token = $5
      RETURNING workspace_id`,
    [workspaceId, weekStartDate, channel, hashDigestRecipientKey(recipientKey), claimToken || null],
  );
  return res.rowCount > 0;
}

async function markWeeklyDigestRecipientSent(
  client,
  { workspaceId, weekStartDate, channel, recipientKey, claimToken },
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
        AND claim_token = $5
      RETURNING *`,
    [workspaceId, weekStartDate, channel, hashDigestRecipientKey(recipientKey), claimToken || null],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function noteWeeklyDigestProviderAccepted(client, input) {
  const res = await client.query(
    `${ownedPendingSql(`provider_accepted_at = COALESCE(provider_accepted_at, NOW()),
          delivery_state = 'accepted',
          retry_after = NULL`)}
    RETURNING claim_token, provider_accepted_at`,
    [
      input.workspaceId,
      input.weekStartDate,
      input.channel,
      hashDigestRecipientKey(input.recipientKey),
      input.claimToken || null,
    ],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function noteWeeklyDigestRejected(client, input) {
  const res = await client.query(
    `${ownedPendingSql(`delivery_state = 'rejected',
          lease_expires_at = NOW() + ($6::int * interval '1 millisecond')`)}
      AND provider_accepted_at IS NULL
    RETURNING claim_token, delivery_state`,
    [
      input.workspaceId,
      input.weekStartDate,
      input.channel,
      hashDigestRecipientKey(input.recipientKey),
      input.claimToken || null,
      input.leaseMs,
    ],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function noteWeeklyDigestUncertain(client, input) {
  const res = await client.query(
    `${ownedPendingSql(`delivery_state = 'uncertain',
          retry_after = NOW() + ($6::int * interval '1 second'),
          lease_expires_at = NOW() + ($6::int * interval '1 second')`)}
      AND provider_accepted_at IS NULL
    RETURNING claim_token, delivery_state, retry_after`,
    [
      input.workspaceId,
      input.weekStartDate,
      input.channel,
      hashDigestRecipientKey(input.recipientKey),
      input.claimToken || null,
      digestUncertainRetrySeconds(input.uncertainRetrySeconds),
    ],
  );
  return res.rows && res.rows[0] ? res.rows[0] : null;
}

async function finalizeWeeklyDigestDelivery(client, input) {
  const accepted = await noteWeeklyDigestProviderAccepted(client, input);
  if (!accepted) return { completion: "delivered-ownership-lost", row: null };
  const finalized = await markWeeklyDigestRecipientSent(client, input);
  if (!finalized) return { completion: "delivered-ownership-lost", row: null };
  return { completion: "confirmed", row: finalized };
}

async function runOwnedDigestDelivery(client, input, deliver) {
  if (input.providerAcceptedAt) {
    const finalized = await markWeeklyDigestRecipientSent(client, input);
    return finalized
      ? { completion: "confirmed", row: finalized, sentExternal: false }
      : { completion: "ownership-lost", row: null, sentExternal: false };
  }
  const started = await beginWeeklyDigestDelivery(client, input);
  if (!started) return { completion: "ownership-lost", row: null, sentExternal: false };
  let result = null;
  let thrown = null;
  try {
    result = await deliver({
      renew: () => renewWeeklyDigestClaimLease(client, input),
    });
  } catch (error) {
    thrown = error;
  }
  const stillOwned = await renewWeeklyDigestClaimLease(client, input);
  if (!stillOwned) return { completion: "ownership-lost", row: null, sentExternal: Boolean(result && result.success) };
  const uncertain = isUncertainProviderFailure(result) || isUncertainProviderFailure(thrown);
  if (uncertain) {
    const noted = await noteWeeklyDigestUncertain(client, input);
    return noted
      ? { completion: "uncertain", row: noted, sentExternal: false }
      : { completion: "ownership-lost", row: null, sentExternal: false };
  }
  if (thrown || !result || !result.success) {
    await noteWeeklyDigestRejected(client, input);
    return { completion: "rejected", row: null, sentExternal: false };
  }
  const finalized = await finalizeWeeklyDigestDelivery(client, input);
  return { ...finalized, sentExternal: true };
}

function weeklyDigestWhatsAppIdempotencyKey({
  workspaceId,
  weekStartDate,
  phone,
}) {
  return `weekly-digest:${workspaceId}:${weekStartDate}:whatsapp:${hashDigestRecipientKey(phone)}`;
}

export {
  aggregateDigestRecipients,
  invertDigestCandidates,
  claimWeeklyDigestRecipient,
  releaseWeeklyDigestRecipientClaim,
  markWeeklyDigestRecipientSent,
  noteWeeklyDigestProviderAccepted,
  beginWeeklyDigestDelivery,
  renewWeeklyDigestClaimLease,
  finalizeWeeklyDigestDelivery,
  runOwnedDigestDelivery,
  isUncertainProviderFailure,
  weeklyDigestWhatsAppIdempotencyKey,
  hashDigestRecipientKey,
};
