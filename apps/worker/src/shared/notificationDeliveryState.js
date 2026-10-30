import { createRequire } from "node:module";
import alertEligibility from "@tokentimer/alert-eligibility";
import { recipientDeliveryComplete } from "./deliveryEvidence.js";

const require = createRequire(import.meta.url);
function installedVerification() {
  let path;
  try {
    path =
      require.resolve("../../../../packages/recipient-verification/index.js");
  } catch (error) {
    if (error.code === "MODULE_NOT_FOUND") return null;
    throw error;
  }
  // A broken installed module must never fall back to weaker behavior.
  return require(path);
}

export function createNotificationDeliveryState(
  verification = installedVerification(),
) {
  const engine = verification || alertEligibility;
  const state = {
    parse(value) {
      const parsed = alertEligibility.parseDeliveryLedger(value);
      if (!parsed) return null;
      return verification
        ? { ...parsed, ...verification.parseDeliveryLedger(value) }
        : parsed;
    },
    channels(value) {
      const parsed = alertEligibility.parseDeliveryLedger(value);
      if (!parsed) return null;
      const names = verification?.channelNamesForSettlement
        ? verification.channelNamesForSettlement(value)
        : parsed.required;
      return (
        names && [
          ...new Set([
            ...names,
            ...parsed.retry,
            ...Object.keys(parsed.outcomes),
          ]),
        ]
      );
    },
    recipientComplete(channel, recipients, history) {
      return verification?.requiredRecipientDelivery
        ? verification.requiredRecipientDelivery({
            channel,
            recipients,
            history,
          }).delivered
        : recipientDeliveryComplete(channel, recipients, history);
    },
    settle(input) {
      const parsed = alertEligibility.parseDeliveryLedger(input.prior);
      if (!parsed) throw new Error("unsupported_delivery_ledger");
      const result = engine.mergeDeliveryAttempt({ ...input, logRows: [] });
      // Preserve evidence extensions and endpoint retry generations even when
      // the companion's settlement reconstructs its known outcome fields.
      for (const [channel, outcome] of Object.entries(result.ledger.outcomes)) {
        result.ledger.outcomes[channel] = {
          ...parsed.outcomes[channel],
          ...outcome,
        };
        if (parsed.outcomes[channel]?.endpoints || outcome.endpoints)
          result.ledger.outcomes[channel].endpoints = {
            ...parsed.outcomes[channel]?.endpoints,
            ...outcome.endpoints,
          };
      }
      const { legacy: _legacy, ...base } = parsed;
      result.ledger = { ...base, ...result.ledger };
      return result;
    },
    async recipients(client, workspaceId, channel, recipients) {
      if (verification) {
        const result = await verification.filterDeliveryRecipients({
          client,
          workspaceId,
          channel,
          recipients,
        });
        if (
          result.blocked.some(
            (row) =>
              !row.shadow && row.code === "RECIPIENT_VERIFICATION_UNAVAILABLE",
          )
        )
          result.unavailable = true;
        return result;
      }
      const deployment = String(process.env.TT_DEPLOYMENT || "self-hosted")
        .trim()
        .toLowerCase();
      const mode = String(process.env.RECIPIENT_VERIFICATION_MODE || "off")
        .trim()
        .toLowerCase();
      const shadow = deployment === "self-hosted" && mode === "shadow";
      if (deployment === "self-hosted" && ["off", "shadow"].includes(mode))
        return {
          allowed: recipients,
          blocked: [],
          enforced: false,
          mode: shadow ? "shadow" : "off",
        };
      // Verification is enforced but its dependency is unavailable. This is
      // unknown eligibility, not proof that nobody needs delivery.
      return {
        allowed: [],
        blocked: recipients.map((row) => ({
          ...row,
          code: "RECIPIENT_VERIFICATION_UNAVAILABLE",
        })),
        enforced: true,
        unavailable: true,
        code: "RECIPIENT_VERIFICATION_UNAVAILABLE",
      };
    },
    async assertRecipient(client, workspaceId, channel, recipient) {
      const gated = await state.recipients(client, workspaceId, channel, [
        recipient,
      ]);
      if (gated.allowed.length === 0)
        throw new Error(gated.code || "RECIPIENT_NOT_VERIFIED");
    },
  };
  return state;
}

export const notificationDeliveryState = createNotificationDeliveryState();

// Same terminal-partial admission contract as #461's ordinary worker.
export const DELIVERY_CLAIM_EXCLUSION_SQL = `AND NOT (
  aq.status = 'partial' AND (
    aq.channels IS NULL OR aq.channels = '[]'::jsonb OR (
      jsonb_typeof(aq.channels) = 'object'
      AND COALESCE(aq.channels->'retry', '[]'::jsonb) = '[]'::jsonb
    )
  )
)`;
