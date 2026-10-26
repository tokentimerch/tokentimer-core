import recipientVerification from "../../../../packages/recipient-verification/index.js";

async function gateDestinations(client, workspaceId, channel, rows) {
  return recipientVerification.filterDeliveryRecipients({
    client,
    workspaceId,
    channel,
    recipients: rows,
  });
}

async function recheckDestination(client, workspaceId, channel, recipient) {
  return recipientVerification.canDeliverToRecipient({
    client,
    workspaceId,
    contactId: recipient.contactId,
    channel,
    destination: recipient.destination,
  });
}

async function destinationAllowed(client, workspaceId, channel, destination) {
  return recipientVerification.canDeliverToDestination({
    client,
    workspaceId,
    channel,
    destination,
  });
}

function verificationMode() {
  return recipientVerification.resolveEnforcementMode();
}

function queueDeliveryOutcome(results, options) {
  return recipientVerification.queueDeliveryOutcome(results, options);
}

function selectDeliverableDestinations(rows) {
  return recipientVerification.selectDeliverableDestinations(rows);
}

function mergeDeliveryAttempt(input) {
  return recipientVerification.mergeDeliveryAttempt(input);
}

function webhookRetryGenerationFromStored(stored) {
  return recipientVerification.webhookRetryGenerationFromStored(stored);
}

function webhookPermanentHashes(logRows, stored) {
  return recipientVerification.webhookPermanentHashes(logRows, stored);
}

const DELIVERY_CLAIM_EXCLUSION_SQL = recipientVerification.DELIVERY_CLAIM_EXCLUSION_SQL;

export {
  gateDestinations,
  recheckDestination,
  destinationAllowed,
  verificationMode,
  queueDeliveryOutcome,
  selectDeliverableDestinations,
  mergeDeliveryAttempt,
  webhookRetryGenerationFromStored,
  webhookPermanentHashes,
  DELIVERY_CLAIM_EXCLUSION_SQL,
};
