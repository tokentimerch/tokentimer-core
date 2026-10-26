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

export {
  gateDestinations,
  recheckDestination,
  destinationAllowed,
  verificationMode,
  queueDeliveryOutcome,
  selectDeliverableDestinations,
};
