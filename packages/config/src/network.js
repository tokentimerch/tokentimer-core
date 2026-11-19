import network from "./network.cjs";

export const {
  assertOutboundHost,
  assertOutboundUrl,
  getNetworkConfig,
  isAllowedHost,
  isAllowedOutboundUrl,
  getDefaultWebhookHosts,
  isWebhookAllowed,
  OUTBOUND_POLICY_DENIED,
} = network;
