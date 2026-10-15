"use strict";
// Synthetic bounded public proof only, never native observations.
module.exports.fixture = () => ({
  scope: "installed-system-corrupt-signing-pin-startup-refusal",
  pins: ["malformed-pin-json", "invalid-pin-shape"],
  startupFailureCount: 2,
  missingPinQualified: false,
  inFlightMutationQualified: false,
  twoActualSystemPinFailures: true,
  freshStoppedServiceForEach: true,
  configurationAndCredentialPreserved: true,
  nativeCngAndBindingPreserved: true,
  trustedTlsPreserved: true,
  noNewAgentOrJob: true,
  exactOriginalPinRestored: true,
  actualRepairedSystemChild: true,
  freshAuthenticatedHeartbeat: true,
  ownedPinGuardCleared: true,
});
