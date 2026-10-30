"use strict";
// Closed capability descriptions, never a remote command interface.
const CONNECTORS = Object.freeze([
  Object.freeze({
    id: "linux-material-files-v1",
    platform: "linux",
    target: "endpoint",
    activationMethods: Object.freeze(["none", "reload"]),
    operations: Object.freeze([
      "discover-configured",
      "preflight",
      "stage",
      "activate",
      "verify",
      "reconcile",
    ]),
    verificationMethods: Object.freeze(["installed", "served", "trust"]),
    requiredCapabilities: Object.freeze([
      "material-store-vault-kv2-v1",
      "deploy-from-store-v1",
    ]),
    available: true,
    qualification: "existing-material-release-gates",
  }),
  Object.freeze({
    id: "windows-material-iis-v1",
    platform: "win32",
    target: "windows-iis",
    activationMethods: Object.freeze(["rebind"]),
    operations: Object.freeze([
      "discover",
      "preflight",
      "stage",
      "activate",
      "verify",
      "reconcile",
    ]),
    verificationMethods: Object.freeze(["served", "trust"]),
    requiredCapabilities: Object.freeze(["windows-material-iis-v1"]),
    available: false,
    qualification: "unmerged-pr-460-and-protected-real-host-campaign-required",
  }),
]);
module.exports = { CONNECTORS };
