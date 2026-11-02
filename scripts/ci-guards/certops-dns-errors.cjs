/**
 * Reject drift between supported production DNS adapters and mandatory fault-case inventory.
 * This cheap source guard does not contact providers or qualify live credentials. */
"use strict";
try {
  const result = require("../certops-dns-provider-errors-report").validateInventory();
  console.log(`certops-dns-errors: ${result.providers} providers, ${result.adapterCases} mandatory contract cases`);
} catch {
  console.error("certops-dns-errors: mandatory adapter inventory drift requires review");
  process.exitCode = 1;
}
