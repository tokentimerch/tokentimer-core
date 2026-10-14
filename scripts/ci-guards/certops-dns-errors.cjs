"use strict";
try {
  const result = require("../certops-dns-provider-errors-report").validateInventory();
  console.log(`certops-dns-errors: ${result.providers} providers, ${result.adapterCases} mandatory contract cases`);
} catch {
  console.error("certops-dns-errors: mandatory adapter inventory drift requires review");
  process.exitCode = 1;
}
