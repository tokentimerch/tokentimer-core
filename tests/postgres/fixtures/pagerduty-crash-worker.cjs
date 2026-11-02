"use strict";

// Deliberately die in the send/commit window using an injected fake provider.
// Only the public correlation key is returned to the parent test process.
const { Client } = require("pg");
(async () => {
  if (!/_issue364_test$/.test(process.env.DB_NAME || ""))
    throw new Error("Disposable database required");
  const client = new Client({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
  await client.connect();
  const { processPagerDutyIncident } =
    await import("../../../apps/worker/src/pagerduty-incidents.js");
  await processPagerDutyIncident(client, process.argv[2], {
    send: async (_url, payload) => {
      process.stdout.write(payload.dedup_key);
      process.exit(23);
    },
  });
  process.exit(24);
})().catch(() => process.exit(25));
