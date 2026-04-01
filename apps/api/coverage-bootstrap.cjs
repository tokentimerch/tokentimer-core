"use strict";

const { runMigrations } = require("./migrations/migrate");

async function main() {
  await runMigrations();
  require("./index");
}

main().catch((error) => {
  console.error("Coverage bootstrap failed", error);
  process.exit(1);
});
