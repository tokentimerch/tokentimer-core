"use strict";

// Isolate real route modules and their database pools from the parent suite.
// Only the session boundary is supplied by the fixture; route authorization,
// queries, serialization and export formatting are the production code.
if (typeof process.send !== "function")
  throw new Error("Audit fixture requires an IPC parent");
const path = require("node:path");
const api = path.resolve(__dirname, "../../../apps/api");
const express = require(require.resolve("express", { paths: [api] }));
const actors = JSON.parse(process.env.TT_AUDIT_TEST_ACTORS);
const { pool } = require(path.join(api, "db/database"));
const app = express();
app.use((req, _res, next) => {
  req.user = actors[req.get("X-Audit-Test-Actor") || "owner"];
  req.isAuthenticated = () => Boolean(req.user);
  next();
});
if (path.basename(api) === "saas")
  app.use("/api", require(path.join(api, "routes/audit")));
app.use(require(path.join(api, "routes/usage")));
app.use(require(path.join(api, "routes/workspaces")));
const server = app.listen(0, "127.0.0.1", () =>
  process.send({ port: server.address().port }),
);
process.on("message", async (message) => {
  if (message !== "close") return;
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
});
