"use strict";

// Exercise the actual identity route and projection with an injected session
// boundary; the route's role redaction and PostgreSQL queries are unchanged.
const path = require("node:path");
const api = path.resolve(__dirname, "../../../apps/api");
const express = require(require.resolve("express", { paths: [api] }));
const { pool } = require(path.join(api, "db/database"));
const app = express();
app.use((req, _res, next) => {
  req.workspace = { id: process.env.TT_PROJECTION_WORKSPACE };
  req.authz = { workspaceRole: req.get("X-Test-Role") === "manager" ? "workspace_manager" : "viewer" };
  req.user = { id: Number(process.env.TT_PROJECTION_USER) };
  req.isAuthenticated = () => true;
  next();
});
app.use(require(path.join(api, "routes/certops")));
const server = app.listen(0, "127.0.0.1", () => process.send({ port: server.address().port }));
process.on("message", (message) => {
  if (message === "close") server.close(async () => { await pool.end(); process.exit(0); });
});
