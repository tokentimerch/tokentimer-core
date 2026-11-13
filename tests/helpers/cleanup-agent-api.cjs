"use strict";
// Actual agent routes/auth/transactions in a restartable disposable API process.
const assert = require("node:assert/strict");
assert.equal(process.env.TT_CLEANUP_COMPLETION_DISPOSABLE, "1");
assert.equal(process.env.NODE_ENV, "test");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^distribution_lifecycle_[a-f0-9]+_test$/);
const express = require("../../apps/api/node_modules/express");
const { createCertOpsAgentRouter } = require("../../apps/api/routes/certops-agent");
const app = express();
app.use(express.json());
let interruptNextResult = false;
app.use((req, res, next) => {
  if (req.path === "/api/v1/certops/agent/jobs/results" && interruptNextResult) {
    interruptNextResult = false;
    // Called by the real route only after ingestResult committed. Destroy the
    // response transport to exercise the customer's durable result retry.
    res.json = () => { res.destroy(); return res; };
  }
  next();
});
app.use(createCertOpsAgentRouter());
const server = app.listen(0, "127.0.0.1", () => process.send({ type: "ready", port: server.address().port }));
process.on("message", message => {
  if (message?.type === "interrupt-next-result") {
    interruptNextResult = true;
    process.send({ type: "armed" });
  }
});
