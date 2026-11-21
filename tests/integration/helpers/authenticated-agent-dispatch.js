"use strict";

// These service-level fixtures start after authentication. Separate tests use
// the real credential fence and concurrent database connections.
const dispatch = require("../../../apps/api/services/certops/agentDispatch");
const wrap = fn => options => fn({ ...options, deps: { assertCurrentAgentCredential: async () => {}, ...options.deps } });
module.exports = { ...dispatch, claimJobs: wrap(dispatch.claimJobs), recordHeartbeat: wrap(dispatch.recordHeartbeat),
  renewJobLease: wrap(dispatch.renewJobLease), ingestResult: wrap(dispatch.ingestResult) };
