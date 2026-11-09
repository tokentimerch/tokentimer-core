"use strict";
const assert = require("node:assert/strict");

// Run against the actual public profile API and production SQL due selector.
// The override is a positive control, not evidence that the midpoint elapsed.
async function qualifyAdaptiveLead({ fixture, api, scheduler, source, profileId }) {
  const profile = await fixture.request(`${api}/profiles/${profileId}`);
  assert.equal(profile.status, 200);
  assert.equal(profile.body.renewBeforeDays, null, "Profile must inherit the deployment window");
  const selectDue = () => scheduler.findCertificatesDueForRenewal({
    db: fixture.pool,
    thresholdDays: scheduler.DEFAULT_RENEWAL_THRESHOLD_DAYS,
    adaptive: true,
    batchSize: 10000,
    terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES,
  });
  const selected = rows => rows.some(value => value.workspace_id === fixture.workspaceId && value.id === source.id);
  assert.equal(selected(await selectDue()), false, "Fresh native certificate must not be due under the inherited window");
  const override = await fixture.request(`${api}/profiles/${profileId}`, "PATCH", { renewBeforeDays: 30 });
  assert.equal(override.status, 200);
  assert.equal(override.body.renewBeforeDays, 30);
  assert.equal(selected(await selectDue()), true, "The same source must be due after the explicit override");
}

module.exports = { qualifyAdaptiveLead };
