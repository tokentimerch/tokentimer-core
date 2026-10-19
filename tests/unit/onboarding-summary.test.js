const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  summarizeContactGroups,
  splitExisting,
} = require("../../apps/api/services/onboarding/summary");

const emailContact = { id: "c1", details: { email: "ops@example.com" } };
const phoneOnly = { id: "c2", details: {} };

describe("onboarding summary helpers", () => {
  it("only counts groups that can reach an email recipient", () => {
    const summary = summarizeContactGroups(
      {
        contact_groups: [
          { id: "g1", name: "Ops", email_contact_ids: ["c1"] },
          { id: "g2", name: "Phones", email_contact_ids: ["c2"] },
          { id: "g3", name: "Hook", webhook_names: ["x"] },
        ],
        default_contact_group_id: "g1",
        email_alerts_enabled: true,
      },
      [emailContact, phoneOnly],
    );
    assert.equal(summary.count, 3);
    assert.equal(summary.withEmailRecipient, 1);
    assert.equal(summary.defaultHasEmailRecipient, true);
  });

  it("does not treat a default group without an email recipient as ready", () => {
    const summary = summarizeContactGroups(
      {
        contact_groups: [{ id: "g2", name: "Phones", email_contact_ids: ["c2"] }],
        default_contact_group_id: "g2",
      },
      [emailContact, phoneOnly],
    );
    assert.equal(summary.defaultHasEmailRecipient, false);
  });

  it("handles a missing default group and missing settings", () => {
    const noDefault = summarizeContactGroups(
      { contact_groups: [{ id: "g1", name: "Ops", email_contact_ids: ["c1"] }] },
      [emailContact],
    );
    assert.equal(noDefault.defaultHasEmailRecipient, false);
    assert.equal(noDefault.withEmailRecipient, 1);

    const empty = summarizeContactGroups(undefined, []);
    assert.equal(empty.count, 0);
    assert.equal(empty.defaultHasEmailRecipient, false);
    assert.equal(empty.emailAlertsEnabled, null);
  });

  it("reports which referenced ids still exist", () => {
    assert.deepEqual(splitExisting([1, 2, 3], [2]), {
      existing: [2],
      missing: [1, 3],
    });
    assert.deepEqual(splitExisting(["a"], ["a"]), {
      existing: ["a"],
      missing: [],
    });
  });
});
