"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  attachUserDisplayNames,
  displayNameForUserId,
  _test: { labelFromUserRow, normalizeUserId },
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/userDisplayNames.js",
  ),
);

describe("userDisplayNames", () => {
  it("normalizes positive integer user ids and rejects everything else", () => {
    assert.equal(normalizeUserId(9), 9);
    assert.equal(normalizeUserId("12"), 12);
    assert.equal(normalizeUserId("user-42"), null);
    assert.equal(normalizeUserId(null), null);
    assert.equal(normalizeUserId(""), null);
  });

  it("prefers display_name and falls back to email", () => {
    assert.equal(
      labelFromUserRow({ display_name: "Alice Admin", email: "a@example.com" }),
      "Alice Admin",
    );
    assert.equal(
      labelFromUserRow({ display_name: "  ", email: "a@example.com" }),
      "a@example.com",
    );
    assert.equal(labelFromUserRow({ display_name: "", email: "" }), null);
  });

  it("attaches the looked-up label and leaves unknown ids as null", async () => {
    const db = {
      async query(sql, params) {
        assert.match(sql, /FROM users/);
        assert.deepEqual(params[0], [9, 11]);
        return {
          rows: [
            { id: 9, display_name: "Alice Admin", email: "a@example.com" },
          ],
        };
      },
    };

    const attached = await attachUserDisplayNames({
      db,
      records: [
        { id: "job-1", approvedByUserId: 9 },
        { id: "job-2", approvedByUserId: 11 },
        { id: "job-3", approvedByUserId: null },
      ],
      idKey: "approvedByUserId",
      nameKey: "approvedByDisplayName",
    });

    assert.equal(attached[0].approvedByDisplayName, "Alice Admin");
    assert.equal(attached[1].approvedByDisplayName, null);
    assert.equal(attached[2].approvedByDisplayName, null);
    assert.equal(displayNameForUserId(new Map([[9, "Alice Admin"]]), 9), "Alice Admin");
  });
});
