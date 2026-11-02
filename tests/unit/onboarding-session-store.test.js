"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { writeSession } = require("../../apps/api/services/onboarding/sessionStore");
const {
  OnboardingValidationError,
} = require("../../apps/api/services/onboarding/sessionSchema");
const {
  createCompactPrivateMaterialFixture,
} = require("../helpers/private-material-fixtures");

const identity = { userId: 11, workspaceId: 22, flow: "certops" };

describe("onboarding session persistence secret boundary", () => {
  for (const expectedRevision of [0, 2]) {
    const operation = expectedRevision === 0 ? "insert" : "update";
    for (const section of ["intent", "progress", "operation_refs"]) {
      it(`rejects private material before ${operation} of ${section}`, async () => {
        const { representations } = createCompactPrivateMaterialFixture();
        const calls = [];
        const pool = {
          async query(sql, values) {
            calls.push({ sql, values });
            throw new Error("Rejected input must not reach the database");
          },
        };
        for (const value of representations) {
          // Call the real store directly, without the route or schema helper.
          await assert.rejects(
            writeSession(pool, {
              ...identity,
              expectedRevision,
              patch: { [section]: { details: [{ note: value }] } },
            }),
            (error) =>
              error instanceof OnboardingValidationError &&
              error.code === "SECRET_REJECTED",
          );
        }
        assert.equal(calls.length, 0);
      });
    }

    it(`preserves legitimate section values during ${operation}`, async () => {
      const { publicDer } = createCompactPrivateMaterialFixture();
      const patch = {
        plannerVersion: 2,
        status: "in_progress",
        intent: { goal: "vault_distribution" },
        progress: {
          note: "Review public status",
          evidence: publicDer.toString("base64"),
        },
        operation_refs: { monitorUrl: "https://example.com", tokenIds: [4, 5] },
      };
      const calls = [];
      const pool = {
        async query(sql, values) {
          calls.push({ sql, values });
          return {
            rows: [
              {
                flow: identity.flow,
                schema_version: 1,
                planner_version: patch.plannerVersion,
                status: patch.status,
                intent: patch.intent,
                progress: patch.progress,
                operation_refs: patch.operation_refs,
                revision: expectedRevision + 1,
              },
            ],
          };
        },
      };
      const session = await writeSession(pool, { ...identity, expectedRevision, patch });
      assert.equal(calls.length, 1);
      assert.match(
        calls[0].sql,
        expectedRevision === 0
          ? /INSERT INTO onboarding_sessions/
          : /UPDATE onboarding_sessions SET/,
      );
      const sectionOffset = expectedRevision === 0 ? 5 : 6;
      for (const [index, section] of ["intent", "progress", "operation_refs"].entries()) {
        assert.deepEqual(JSON.parse(calls[0].values[sectionOffset + index]), patch[section]);
      }
      assert.deepEqual(session.progress, patch.progress);
      assert.deepEqual(session.operationRefs, patch.operation_refs);
      assert.equal(session.revision, expectedRevision + 1);
    });
  }

  it("leaves omitted sections untouched during a status-only update", async () => {
    let parameters;
    const pool = {
      async query(_sql, values) {
        parameters = values;
        return { rows: [{ flow: identity.flow, revision: 3, status: "dismissed" }] };
      },
    };
    await writeSession(pool, {
      ...identity,
      expectedRevision: 2,
      patch: { status: "dismissed" },
    });
    assert.deepEqual(parameters.slice(6, 9), [null, null, null]);
  });
});
