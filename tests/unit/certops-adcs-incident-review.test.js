"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  refreshState,
  preflightFailure,
  issuerRefreshStates,
} = require("../../apps/api/services/certops/adcsPreflightRefresh");
const {
  summarizeReadiness,
  projectRenewalPath,
  reconcileIssuerPreflightIncident,
} = require("../../apps/api/services/certops/adcsPreflightIncidents");
const NOW = Date.parse("2026-11-16T12:00:00Z"),
  DAY = 86400000;
const W = "11111111-1111-4111-8111-111111111111",
  I = "22222222-2222-4222-8222-222222222222";
const version = {
  version: 1,
  confirmed_at: new Date(NOW - 7 * DAY),
  ca_config: "ca.example\\CA",
  template: "WebServer",
  ca_key_sha256: "ab".repeat(32),
};
const verdict = {
  caConfig: version.ca_config,
  template: version.template,
  caKeySha256s: [version.ca_key_sha256],
  templateCheck: "safe",
  caCheck: "safe",
};
const failed = (patch = {}) => ({
  id: "1",
  status: "failed",
  source: "automation",
  created_at: new Date(NOW - 60000),
  completed_at: new Date(NOW),
  ...patch,
});
const agent = (patch = {}) => ({
  id: "agent-1",
  status: "active",
  platform: "win32",
  agent_version: "0.18.0",
  protocol_version: "1.0.0",
  supported_operations: ["renew", "adcs-preflight"],
  declared_target_selectors: ["app.example"],
  declared_capabilities: ["adcs-enroll-v1"],
  capabilities_updated_at: new Date(NOW),
  ...patch,
});
const certificate = (patch = {}) => ({
  id: "cert-1",
  common_name: "app.example",
  not_after: new Date(NOW + DAY),
  profile_public_metadata: {
    renewalProfile: {
      target: {
        type: "windows-iis",
        reference: "app.example",
        store: "My",
        binding: { site: "App", port: 443 },
      },
      sanPolicy: { sans: ["app.example"] },
      keyAlgorithm: "rsa",
      keySize: 2048,
    },
  },
  ...patch,
});

describe("preflight review: truthful failure reasons", () => {
  it("does not invent CA unreachability for generic or unreadable failures", () => {
    assert.equal(
      preflightFailure(failed(), version).code,
      "CERTOPS_PREFLIGHT_OPERATION_FAILED",
    );
    assert.equal(
      preflightFailure(failed({ status: "succeeded" }), version).code,
      "CERTOPS_PREFLIGHT_RESULT_UNREADABLE",
    );
    assert.equal(
      preflightFailure(
        failed({
          status: "succeeded",
          result_metadata: {
            preflightVerdict: { templateCheck: "unreadable" },
          },
        }),
        version,
      ).code,
      "CERTOPS_PREFLIGHT_RESULT_UNREADABLE",
    );
    for (const [error_code, code] of [
      ["ADCS_CA_UNREACHABLE", "ADCS_CA_UNREACHABLE"],
      ["ETIMEDOUT", "CERTOPS_PREFLIGHT_NETWORK_TIMEOUT"],
      ["CERTOPS_PREFLIGHT_QUEUE_TIMEOUT", "CERTOPS_PREFLIGHT_QUEUE_TIMEOUT"],
      ["effects_unknown", "CERTOPS_PREFLIGHT_EXECUTION_INTERRUPTED"],
    ]) {
      const state = refreshState([failed({ error_code })], version, NOW);
      assert.equal(state.code, code);
      assert.equal(state.errorCode, error_code);
      assert.equal(state.retryable, true);
      assert.ok(state.action);
    }
  });
  it("does not consume a new confirmation/version episode with older failures", () => {
    const old = failed({
      result_metadata: {
        preflightContext: {
          issuerVersion: 0,
          caKeySha256: version.ca_key_sha256,
          confirmedAt: version.confirmed_at,
        },
      },
    });
    assert.equal(refreshState([old], version, NOW).state, "required");
    assert.equal(
      refreshState([failed(), old, old, old, old], version, NOW).attempts,
      1,
    );
    assert.equal(
      refreshState(
        [failed(), failed({ created_at: new Date(NOW - 8 * DAY) })],
        version,
        NOW,
      ).attempts,
      1,
    );
  });
  it("retains the last cause at exhaustion and never retries a known security failure", () => {
    const jobs = Array.from({ length: 5 }, () =>
      failed({ error_code: "ETIMEDOUT" }),
    );
    const state = refreshState(jobs, version, NOW);
    assert.equal(state.code, "CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED");
    assert.equal(state.failureCode, "CERTOPS_PREFLIGHT_NETWORK_TIMEOUT");
    assert.equal(state.errorCode, "ETIMEDOUT");
    for (const error_code of [
      "ADCS_CA_KEY_CHANGED",
      "ADCS_TEMPLATE_UNSAFE",
      "ADCS_CA_CONFIG_UNSAFE",
      "issuer_not_allowlisted",
    ])
      assert.equal(
        refreshState([failed({ error_code })], version, NOW).retryable,
        false,
      );
  });
  it("orders by sequence, timestamp and final job id without mutating supplied history", () => {
    const safe = {
      ...failed(),
      assigned_agent_id: "a",
      status: "succeeded",
      result_metadata: { preflightVerdict: verdict },
    };
    const unsafe = {
      ...safe,
      id: "b",
      preflight_seq: "9",
      result_metadata: { preflightVerdict: { ...verdict, caCheck: "unsafe" } },
    };
    const history = [
      { ...safe, id: "z", preflight_seq: "8" },
      unsafe,
      { ...safe, id: "a", preflight_seq: "9" },
    ];
    assert.equal(
      issuerRefreshStates(history, version, NOW)[0].code,
      "ADCS_CA_CONFIG_UNSAFE",
    );
    assert.equal(history[0].id, "z");
  });
});

describe("preflight review: current shared risk", () => {
  it("scopes the authoritative due query without a dispatch-batch limit", async () => {
    const {
      findCertificatesDueForRenewal,
      RENEWAL_JOB_TERMINAL_STATUSES,
    } = require("../../apps/api/services/certops/renewalScheduler");
    await findCertificatesDueForRenewal({
      workspaceId: W,
      issuerId: I,
      batchSize: null,
      terminalStatuses: RENEWAL_JOB_TERMINAL_STATUSES,
      db: {
        query: async (sql, params) => {
          assert.match(sql, /mc.workspace_id=\$5/);
          assert.match(sql, /cp.issuer_id=\$6/);
          assert.match(sql, /NOT EXISTS/);
          assert.match(sql, /automation_enabled/);
          assert.equal(params[2], null);
          assert.deepEqual(params.slice(4), [W, I]);
          return { rows: [] };
        },
      },
    });
  });
  it("publishes current readiness without exporting agent internals or promoting unrelated evidence", async () => {
    const {
      listIssuers,
    } = require("../../apps/api/services/certops/certificateEnrollments");
    const safe = {
      ...failed(),
      assigned_agent_id: "agent-1",
      status: "succeeded",
      result_metadata: { preflightVerdict: verdict },
    };
    const db = {
      query: async (sql) => ({
        rows: sql.includes("count(*)")
          ? [{ n: 1 }]
          : [
              {
                id: I,
                kind: "adcs",
                current_version: 1,
                confirmed_at: version.confirmed_at,
                confirmed_key_sha256: version.ca_key_sha256,
                ca_config: version.ca_config,
                template: version.template,
                refresh_jobs: [safe],
              },
            ],
      }),
    };
    const page = await listIssuers({
      client: db,
      workspaceId: W,
      env: {},
      readinessLoader: async (args) => {
        assert.equal(args.workspaceId, W);
        assert.equal(args.issuerId, I);
        return {
          agents: [agent({ credential_secret: "DO_NOT_EXPORT" })],
          dueCount: 1,
          affectedCount: 1,
          checks: [
            {
              state: "agent_unavailable",
              agentId: null,
              code: "CERTOPS_ADCS_AGENT_UNAVAILABLE",
            },
          ],
        };
      },
    });
    assert.equal(
      page.items[0].renewalReadiness.checks[0].state,
      "agent_unavailable",
    );
    assert.equal(page.items[0].preflightRefresh[0].renewalReady, false);
    assert.equal(JSON.stringify(page).includes("DO_NOT_EXPORT"), false);
  });
  const path = (id, days, state = "blocked") => ({
    certificateId: id,
    notAfter: new Date(NOW + days * DAY),
    state,
    code: "ADCS_TEMPLATE_UNSAFE",
    action: "Correct template",
  });
  it("keeps the earliest certificate independently of update order and bounds metadata", () => {
    for (const paths of [
      [path("A", 1), path("B", 25)],
      [path("B", 25), path("A", 1)],
    ]) {
      const risk = summarizeReadiness(paths, NOW);
      assert.equal(risk.mostUrgentCertificateId, "A");
      assert.equal(risk.severity, "critical");
      assert.equal(risk.affectedCount, 2);
    }
    const risk = summarizeReadiness(
      Array.from({ length: 1000 }, (_, n) => ({
        ...path(String(n), n + 1),
        agentId: String(n),
      })),
      NOW,
    );
    assert.equal(risk.affectedCount, 1000);
    assert.equal(risk.checks.length, 20);
    assert.equal(risk.truncated, true);
  });
  it("does not resolve after only one path recovers, and recomputes downgrade/removal", () => {
    const remaining = summarizeReadiness(
      [path("A", 1, "fresh"), path("B", 25)],
      NOW,
    );
    assert.equal(remaining.alert, true);
    assert.equal(remaining.severity, "warning");
    assert.equal(remaining.mostUrgentCertificateId, "B");
    assert.equal(
      summarizeReadiness([path("B", 25, "fresh")], NOW).alert,
      false,
    );
    assert.equal(summarizeReadiness([], NOW).affectedCount, 0);
  });
  it("derives a jobless unavailable/ineligible state and rejects unrelated agents", () => {
    assert.equal(
      projectRenewalPath(certificate(), [], version, NOW, {}).state,
      "agent_unavailable",
    );
    assert.equal(
      projectRenewalPath(
        certificate(),
        [agent({ declared_capabilities: [] })],
        version,
        NOW,
        {},
      ).state,
      "agent_ineligible",
    );
    const checked = agent({
      preflight_jobs: [
        failed({
          status: "succeeded",
          result_metadata: { preflightVerdict: verdict },
        }),
      ],
    });
    assert.equal(
      projectRenewalPath(certificate(), [checked], version, NOW, {}).state,
      "fresh",
    );
    assert.equal(
      projectRenewalPath(
        certificate(),
        [{ ...checked, status: "inactive" }],
        version,
        NOW,
        {},
      ).state,
      "agent_unavailable",
    );
    const superseded = {
      ...checked,
      preflight_jobs: [
        {
          ...checked.preflight_jobs[0],
          preflight_seq: 2,
          result_metadata: {
            preflightVerdict: verdict,
            preflightContext: { issuerVersion: 0 },
          },
        },
        { ...checked.preflight_jobs[0], preflight_seq: 1 },
      ],
    };
    assert.equal(
      projectRenewalPath(certificate(), [superseded], version, NOW, {}).state,
      "required",
    );
    assert.equal(
      projectRenewalPath(
        certificate(),
        [{ ...checked, declared_target_selectors: ["unrelated.example"] }],
        version,
        NOW,
        {},
      ).state,
      "agent_unavailable",
    );
  });
  it("persists recomputed issuer scope and preserves delivery receipts on repeated updates", async () => {
    let due = [
      certificate(),
      certificate({ id: "cert-2", not_after: new Date(NOW + 25 * DAY) }),
    ];
    const writes = [];
    const db = {
      query: async (sql, params) => {
        if (sql.includes("SELECT v.*")) return { rows: [version] };
        if (sql.includes("FROM certops_agents a")) return { rows: [] };
        if (sql.includes("FROM managed_certificates mc")) {
          assert.ok(params.includes(W));
          assert.ok(params.includes(I));
          return { rows: due };
        }
        if (sql.includes("INSERT INTO operational_notifications")) {
          writes.push(params);
          assert.match(sql, /emailDelivery/);
          return { rows: [{ id: "incident" }] };
        }
        if (sql.includes("UPDATE operational_notifications")) {
          writes.push(params);
          return { rows: [] };
        }
        if (sql.includes("pg_advisory_xact_lock")) return { rows: [] };
        throw Error(sql);
      },
    };
    const run = () =>
      reconcileIssuerPreflightIncident({
        db,
        workspaceId: W,
        issuerId: I,
        env: { CERTOPS_ENABLED: "true" },
        now: NOW,
        transactionOwned: true,
      });
    await run();
    const metadata = JSON.parse(writes.at(-1)[4]);
    assert.equal(metadata.mostUrgentCertificateId, "cert-1");
    assert.equal(metadata.affectedCount, 2);
    due = [due[1]];
    await run();
    assert.equal(writes.at(-1)[1], "warning");
    due = [];
    await run();
    assert.equal(writes.at(-1)[3], true);
  });
});
