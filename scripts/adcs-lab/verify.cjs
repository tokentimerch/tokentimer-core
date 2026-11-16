"use strict";
// Real services/PG/SMTP, simulated Windows verdicts and installation attestations.
const fs = require("node:fs"),
  path = require("node:path"),
  assert = require("node:assert/strict"),
  { spawn } = require("node:child_process");
const { guard, database, root, dir, login } = require("./common.cjs");
const results = [];
async function main() {
  const state = guard(),
    db = database();
  async function control(command) {
    const response = await fetch("http://127.0.0.1:55474/", {
      method: "POST",
      headers: {
        authorization: `Bearer ${state.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ command }),
    });
    assert.equal(response.status, 200);
    return response.json();
  }
  async function step(...args) {
    return new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        ["scripts/adcs-lab/step.cjs", ...args],
        { cwd: root, env: process.env, windowsHide: true },
      );
      let output = "";
      child.stdout.on("data", (c) => (output += c));
      child.stderr.on("data", (c) => (output += c));
      child.on("error", reject);
      child.on("exit", (code) =>
        code === 0 ? resolve(output) : reject(Error(output)),
      );
    });
  }
  async function check(name, fn) {
    await fn();
    results.push({ name, status: "PASS" });
    console.log(`PASS ${name}`);
  }
  const scenario = (name) => state.scenarios.find((s) => s.name === name);
  const jobs = async (name, operation = "adcs-preflight") =>
    (
      await db.query(
        "SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND operation=$3 AND subject_id=$2 ORDER BY preflight_seq NULLS FIRST,created_at",
        [state.workspaceId, scenario(name).issuerId, operation],
      )
    ).rows;
  const enrollments = async (name) =>
    (
      await db.query(
        "SELECT e.*,mc.not_after,mc.fingerprint_sha256 AS current_fingerprint,mc.reconciliation_reason FROM certificate_enrollments e JOIN managed_certificates mc ON mc.id=e.certificate_id WHERE e.workspace_id=$1 AND e.issuer_id=$2",
        [state.workspaceId, scenario(name).issuerId],
      )
    ).rows;
  try {
    await control("pause");
    await check(
      "actual services, migrations and complete deterministic fixture",
      async () => {
        assert.equal(state.seedComplete, true);
        assert.equal(state.scenarios.length, 12);
        assert.equal((await fetch("http://localhost:55174")).status, 200);
        assert.equal((await fetch("http://localhost:55471")).status, 200);
        assert.equal(
          (
            await db.query(
              "SELECT count(*)::int AS n FROM certops_agents WHERE workspace_id=$1",
              [state.workspaceId],
            )
          ).rows[0].n,
          136,
        );
        const request = await login(state);
        const list = await request(
          `/api/v1/workspaces/${state.workspaceId}/certops/issuers?includeUnconfigured=true`,
        );
        assert.equal(list.items.length, 12);
      },
    );
    const normalIds = [
      "expired",
      "success",
      "shared",
      "concurrent",
      "large",
    ].map((name) => scenario(name).issuerId);
    for (let i = 0; i < 20; i++) {
      await step("tick");
      const count = (
        await db.query(
          "SELECT count(*)::int AS n FROM certificate_enrollments WHERE workspace_id=$1 AND issuer_id=ANY($2::uuid[]) AND state='installed'",
          [state.workspaceId, normalIds],
        )
      ).rows[0].n;
      if (count === 112) break;
    }
    await check(
      "expired preflight refresh and successful renewal reconcile through signed protocol",
      async () => {
        for (const name of [
          "expired",
          "success",
          "shared",
          "concurrent",
          "large",
        ]) {
          const automatic = (await jobs(name)).filter(
            (j) => j.source === "automation",
          );
          assert.equal(automatic.length, 1, `${name} shares one refresh`);
          assert.equal(automatic[0].status, "succeeded");
          const rows = await enrollments(name);
          assert.equal(rows.length, scenario(name).certificates.length);
          for (const row of rows) {
            assert.equal(row.state, "installed");
            assert.ok(
              new Date(row.not_after) > new Date(Date.now() + 300 * 86400000),
            );
            assert.equal(row.reconciliation_reason, null);
          }
        }
        const cert = scenario("success").certificates[0].id;
        const associations = (
          await db.query(
            "SELECT count(*)::int AS n FROM certops_management_associations a JOIN certops_management_periods p ON p.id=a.period_id WHERE p.managed_certificate_id=$1",
            [cert],
          )
        ).rows[0].n;
        assert.ok(
          associations >= 2,
          "predecessor and successor identity retained",
        );
      },
    );
    await check(
      "agent 101 is selected beyond the first 100 ineligible declarations",
      async () => {
        const row = (await jobs("large")).find(
          (j) => j.source === "automation",
        );
        assert.equal(
          row.assigned_agent_id,
          scenario("large").extraAgents[99].rowId,
        );
      },
    );
    await check(
      "unapproved, unsafe, changed-key and offline paths fail closed",
      async () => {
        for (const name of [
          "initial",
          "unsafe",
          "changed-key",
          "offline",
          "unavailable",
          "critical",
          "exhausted",
        ])
          assert.equal((await enrollments(name)).length, 0, name);
        const issuer = (
          await db.query(
            "SELECT current_version FROM certificate_issuers WHERE id=$1",
            [scenario("initial").issuerId],
          )
        ).rows[0];
        assert.equal(issuer.current_version, 0);
        assert.equal(
          (await jobs("offline")).filter((j) => j.source === "automation")
            .length,
          0,
        );
        assert.equal(
          (await jobs("unsafe")).filter((j) => j.source === "automation")
            .length,
          1,
        );
        assert.equal(
          (await jobs("changed-key")).filter((j) => j.source === "automation")
            .length,
          1,
        );
      },
    );
    await check(
      "transient backoff prevents immediate retry floods",
      async () => {
        assert.equal(
          (await jobs("unavailable")).filter((j) => j.source === "automation")
            .length,
          1,
        );
        assert.match(
          (await jobs("unavailable")).at(-1).error_message,
          /ADCS_CA_UNREACHABLE/,
        );
      },
    );
    await check(
      "critical issuer aggregates three certificates and actually sends scoped SMTP links",
      async () => {
        const rows = (
          await db.query(
            "SELECT * FROM operational_notifications WHERE workspace_id=$1 AND metadata->>'issuerId'=$2 AND resolved_at IS NULL",
            [state.workspaceId, scenario("critical").issuerId],
          )
        ).rows;
        assert.equal(rows.length, 1);
        assert.equal(rows[0].severity, "critical");
        assert.equal(rows[0].metadata.affectedCount, 3);
        assert.ok(rows[0].email_sent_at);
        const mail = await (
          await fetch("http://localhost:18025/api/v2/messages?limit=100")
        ).json();
        const decode = (s) =>
          s
            .replace(/=\r?\n/g, "")
            .replace(/=([0-9a-f]{2})/gi, (_, h) =>
              String.fromCharCode(parseInt(h, 16)),
            );
        const messages = mail.items.filter((m) =>
          decode(m.Content.Body).includes(scenario("critical").issuerId),
        );
        assert.equal(messages.length, 1);
        const content = decode(messages[0].Content.Body);
        assert.ok(
          content.includes(`/certops/renewals?workspace=${state.workspaceId}`),
        );
        assert.ok(content.includes("check-adcs-issuer"));
        fs.writeFileSync(
          path.join(dir, "smtp-evidence.json"),
          JSON.stringify(
            {
              simulated: true,
              received: messages.length,
              workspaceId: state.workspaceId,
              issuerId: scenario("critical").issuerId,
              href: rows[0].metadata.href,
              htmlAndTextInternalLink: true,
            },
            null,
            2,
          ),
        );
      },
    );
    await check(
      "five transient attempts exhaust without a sixth automatic dispatch",
      async () => {
        for (let i = 0; i < 4; i++) {
          await step("advance", "exhausted", "121");
          await step("scheduler");
          await step("agent");
        }
        await step("advance", "exhausted", "121");
        await step("scheduler");
        assert.equal(
          (await jobs("exhausted")).filter((j) => j.source === "automation")
            .length,
          5,
        );
        assert.equal((await enrollments("exhausted")).length, 0);
      },
    );
    await check(
      "manual reset and healthy CA recover through normal admission",
      async () => {
        for (const name of ["unavailable", "exhausted"]) {
          await step("scenario", name, "safe");
          await step("manual", name);
        }
        for (let i = 0; i < 3; i++) await step("tick");
        for (const name of ["unavailable", "exhausted"])
          assert.equal((await enrollments(name))[0].state, "installed");
      },
    );
    await check(
      "independent concurrent schedulers preserve job and enrollment idempotency",
      async () => {
        const before = (
          await db.query(
            "SELECT count(*)::int AS n FROM certificate_enrollments WHERE workspace_id=$1",
            [state.workspaceId],
          )
        ).rows[0].n;
        const sweeps = await Promise.all(
          Array.from({ length: 3 }, () => step("scheduler")),
        );
        assert.ok(sweeps.some((text) => text.includes('"lockAcquired":false')));
        assert.equal(
          (
            await db.query(
              "SELECT count(*)::int AS n FROM certificate_enrollments WHERE workspace_id=$1",
              [state.workspaceId],
            )
          ).rows[0].n,
          before,
        );
      },
    );
    fs.writeFileSync(
      path.join(dir, "verification.json"),
      JSON.stringify(
        {
          candidate: require("node:child_process")
            .execFileSync("git", ["rev-parse", "HEAD"], {
              cwd: root,
              encoding: "utf8",
            })
            .trim(),
          simulatedWindowsAndCa: true,
          native: false,
          results,
        },
        null,
        2,
      ),
    );
    console.log(
      `PASS ${results.length} integrated scenario groups. Background cycles remain paused for inspection; use resume.`,
    );
  } finally {
    await db.end();
  }
}
main().catch((error) => {
  console.error(error.stack);
  process.exitCode = 1;
});
