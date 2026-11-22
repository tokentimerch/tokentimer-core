"use strict";
const { guard, database, login, saveState } = require("./common.cjs");
async function main() {
  const state = guard(),
    command = process.argv[2] || "tick",
    name = process.argv[3],
    value = process.argv[4];
  const db = database();
  try {
    if (command === "scenario") {
      const scenario = state.scenarios.find((s) => s.name === name);
      if (
        !scenario ||
        ![
          "safe",
          "unavailable",
          "changed-key",
          "unsafe",
          "offline",
          "timeout",
          "hold",
          "exhausted",
        ].includes(value)
      )
        throw Error(
          "Use scenario <name> safe|unavailable|changed-key|unsafe|offline|timeout|hold|exhausted",
        );
      scenario.mode = value;
      saveState(state);
      if (value === "offline")
        await db.query(
          "UPDATE certops_agents SET status='offline',last_seen_at=NOW()-interval '1 hour' WHERE workspace_id=$1 AND id=$2",
          [state.workspaceId, scenario.agent.rowId],
        );
      console.log(JSON.stringify({ scenario: name, mode: value }));
      return;
    }
    if (command === "advance") {
      const scenario = state.scenarios.find((s) => s.name === name);
      if (!scenario) throw Error("Unknown scenario");
      const minutes = Number(value || 121);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1500)
        throw Error("Fixture age must be 1..1500 minutes");
      await db.query(
        "UPDATE certificate_jobs SET completed_at=completed_at-$3*interval '1 minute',updated_at=updated_at-$3*interval '1 minute' WHERE workspace_id=$1 AND subject_id=$2 AND operation='adcs-preflight'",
        [state.workspaceId, scenario.issuerId, minutes],
      );
      console.log(
        "Only this scenario's persisted fixture preflight timestamps were aged",
      );
      return;
    }
    if (command === "expire" || command === "expire-lease") {
      const scenario = state.scenarios.find((s) => s.name === name);
      if (!scenario) throw Error("Unknown scenario");
      if (command === "expire") {
        await db.query(
          "UPDATE certificate_issuer_versions SET confirmed_at=LEAST(confirmed_at,NOW()-interval '2 days') WHERE workspace_id=$1 AND issuer_id=$2",
          [state.workspaceId, scenario.issuerId],
        );
        await db.query(
          "UPDATE certificate_jobs SET created_at=NOW()-interval '25 hours' WHERE workspace_id=$1 AND subject_id=$2 AND operation='adcs-preflight' AND status NOT IN ('pending','claimed','running')",
          [state.workspaceId, scenario.issuerId],
        );
      } else
        await db.query(
          "UPDATE certificate_jobs SET lease_expires_at=NOW()-interval '2 hours',lease_renewed_at=NOW()-interval '2 hours',updated_at=NOW()-interval '2 hours' WHERE workspace_id=$1 AND subject_id=$2 AND operation='adcs-preflight' AND status IN ('claimed','running')",
          [state.workspaceId, scenario.issuerId],
        );
      console.log(
        "Aged only the selected simulated scenario's freshness/lease fixture; production timekeeping unchanged",
      );
      return;
    }
    if (command === "manual") {
      const scenario = state.scenarios.find((s) => s.name === name);
      if (!scenario) throw Error("Unknown scenario");
      const request = await login(state);
      console.log(
        JSON.stringify(
          await request(
            `/api/v1/workspaces/${state.workspaceId}/certops/issuers/${scenario.issuerId}/preflight`,
            "POST",
            {
              agentId: scenario.agent.rowId,
              caConfig: require("./simulator.cjs").CA,
              template: require("./simulator.cjs").TEMPLATE,
            },
          ),
        ),
      );
      return;
    }
    if (command === "status") {
      const jobs = (
        await db.query(
          "SELECT id,subject_id,operation,status,error_code,source,assigned_agent_id,created_at FROM certificate_jobs WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 40",
          [state.workspaceId],
        )
      ).rows;
      const enrollments = (
        await db.query(
          "SELECT id,certificate_id,state,request_id,agent_id FROM certificate_enrollments WHERE workspace_id=$1",
          [state.workspaceId],
        )
      ).rows;
      const incidents = (
        await db.query(
          "SELECT id,severity,resolved_at,email_sent_at,metadata FROM operational_notifications WHERE workspace_id=$1 AND category='certops'",
          [state.workspaceId],
        )
      ).rows;
      console.log(
        JSON.stringify(
          {
            workspaceId: state.workspaceId,
            scenarios: state.scenarios.map(({ name, mode, issuerId }) => ({
              name,
              mode,
              issuerId,
            })),
            jobs,
            enrollments,
            incidents,
          },
          null,
          2,
        ),
      );
      return;
    }
    if (command === "scheduler") {
      console.log(
        JSON.stringify(
          await require("../../apps/api/services/certops/renewalScheduler").runRenewalSchedulerSweep(
            { env: process.env },
          ),
        ),
      );
      return;
    }
    if (command !== "agent")
      await (
        await import("../../apps/worker/src/certops-worker.js")
      ).runCertOpsMaintenance();
    const sim = require("./simulator.cjs");
    for (const scenario of state.scenarios) {
      if (["offline", "hold"].includes(scenario.mode)) continue;
      for (const agent of [
        scenario.agent,
        ...(scenario.extraAgents || []).filter((a) => a.eligible),
      ]) {
        const outcomes = await sim.execute(agent, {
          mode: scenario.mode,
          maxJobs: 16,
        });
        for (const outcome of outcomes)
          console.log(JSON.stringify({ scenario: scenario.name, ...outcome }));
      }
    }
    if (command === "agent") return;
    // The actual maintenance worker and delivery worker run unchanged.
    await (
      await import("../../apps/worker/src/delivery-worker.js")
    ).deliveryWorkerJob({ closePool: false });
  } finally {
    await db.end();
    await require("../../apps/api/db/database").pool.end();
    await (await import("../../apps/worker/src/db.js")).pool.end();
  }
}
main().catch((error) => {
  console.error(error.stack);
  process.exitCode = 1;
});
