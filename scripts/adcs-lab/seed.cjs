"use strict";
const crypto = require("node:crypto");
const { guard, database, login, saveState } = require("./common.cjs");
const sim = require("./simulator.cjs");
const catalog = [
  ["initial", 1, "hold", false],
  ["expired", 1, "safe"],
  ["success", 1, "safe"],
  ["unavailable", 1, "unavailable"],
  ["changed-key", 1, "changed-key"],
  ["unsafe", 1, "unsafe"],
  ["offline", 1, "offline"],
  ["shared", 5, "safe"],
  ["critical", 3, "unavailable"],
  ["exhausted", 1, "exhausted"],
  ["large", 100, "safe"],
  ["concurrent", 5, "safe"],
];
async function seed() {
  const state = guard(),
    db = database();
  try {
    if (state.workspaceId)
      throw Error("Already seeded; use reset for a clean lab");
    const bcrypt = require("bcryptjs");
    const owner = (
      await db.query(
        "INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'SIMULATED AD CS Developer',$2,'local',true) RETURNING id",
        [state.email, await bcrypt.hash(state.password, 10)],
      )
    ).rows[0].id;
    const workspaceId = crypto.randomUUID();
    await db.query(
      "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'SIMULATED AD CS — developer lab',$2,'oss')",
      [workspaceId, owner],
    );
    await db.query(
      "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager') ON CONFLICT(workspace_id,user_id) DO UPDATE SET role='workspace_manager'",
      [workspaceId, owner],
    );
    Object.assign(state, { workspaceId, owner });
    saveState(state);
    const request = await login(state),
      prefix = `/api/v1/workspaces/${workspaceId}/certops`;
    for (const [name, count, mode, confirmed = true] of catalog) {
      const targets = Array.from(
        { length: Math.min(count, 50) },
        (_, i) => `${name}-${i + 1}.example.test`,
      );
      const agent = await sim.register(request, prefix, name, targets);
      agent.rowId = (
        await db.query(
          "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
          [workspaceId, agent.agentId],
        )
      ).rows[0].id;
      const issuer = (
        await request(`${prefix}/issuers`, "POST", {
          kind: "adcs",
          name: `SIMULATED ${name}`,
        })
      ).issuer;
      const scenario = {
        name,
        mode,
        issuerId: issuer.id,
        agent,
        certificates: [],
      };
      state.scenarios.push(scenario);
      saveState(state);
      await request(`${prefix}/issuers/${issuer.id}/preflight`, "POST", {
        agentId: agent.rowId,
        caConfig: sim.CA,
        template: sim.TEMPLATE,
      });
      await sim.execute(agent, { mode: "safe" });
      if (confirmed)
        await request(`${prefix}/issuers/${issuer.id}/confirm`, "POST", {
          caKeySha256: sim.KEY,
          caConfig: sim.CA,
          template: sim.TEMPLATE,
        });
      for (let i = 0; i < count; i++) {
        const domain = targets[i % targets.length],
          days =
            name === "critical" ? [1, 5, 25][i] : name === "large" ? 10 : 1;
        const target = {
          type: "windows-iis",
          reference: domain,
          store: "My",
          binding: { site: `Simulated${i + 1}`, port: 443, sniHost: domain },
        };
        const profile = (
          await db.query(
            `INSERT INTO certificate_profiles(workspace_id,name,status,source,source_ref,issuer_id,renew_before_days,key_mode,public_metadata,created_by)
          VALUES($1,$2,'active','manual',$3,$4,30,'os-store-managed',$5::jsonb,$6) RETURNING id`,
            [
              workspaceId,
              `SIMULATED ${name} ${i + 1}`,
              crypto.randomUUID(),
              issuer.id,
              JSON.stringify({
                renewalProfile: {
                  target,
                  sanPolicy: { sans: [domain] },
                  keyAlgorithm: "rsa",
                  keySize: 2048,
                },
              }),
              owner,
            ],
          )
        ).rows[0].id;
        const cert = (
          await db.query(
            `INSERT INTO managed_certificates(workspace_id,status,source,source_ref,name,common_name,subject_alt_names,key_mode,key_reference,public_metadata,deployed_agent_id,profile_id,not_after,fingerprint_sha256)
          VALUES($1,'active','agent_issuance',$2,$3,$4,$5,'os-store-managed',$6,$7::jsonb,$8,$9,NOW()+$10*interval '1 day',$11) RETURNING id`,
            [
              workspaceId,
              crypto.randomUUID(),
              `SIMULATED ${name} ${i + 1}`,
              domain,
              [domain],
              `winstore://My/Simulated${i + 1}:443`,
              JSON.stringify({
                simulated: true,
                issuance: { requestedAt: new Date().toISOString(), target },
              }),
              agent.rowId,
              profile,
              days,
              crypto.randomBytes(32).toString("hex"),
            ],
          )
        ).rows[0].id;
        await db.query(
          "UPDATE certops_management_periods SET renewal_profile_id=$2,automation_enabled=$3 WHERE managed_certificate_id=$1 AND ended_at IS NULL",
          [cert, profile, confirmed],
        );
        scenario.certificates.push({ id: cert, profileId: profile, domain });
      }
      // Only fixture timestamps move; production TTL/backoff constants do not.
      await db.query(
        "UPDATE certificate_jobs SET created_at=NOW()-interval '25 hours',completed_at=NOW()-interval '25 hours' WHERE workspace_id=$1 AND subject_id=$2 AND operation='adcs-preflight'",
        [workspaceId, issuer.id],
      );
      if (name === "offline")
        await db.query(
          "UPDATE certops_agents SET status='offline',last_seen_at=NOW()-interval '1 hour' WHERE id=$1",
          [agent.rowId],
        );
      if (name === "large") {
        // Real registered protocol identities, first 100 lack enrollment capability.
        scenario.extraAgents = [];
        agent.eligible = false;
        await sim.heartbeat(agent);
        for (let i = 1; i < 125; i++) {
          const extra = await sim.register(
            request,
            prefix,
            `large-${i + 1}`,
            targets,
            i >= 100,
          );
          extra.rowId = (
            await db.query(
              "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
              [workspaceId, extra.agentId],
            )
          ).rows[0].id;
          scenario.extraAgents.push(extra);
        }
        // Deterministic ordering places the eligible 101st declaration beyond page one.
        const ordered = [agent, ...scenario.extraAgents];
        for (let i = 0; i < ordered.length; i++)
          await db.query(
            "UPDATE certops_agents SET last_seen_at=NOW()-$2*interval '1 second' WHERE id=$1",
            [ordered[i].rowId, i],
          );
      }
      saveState(state);
      console.log(
        JSON.stringify({
          seeded: name,
          issuerId: issuer.id,
          certificates: count,
          simulated: true,
        }),
      );
    }
    state.seedComplete = true;
    saveState(state);
    console.log(
      "All simulated scenarios seeded. Credentials: pnpm adcs:lab credentials",
    );
  } finally {
    await db.end();
  }
}
if (require.main === module)
  seed().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
module.exports = { seed, catalog };
