const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  CERTOPS_ADCS_AGENT_NOT_PREPARED,
  createAutomaticAdcsRenewal,
} = require("../../apps/api/services/certops/renewalScheduler");

// Realistic values: the CA config and template are plain text, and the
// readiness gate compares them as text.
const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const OTHER_TEMPLATE = "LegacyWebServer";
const KEY = "ab".repeat(32);
const OTHER_KEY = "cd".repeat(32);
const REFERENCE = "app.example.com";

describe("AD CS automatic renewal readiness (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();
    const email = `adcs-ready-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'AD CS Readiness', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;
    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'AD CS Readiness WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    await TestUtils.execQuery(
      `DELETE FROM audit_events
        WHERE workspace_id = $1
           OR subject_user_id = $2
           OR actor_user_id = $2`,
      [workspaceId, ownerId],
    );
    await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
  });
  beforeEach(async () => {
    await pool.query("DELETE FROM certificate_jobs WHERE workspace_id=$1",[workspaceId]);
  });

  // Each scenario gets its own issuer and agent so earlier evidence cannot
  // change which preflight is the latest one.
  async function scenario(template = TEMPLATE) {
    const issuer = await TestUtils.execQuery(
      `INSERT INTO certificate_issuers (workspace_id, kind, name, current_version, revalidation_required)
       VALUES ($1, 'adcs', $2, 1, false)
       RETURNING id`,
      [workspaceId, `Issuing CA ${crypto.randomUUID()}`],
    );
    const issuerId = issuer.rows[0].id;
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 1, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, template, KEY],
    );
    const agent = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, platform, declared_target_selectors, supported_operations
       ) VALUES ($1, $2, 'adcs-agent', '0.1.0', '1.0.0', $3, $4, 'active', 'win32', $5::jsonb, '["adcs-preflight"]'::jsonb)
       RETURNING id`,
      [
        workspaceId,
        `agent-${crypto.randomUUID()}`,
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
        JSON.stringify([REFERENCE]),
      ],
    );
    await pool.query(`UPDATE certops_agents SET agent_version='0.18.0',
      supported_operations='["adcs-preflight","renew"]',declared_capabilities='["adcs-enroll-v1"]',
      capabilities_updated_at=NOW() WHERE id=$1`,[agent.rows[0].id]);
    return { issuerId, agentId: agent.rows[0].id };
  }

  async function addPreflight({ issuerId, agentId, verdict, hoursAgo = 0 }) {
    await TestUtils.execQuery(
      `INSERT INTO certificate_jobs (
         workspace_id, operation, status, executor_kind, mode, subject_type,
         subject_id, payload, requested_by_user_id, assigned_agent_id, result_metadata,
         created_at
       ) VALUES ($1, 'adcs-preflight', 'succeeded', 'agent', 'real', 'external',
         $2, '{}'::jsonb, $3, $4, $5::jsonb,
         NOW() - make_interval(hours => $6::int))`,
      [
        workspaceId,
        issuerId,
        ownerId,
        agentId,
        JSON.stringify({ preflightVerdict: verdict }),
        hoursAgo,
      ],
    );
  }

  // Moves confirmation back so an older preflight can still be after it.
  async function backdateConfirmation(issuerId, hoursAgo) {
    await TestUtils.execQuery(
      `UPDATE certificate_issuer_versions
          SET confirmed_at = NOW() - make_interval(hours => $3::int)
        WHERE workspace_id = $1 AND issuer_id = $2 AND version = 1`,
      [workspaceId, issuerId, hoursAgo],
    );
  }

  // Shape written by the agent-result path: the verdict fields the gate reads.
  function verdict({ template = TEMPLATE, keySha256 = KEY } = {}) {
    return {
      templateCheck: "safe",
      caCheck: "safe",
      caConfig: CA,
      template,
      caKeySha256s: [keySha256],
    };
  }

  // Runs the real gate against the database and reports the scheduler outcome.
  async function runGate(issuerId, { automaticPreflight = false } = {}) {
    const certificate = {
      id: crypto.randomUUID(),
      workspace_id: workspaceId,
      profile_id: null,
      profile_issuer_id: issuerId,
      common_name: "app.example.com",
      not_after: "2027-12-01T00:00:00Z",
      profile_public_metadata: {
        renewalProfile: {
          target: {
            type: "windows-iis",
            reference: REFERENCE,
            store: "WebHosting",
            binding: { site: "Shop", port: 443 },
          },
          sanPolicy: { sans: ["app.example.com"] },
          keyAlgorithm: "rsa",
          keySize: 2048,
        },
      },
    };
    const error = await createAutomaticAdcsRenewal({
      dbPool: pool,
      certificate,
      mode: "real",
      env: { CERTOPS_ENABLED: "true" },
      auditWriter: async () => {},
      ...(automaticPreflight ? {} : { preflightDispatcher: async () => {} }),
    }).catch((caught) => caught);
    return { error };
  }

  it("queues only one preflight when a due renewal lacks fresh evidence", async () => {
    const { issuerId } = await scenario();
    const first = await runGate(issuerId, { automaticPreflight: true });
    expect(first.error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
    const second = await runGate(issuerId, { automaticPreflight: true });
    expect(second.error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
    const jobs = await TestUtils.execQuery(
      `SELECT operation, source, status FROM certificate_jobs
        WHERE workspace_id = $1 AND subject_id = $2 AND operation = 'adcs-preflight'`,
      [workspaceId, issuerId],
    );
    expect(jobs.rows).to.have.length(1);
    expect(jobs.rows[0].source).to.equal("automation");
  });

  it("qualifies an agent whose safe preflight matches the confirmed CA, template, and key", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({ issuerId, agentId, verdict: verdict() });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.not.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("does not qualify a preflight older than the 24-hour freshness bound", async () => {
    const { issuerId, agentId } = await scenario();
    await backdateConfirmation(issuerId, 48);
    await addPreflight({ issuerId, agentId, verdict: verdict(), hoursAgo: 25 });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("qualifies a preflight 23 hours old, inside the freshness bound", async () => {
    const { issuerId, agentId } = await scenario();
    await backdateConfirmation(issuerId, 48);
    await addPreflight({ issuerId, agentId, verdict: verdict(), hoursAgo: 23 });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.not.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("does not qualify a preflight that checked a different template", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({
      issuerId,
      agentId,
      verdict: verdict({ template: OTHER_TEMPLATE }),
    });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("does not qualify a preflight that pinned a different CA key", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({
      issuerId,
      agentId,
      verdict: verdict({ keySha256: OTHER_KEY }),
    });
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("stops qualifying evidence once the issuer is re-confirmed with a different template", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({ issuerId, agentId, verdict: verdict() });
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 2, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, OTHER_TEMPLATE, KEY],
    );
    await TestUtils.execQuery(
      "UPDATE certificate_issuers SET current_version = 2 WHERE id = $1",
      [issuerId],
    );
    const { error } = await runGate(issuerId);
    expect(error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  it("requires a new preflight job created after re-confirmation even when nothing changed", async () => {
    const { issuerId, agentId } = await scenario();
    await addPreflight({ issuerId, agentId, verdict: verdict() });
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 2, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, TEMPLATE, KEY],
    );
    await TestUtils.execQuery(
      "UPDATE certificate_issuers SET current_version = 2 WHERE id = $1",
      [issuerId],
    );
    const before = await runGate(issuerId);
    expect(before.error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);

    await addPreflight({ issuerId, agentId, verdict: verdict() });
    const after = await runGate(issuerId);
    expect(after.error?.code).to.not.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
  });

  async function refreshInput(context) {
    const row=(await pool.query(`SELECT confirmed_at FROM certificate_issuer_versions
      WHERE workspace_id=$1 AND issuer_id=$2 AND version=1`,[workspaceId,context.issuerId])).rows[0];
    return { client:pool,workspaceId,...context,caConfig:CA,template:TEMPLATE,
      automatic:true,confirmedAt:row.confirmed_at,env:{CERTOPS_ENABLED:"true"} };
  }

  it("deduplicates concurrent dispatch across independent PostgreSQL transactions", async () => {
    const {dispatchPreflight}=require("../../apps/api/services/certops/certificateEnrollments");
    const context=await scenario();
    const input=await refreshInput(context);
    const results=await Promise.all(Array.from({length:6},()=>dispatchPreflight(input)));
    expect(results.filter(Boolean)).to.have.length(1);
    const jobs=await pool.query(`SELECT id FROM certificate_jobs WHERE workspace_id=$1
      AND subject_id=$2 AND operation='adcs-preflight'`,[workspaceId,context.issuerId]);
    expect(jobs.rows).to.have.length(1);
  });

  it("persists bounded retries across calls and deduplicates exhaustion alerts", async () => {
    const {dispatchPreflight}=require("../../apps/api/services/certops/certificateEnrollments");
    const input=await refreshInput(await scenario());
    for(let attempt=0;attempt<5;attempt++) {
      const job=await dispatchPreflight(input);
      expect(job?.id).to.be.a("string");
      await pool.query(`UPDATE certificate_jobs SET status='failed',completed_at=NOW(),updated_at=NOW() WHERE id=$1`,[job.id]);
      if(attempt<4) expect(await dispatchPreflight(input)).to.equal(null);
      await pool.query(`UPDATE certificate_jobs SET completed_at=NOW()-INTERVAL '4 hours' WHERE id=$1`,[job.id]);
    }
    expect(await dispatchPreflight(input)).to.equal(null);
    expect(await dispatchPreflight(input)).to.equal(null);
    const notification=await pool.query(`SELECT metadata->>'code' AS code FROM operational_notifications
      WHERE workspace_id=$1 AND dedupe_key=$2 AND resolved_at IS NULL`,[workspaceId,`adcs-preflight:${input.issuerId}:${input.agentId}`]);
    expect(notification.rows).to.deep.equal([{code:"CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED"}]);
    // An operator can deliberately check again after restoring connectivity.
    expect((await dispatchPreflight({...input,automatic:false})).id).to.be.a("string");
  });

  it("blocks unsafe results and a changed CA key without creating automatic retries", async () => {
    const {dispatchPreflight}=require("../../apps/api/services/certops/certificateEnrollments");
    for(const patch of [{templateCheck:"unsafe"},{caCheck:"unsafe"},{caKeySha256s:[OTHER_KEY]}]) {
      const input=await refreshInput(await scenario());
      const job=await dispatchPreflight(input);
      await pool.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=NOW(),result_metadata=$2::jsonb WHERE id=$1`,
        [job.id,JSON.stringify({preflightVerdict:{...verdict(),...patch}})]);
      expect(await dispatchPreflight(input)).to.equal(null);
      expect((await pool.query(`SELECT count(*)::int AS n FROM certificate_jobs
        WHERE workspace_id=$1 AND subject_id=$2`,[workspaceId,input.issuerId])).rows[0].n).to.equal(1);
    }
  });

  it("recovers a stranded pending check and interrupted read-only execution with the same bounded policy", async () => {
    const {dispatchPreflight}=require("../../apps/api/services/certops/certificateEnrollments");
    for(const status of ["pending","orphaned_unknown_effect"]) {
      const context=await scenario();await backdateConfirmation(context.issuerId,3);
      const input=await refreshInput(context),job=await dispatchPreflight(input);
      await pool.query(`UPDATE certificate_jobs SET status=$2,created_at=NOW()-INTERVAL '2 hours',
        completed_at=NOW()-INTERVAL '2 hours',updated_at=NOW()-INTERVAL '2 hours' WHERE id=$1`,[job.id,status]);
      if(status==="pending") {
        expect(await dispatchPreflight(input)).to.equal(null);
        await pool.query(`UPDATE certificate_jobs SET completed_at=NOW()-INTERVAL '20 minutes' WHERE id=$1`,[job.id]);
      }
      const recovered=await dispatchPreflight(input);
      expect(recovered?.id).to.be.a("string");expect(recovered.id).not.to.equal(job.id);
      expect(await dispatchPreflight(input)).to.equal(null);
    }
  });

  it("retains workspace pause and current issuer-version admission fences", async () => {
    const {dispatchPreflight}=require("../../apps/api/services/certops/certificateEnrollments");
    const context=await scenario(),input=await refreshInput(context);
    await pool.query("UPDATE workspaces SET certops_paused=TRUE WHERE id=$1",[workspaceId]);
    try { await dispatchPreflight(input);throw new Error("expected pause refusal"); }
    catch(error) { expect(error.code).to.equal("CERTOPS_WORKSPACE_PAUSED"); }
    finally { await pool.query("UPDATE workspaces SET certops_paused=FALSE WHERE id=$1",[workspaceId]); }
    await pool.query(`UPDATE certificate_issuer_versions SET confirmed_at=clock_timestamp() WHERE workspace_id=$1 AND issuer_id=$2`,[workspaceId,context.issuerId]);
    try { await dispatchPreflight(input);throw new Error("expected version refusal"); }
    catch(error) { expect(error.code).to.equal("CERTOPS_ISSUER_REVALIDATION_REQUIRED"); }
  });

  it("selects an eligible alternate agent after enrollment capability disappears", async () => {
    const context=await scenario();
    await pool.query("UPDATE certops_agents SET declared_capabilities='[]' WHERE id=$1",[context.agentId]);
    const result=await runGate(context.issuerId,{automaticPreflight:true});
    expect(result.error?.code).to.equal(CERTOPS_ADCS_AGENT_NOT_PREPARED);
    const jobs=(await pool.query("SELECT assigned_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2",[workspaceId,context.issuerId])).rows;
    expect(jobs).to.have.length(1);
    expect(jobs[0].assigned_agent_id).not.to.equal(context.agentId);
  });

  it("continues the actual renewal sweep automatically after success, once, retaining approval", async () => {
    const {runRenewalSchedulerSweep}=require("../../apps/api/services/certops/renewalScheduler");
    const context=await scenario();
    const domain=`renew-${crypto.randomBytes(4).toString("hex")}.example.com`;
    const target={type:"windows-iis",reference:domain,store:"My",binding:{site:"Refresh",port:18443,sniHost:domain}};
    await pool.query("UPDATE certops_agents SET declared_target_selectors=$2::jsonb WHERE id=$1",[context.agentId,JSON.stringify([domain])]);
    const {provisionSurvivorSource}=require("../e2e/helpers/certops-adcs-local-rules");
    const certificateId=await provisionSurvivorSource({fixture:{workspaceId,pool},agentRowId:context.agentId,domain,site:"Refresh",port:18443,ownedCertificateIds:[]});
    const profile=(await pool.query(`INSERT INTO certificate_profiles(workspace_id,name,status,source,source_ref,
      issuer_id,renew_before_days,key_mode,public_metadata,created_by)
      VALUES($1,$2,'active','manual',$2,$3,10,'os-store-managed',$4::jsonb,$5) RETURNING id`,
      [workspaceId,domain,context.issuerId,JSON.stringify({renewalProfile:{target,sanPolicy:{sans:[domain]},keyAlgorithm:"rsa",keySize:2048}}),ownerId])).rows[0].id;
    await pool.query(`UPDATE managed_certificates SET status='active',profile_id=$2,not_after=NOW()+INTERVAL '2 days',fingerprint_sha256=$3 WHERE id=$1`,
      [certificateId,profile,crypto.randomBytes(32).toString("hex")]);
    await pool.query(`UPDATE certops_management_periods SET renewal_profile_id=$2,automation_enabled=TRUE
      WHERE managed_certificate_id=$1 AND ended_at IS NULL`,[certificateId,profile]);
    const sweep=()=>runRenewalSchedulerSweep({dbPool:pool,env:{CERTOPS_ENABLED:"true"},auditWriter:async()=>{}});
    await pool.query("UPDATE certops_agents SET declared_capabilities='[]'::jsonb WHERE id=$1",[context.agentId]);
    expect((await sweep()).skippedNotAgentDeployable).to.equal(1);
    expect((await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2",[workspaceId,context.issuerId])).rows).to.have.length(0);
    const unavailable=await pool.query("SELECT severity,metadata->>'code' AS code FROM operational_notifications WHERE workspace_id=$1 AND metadata->>'issuerId'=$2 AND resolved_at IS NULL",[workspaceId,context.issuerId]);
    expect(unavailable.rows).to.deep.equal([{severity:"critical",code:"CERTOPS_ADCS_AGENT_UNAVAILABLE"}]);
    await pool.query("UPDATE certops_agents SET declared_capabilities='[\"adcs-enroll-v1\"]'::jsonb WHERE id=$1",[context.agentId]);
    const first=await sweep();expect(first.skippedAdcsAgentNotPrepared,JSON.stringify(first)).to.equal(1);
    expect((await pool.query("SELECT id FROM certificate_enrollments WHERE certificate_id=$1",[certificateId])).rows).to.have.length(0);
    const check=(await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='adcs-preflight'",[workspaceId,context.issuerId])).rows[0];
    await pool.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=NOW(),result_metadata=result_metadata || $2::jsonb WHERE id=$1`,
      [check.id,JSON.stringify({preflightVerdict:verdict()})]);
    const issuerPage=await require("../../apps/api/services/certops/certificateEnrollments").listIssuers({client:pool,workspaceId,limit:100});
    expect(issuerPage.items.find(i=>i.id===context.issuerId).preflightRefresh.find(a=>a.agentId===context.agentId).state).to.equal("fresh");
    const summary=await require("../../apps/api/services/onboarding/certopsReality").loadAdcsReality(pool,workspaceId,{agentId:context.agentId});
    expect(summary.issuers.find(i=>i.id===context.issuerId).checkedAfterPin).to.equal(true);
    await pool.query("UPDATE workspaces SET certops_require_approval_always=TRUE WHERE id=$1",[workspaceId]);
    try {
      // Cross the TTL after scheduler selection, inside final admission. The
      // failed transaction rolls the fixture clock change back for the next sweep.
      const racingPool={query:pool.query.bind(pool),get idleCount(){return pool.idleCount;},connect:async()=>{
        const tx=await pool.connect();return {release:()=>tx.release(),query:async(sql,params)=>{
          const result=await tx.query(sql,params);
          if(sql.includes("certificate_issuer_versions v") && sql.includes("FOR UPDATE OF i")) {
            await tx.query("UPDATE certificate_jobs SET created_at=NOW()-INTERVAL '25 hours' WHERE id=$1",[check.id]);
          }
          return result;
        }};
      }};
      const raced=await runRenewalSchedulerSweep({dbPool:racingPool,env:{CERTOPS_ENABLED:"true"},auditWriter:async()=>{}});
      expect(raced.created).to.equal(0);expect(raced.skippedAdcsAgentNotPrepared).to.equal(1);
      const resumed=await sweep();expect(resumed.created).to.equal(1);
      await sweep();
      const enrollments=(await pool.query("SELECT snapshot_bytes,current_job_id FROM certificate_enrollments WHERE certificate_id=$1",[certificateId])).rows;
      expect(enrollments).to.have.length(1);
      expect(JSON.parse(enrollments[0].snapshot_bytes.toString()).caKeySha256).to.equal(KEY);
      expect((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[enrollments[0].current_job_id])).rows[0].status).to.equal("pending_approval");
      expect((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",
        [workspaceId,`adcs-preflight:${context.issuerId}:${context.agentId}`])).rows[0].resolved_at).not.to.equal(null);
      expect((await pool.query("SELECT id FROM operational_notifications WHERE workspace_id=$1 AND metadata->>'issuerId'=$2 AND resolved_at IS NULL",[workspaceId,context.issuerId])).rows).to.have.length(0);
    } finally { await pool.query("UPDATE workspaces SET certops_require_approval_always=FALSE WHERE id=$1",[workspaceId]); }
  });
});
