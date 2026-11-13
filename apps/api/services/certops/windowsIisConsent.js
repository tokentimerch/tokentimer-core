"use strict";

const { iisSelectorKey, classifyBinding } = require("./windowsRenewalOwnership");
const { classifyAgentLiveness } = require("./agentLiveness");
const { writeAudit } = require("../audit");
const { pool } = require("../../db/database");

async function listWindowsRenewal({ workspaceId, identityId, client = pool }) {
  const result = await client.query(`SELECT DISTINCT p.id AS period_id,p.managed_certificate_id,p.renewal_profile_id,
      mc.fingerprint_sha256,mc.name,cp.name AS profile_name,cp.public_metadata AS profile_metadata,
      a.id AS agent_id,a.agent_id AS public_agent_id,a.name AS agent_name,a.status AS agent_status,
      a.last_seen_at,a.created_at,a.declared_capabilities,a.capabilities_updated_at,
      COALESCE(store.hostname,cp.public_metadata->'renewalProfile'->'target'->>'reference',a.name) AS hostname
    FROM certops_management_periods p
    JOIN managed_certificates mc ON mc.workspace_id=p.workspace_id AND mc.id=p.managed_certificate_id
    LEFT JOIN certificate_profiles cp ON cp.workspace_id=p.workspace_id AND cp.id=p.renewal_profile_id
    LEFT JOIN LATERAL (SELECT ct.* FROM certificate_instances ci JOIN certificate_targets ct
      ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id
      WHERE ci.workspace_id=p.workspace_id AND ci.managed_certificate_id=mc.id
        AND ct.source='agent_windows' AND ct.location_kind='windows_store' AND ct.windows_store='My'
        AND ci.observed_fingerprint_sha256=mc.fingerprint_sha256
      ORDER BY ci.captured_at DESC NULLS LAST LIMIT 1) store ON true
    JOIN certops_agents a ON a.workspace_id=p.workspace_id AND
      ((store.id IS NOT NULL AND a.agent_id=store.public_metadata->>'agentId') OR
       (store.id IS NULL AND a.id=mc.deployed_agent_id AND cp.public_metadata->'renewalProfile'->'target'->>'type'='windows-cert-store'))
    WHERE p.workspace_id=$1 AND p.current_identity_id=$2 AND p.ended_at IS NULL`, [workspaceId,identityId]);
  const groups=[];
  for (const owner of result.rows) {
    const ambiguous=result.rows.filter(item => item.agent_id===owner.agent_id).length > 1;
    const capable=require("./agentJobEligibility").hasFreshCapability({ declaredCapabilities:owner.declared_capabilities,
      capabilitiesUpdatedAt:owner.capabilities_updated_at,capability:"windows-store-iis-consumers-v1" });
    const storeProfile=owner.profile_metadata?.renewalProfile?.target?.type === "windows-cert-store";
    const rows=await client.query(`SELECT ct.id,ct.windows_site,ct.windows_port,ct.windows_sni_host,ct.windows_store,
        ci.managed_certificate_id,ci.observed_fingerprint_sha256,ci.presence_state,ci.captured_at,
        c.id AS consumer_id,c.automatic_update,c.authorization_revision,
        EXISTS(SELECT 1 FROM certops_management_periods bp WHERE bp.workspace_id=ci.workspace_id
          AND bp.managed_certificate_id=ci.managed_certificate_id AND bp.ended_at IS NULL AND bp.renewal_profile_id IS NOT NULL) AS conflict,
        (SELECT jsonb_build_object('updated',e.metadata->'updated','code',e.metadata->>'code','at',e.created_at)
          FROM certificate_evidence e WHERE e.workspace_id=ct.workspace_id AND e.created_by_agent_id=$2
            AND e.metadata->>'step'='windows-store-iis-consumer' AND e.metadata->>'consumerId'=c.id::text
          ORDER BY e.created_at DESC LIMIT 1) AS last_result
      FROM certificate_targets ct
      LEFT JOIN LATERAL(SELECT * FROM certificate_instances item WHERE item.workspace_id=ct.workspace_id
        AND item.target_id=ct.id ORDER BY captured_at DESC NULLS LAST LIMIT 1) ci ON true
      LEFT JOIN certops_windows_store_renewal_owners o ON o.workspace_id=ct.workspace_id AND o.management_period_id=$3
      LEFT JOIN certops_windows_iis_renewal_consumers c ON c.workspace_id=ct.workspace_id AND c.owner_id=o.id
        AND c.target_id=ct.id AND c.removed_at IS NULL
      WHERE ct.workspace_id=$1 AND ct.source='agent_windows' AND ct.location_kind='iis_binding'
        AND ct.windows_store='My' AND ct.public_metadata->>'agentId'=$4
        AND (ci.observed_fingerprint_sha256=$5 OR c.id IS NOT NULL)
      ORDER BY ct.windows_site,ct.windows_port,ct.id`, [workspaceId,owner.agent_id,owner.period_id,owner.public_agent_id,owner.fingerprint_sha256]);
    const bindings=rows.rows.map(row => {
      const captured=row.captured_at ? new Date(row.captured_at).getTime() : NaN;
      const state=classifyBinding({ owner:{ workspaceId,agentId:owner.agent_id,managementPeriodId:owner.period_id,
        storeName:"My",fingerprintSha256:owner.fingerprint_sha256,managementActive:true,renewalEligible:true },
        binding:{ id:row.id,workspaceId,agentId:owner.agent_id,storeName:row.windows_store,
          fingerprintSha256:row.observed_fingerprint_sha256,presence:row.presence_state,renewalProfileId:row.conflict ? "conflict":null,
          automaticUpdate:row.automatic_update },agentOnline:owner.agent_status === "active" && classifyAgentLiveness(ownerAgentLiveness(owner)) === "live",
        observationFresh:Number.isFinite(captured) && captured<=Date.now() && Date.now()-captured<=86400000 });
      return { targetId:row.id,managedCertificateId:row.managed_certificate_id,consumerId:row.consumer_id,
        site:row.windows_site,port:row.windows_port,sniHost:row.windows_sni_host,automaticUpdate:row.automatic_update === true,
        ...state,lastResult:row.last_result,canEnable:!ambiguous && capable && storeProfile && state.deployment === "observed_only" };
    });
    groups.push({ periodId:owner.period_id,managedCertificateId:owner.managed_certificate_id,agentId:owner.agent_id,
      host:owner.hostname,store:"LocalMachine\\My",profileId:owner.renewal_profile_id,profileName:owner.profile_name,
      bindings,ambiguous,ready:capable && storeProfile && !ambiguous,
      readinessReason:ambiguous ? "Consolidate the duplicate Store registrations first." : !storeProfile ? "Configure renewal on this Windows Store certificate first." :
        !capable ? "IIS automatic updates require a qualified agent build. These bindings are observation only." : null });
  }
  return { groups };
}
function ownerAgentLiveness(owner) { return { lastSeenAt:owner.last_seen_at,createdAt:owner.created_at }; }

function refusal(message) {
  const error = new Error(message);
  error.code = "CERTOPS_WINDOWS_CONSENT_REFUSED";
  error.statusCode = 409;
  return error;
}

// Caller supplies a checked-out client with an open transaction and write
// authorization. The source rows and selector are resolved server-side.
async function enableWindowsIisConsumer({ client, workspaceId, periodId, targetId, actorUserId, audit = writeAudit }) {
  if (!client || !workspaceId || !periodId || !targetId || !Number.isSafeInteger(actorUserId) || actorUserId <= 0) {
    throw refusal("An authorized operator and a Store registration are required.");
  }
  const ownerResult = await client.query(`SELECT p.id AS period_id, p.managed_certificate_id, p.ended_at,
      p.renewal_profile_id, mc.fingerprint_sha256, mc.deployed_agent_id, mc.status AS certificate_status,
      mc.public_metadata, a.agent_id AS agent_public_id, a.status AS agent_status, a.last_seen_at, a.created_at,
      cp.public_metadata AS profile_metadata, a.declared_capabilities,a.capabilities_updated_at
    FROM certops_management_periods p
    JOIN managed_certificates mc ON mc.workspace_id=p.workspace_id AND mc.id=p.managed_certificate_id
    JOIN certops_agents a ON a.workspace_id=mc.workspace_id AND a.id=mc.deployed_agent_id
    JOIN certops_certificate_identities identity ON identity.workspace_id=mc.workspace_id
      AND identity.id=p.current_identity_id AND identity.fingerprint_sha256=certops_normalize_fingerprint(mc.fingerprint_sha256)
      AND identity.lifecycle_status='active'
    LEFT JOIN certificate_profiles cp ON cp.workspace_id=p.workspace_id AND cp.id=p.renewal_profile_id
    WHERE p.workspace_id=$1 AND p.id=$2 FOR UPDATE OF p,mc`, [workspaceId, periodId]);
  const owner = ownerResult.rows[0];
  const targetType = owner?.profile_metadata?.renewalProfile?.target?.type;
  if (!require("./agentJobEligibility").hasFreshCapability({ declaredCapabilities: owner?.declared_capabilities,
    capabilitiesUpdatedAt: owner?.capabilities_updated_at, capability: "windows-store-iis-consumers-v1" })) {
    throw refusal("Update to an agent qualified for Store renewal with dependent IIS updates first.");
  }
  if (!owner || owner.ended_at || targetType !== "windows-cert-store" ||
      owner.profile_metadata?.renewalProfile?.target?.store !== "My" ||
      ["revoked", "decommissioned"].includes(owner.certificate_status)) {
    throw refusal("Configure an active LocalMachine\\My renewal before enabling IIS updates.");
  }
  const targetResult = await client.query(`SELECT ct.id,ct.windows_store,ct.windows_site,ct.windows_port,ct.windows_sni_host,
      ct.public_metadata, ci.observed_fingerprint_sha256, ci.presence_state, ci.captured_at,
      EXISTS (SELECT 1 FROM certops_management_periods bp
        WHERE bp.workspace_id=ci.workspace_id AND bp.managed_certificate_id=ci.managed_certificate_id
          AND bp.ended_at IS NULL AND bp.renewal_profile_id IS NOT NULL) AS profile_conflict
    FROM certificate_targets ct JOIN certificate_instances ci ON ci.workspace_id=ct.workspace_id AND ci.target_id=ct.id
    WHERE ct.workspace_id=$1 AND ct.id=$2 AND ct.source='agent_windows' AND ct.location_kind='iis_binding'
    ORDER BY ci.captured_at DESC NULLS LAST LIMIT 1 FOR UPDATE OF ct,ci`, [workspaceId, targetId]);
  const target = targetResult.rows[0];
  if (!target || target.public_metadata?.agentId !== owner.agent_public_id || !target.windows_site) {
    throw refusal("The IIS binding is not confirmed on the Store agent.");
  }
  const captured = target.captured_at ? new Date(target.captured_at).getTime() : NaN;
  const now = Date.now();
  const decision = classifyBinding({
    owner: { workspaceId, agentId: owner.deployed_agent_id, managementPeriodId: owner.period_id,
      storeName: "My", fingerprintSha256: owner.fingerprint_sha256, managementActive: true, renewalEligible: true },
    binding: { id: target.id, workspaceId, agentId: owner.deployed_agent_id, storeName: target.windows_store,
      fingerprintSha256: target.observed_fingerprint_sha256, presence: target.presence_state,
      renewalProfileId: target.profile_conflict ? "conflict" : null },
    agentOnline: owner.agent_status === "active" && classifyAgentLiveness({ lastSeenAt: owner.last_seen_at, createdAt: owner.created_at }) === "live",
    observationFresh: Number.isFinite(captured) && captured <= now && now - captured <= 24 * 60 * 60 * 1000,
  });
  if (decision.relationship !== "observed" || decision.deployment !== "observed_only") {
    throw refusal(decision.deployment === "conflict" ? "Resolve the existing IIS renewal profile first." :
      "The IIS binding is missing, stale, changed, or cannot be confirmed.");
  }
  const selector = iisSelectorKey({ port: target.windows_port, sniHost: target.windows_sni_host });
  const inFlight = await client.query(`SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND assigned_agent_id=$2
    AND status IN ('pending_approval','approved','pending','claimed','running') AND payload->'target'->>'type'='windows-iis'
    AND payload->'target'->'binding'->>'port'=$3
    AND lower(COALESCE(payload->'target'->'binding'->>'sniHost',''))=lower($4) LIMIT 1`,
    [workspaceId,owner.deployed_agent_id,String(target.windows_port),target.windows_sni_host || ""]);
  if (inFlight.rows[0]) throw refusal("Finish or cancel the existing IIS renewal job before enabling Store updates.");
  await client.query(`UPDATE certops_windows_iis_renewal_consumers c SET automatic_update=false,
      removed_at=clock_timestamp(),authorization_revision=authorization_revision+1
    FROM certops_windows_store_renewal_owners o JOIN certops_management_periods p
      ON p.workspace_id=o.workspace_id AND p.id=o.management_period_id
    WHERE c.workspace_id=$1 AND c.owner_id=o.id AND c.workspace_id=o.workspace_id AND p.ended_at IS NOT NULL
      AND c.agent_id=$2 AND c.selector_key=$3 AND c.removed_at IS NULL`,[workspaceId,owner.deployed_agent_id,selector]);
  const ownerRow = await client.query(`INSERT INTO certops_windows_store_renewal_owners
    (workspace_id,managed_certificate_id,management_period_id,agent_id,store_name) VALUES($1,$2,$3,$4,'My')
    ON CONFLICT (workspace_id,managed_certificate_id,management_period_id) DO UPDATE SET store_name='My'
    WHERE certops_windows_store_renewal_owners.agent_id=EXCLUDED.agent_id RETURNING id`,
  [workspaceId,owner.managed_certificate_id,periodId,owner.deployed_agent_id]);
  if (!ownerRow.rows[0]) throw refusal("The Store registration belongs to another agent.");
  const row = await client.query(`INSERT INTO certops_windows_iis_renewal_consumers
    (workspace_id,owner_id,agent_id,target_id,selector_key,automatic_update,authorized_by,authorized_at)
    VALUES($1,$2,$3,$4,$5,true,$6,clock_timestamp())
    ON CONFLICT (workspace_id,agent_id,selector_key) WHERE removed_at IS NULL
    DO UPDATE SET automatic_update=true, authorized_by=EXCLUDED.authorized_by, authorized_at=EXCLUDED.authorized_at,
      authorization_revision=certops_windows_iis_renewal_consumers.authorization_revision+1
    WHERE certops_windows_iis_renewal_consumers.owner_id=EXCLUDED.owner_id
      AND certops_windows_iis_renewal_consumers.target_id=EXCLUDED.target_id
    RETURNING id,authorization_revision`,
  [workspaceId,ownerRow.rows[0].id,owner.deployed_agent_id,targetId,selector,actorUserId]);
  if (!row.rows[0]) throw refusal("This IIS selector is already managed by another Store registration.");
  await audit({ client, workspaceId, actorUserId, subjectUserId: null, action: "CERTOPS_WINDOWS_IIS_UPDATE_ENABLED",
    targetType: "certificate_target", targetId, metadata: { periodId, consumerId: row.rows[0].id } });
  return { id: row.rows[0].id, authorizationRevision: Number(row.rows[0].authorization_revision) };
}

// Revocation must remain available even if the agent or binding is offline.
// A dispatcher must re-check the revision before authorizing each mutation.
async function disableWindowsIisConsumer({ client, workspaceId, consumerId, actorUserId, audit = writeAudit }) {
  if (!client || !workspaceId || !consumerId || !Number.isSafeInteger(actorUserId) || actorUserId <= 0) {
    throw refusal("An authorized operator and a consumer are required.");
  }
  const updated = await client.query(`UPDATE certops_windows_iis_renewal_consumers
    SET automatic_update=false, authorization_revision=authorization_revision+1
    WHERE workspace_id=$1 AND id=$2 AND removed_at IS NULL RETURNING id,target_id,authorization_revision`,
  [workspaceId, consumerId]);
  if (!updated.rows[0]) throw refusal("The IIS consumer does not exist.");
  await audit({ client, workspaceId, actorUserId, subjectUserId: null, action: "CERTOPS_WINDOWS_IIS_UPDATE_DISABLED",
    targetType: "certificate_target", targetId: updated.rows[0].target_id, metadata: { consumerId } });
  return { id: updated.rows[0].id, authorizationRevision: Number(updated.rows[0].authorization_revision) };
}

// The caller must authenticate the agent credential before invoking this check.
// A consumer is valid only for the exact active job claim and frozen revision.
async function authorizeWindowsIisConsumer({ client, agent, jobId, claimId, consumerId, authorizationRevision }) {
  if (!client || !agent?.id || !agent?.workspaceId || !jobId || !claimId || !consumerId ||
      !Number.isSafeInteger(authorizationRevision) || authorizationRevision < 1) return false;
  const result = await client.query(`SELECT c.selector_key,ct.windows_port,ct.windows_sni_host
    FROM certops_windows_iis_renewal_consumers c
    JOIN certops_windows_store_renewal_owners o ON o.workspace_id=c.workspace_id AND o.id=c.owner_id AND o.agent_id=c.agent_id
    JOIN certops_management_periods p ON p.workspace_id=o.workspace_id AND p.id=o.management_period_id
    JOIN certificate_targets ct ON ct.workspace_id=c.workspace_id AND ct.id=c.target_id
    JOIN certops_agents a ON a.workspace_id=c.workspace_id AND a.id=c.agent_id
    JOIN workspaces w ON w.id=c.workspace_id AND w.certops_paused=false
    JOIN certificate_jobs j ON j.workspace_id=c.workspace_id AND j.id=$3
    LEFT JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.id=j.enrollment_id
      AND e.agent_id=c.agent_id AND e.certificate_id=o.managed_certificate_id
    LEFT JOIN certops_acme_store_enrollments acme ON acme.workspace_id=j.workspace_id AND acme.current_job_id=j.id
      AND acme.agent_id=c.agent_id AND acme.certificate_id=o.managed_certificate_id
    WHERE c.workspace_id=$1 AND c.id=$2 AND c.agent_id=$4 AND c.automatic_update=true
      AND c.removed_at IS NULL AND c.authorization_revision=$5 AND p.ended_at IS NULL
      AND a.status='active' AND ct.source='agent_windows' AND ct.location_kind='iis_binding'
      AND ct.windows_store='My' AND ct.public_metadata->>'agentId'=a.agent_id
      AND j.management_period_id=p.id AND j.operation IN ('renew','continue-enrollment') AND j.status IN ('claimed','running')
      AND j.claimed_by_agent_id=$4 AND j.claim_id=$6 AND j.lease_expires_at > clock_timestamp()
      AND j.payload->'target'->>'type'='windows-cert-store'
      AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(convert_from(e.snapshot_bytes,'UTF8')::jsonb->'iisConsumers',
        convert_from(acme.request_bytes,'UTF8')::jsonb->'iisConsumers','[]'::jsonb)) item
        WHERE item->>'consumerId'=c.id::text AND item->>'authorizationRevision'=c.authorization_revision::text)
      AND NOT EXISTS (SELECT 1 FROM certificate_instances ci JOIN certops_management_periods bp
        ON bp.workspace_id=ci.workspace_id AND bp.managed_certificate_id=ci.managed_certificate_id
        WHERE ci.workspace_id=c.workspace_id AND ci.target_id=c.target_id AND bp.ended_at IS NULL
          AND bp.renewal_profile_id IS NOT NULL)
    LIMIT 1`, [agent.workspaceId,consumerId,jobId,agent.id,authorizationRevision,claimId]);
  const row = result.rows[0];
  if (!row) return false;
  try { return iisSelectorKey({ port: row.windows_port, sniHost: row.windows_sni_host }) === row.selector_key; }
  catch { return false; }
}

// Resolve a server-owned immutable list before a Store renewal is signed.
// Missing, stale or conflicting bindings never prevent Store renewal.
async function snapshotWindowsIisConsumers({ client, workspaceId, certificateId, agentId }) {
  const result = await client.query(`SELECT c.id AS consumer_id,c.authorization_revision,c.selector_key,
      o.id AS owner_id,o.management_period_id,mc.fingerprint_sha256,mc.status AS certificate_status,
      a.status AS agent_status,a.last_seen_at,a.created_at,a.agent_id AS agent_public_id,
      ct.id AS target_id,ct.windows_store,ct.windows_site,ct.windows_port,ct.windows_sni_host,ct.public_metadata,
      ci.observed_fingerprint_sha256,ci.presence_state,ci.captured_at,
      EXISTS (SELECT 1 FROM certificate_instances conflict_ci JOIN certops_management_periods bp
        ON bp.workspace_id=conflict_ci.workspace_id AND bp.managed_certificate_id=conflict_ci.managed_certificate_id
        WHERE conflict_ci.workspace_id=c.workspace_id AND conflict_ci.target_id=c.target_id
          AND bp.ended_at IS NULL AND bp.renewal_profile_id IS NOT NULL) AS profile_conflict
    FROM certops_windows_iis_renewal_consumers c
    JOIN certops_windows_store_renewal_owners o ON o.workspace_id=c.workspace_id AND o.id=c.owner_id AND o.agent_id=c.agent_id
    JOIN certops_management_periods p ON p.workspace_id=o.workspace_id AND p.id=o.management_period_id AND p.ended_at IS NULL
    JOIN managed_certificates mc ON mc.workspace_id=o.workspace_id AND mc.id=o.managed_certificate_id AND mc.deployed_agent_id=o.agent_id
    JOIN certops_certificate_identities identity ON identity.workspace_id=mc.workspace_id AND identity.id=p.current_identity_id
      AND identity.fingerprint_sha256=certops_normalize_fingerprint(mc.fingerprint_sha256) AND identity.lifecycle_status='active'
    JOIN certops_agents a ON a.workspace_id=c.workspace_id AND a.id=c.agent_id
    JOIN certificate_targets ct ON ct.workspace_id=c.workspace_id AND ct.id=c.target_id
    LEFT JOIN LATERAL (SELECT * FROM certificate_instances item WHERE item.workspace_id=c.workspace_id
      AND item.target_id=c.target_id ORDER BY item.captured_at DESC NULLS LAST LIMIT 1) ci ON true
    WHERE c.workspace_id=$1 AND o.managed_certificate_id=$2 AND c.agent_id=$3
      AND c.automatic_update=true AND c.removed_at IS NULL AND ct.source='agent_windows'
      AND ct.location_kind='iis_binding' AND ct.target_type='windows-iis'
    ORDER BY c.id LIMIT 33 FOR SHARE OF c`, [workspaceId,certificateId,agentId]);
  if (result.rows.length > 32) throw refusal("A Store renewal supports at most 32 IIS bindings.");
  const now=Date.now(), items=[];
  for (const row of result.rows) {
    if (row.public_metadata?.agentId !== row.agent_public_id || !row.windows_site || row.certificate_status === "revoked" || row.certificate_status === "decommissioned") continue;
    const captured=row.captured_at ? new Date(row.captured_at).getTime() : NaN;
    const binding={ address:"*",store:"My",site:row.windows_site,port:row.windows_port,
      ...(row.windows_sni_host ? { sniHost:row.windows_sni_host } : {}) };
    let selector;
    try { selector=iisSelectorKey(binding); } catch { continue; }
    if (selector !== row.selector_key) continue;
    const state=classifyBinding({
      owner:{ workspaceId,agentId,managementPeriodId:row.management_period_id,storeName:"My",
        fingerprintSha256:row.fingerprint_sha256,managementActive:true,renewalEligible:true },
      binding:{ id:row.target_id,workspaceId,agentId,storeName:row.windows_store,
        fingerprintSha256:row.observed_fingerprint_sha256,presence:row.presence_state,
        renewalProfileId:row.profile_conflict ? "conflict" : null,automaticUpdate:true },
      agentOnline:row.agent_status === "active" && classifyAgentLiveness({ lastSeenAt:row.last_seen_at,createdAt:row.created_at }) === "live",
      observationFresh:Number.isFinite(captured) && captured <= now && now-captured <= 24*60*60*1000,
    });
    if (state.deployment !== "authorized") continue;
    const revision=Number(row.authorization_revision);
    if (!Number.isSafeInteger(revision) || revision < 1) continue;
    items.push({ consumerId:row.consumer_id,authorizationRevision:revision,binding });
  }
  return items;
}

// Re-check the current credential and anti-replay sequence in the same
// transaction as the live consent lookup. A denial is a normal response.
async function checkWindowsIisConsumerForAgent({ dbPool, agent, jobId, claimId, consumerId, authorizationRevision, sequence }) {
  const { pool } = require("../../db/database");
  const { enforceAgentSequence } = require("./agentDispatch");
  const { assertCurrentAgentCredential } = require("./agentCredentialFence");
  const client = await (dbPool || pool).connect();
  try {
    await client.query("BEGIN");
    await assertCurrentAgentCredential({ client, agent });
    await enforceAgentSequence({ client, agentRowId: agent.id, envelope: { sequence } });
    const allowed = await authorizeWindowsIisConsumer({ client, agent, jobId, claimId, consumerId, authorizationRevision });
    await client.query("COMMIT");
    return { allowed };
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* preserve original error */ }
    throw error;
  } finally { client.release(); }
}

async function setWindowsIisConsumer({ workspaceId, periodId, targetId, enabled, actorUserId, dbPool = pool }) {
  const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
  if (!uuid.test(periodId || "") || !uuid.test(targetId || "") || typeof enabled !== "boolean") throw refusal("Select a Store registration and IIS binding.");
  const client=await dbPool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`windows-iis-consent:${workspaceId}`]);
    let result;
    if (enabled) result=await enableWindowsIisConsumer({ client,workspaceId,periodId,targetId,actorUserId });
    else {
      const row=(await client.query(`SELECT c.id FROM certops_windows_iis_renewal_consumers c
        JOIN certops_windows_store_renewal_owners o ON o.workspace_id=c.workspace_id AND o.id=c.owner_id
        WHERE c.workspace_id=$1 AND o.management_period_id=$2 AND c.target_id=$3 AND c.removed_at IS NULL`, [workspaceId,periodId,targetId])).rows[0];
      if (!row) throw refusal("The IIS consumer does not exist.");
      result=await disableWindowsIisConsumer({ client,workspaceId,consumerId:row.id,actorUserId });
    }
    await client.query("COMMIT"); return result;
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}

async function assertIndependentIisTarget({ client, workspaceId, agentId, target }) {
  if (target?.type !== "windows-iis" || !agentId) return;
  const selector=iisSelectorKey(target.binding);
  const row=(await client.query(`SELECT c.id FROM certops_windows_iis_renewal_consumers c
    JOIN certops_windows_store_renewal_owners o ON o.workspace_id=c.workspace_id AND o.id=c.owner_id
    JOIN certops_management_periods p ON p.workspace_id=o.workspace_id AND p.id=o.management_period_id AND p.ended_at IS NULL
    WHERE c.workspace_id=$1 AND c.agent_id=$2 AND c.selector_key=$3 AND c.removed_at IS NULL LIMIT 1`,[workspaceId,agentId,selector])).rows[0];
  if (row) throw refusal("Renewal is managed by the Windows Store registration. Update the Store certificate instead.");
}

module.exports = { listWindowsRenewal, setWindowsIisConsumer, assertIndependentIisTarget, enableWindowsIisConsumer, disableWindowsIisConsumer, authorizeWindowsIisConsumer, snapshotWindowsIisConsumers, checkWindowsIisConsumerForAgent };
