"use strict";

const { pool } = require("../../db/database");
const { acquireManagedCertificateImportLock } = require("./inventory");
const { stopManagingSource, readdManagingSource } = require("./certificateIdentity");
const { classifyAgentLiveness } = require("./agentLiveness");
const { X509Certificate } = require("node:crypto");
const { writeAudit } = require("../audit");

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
function refuse(message) {
  const error = new Error(message);
  error.code = "CERTOPS_WINDOWS_REASSOCIATION_REFUSED";
  throw error;
}

// The operator must name both sources and the exact current fingerprint.
// A CN, an old source fingerprint or a client-supplied binding is not proof.
async function reassociateWindowsStore({ dbPool = pool, workspaceId, legacyId, currentId,
  legacyPeriodId, currentPeriodId, agentId, expectedFingerprintSha256, expectedDnsName,
  actorUserId }) {
  if (![workspaceId, legacyId, currentId, legacyPeriodId, currentPeriodId, agentId].every((v) => UUID.test(String(v || ""))) ||
      legacyId === currentId || !SHA256.test(expectedFingerprintSha256 || "") ||
      typeof expectedDnsName !== "string" || !expectedDnsName.trim() ||
      !Number.isSafeInteger(actorUserId) || actorUserId <= 0) refuse("Select two sources, the owning agent, the exact SHA-256 fingerprint and DNS name.");
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    // Match agent evidence ingestion's order: agent row, workspace import lock,
    // store lock, then certificate/period rows.
    const a = (await client.query(`SELECT id,agent_id,status,last_seen_at,created_at,declared_target_selectors
      FROM certops_agents WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, [workspaceId, agentId])).rows[0];
    if (!a || a.status !== "active" || classifyAgentLiveness({ lastSeenAt: a.last_seen_at, createdAt: a.created_at }) !== "live")
      refuse("The owning agent must be online.");
    await acquireManagedCertificateImportLock(client, workspaceId);
    const candidates = (await client.query(`SELECT mc.id,mc.source,mc.source_ref,mc.deployed_agent_id,mc.fingerprint_sha256,mc.certificate_pem,mc.status,mc.key_mode,mc.key_reference,
      p.id AS period_id,p.renewal_profile_id,p.automation_enabled,cp.public_metadata AS profile_metadata,identity.lifecycle_status AS identity_status
      FROM managed_certificates mc JOIN certops_management_periods p ON p.workspace_id=mc.workspace_id AND p.managed_certificate_id=mc.id AND p.ended_at IS NULL
      LEFT JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=p.renewal_profile_id
      LEFT JOIN certops_certificate_identities identity ON identity.workspace_id=p.workspace_id AND identity.id=p.current_identity_id
        AND identity.fingerprint_sha256=certops_normalize_fingerprint(mc.fingerprint_sha256)
      WHERE mc.workspace_id=$1 AND mc.id=ANY($2::uuid[]) ORDER BY mc.id FOR UPDATE OF mc,p`, [workspaceId, [legacyId, currentId]])).rows;
    const old = candidates.find((row) => row.id === legacyId);
    const current = candidates.find((row) => row.id === currentId);
    const profile = old?.profile_metadata?.renewalProfile;
    const isIis = profile?.target?.type === "windows-iis";
    if (!isIis) refuse("Only IIS renewal profiles can be reassociated by this workflow.");
    if (!old || !current || old.period_id !== legacyPeriodId || current.period_id !== currentPeriodId ||
        old.source !== "agent_windows" || !String(old.source_ref || "").includes("/windows_store/") ||
        current.source !== "agent_windows" || !(isIis ? String(current.source_ref || "").includes("/iis_binding/") : /\/windows_store_v2\/LocalMachine\/My\/sha256-[a-f0-9]{64}$/.test(current.source_ref || "")) ||
        old.deployed_agent_id !== agentId || current.deployed_agent_id !== agentId ||
        current.fingerprint_sha256 !== expectedFingerprintSha256 || (!isIis && !current.source_ref.endsWith(`/sha256-${expectedFingerprintSha256}`)) ||
        current.key_mode !== "os-store-managed" || !String(current.key_reference || "").startsWith("winstore://LocalMachine/My/") ||
        ["revoked", "decommissioned"].includes(current.status) || current.identity_status !== "active" || !old.renewal_profile_id || !old.automation_enabled ||
        current.renewal_profile_id || current.automation_enabled) refuse("The selected sources changed or do not identify the same agent and My store.");
    const dns = expectedDnsName.trim().toLowerCase();
    if (!(["windows-cert-store", "windows-iis"].includes(profile?.target?.type)) || profile.target.store !== "My" ||
        (isIis && (!profile.target.binding?.site || !Number.isInteger(profile.target.binding?.port))) ||
        String(profile.target.reference || "").toLowerCase() !== dns ||
        !Array.isArray(profile.sanPolicy?.sans) || !profile.sanPolicy.sans.some((name) => String(name).toLowerCase() === dns) ||
        !Array.isArray(a.declared_target_selectors) || !a.declared_target_selectors.some((name) => String(name).toLowerCase() === dns))
      refuse("The profile DNS, target or agent authorization no longer matches.");
    const evidence = await client.query(`SELECT ci.id, e.metadata->>'subjectAltNames' AS observed_sans FROM certificate_instances ci
      JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id
      JOIN certificate_evidence e ON e.workspace_id=ci.workspace_id AND e.created_by_agent_id=$4
        AND e.evidence_type='certificate.observed' AND e.metadata->>'managedCertificateId'=$2::text
        AND e.metadata->>'fingerprintSha256'=$3 AND e.metadata->>'locationKind'=$6
      WHERE ci.workspace_id=$1 AND ci.managed_certificate_id=$2::uuid AND ci.observed_fingerprint_sha256=$3
        AND ci.presence_state='confirmed_present' AND ci.captured_at BETWEEN clock_timestamp()-interval '24 hours' AND clock_timestamp()
        AND ct.location_kind=$6 AND ct.windows_store='My' AND ct.public_metadata->>'agentId'=$5
        AND ($6 <> 'iis_binding' OR (ct.windows_site=$7 AND ct.windows_port=$8
          AND lower(COALESCE(ct.windows_sni_host,''))=lower(COALESCE($9,''))))
        AND e.metadata->>'targetId'=ct.id::text AND e.metadata->>'certificateInstanceId'=ci.id::text
        AND e.created_at BETWEEN clock_timestamp()-interval '24 hours' AND clock_timestamp()
      LIMIT 1 FOR UPDATE OF ci,ct`, [workspaceId,currentId,expectedFingerprintSha256,agentId,a.agent_id,
        isIis ? "iis_binding" : "windows_store", isIis ? profile.target.binding.site : null,
        isIis ? profile.target.binding.port : null, isIis ? profile.target.binding.sniHost || "" : null]);
    if (!evidence.rows.length) refuse("The owning agent must freshly observe this fingerprint at the exact configured target.");
    if (current.certificate_pem) {
      try {
        const leaf = new X509Certificate(current.certificate_pem);
        if (leaf.fingerprint256.replaceAll(":", "").toLowerCase() !== expectedFingerprintSha256 ||
            !leaf.checkHost(dns, { subject: "never" })) refuse("The certificate fingerprint or DNS SAN does not match.");
      } catch (error) {
        if (error.code === "CERTOPS_WINDOWS_REASSOCIATION_REFUSED") throw error;
        refuse("The public certificate could not be validated.");
      }
    } else {
      // Existing agents send SANs and fingerprint together in the authenticated
      // observation, but do not send certificate bytes. Require an exact DNS
      // SAN from that same fresh observation; never infer it from the CN.
      let sans;
      try { sans = JSON.parse(evidence.rows[0].observed_sans || "null"); } catch (_) { sans = null; }
      if (!Array.isArray(sans) || !sans.some((name) => typeof name === "string" && name.toLowerCase() === dns))
        refuse("The fresh observation must include the exact authorized DNS SAN.");
    }
    const busy = await client.query(`SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND subject_type='managed_certificate'
      AND subject_id=ANY($2::text[]) AND status IN ('pending_approval','approved','pending','claimed','running','orphaned_unknown_effect') LIMIT 1`, [workspaceId,[legacyId,currentId]]);
    if (busy.rows.length) refuse("Finish or cancel outstanding jobs on both sources first.");
    const enrollment = await client.query(`SELECT 1 FROM certificate_enrollments WHERE workspace_id=$1
      AND certificate_id=ANY($2::uuid[]) AND state NOT IN
      ('installed','denied','rejected_invalid','validation_expired','refused','abandoned','expired','cancelled') LIMIT 1`,
      [workspaceId,[legacyId,currentId]]);
    if (enrollment.rows.length) refuse("Resolve pending certificate enrollment before moving this profile.");
    const sharedProfile = await client.query(`SELECT 1 FROM certops_management_periods
      WHERE workspace_id=$1 AND renewal_profile_id=$2 AND ended_at IS NULL AND id<>$3 LIMIT 1`,
      [workspaceId,old.renewal_profile_id,legacyPeriodId]);
    if (sharedProfile.rows.length) refuse("This profile is used by another registration and cannot be moved automatically.");
    await stopManagingSource({ client, workspaceId, periodId: legacyPeriodId, actorUserId });
    await stopManagingSource({ client, workspaceId, periodId: currentPeriodId, actorUserId });
    const replacement = await readdManagingSource({ client, workspaceId, managedCertificateId: currentId,
      renewalProfileId: old.renewal_profile_id, automationEnabled: true, actorUserId });
    await writeAudit({ client, actorUserId, subjectUserId: actorUserId,
      action: "CERTOPS_WINDOWS_STORE_REASSOCIATED", targetType: "managed_certificate", targetId: null, workspaceId,
      metadata: { legacyId,currentId,legacyPeriodId,currentPeriodId,newPeriodId:replacement.periodId,agentId,
        fingerprintSha256:expectedFingerprintSha256,dnsName:dns,profileId:old.renewal_profile_id } });
    await client.query("COMMIT");
    return { managedCertificateId: currentId, periodId: replacement.periodId };
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}

async function listIisReassociationCandidates({ client = pool, workspaceId, legacyId }) {
  if (!UUID.test(String(workspaceId || "")) || !UUID.test(String(legacyId || ""))) refuse("Select a valid registration.");
  const result = await client.query(`SELECT DISTINCT ON (mc.id) oldp.id AS legacy_period_id, a.id AS agent_id,
      cp.public_metadata->'renewalProfile'->'target'->>'reference' AS dns_name,
      ct.windows_site,ct.windows_port,ct.windows_sni_host,mc.id AS current_id,
      p.id AS current_period_id,mc.fingerprint_sha256,ct.hostname,ci.captured_at
    FROM managed_certificates old
    JOIN certops_management_periods oldp ON oldp.workspace_id=old.workspace_id AND oldp.managed_certificate_id=old.id AND oldp.ended_at IS NULL
    JOIN certificate_profiles cp ON cp.workspace_id=old.workspace_id AND cp.id=oldp.renewal_profile_id
    JOIN certops_agents a ON a.workspace_id=old.workspace_id AND a.id=old.deployed_agent_id
    JOIN certificate_targets ct ON ct.workspace_id=old.workspace_id AND ct.source='agent_windows'
      AND ct.location_kind='iis_binding' AND ct.windows_store='My' AND ct.public_metadata->>'agentId'=a.agent_id
      AND ct.windows_site=cp.public_metadata->'renewalProfile'->'target'->'binding'->>'site'
      AND ct.windows_port::text=cp.public_metadata->'renewalProfile'->'target'->'binding'->>'port'
      AND lower(COALESCE(ct.windows_sni_host,''))=lower(COALESCE(cp.public_metadata->'renewalProfile'->'target'->'binding'->>'sniHost',''))
    JOIN certificate_instances ci ON ci.workspace_id=ct.workspace_id AND ci.target_id=ct.id
      AND ci.presence_state='confirmed_present' AND ci.captured_at BETWEEN clock_timestamp()-interval '24 hours' AND clock_timestamp()
    JOIN managed_certificates mc ON mc.workspace_id=ci.workspace_id AND mc.id=ci.managed_certificate_id
      AND mc.deployed_agent_id=a.id AND mc.fingerprint_sha256=ci.observed_fingerprint_sha256
    JOIN certops_management_periods p ON p.workspace_id=mc.workspace_id AND p.managed_certificate_id=mc.id AND p.ended_at IS NULL
    WHERE old.workspace_id=$1 AND old.id=$2::uuid AND old.source='agent_windows'
      AND position('/windows_store/' in COALESCE(old.source_ref,''))>0
      AND cp.public_metadata->'renewalProfile'->'target'->>'type'='windows-iis'
      AND p.renewal_profile_id IS NULL AND NOT p.automation_enabled
    ORDER BY mc.id,ci.captured_at DESC LIMIT 50`, [workspaceId, legacyId]);
  return result.rows.map(row => ({ legacyPeriodId:row.legacy_period_id,agentId:row.agent_id,
    expectedDnsName:row.dns_name,currentId:row.current_id,currentPeriodId:row.current_period_id,
    expectedFingerprintSha256:row.fingerprint_sha256,host:row.hostname,site:row.windows_site,
    port:row.windows_port,sniHost:row.windows_sni_host,observedAt:row.captured_at }));
}

module.exports = { reassociateWindowsStore, listIisReassociationCandidates };
