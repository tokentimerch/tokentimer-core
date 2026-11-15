import { pagerDutyDestinationId } from "./webhookDestinations.js";
import { resolveContactGroupsForAsset, getWebhookNames } from "./contactGroups.js";
import crypto from "node:crypto";

const retryMs = attempt => Math.min(60_000 * 2 ** Math.max(0, attempt - 1), 3_600_000);
const lockName = (incidentId, destinationId) => `distribution-pagerduty:${incidentId}:${destinationId}`;

// Hold a session advisory lock over HTTP, but never a database transaction.
// Recording uncertainty first protects a trigger whose response is lost.
export async function deliverDistributionPagerDutyTrigger(client, { alert, webhook, payload, send }) {
  const incidentId = alert.distributionContext?.incidentId;
  const destinationId = pagerDutyDestinationId(alert.workspace_id, webhook);
  if (!incidentId || !destinationId) return { success: false, error: "invalid_distribution_destination" };
  const lock = lockName(incidentId, destinationId);
  if (!(await client.query("SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS owned", [lock])).rows[0]?.owned)
    return { success: false, error: "distribution_destination_busy" };
  try {
    const active = await client.query("SELECT 1 FROM certops_distribution_incidents WHERE workspace_id=$1 AND id=$2 AND resolved_at IS NULL", [alert.workspace_id, incidentId]);
    if (!active.rowCount) return { success: true, skipped: true };
    await client.query(`INSERT INTO certops_distribution_pagerduty(workspace_id,incident_id,destination_id,trigger_delivery_uncertain)
      VALUES($1,$2,$3,TRUE) ON CONFLICT(workspace_id,incident_id,destination_id)
      DO UPDATE SET trigger_delivery_uncertain=(certops_distribution_pagerduty.trigger_accepted_at IS NULL),historical_resolution_at=NULL`, [alert.workspace_id,incidentId,destinationId]);
    let result;
    try { result = await send(String(webhook.url).trim(), payload, "pagerduty"); }
    catch { result = { success: false }; }
    if (result?.success) await client.query(`UPDATE certops_distribution_pagerduty SET
      trigger_accepted_at=COALESCE(trigger_accepted_at,clock_timestamp()),trigger_delivery_uncertain=FALSE
      WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3`, [alert.workspace_id,incidentId,destinationId]);
    return result || { success: false, error: "pagerduty_transport_failure" };
  } finally {
    await client.query("SELECT pg_advisory_unlock(hashtextextended($1,0))", [lock]);
  }
}

// A resolved PagerDuty destination can outlive the ordinary queue's retry limit.
// Reconcile only proven endpoints, and never take over an in-flight claim or
// clear another channel's failure. Repeating this sweep repairs a crash or a
// queue worker that finishes its claim after the recovery request succeeded.
async function settleRecoveredDistributionAlerts(client, batchSize, canRecover) {
  const candidates = await client.query(`SELECT DISTINCT aq.id
    FROM alert_queue aq
    JOIN certops_agents a ON a.id=aq.certops_agent_id
    JOIN certops_distribution_pagerduty p ON p.workspace_id=a.workspace_id AND p.incident_id::text=aq.metadata->>'incidentId'
    WHERE aq.alert_key LIKE 'cert_distribution:%' AND aq.metadata->>'transition'='resolved'
      AND aq.status='blocked' AND aq.delivery_claim_id IS NULL AND aq.error_message LIKE '%MAX_ATTEMPTS%'
      AND p.resolved_at IS NOT NULL AND (
        (aq.channels->'version'='1'::jsonb AND jsonb_typeof(aq.channels->'required')='array'
          AND jsonb_typeof(aq.channels->'retry')='array' AND jsonb_typeof(aq.channels->'outcomes'->'webhooks'->'endpoints')='object'
          AND aq.channels->'outcomes'->'webhooks'->'endpoints'->>p.destination_id IN ('pending','failed'))
        OR (aq.metadata->>'pagerdutyRecoveryRequeued'='true' AND
          (aq.channels='["webhooks"]'::jsonb OR (aq.channels->'required'='["webhooks"]'::jsonb
            AND aq.channels->'retry' IN ('[]'::jsonb,'["webhooks"]'::jsonb) AND aq.channels->'outcomes'->'webhooks'->'endpoints'='{}'::jsonb))
          AND aq.error_message LIKE '%No webhook names defined in the selected contact group%'
          AND (aq.next_attempt_at IS NULL OR aq.next_attempt_at<=clock_timestamp()))
        OR (aq.channels='["webhooks"]'::jsonb AND aq.metadata->>'pagerdutyRecoveryRequeued' IS DISTINCT FROM 'true'
          AND (aq.next_attempt_at IS NULL OR aq.next_attempt_at<=clock_timestamp())
          AND NOT EXISTS (SELECT 1 FROM certops_distribution_pagerduty pending
            WHERE pending.workspace_id=p.workspace_id AND pending.incident_id=p.incident_id AND pending.resolved_at IS NULL))
      )
    ORDER BY aq.id LIMIT $1`, [batchSize]);
  for (const { id } of candidates.rows) {
    await client.query("BEGIN");
    try {
      const queue = (await client.query(`SELECT aq.channels,aq.metadata,aq.error_message,a.workspace_id
        FROM alert_queue aq JOIN certops_agents a ON a.id=aq.certops_agent_id
        WHERE aq.id=$1 AND aq.status='blocked' AND aq.delivery_claim_id IS NULL AND aq.error_message LIKE '%MAX_ATTEMPTS%'
        FOR UPDATE OF aq SKIP LOCKED`, [id])).rows[0];
      if (!queue) { await client.query("COMMIT"); continue; }
      const ledger = queue.channels;
      if (queue.metadata?.pagerdutyRecoveryRequeued === true && String(queue.error_message || "").includes("No webhook names defined in the selected contact group") &&
          (JSON.stringify(ledger) === '["webhooks"]' || (JSON.stringify(ledger?.required) === '["webhooks"]' &&
          ['[]','["webhooks"]'].includes(JSON.stringify(ledger?.retry)) && JSON.stringify(ledger?.outcomes?.webhooks?.endpoints) === '{}'))) {
        const settings = (await client.query(`SELECT ws.contact_groups,ws.default_contact_group_id,ws.webhook_urls,policy.policy
          FROM certops_distribution_incidents i
          JOIN certops_distribution_policies policy ON policy.workspace_id=i.workspace_id AND policy.group_id=i.group_id
          JOIN workspace_settings ws ON ws.workspace_id=i.workspace_id
          WHERE i.workspace_id=$1 AND i.id::text=$2`,[queue.workspace_id,queue.metadata?.incidentId])).rows[0];
        const groups = resolveContactGroupsForAsset({contactGroups:settings?.contact_groups,
          assignedIds:settings?.policy?.alerts?.contactGroupIds,defaultContactGroupId:settings?.default_contact_group_id});
        const names = new Set(groups.flatMap(group => getWebhookNames(group)));
        const recovered = await client.query(`SELECT destination_id FROM certops_distribution_pagerduty
          WHERE workspace_id=$1 AND incident_id::text=$2 AND resolved_at IS NOT NULL`,[queue.workspace_id,queue.metadata?.incidentId]);
        const ids = new Set(recovered.rows.map(row => row.destination_id));
        const hooks = Array.isArray(settings?.webhook_urls) ? settings.webhook_urls : [];
        const selected = hooks.filter(hook => names.has(String(hook?.name || "").trim()));
        const selectedNames = new Set(selected.map(hook => String(hook?.name || "").trim()));
        const eligible = names.size > 0 && selectedNames.size === names.size && selected.every(hook => ids.has(pagerDutyDestinationId(queue.workspace_id,hook)));
        const fingerprint = crypto.createHash("sha256").update(JSON.stringify([settings?.contact_groups,settings?.default_contact_group_id,settings?.webhook_urls,settings?.policy?.alerts])).digest("hex");
        if (eligible && settings?.policy?.alerts?.enabled === true && queue.metadata?.pagerdutyRecoveryRetryFingerprint !== fingerprint &&
            await canRecover(client,{workspace_id:queue.workspace_id})) {
          await client.query(`UPDATE alert_queue SET status='pending',attempts_webhooks=0,next_attempt_at=clock_timestamp(),
            channels=CASE WHEN jsonb_typeof(channels)='object' THEN jsonb_set(channels,'{retry}','["webhooks"]'::jsonb,true) ELSE channels END,
            metadata=jsonb_set(metadata,'{pagerdutyRecoveryRetryFingerprint}',to_jsonb($2::text),true),updated_at=clock_timestamp() WHERE id=$1`,[id,fingerprint]);
        } else await client.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp()+interval '5 minutes' WHERE id=$1",[id]);
        await client.query("COMMIT"); continue;
      }
      if (Array.isArray(ledger)) {
        // Legacy retry arrays have no per-endpoint proof. Requeue only the
        // single-channel case once; the ordinary worker settles actual targets.
        if (ledger.length !== 1 || ledger[0] !== "webhooks" || queue.metadata?.pagerdutyRecoveryRequeued === true) {
          await client.query("COMMIT"); continue;
        }
        const policyEnabled = (await client.query(`SELECT 1 FROM certops_distribution_incidents i
          JOIN certops_distribution_policies policy ON policy.workspace_id=i.workspace_id AND policy.group_id=i.group_id
          WHERE i.workspace_id=$1 AND i.id::text=$2 AND policy.policy->'alerts'->>'enabled'='true'`,
        [queue.workspace_id,queue.metadata?.incidentId])).rowCount > 0;
        if (!policyEnabled || !(await canRecover(client,{workspace_id:queue.workspace_id}))) {
          await client.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp()+interval '5 minutes' WHERE id=$1",[id]);
          await client.query("COMMIT"); continue;
        }
        await client.query(`UPDATE alert_queue SET status='pending',attempts_webhooks=0,next_attempt_at=clock_timestamp(),
          metadata=jsonb_set(metadata,'{pagerdutyRecoveryRequeued}','true'::jsonb,true),updated_at=clock_timestamp() WHERE id=$1`,[id]);
        await client.query("COMMIT"); continue;
      }
      const webhook = ledger?.outcomes?.webhooks;
      if (!ledger || ledger.version !== 1 || !Array.isArray(ledger.required) || !Array.isArray(ledger.retry) ||
          !webhook?.endpoints || typeof webhook.endpoints !== "object" || Array.isArray(webhook.endpoints)) {
        await client.query("COMMIT"); continue;
      }
      const recovered = await client.query(`SELECT destination_id FROM certops_distribution_pagerduty
        WHERE workspace_id=$1 AND incident_id::text=$2 AND resolved_at IS NOT NULL`,
      [queue.workspace_id,queue.metadata?.incidentId]);
      let changed = false;
      for (const { destination_id: destination } of recovered.rows) {
        if (["pending","failed"].includes(webhook.endpoints[destination])) {
          webhook.endpoints[destination] = "sent";
          changed = true;
        }
      }
      if (!changed) { await client.query("COMMIT"); continue; }
      const endpoints = Object.values(webhook.endpoints);
      const allWebhooksSent = endpoints.length > 0 && endpoints.every(state => state === "sent");
      if (allWebhooksSent) {
        Object.assign(webhook,{state:"sent",terminal:true,reason:null,code:null});
        ledger.retry = ledger.retry.filter(channel => channel !== "webhooks");
      } else {
        const remaining = endpoints.filter(state => state !== "sent");
        const terminal = remaining.every(state => state === "permanent");
        Object.assign(webhook,{state:"partial",terminal,reason:terminal ? "provider" : null});
      }
      const allSent = allWebhooksSent && ledger.required.includes("webhooks") && ledger.required.length > 0 &&
        ledger.required.every(channel => ledger.outcomes?.[channel]?.state === "sent") &&
        ledger.retry.every(channel => ledger.outcomes?.[channel]?.state === "sent");
      await client.query(`UPDATE alert_queue SET channels=$2::jsonb,
        status=CASE WHEN $3 THEN 'sent' ELSE status END,
        error_message=CASE WHEN $3 THEN NULL ELSE error_message END,
        attempts_webhooks=CASE WHEN $4 THEN 0 ELSE attempts_webhooks END,
        next_attempt_at=CASE WHEN $3 THEN NULL ELSE next_attempt_at END,updated_at=clock_timestamp()
        WHERE id=$1`, [id,JSON.stringify(ledger),allSent,allWebhooksSent]);
      if (allSent) await client.query(`UPDATE operational_notifications SET resolved_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE workspace_id=$1 AND dedupe_key=ANY($2::text[]) AND resolved_at IS NULL`,
      [queue.workspace_id,[`delivery_blocked:${id}`,`delivery_degraded:${id}`]]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }
}

// Recovery is independent of today's groups. A removed or
// rotated integration is parked until its exact original configuration returns.
// An uncertain trigger can have reached PagerDuty: resolve the same dedup key
// without claiming the trigger was accepted. Retry unresolved sends with backoff.
export async function reconcileDistributionPagerDuty(client, { send, batchSize = 100, canRecover = () => true } = {}) {
  const due = await client.query(`SELECT p.workspace_id,p.incident_id,p.destination_id
    FROM certops_distribution_pagerduty p
    JOIN certops_distribution_incidents i ON i.workspace_id=p.workspace_id AND i.id=p.incident_id
    WHERE i.resolved_at IS NOT NULL AND (p.trigger_accepted_at IS NOT NULL OR p.trigger_delivery_uncertain) AND p.resolved_at IS NULL
      AND p.next_attempt_at<=clock_timestamp()
    ORDER BY p.next_attempt_at,p.incident_id LIMIT $1`, [Math.max(1,Math.min(500,batchSize))]);
  for (const row of due.rows) {
    const lock = lockName(row.incident_id,row.destination_id);
    if (!(await client.query("SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS owned", [lock])).rows[0]?.owned) continue;
    try {
      const current = (await client.query(`SELECT p.*,ws.webhook_urls,policy.policy AS distribution_policy FROM certops_distribution_pagerduty p
        JOIN certops_distribution_incidents i ON i.workspace_id=p.workspace_id AND i.id=p.incident_id
        LEFT JOIN workspace_settings ws ON ws.workspace_id=p.workspace_id
        LEFT JOIN certops_distribution_policies policy ON policy.workspace_id=i.workspace_id AND policy.group_id=i.group_id
        WHERE p.workspace_id=$1 AND p.incident_id=$2 AND p.destination_id=$3
          AND i.resolved_at IS NOT NULL AND (p.trigger_accepted_at IS NOT NULL OR p.trigger_delivery_uncertain)
          AND p.resolved_at IS NULL AND p.next_attempt_at<=clock_timestamp()`,
      [row.workspace_id,row.incident_id,row.destination_id])).rows[0];
      if (!current) continue;
      if (current.distribution_policy?.alerts?.enabled !== true ||
          !(await canRecover(client,row))) {
        await client.query(`UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp()+interval '5 minutes'
          WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3`,[row.workspace_id,row.incident_id,row.destination_id]);
        continue;
      }
      const hook = (Array.isArray(current.webhook_urls) ? current.webhook_urls : [])
        .find(item => pagerDutyDestinationId(row.workspace_id,item) === row.destination_id);
      if (!hook) {
        await client.query(`UPDATE certops_distribution_pagerduty SET last_error=CASE WHEN trigger_delivery_uncertain AND trigger_accepted_at IS NOT NULL AND last_error='historical_destination_unverified' THEN 'historical_destination_unverified' ELSE 'original_destination_unavailable' END,
          next_attempt_at=clock_timestamp()+interval '5 minutes' WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3`,
        [row.workspace_id,row.incident_id,row.destination_id]);
        continue;
      }
      // Historical hashes become actionable only when they match the current
      // tenant, endpoint, and routing-key fingerprint. URL-only hashes cannot match.
      if (current.trigger_delivery_uncertain && current.historical_resolution_at) {
        await client.query(`UPDATE certops_distribution_pagerduty SET trigger_delivery_uncertain=FALSE,
          resolved_at=historical_resolution_at,last_error=NULL WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3
          AND trigger_delivery_uncertain AND last_error='historical_destination_unverified'`,
        [row.workspace_id,row.incident_id,row.destination_id]);
        continue;
      }
      if (current.trigger_delivery_uncertain) await client.query(`UPDATE certops_distribution_pagerduty
        SET trigger_delivery_uncertain=FALSE,last_error=NULL
        WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3
          AND trigger_delivery_uncertain AND last_error='historical_destination_unverified'`,
      [row.workspace_id,row.incident_id,row.destination_id]);
      const attempt = Number(current.resolve_attempts) + 1;
      await client.query(`UPDATE certops_distribution_pagerduty SET resolve_attempts=$4,
        next_attempt_at=clock_timestamp()+($5 * interval '1 millisecond'),last_error='delivery_uncertain'
        WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3`,
      [row.workspace_id,row.incident_id,row.destination_id,attempt,retryMs(attempt)]);
      let result;
      try { result = await send(String(hook.url).trim(),{routing_key:String(hook.routingKey).trim(),
        event_action:"resolve",dedup_key:`distribution:${row.incident_id}`},"pagerduty"); }
      catch { result = { success:false }; }
      await client.query("BEGIN");
      try {
        await client.query(`UPDATE certops_distribution_pagerduty SET
          resolved_at=CASE WHEN $4 THEN clock_timestamp() ELSE NULL END,
          last_error=CASE WHEN $4 THEN NULL ELSE 'pagerduty_delivery_failed' END
          WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3`,
        [row.workspace_id,row.incident_id,row.destination_id,result?.success === true]);
        await client.query(`INSERT INTO alert_delivery_log(alert_queue_id,user_id,workspace_id,channel,status,error_message,metadata)
          SELECT q.id,w.created_by,$1,'webhooks',CASE WHEN $4 THEN 'success' ELSE 'failed' END,
            CASE WHEN $4 THEN NULL ELSE 'pagerduty_delivery_failed' END,
            jsonb_build_object('kind','pagerduty','payload_type','certops_distribution','event_action','resolve',
              'destination_id',$3::text,'urlHash',$3::text,'incident_id',$2::text)
          FROM workspaces w LEFT JOIN LATERAL (
            SELECT aq.id FROM alert_queue aq JOIN certops_agents a ON a.id=aq.certops_agent_id
              WHERE a.workspace_id=$1 AND aq.alert_key LIKE 'cert_distribution:%'
                AND aq.metadata->>'incidentId'=$2::text AND aq.metadata->>'transition'='resolved'
            ORDER BY aq.id DESC LIMIT 1
          ) q ON TRUE WHERE w.id=$1 AND w.created_by IS NOT NULL`,
        [row.workspace_id,row.incident_id,row.destination_id,result?.success === true]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    } finally {
      await client.query("SELECT pg_advisory_unlock(hashtextextended($1,0))", [lock]);
    }
  }
  await settleRecoveredDistributionAlerts(client,Math.max(1,Math.min(500,batchSize)),canRecover);
}
