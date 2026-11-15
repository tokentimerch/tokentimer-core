import { pagerDutyDestinationId } from "./webhookDestinations.js";

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
      DO UPDATE SET trigger_delivery_uncertain=TRUE`, [alert.workspace_id,incidentId,destinationId]);
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

// Recovery is independent of today's groups and channel settings. A removed or
// rotated integration is parked until its exact original configuration returns.
export async function reconcileDistributionPagerDuty(client, { send, batchSize = 100 } = {}) {
  const due = await client.query(`SELECT p.workspace_id,p.incident_id,p.destination_id
    FROM certops_distribution_pagerduty p
    JOIN certops_distribution_incidents i ON i.workspace_id=p.workspace_id AND i.id=p.incident_id
    WHERE i.resolved_at IS NOT NULL AND p.trigger_accepted_at IS NOT NULL AND NOT p.trigger_delivery_uncertain AND p.resolved_at IS NULL
      AND p.next_attempt_at<=clock_timestamp() AND p.resolve_attempts<8
    ORDER BY p.next_attempt_at,p.incident_id LIMIT $1`, [Math.max(1,Math.min(500,batchSize))]);
  for (const row of due.rows) {
    const lock = lockName(row.incident_id,row.destination_id);
    if (!(await client.query("SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS owned", [lock])).rows[0]?.owned) continue;
    try {
      const current = (await client.query(`SELECT p.*,ws.webhook_urls FROM certops_distribution_pagerduty p
        JOIN certops_distribution_incidents i ON i.workspace_id=p.workspace_id AND i.id=p.incident_id
        LEFT JOIN workspace_settings ws ON ws.workspace_id=p.workspace_id
        WHERE p.workspace_id=$1 AND p.incident_id=$2 AND p.destination_id=$3
          AND i.resolved_at IS NOT NULL AND p.trigger_accepted_at IS NOT NULL AND NOT p.trigger_delivery_uncertain
          AND p.resolved_at IS NULL AND p.next_attempt_at<=clock_timestamp() AND p.resolve_attempts<8`,
      [row.workspace_id,row.incident_id,row.destination_id])).rows[0];
      if (!current) continue;
      const hook = (Array.isArray(current.webhook_urls) ? current.webhook_urls : [])
        .find(item => pagerDutyDestinationId(row.workspace_id,item) === row.destination_id);
      if (!hook) {
        await client.query(`UPDATE certops_distribution_pagerduty SET last_error='original_destination_unavailable',
          next_attempt_at=clock_timestamp()+interval '5 minutes' WHERE workspace_id=$1 AND incident_id=$2 AND destination_id=$3`,
        [row.workspace_id,row.incident_id,row.destination_id]);
        continue;
      }
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
}
