-- Retain immutable Vault execution provenance in its original workspace.
-- Only public inventory/history moves; destination management starts unconfigured.
CREATE OR REPLACE FUNCTION certops_transfer_management_sources(from_workspace UUID, to_workspace UUID, source_ids UUID[])
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE historic_period RECORD; association RECORD; new_period UUID; new_identity UUID; mc RECORD; moved INTEGER; open_source_ids UUID[]; distribution_source_ids UUID[];
BEGIN
  -- Same workspace boundary as dispatch/admission. Lock both tenants in order.
  PERFORM id FROM workspaces WHERE id IN (from_workspace,to_workspace) ORDER BY id FOR UPDATE;
  PERFORM pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || id::text))
    FROM (SELECT from_workspace id UNION SELECT to_workspace id) workspaces ORDER BY id;
  SELECT COALESCE(array_agg(DISTINCT managed_certificate_id),'{}'::uuid[]) INTO distribution_source_ids
    FROM certops_distribution_groups WHERE workspace_id=from_workspace AND managed_certificate_id=ANY(source_ids);
  -- Result ingestion can own a job before requesting group/period locks.
  -- Refuse a busy job instead of waiting while holding authority locks.
  BEGIN
    PERFORM id FROM certificate_jobs WHERE workspace_id=from_workspace
      AND subject_type='managed_certificate' AND subject_id=ANY(SELECT unnest(distribution_source_ids)::text)
      ORDER BY id FOR UPDATE NOWAIT;
  EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED' USING ERRCODE='55000';
  END;
  PERFORM id FROM certops_distribution_groups WHERE workspace_id=from_workspace
    AND managed_certificate_id=ANY(distribution_source_ids) ORDER BY id FOR UPDATE;
  PERFORM id FROM certops_management_periods WHERE workspace_id=from_workspace
    AND managed_certificate_id=ANY(distribution_source_ids) ORDER BY id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM certificate_jobs j WHERE j.workspace_id=from_workspace
    AND j.subject_type='managed_certificate' AND j.subject_id=ANY(SELECT unnest(distribution_source_ids)::text)
    AND (j.status IN ('claimed','running','orphaned_unknown_effect') OR j.needs_operator_reconciliation
      OR (j.status IN ('pending','pending_approval','approved') AND j.attempt_count>0)
      OR EXISTS (SELECT 1 FROM certops_material_versions v WHERE v.workspace_id=j.workspace_id
        AND v.publishing_job_id=j.id AND v.state IN ('allocated','staged','orphaned_unknown_effect')
        AND (j.attempt_count>0 OR j.claim_id IS NOT NULL OR j.started_at IS NOT NULL)))) THEN
    RAISE EXCEPTION 'CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM certificate_jobs WHERE workspace_id = from_workspace
    AND subject_type = 'managed_certificate' AND subject_id = ANY(SELECT unnest(source_ids)::text)
    AND status IN ('claimed', 'running')) THEN
    RAISE EXCEPTION 'CertOps in-flight work must reconcile before workspace transfer' USING ERRCODE = '55000';
  END IF;
  -- Seed all historically associated fingerprints without reactivating any
  -- existing retired destination identity or mutating the original identity.
  INSERT INTO certops_certificate_identities(workspace_id,fingerprint_sha256,lifecycle_status,lifecycle_reason,retired_at,common_name,issuer,not_after)
    SELECT DISTINCT to_workspace,i.fingerprint_sha256,i.lifecycle_status,i.lifecycle_reason,i.retired_at,i.common_name,i.issuer,i.not_after
      FROM certops_certificate_identities i JOIN certops_management_associations a ON a.identity_id = i.id
      JOIN certops_management_periods p ON p.id = a.period_id
      WHERE p.workspace_id = from_workspace AND p.managed_certificate_id = ANY(source_ids)
    ON CONFLICT (workspace_id,fingerprint_sha256) DO UPDATE SET lifecycle_status = CASE
      WHEN certops_certificate_identities.lifecycle_status = 'revoked' OR EXCLUDED.lifecycle_status = 'revoked' THEN 'revoked'
      WHEN certops_certificate_identities.lifecycle_status = 'decommissioned' THEN 'decommissioned'
      ELSE EXCLUDED.lifecycle_status END;
  PERFORM set_config('certops.workspace_transfer', from_workspace::text || ':' || to_workspace::text, TRUE);
  SELECT array_agg(managed_certificate_id) INTO open_source_ids FROM certops_management_periods
    WHERE workspace_id = from_workspace AND managed_certificate_id = ANY(source_ids) AND ended_at IS NULL;
  UPDATE certops_management_periods SET ended_at = GREATEST(NOW(),started_at), ended_reason = 'workspace_transfer'
    WHERE workspace_id = from_workspace AND managed_certificate_id = ANY(source_ids) AND ended_at IS NULL;
  UPDATE certops_distribution_rollouts r SET state='retired' FROM certops_distribution_groups g
    WHERE g.workspace_id=from_workspace AND g.managed_certificate_id=ANY(distribution_source_ids)
      AND r.workspace_id=g.workspace_id AND r.group_id=g.id AND r.state IN ('pending','deploying','paused','degraded');
  UPDATE certops_distribution_groups SET state='retired' WHERE workspace_id=from_workspace
    AND managed_certificate_id=ANY(distribution_source_ids);
  -- No source execution configuration or agent assignment crosses the tenant boundary.
  UPDATE managed_certificates SET workspace_id = to_workspace, profile_id = NULL,
    key_reference=CASE WHEN id=ANY(distribution_source_ids) THEN NULL ELSE key_reference END,
    deployed_agent_id=CASE WHEN id=ANY(distribution_source_ids) THEN NULL ELSE deployed_agent_id END,
    deployed_cert_path=CASE WHEN id=ANY(distribution_source_ids) THEN NULL ELSE deployed_cert_path END,
    source_ref=CASE WHEN id=ANY(distribution_source_ids) THEN NULL ELSE source_ref END,
    public_metadata=CASE WHEN id=ANY(distribution_source_ids) THEN '{}'::jsonb ELSE public_metadata END,
    updated_at = NOW()
    WHERE workspace_id = from_workspace AND id = ANY(source_ids);
  GET DIAGNOSTICS moved = ROW_COUNT;
  FOR historic_period IN SELECT * FROM certops_management_periods WHERE workspace_id = from_workspace
    AND managed_certificate_id = ANY(source_ids) LOOP
    SELECT destination.id INTO new_identity FROM certops_certificate_identities original
      JOIN certops_certificate_identities destination ON destination.workspace_id = to_workspace
        AND destination.fingerprint_sha256 = original.fingerprint_sha256 WHERE original.id = historic_period.current_identity_id;
    INSERT INTO certops_management_periods(workspace_id,managed_certificate_id,current_identity_id,started_at,ended_at,ended_reason,automation_enabled,created_by)
      VALUES(to_workspace,historic_period.managed_certificate_id,new_identity,historic_period.started_at,historic_period.ended_at,historic_period.ended_reason,historic_period.automation_enabled,historic_period.created_by)
      RETURNING id INTO new_period;
    FOR association IN SELECT a.*,i.fingerprint_sha256 FROM certops_management_associations a
      JOIN certops_certificate_identities i ON i.id = a.identity_id WHERE a.period_id = historic_period.id LOOP
      INSERT INTO certops_management_associations(workspace_id,period_id,identity_id,associated_at,superseded_at)
        SELECT to_workspace,new_period,id,association.associated_at,association.superseded_at FROM certops_certificate_identities
          WHERE workspace_id = to_workspace AND fingerprint_sha256 = association.fingerprint_sha256;
    END LOOP;
    UPDATE certificate_jobs j SET workspace_id = to_workspace,management_period_id = new_period,
      certificate_identity_id = (SELECT destination.id FROM certops_certificate_identities original
        JOIN certops_certificate_identities destination ON destination.workspace_id = to_workspace
          AND destination.fingerprint_sha256 = original.fingerprint_sha256 WHERE original.id = j.certificate_identity_id),
      requested_by_api_token_id = NULL WHERE j.workspace_id = from_workspace AND j.management_period_id = historic_period.id
      AND NOT (historic_period.managed_certificate_id=ANY(distribution_source_ids));
  END LOOP;
  FOR mc IN SELECT * FROM managed_certificates WHERE workspace_id = to_workspace AND id = ANY(open_source_ids) LOOP
    INSERT INTO certops_management_periods(workspace_id,managed_certificate_id,current_identity_id,automation_enabled)
      SELECT to_workspace,mc.id,i.id,FALSE FROM (SELECT 1) singleton LEFT JOIN certops_certificate_identities i
        ON i.workspace_id = to_workspace AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256);
  END LOOP;
  PERFORM set_config('certops.workspace_transfer','',TRUE);
  RETURN moved;
END $$;
