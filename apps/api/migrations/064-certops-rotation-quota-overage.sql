-- Additive repair for installations that already applied identity hardening.
-- Preserve all identities, periods, associations, observations and audit data.
CREATE OR REPLACE FUNCTION certops_admit_management(workspace UUID, identity UUID, excluded_period UUID DEFAULT NULL)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE quota_limit INTEGER; used INTEGER;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || workspace::text));
  SELECT certops_managed_identity_limit INTO quota_limit FROM workspaces WHERE id = workspace;
  IF quota_limit IS NULL THEN RETURN; END IF;
  -- Rotation moves an already-open source period. Other sources may retain
  -- the previous fingerprint, so usage can temporarily exceed the limit.
  -- INSERT admission still passes NULL and must enforce the quota. Validate
  -- the existing period so foreign, closed or invented IDs grant no exemption.
  IF excluded_period IS NOT NULL AND EXISTS (
    SELECT 1 FROM certops_management_periods p
      WHERE p.workspace_id = workspace AND p.id = excluded_period
        AND p.ended_at IS NULL
  ) THEN RETURN; END IF;
  IF identity IS NOT NULL AND EXISTS (SELECT 1 FROM certops_management_periods p
    WHERE p.workspace_id = workspace AND p.ended_at IS NULL AND p.current_identity_id = identity
      AND p.id IS DISTINCT FROM excluded_period) THEN RETURN; END IF;
  SELECT (COUNT(DISTINCT p.current_identity_id) + COUNT(*) FILTER (WHERE p.current_identity_id IS NULL))::int
    INTO used FROM certops_management_periods p
    WHERE p.workspace_id = workspace AND p.ended_at IS NULL AND p.id IS DISTINCT FROM excluded_period;
  IF used + 1 > quota_limit THEN
    RAISE EXCEPTION 'CertOps managed certificate quota exceeded' USING ERRCODE = 'P0001',
      DETAIL = 'CERTOPS_MANAGED_CERT_LIMIT', HINT = format('limit=%s used=%s', quota_limit, used);
  END IF;
END $$;
