-- Existing observations do not contend with lifecycle edits or quota admission.
-- Enrich missing public facts opportunistically; a later observation can fill
-- them when a lifecycle transaction currently owns the identity row.
CREATE OR REPLACE FUNCTION certops_ensure_certificate_identity(
  workspace UUID, fingerprint TEXT, name TEXT DEFAULT NULL,
  certificate_issuer TEXT DEFAULT NULL, expiration TIMESTAMPTZ DEFAULT NULL)
RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE identity UUID;
BEGIN
  SELECT id INTO identity FROM certops_certificate_identities
    WHERE workspace_id = workspace AND fingerprint_sha256 = fingerprint;
  IF identity IS NULL THEN
    INSERT INTO certops_certificate_identities(workspace_id, fingerprint_sha256, common_name, issuer, not_after)
      VALUES (workspace, fingerprint, name, certificate_issuer, expiration)
      ON CONFLICT (workspace_id, fingerprint_sha256) DO NOTHING;
    SELECT id INTO identity FROM certops_certificate_identities
      WHERE workspace_id = workspace AND fingerprint_sha256 = fingerprint;
  END IF;
  UPDATE certops_certificate_identities i SET
    common_name = COALESCE(i.common_name, name),
    issuer = COALESCE(i.issuer, certificate_issuer),
    not_after = COALESCE(i.not_after, expiration)
    WHERE i.id IN (SELECT candidate.id FROM certops_certificate_identities candidate
      WHERE candidate.id = identity
        AND ((candidate.common_name IS NULL AND name IS NOT NULL)
          OR (candidate.issuer IS NULL AND certificate_issuer IS NOT NULL)
          OR (candidate.not_after IS NULL AND expiration IS NOT NULL))
      FOR NO KEY UPDATE SKIP LOCKED);
  RETURN identity;
END $$;

CREATE OR REPLACE FUNCTION certops_prepare_managed_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fingerprint TEXT; lifecycle TEXT; observation_time TIMESTAMPTZ;
BEGIN
  -- ON CONFLICT invokes the INSERT trigger before obtaining its source row.
  -- For an existing source defer preparation to the ensuing UPDATE trigger;
  -- otherwise it would unnecessarily acquire quota/identity locks first.
  IF TG_OP = 'INSERT' AND EXISTS (
    SELECT 1 FROM managed_certificates mc WHERE mc.workspace_id = NEW.workspace_id
      AND ((NEW.source_ref IS NOT NULL AND mc.source = NEW.source AND mc.source_ref = NEW.source_ref
        AND NEW.source IN ('endpoint_monitor','domain_checker','cert_manager','agent_filesystem','agent_issuance','agent_windows'))
        OR (NEW.source NOT IN ('endpoint_monitor','domain_checker','cert_manager','agent_filesystem','agent_issuance','agent_windows')
          AND mc.source NOT IN ('endpoint_monitor','domain_checker','cert_manager','agent_filesystem','agent_issuance','agent_windows')
          AND mc.fingerprint_sha256 = certops_normalize_fingerprint(NEW.fingerprint_sha256)))
  ) THEN
    NEW.fingerprint_sha256 := certops_normalize_fingerprint(NEW.fingerprint_sha256);
    RETURN NEW;
  END IF;
  IF TG_OP = 'INSERT' OR (certops_normalize_fingerprint(NEW.fingerprint_sha256)
      IS DISTINCT FROM certops_normalize_fingerprint(OLD.fingerprint_sha256)
      AND EXISTS (SELECT 1 FROM certops_management_periods p
        WHERE p.workspace_id = NEW.workspace_id AND p.managed_certificate_id = NEW.id AND p.ended_at IS NULL)) THEN
    PERFORM pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || NEW.workspace_id::text));
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
    IF current_setting('certops.workspace_transfer', TRUE) IS DISTINCT FROM OLD.workspace_id::text || ':' || NEW.workspace_id::text THEN
      RAISE EXCEPTION 'CertOps management source workspace is immutable' USING ERRCODE = '23514';
    END IF;
  END IF;
  observation_time := NEW.identity_observed_at;
  IF observation_time > clock_timestamp() + INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'CertOps observation timestamp is in the future' USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.workspace_id = OLD.workspace_id AND observation_time IS NOT NULL AND OLD.identity_observed_at IS NOT NULL
    AND certops_normalize_fingerprint(OLD.fingerprint_sha256) IS NOT NULL
    AND observation_time <= OLD.identity_observed_at
    AND (observation_time < OLD.identity_observed_at
      OR CASE WHEN NEW.source = 'cert_manager'
          AND NEW.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          AND OLD.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          THEN (NEW.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric <
            (OLD.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric ELSE FALSE END
      OR (certops_normalize_fingerprint(NEW.fingerprint_sha256) IS DISTINCT FROM certops_normalize_fingerprint(OLD.fingerprint_sha256)
        AND NOT CASE WHEN NEW.source = 'cert_manager'
          AND NEW.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          AND OLD.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          THEN (NEW.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric >
            (OLD.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric ELSE FALSE END)) THEN
    -- The instance/evidence write still records this observation separately.
    RETURN OLD;
  END IF;
  fingerprint := certops_normalize_fingerprint(NEW.fingerprint_sha256);
  IF fingerprint IS NULL THEN RETURN NEW; END IF;
  NEW.fingerprint_sha256 := fingerprint;
  IF TG_OP = 'INSERT' OR NEW.fingerprint_sha256 IS DISTINCT FROM OLD.fingerprint_sha256 THEN
    NEW.identity_observed_at := COALESCE(observation_time, clock_timestamp());
  END IF;
  PERFORM certops_ensure_certificate_identity(NEW.workspace_id, fingerprint,
    NEW.common_name, NEW.issuer, NEW.not_after);
  SELECT lifecycle_status INTO lifecycle FROM certops_certificate_identities
    WHERE workspace_id = NEW.workspace_id AND fingerprint_sha256 = fingerprint;
  IF lifecycle IN ('revoked', 'decommissioned') THEN NEW.status := lifecycle;
  ELSIF TG_OP = 'UPDATE' AND certops_normalize_fingerprint(OLD.fingerprint_sha256) IS DISTINCT FROM fingerprint
    AND OLD.status IN ('revoked', 'decommissioned') THEN
    NEW.status := CASE WHEN NEW.source = 'agent_issuance' THEN 'active' ELSE 'discovered' END;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certops_record_positive_observation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fingerprint TEXT;
BEGIN
  fingerprint := certops_normalize_fingerprint(NEW.observed_fingerprint_sha256);
  IF fingerprint IS NULL THEN RETURN NEW; END IF;
  NEW.observed_fingerprint_sha256 := fingerprint;
  PERFORM certops_ensure_certificate_identity(NEW.workspace_id, fingerprint,
    NEW.observed_subject, NEW.observed_issuer, NEW.observed_not_after);
  IF TG_OP = 'UPDATE' AND OLD.captured_at IS NOT NULL
    AND (NEW.observed_at IS NULL OR NEW.observed_at <= OLD.captured_at) THEN
    NEW.observed_at := OLD.observed_at; NEW.captured_at := OLD.captured_at;
    NEW.presence_state := OLD.presence_state; NEW.evidence_kind := OLD.evidence_kind;
  ELSIF NEW.observed_at IS NOT NULL AND NEW.observed_at <= clock_timestamp() + INTERVAL '5 minutes' THEN
    NEW.captured_at := NEW.observed_at; NEW.presence_state := 'confirmed_present';
    NEW.evidence_kind := CASE WHEN NEW.source IN ('endpoint_monitor', 'domain_checker')
      OR NEW.location_kind IN ('iis_binding', 'http_sys') THEN 'service_binding'
      WHEN NEW.location_kind IS NOT NULL THEN 'stored_copy' ELSE 'unknown' END;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certops_track_management_period()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE identity_uuid UUID; period_uuid UUID; previous_uuid UUID;
BEGIN
  SELECT id INTO identity_uuid FROM certops_certificate_identities WHERE workspace_id = NEW.workspace_id
    AND fingerprint_sha256 = certops_normalize_fingerprint(NEW.fingerprint_sha256);
  IF TG_OP = 'INSERT' THEN
    INSERT INTO certops_management_periods(workspace_id, managed_certificate_id, current_identity_id,
      renewal_profile_id, automation_enabled, created_by)
      VALUES (NEW.workspace_id, NEW.id, identity_uuid, NEW.profile_id, NEW.profile_id IS NOT NULL, NEW.created_by)
      RETURNING id INTO period_uuid;
  ELSE
    -- Ordinary captures do not alter management or lock the association.
    IF NEW.workspace_id = OLD.workspace_id AND certops_normalize_fingerprint(NEW.fingerprint_sha256)
        IS NOT DISTINCT FROM certops_normalize_fingerprint(OLD.fingerprint_sha256) THEN RETURN NEW; END IF;
    SELECT id, current_identity_id INTO period_uuid, previous_uuid FROM certops_management_periods
      WHERE workspace_id = NEW.workspace_id AND managed_certificate_id = NEW.id AND ended_at IS NULL FOR UPDATE;
    IF period_uuid IS NULL OR previous_uuid IS NOT DISTINCT FROM identity_uuid THEN RETURN NEW; END IF;
    UPDATE certops_management_periods SET current_identity_id = identity_uuid WHERE id = period_uuid;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certops_sync_token_identity_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE token INTEGER; workspace UUID; next_status TEXT;
BEGIN
  token := NEW.token_id; workspace := NEW.workspace_id;
  IF token IS NULL THEN RETURN NEW; END IF;
  -- Always own the token before downstream public-detail snapshot triggers,
  -- even if its cached lifecycle value does not need changing.
  PERFORM 1 FROM tokens WHERE id = token AND workspace_id = workspace FOR NO KEY UPDATE;
  SELECT CASE
    WHEN bool_or(i.lifecycle_status = 'active' OR (i.id IS NULL AND mc.status NOT IN ('revoked', 'decommissioned'))) THEN 'active'
    WHEN bool_or(i.lifecycle_status = 'revoked') THEN 'revoked'
    WHEN bool_or(i.lifecycle_status = 'decommissioned') THEN 'decommissioned' ELSE NULL END
    INTO next_status FROM managed_certificates mc LEFT JOIN certops_certificate_identities i
      ON i.workspace_id = mc.workspace_id AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
    WHERE mc.workspace_id = workspace AND mc.token_id = token;
  UPDATE tokens SET cert_lifecycle_status = next_status, updated_at = NOW()
    WHERE id = token AND workspace_id = workspace AND cert_lifecycle_status IS DISTINCT FROM next_status;
  RETURN NEW;
END $$;
