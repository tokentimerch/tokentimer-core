-- Retain public certificate/token details independently of mutable sources.
-- Never serialize entire token/source rows: they may acquire secret fields.
CREATE TABLE IF NOT EXISTS certops_identity_detail_history (
  workspace_id UUID NOT NULL,
  identity_id UUID NOT NULL,
  token_id INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
  token_details JSONB NULL,
  certificate_details JSONB NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, identity_id),
  FOREIGN KEY (workspace_id, identity_id)
    REFERENCES certops_certificate_identities(workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_certops_source_token_fingerprint
  ON managed_certificates(workspace_id, token_id, certops_normalize_fingerprint(fingerprint_sha256))
  WHERE token_id IS NOT NULL;

CREATE OR REPLACE FUNCTION certops_public_token_details(t tokens)
RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object(
    'name', t.name, 'expiresAt', t.expiration, 'type', t.type,
    'category', t.category, 'domains', t.domains, 'location', t.location,
    'used_by', t.used_by, 'section', t.section, 'issuer', t.issuer,
    'serial_number', t.serial_number, 'subject', t.subject,
    'key_size', t.key_size, 'algorithm', t.algorithm,
    'contacts', t.contacts, 'description', t.description, 'notes', t.notes,
    'renewal_url', t.renewal_url, 'renewal_date', t.renewal_date,
    'created_at', t.created_at, 'updated_at', t.updated_at,
    'imported_at', t.imported_at, 'last_used', t.last_used
  );
$$;

CREATE OR REPLACE FUNCTION certops_public_certificate_details(mc managed_certificates)
RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object(
    'fingerprintSha256', certops_normalize_fingerprint(mc.fingerprint_sha256),
    'commonName', mc.common_name, 'subjectAltNames', mc.subject_alt_names,
    'issuer', mc.issuer, 'serialNumber', mc.serial_number,
    'spkiFingerprintSha256', mc.spki_fingerprint_sha256,
    'notBefore', mc.not_before, 'notAfter', mc.not_after,
    'publicKeyAlgorithm', mc.public_key_algorithm,
    'publicKeySize', mc.public_key_size, 'signatureAlgorithm', mc.signature_algorithm,
    'subject', mc.public_metadata->>'subject'
  );
$$;

CREATE OR REPLACE FUNCTION certops_token_matches_details(t tokens, c JSONB)
RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS $$
  SELECT t.id IS NOT NULL
    AND (c->>'serialNumber' IS NULL OR lower(replace(t.serial_number, ':', '')) = lower(replace(c->>'serialNumber', ':', '')))
    AND (c->>'issuer' IS NULL OR t.issuer = c->>'issuer')
    AND (c->>'subject' IS NULL OR t.subject = c->>'subject')
    AND (c->>'notAfter' IS NULL OR t.expiration = ((c->>'notAfter')::timestamptz AT TIME ZONE 'UTC')::date);
$$;

CREATE OR REPLACE FUNCTION certops_capture_source_details()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE identity UUID; token_row tokens; safe_token BOOLEAN;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.workspace_id IS NOT DISTINCT FROM OLD.workspace_id
    AND NEW.token_id IS NOT DISTINCT FROM OLD.token_id
    AND certops_public_certificate_details(NEW) IS NOT DISTINCT FROM certops_public_certificate_details(OLD)
    THEN RETURN NEW; END IF;
  SELECT id INTO identity FROM certops_certificate_identities
    WHERE workspace_id = NEW.workspace_id
      AND fingerprint_sha256 = certops_normalize_fingerprint(NEW.fingerprint_sha256);
  IF identity IS NULL THEN RETURN NEW; END IF;
  SELECT * INTO token_row FROM tokens WHERE id = NEW.token_id AND workspace_id = NEW.workspace_id;
  safe_token := certops_token_matches_details(token_row, certops_public_certificate_details(NEW)) AND NOT EXISTS (
    SELECT 1 FROM managed_certificates other
      WHERE other.workspace_id = NEW.workspace_id AND other.token_id = NEW.token_id
        AND other.id <> NEW.id
        AND certops_normalize_fingerprint(other.fingerprint_sha256) IS DISTINCT FROM
          certops_normalize_fingerprint(NEW.fingerprint_sha256)
  );
  INSERT INTO certops_identity_detail_history(workspace_id, identity_id, token_id, token_details, certificate_details)
    VALUES(NEW.workspace_id, identity, CASE WHEN safe_token THEN NEW.token_id END,
      CASE WHEN safe_token THEN certops_public_token_details(token_row) END,
      certops_public_certificate_details(NEW))
    ON CONFLICT (workspace_id, identity_id) DO UPDATE SET
      -- The first verified token is canonical. A later source must not replace
      -- user notes with its own generated notes or change the editing target.
      token_id = CASE WHEN certops_identity_detail_history.token_details IS NULL
        THEN EXCLUDED.token_id ELSE certops_identity_detail_history.token_id END,
      token_details = CASE WHEN certops_identity_detail_history.token_details IS NULL
          OR EXCLUDED.token_id = certops_identity_detail_history.token_id
        THEN COALESCE(EXCLUDED.token_details, certops_identity_detail_history.token_details)
        ELSE certops_identity_detail_history.token_details END,
      certificate_details = jsonb_strip_nulls(EXCLUDED.certificate_details)
        || jsonb_strip_nulls(certops_identity_detail_history.certificate_details),
      captured_at = NOW();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_certops_capture_source_details ON managed_certificates;
DROP TRIGGER IF EXISTS trg_certops_z_capture_source_details ON managed_certificates;
-- Source lifecycle synchronization takes the token lock first. Preserve that
-- ordering before taking the detail-history lock (token -> history).
CREATE TRIGGER trg_certops_z_capture_source_details AFTER INSERT OR UPDATE ON managed_certificates
  FOR EACH ROW EXECUTE FUNCTION certops_capture_source_details();

-- Capture the old public token details before rotation, transfer, or deletion.
-- Ordinary edits refresh the snapshot only if certificate fields are unchanged.
CREATE OR REPLACE FUNCTION certops_capture_token_details()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE details JSONB; chosen tokens;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.workspace_id IS NOT DISTINCT FROM OLD.workspace_id
    AND (certops_public_token_details(NEW) - 'updated_at') IS NOT DISTINCT FROM
      (certops_public_token_details(OLD) - 'updated_at')
    THEN RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' AND TG_WHEN = 'AFTER' THEN
    chosen := NEW;
  ELSE chosen := OLD; END IF;
  details := certops_public_token_details(chosen);
  UPDATE certops_identity_detail_history h SET token_details = details,
    token_id = chosen.id, captured_at = NOW()
    WHERE h.workspace_id = chosen.workspace_id
      AND (h.token_id = chosen.id OR (h.token_id IS NULL AND h.token_details IS NULL))
      AND certops_token_matches_details(chosen, h.certificate_details)
      AND EXISTS (SELECT 1 FROM managed_certificates mc
        JOIN certops_certificate_identities i ON i.workspace_id = mc.workspace_id
          AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
        WHERE mc.workspace_id = chosen.workspace_id AND mc.token_id = chosen.id AND i.id = h.identity_id)
      AND NOT EXISTS (SELECT 1 FROM managed_certificates other
        WHERE other.workspace_id = chosen.workspace_id AND other.token_id = chosen.id
          AND certops_normalize_fingerprint(other.fingerprint_sha256) IS DISTINCT FROM
            (SELECT fingerprint_sha256 FROM certops_certificate_identities WHERE id = h.identity_id));
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_certops_capture_token_before ON tokens;
CREATE TRIGGER trg_certops_capture_token_before BEFORE UPDATE OR DELETE ON tokens
  FOR EACH ROW EXECUTE FUNCTION certops_capture_token_details();
DROP TRIGGER IF EXISTS trg_certops_capture_token_after ON tokens;
CREATE TRIGGER trg_certops_capture_token_after AFTER UPDATE ON tokens
  FOR EACH ROW EXECUTE FUNCTION certops_capture_token_details();

-- Only current, verified fingerprint associations can seed old installations.
-- Historical fingerprints whose sources rotated are deliberately not guessed.
INSERT INTO certops_identity_detail_history(workspace_id, identity_id, token_id, token_details, certificate_details)
SELECT DISTINCT ON (i.id) i.workspace_id, i.id,
  CASE WHEN certops_token_matches_details(t, certops_public_certificate_details(mc)) AND NOT EXISTS (
    SELECT 1 FROM managed_certificates other WHERE other.workspace_id = i.workspace_id
      AND other.token_id = t.id AND certops_normalize_fingerprint(other.fingerprint_sha256)
        IS DISTINCT FROM i.fingerprint_sha256) THEN t.id END,
  CASE WHEN certops_token_matches_details(t, certops_public_certificate_details(mc)) AND NOT EXISTS (
    SELECT 1 FROM managed_certificates other WHERE other.workspace_id = i.workspace_id
      AND other.token_id = t.id AND certops_normalize_fingerprint(other.fingerprint_sha256)
        IS DISTINCT FROM i.fingerprint_sha256) THEN certops_public_token_details(t) END,
  certops_public_certificate_details(mc)
FROM certops_certificate_identities i JOIN managed_certificates mc
  ON mc.workspace_id = i.workspace_id AND certops_normalize_fingerprint(mc.fingerprint_sha256) = i.fingerprint_sha256
LEFT JOIN tokens t ON t.id = mc.token_id AND t.workspace_id = i.workspace_id
ORDER BY i.id, mc.created_at ASC, mc.id ASC
ON CONFLICT (workspace_id, identity_id) DO NOTHING;
