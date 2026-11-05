-- Move the job mapping with its job, translating to the destination tenant's
-- identity for the same certificate during the existing guarded transfer.
ALTER TABLE certops_issuance_job_identities
  DROP CONSTRAINT certops_issuance_job_identities_workspace_id_job_id_fkey,
  ADD CONSTRAINT certops_issuance_job_identities_workspace_id_job_id_fkey
    FOREIGN KEY (workspace_id, job_id) REFERENCES certificate_jobs(workspace_id, id)
    ON DELETE CASCADE ON UPDATE CASCADE;

CREATE OR REPLACE FUNCTION certops_guard_issuance_job_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE destination_id UUID;
BEGIN
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  IF NEW.job_id = OLD.job_id AND NEW.identity_id = OLD.identity_id
    AND NEW.workspace_id <> OLD.workspace_id
    AND current_setting('certops.workspace_transfer', true) = OLD.workspace_id::text || ':' || NEW.workspace_id::text THEN
    SELECT destination.id INTO destination_id
      FROM certops_certificate_identities original
      JOIN certops_certificate_identities destination
        ON destination.workspace_id = NEW.workspace_id
       AND destination.fingerprint_sha256 = original.fingerprint_sha256
     WHERE original.workspace_id = OLD.workspace_id AND original.id = OLD.identity_id;
    IF destination_id IS NOT NULL THEN
      NEW.identity_id := destination_id;
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'Issuance job identity is immutable' USING ERRCODE = '23514';
END $$;
