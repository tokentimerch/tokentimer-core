-- Longer connections and an explicit non-expiring option. OAuth access and
-- refresh tokens still have their own bounded expiry; revocation and live
-- membership checks apply to every connection.
ALTER TABLE operator_connections ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE operator_connections DROP CONSTRAINT operator_connections_expiry_cap_check;
ALTER TABLE operator_connections ADD CONSTRAINT operator_connections_expiry_cap_check
  CHECK (expires_at IS NULL OR expires_at <= created_at + INTERVAL '365 days');

ALTER TABLE operator_enrollment_grants ALTER COLUMN connection_lifetime_days DROP NOT NULL;
ALTER TABLE operator_enrollment_grants DROP CONSTRAINT operator_enrollment_grants_connection_lifetime_days_check;
ALTER TABLE operator_enrollment_grants ADD CONSTRAINT operator_enrollment_grants_connection_lifetime_days_check
  CHECK (connection_lifetime_days IS NULL OR connection_lifetime_days BETWEEN 1 AND 365);

ALTER TABLE operator_oauth_grants ALTER COLUMN expires_at DROP NOT NULL;
