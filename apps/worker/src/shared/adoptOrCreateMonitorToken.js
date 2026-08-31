function formatDateYmd(date) {
  if (!date) return null;
  const d = new Date(date);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().split("T")[0];
}

/**
 * Adopt an existing name+location token instead of inserting a second
 * unattributed row the monitor (and later import cleanup) cannot see.
 */
export async function adoptOrCreateMonitorToken(client, {
  workspaceId,
  hostname,
  url,
  sslData,
  defaultContactGroupId,
}) {
  const name = String(hostname || "").substring(0, 100);
  const location = url;
  const expiration = formatDateYmd(sslData.ssl_valid_to);
  const existing = await client.query(
    `SELECT id FROM tokens
      WHERE workspace_id = $1
        AND name = $2
        AND location = $3
      LIMIT 1`,
    [workspaceId, name, location],
  );
  if (existing.rows[0]) {
    return existing.rows[0].id;
  }
  const tokenRes = await client.query(
    `INSERT INTO tokens (workspace_id, name, expiration, type, category, issuer, serial_number, subject, domains, location, notes, contact_group_id)
     VALUES ($1, $2, $3, 'ssl_cert', 'cert', $4, $5, $6, $7, $8, $9, $10)
     RETURNING id`,
    [
      workspaceId,
      name,
      expiration,
      sslData.ssl_issuer,
      sslData.ssl_serial,
      sslData.ssl_subject,
      [hostname],
      location,
      `Auto-created by endpoint monitor. Fingerprint: ${sslData.ssl_fingerprint || "unknown"}`,
      defaultContactGroupId,
    ],
  );
  return tokenRes.rows[0].id;
}
