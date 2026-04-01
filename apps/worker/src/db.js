import pg from "pg";
import fs from "fs";

const { Pool } = pg;

const caPath = process.env.PGSSLROOTCERT;
const sslMode = process.env.DB_SSL;
const hasCA = Boolean(caPath);
const sslConfig =
  sslMode === "verify" || hasCA
    ? {
        ca: hasCA ? fs.readFileSync(caPath, "utf8") : undefined,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
      }
    : sslMode === "require"
      ? { rejectUnauthorized: false, minVersion: "TLSv1.3" }
      : false;

export const pool = new Pool({
  user: process.env.DB_USER || "tokentimer",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "tokentimer",
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT || "5432", 10),
  ssl: sslConfig,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

export async function withClient(fn) {
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function tryAdvisoryLock(client, key) {
  const hash = Math.abs(hash32(key));
  const res = await client.query("SELECT pg_try_advisory_lock($1)", [hash]);
  return Boolean(res.rows[0]?.pg_try_advisory_lock);
}

export function advisoryUnlock(client, key) {
  const hash = Math.abs(hash32(key));
  return client.query("SELECT pg_advisory_unlock($1)", [hash]).catch(() => {});
}

function hash32(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h << 5) - h + s.charCodeAt(i);
    h |= 0;
  }
  return h;
}
