import pg from "pg";
import fs from "fs";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
try {
  const { loadRootEnv } = require("../../../scripts/load-root-env.js");
  loadRootEnv();
} catch {
  // Docker images do not include repo-level helper scripts; Compose provides env directly.
}

const { Pool } = pg;

const caPath = process.env.PGSSLROOTCERT;
const sslMode = process.env.DB_SSL;
const hasCA = Boolean(caPath);
const isProduction = process.env.NODE_ENV === "production";

// SSL semantics:
//   verify (or a CA provided)  -> encrypted + server identity verified
//   require                    -> encrypted; identity verified in production
//                                 unless DB_SSL=require-no-verify is set
//   require-no-verify          -> encrypted, identity NOT verified (explicit
//                                 opt-in for controlled environments)
const sslConfig =
  sslMode === "verify" || hasCA
    ? {
        ca: hasCA ? fs.readFileSync(caPath, "utf8") : undefined,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
      }
    : sslMode === "require"
      ? { rejectUnauthorized: isProduction, minVersion: "TLSv1.3" }
      : sslMode === "require-no-verify"
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
