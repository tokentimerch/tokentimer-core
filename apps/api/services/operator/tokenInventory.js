"use strict";

const { pool } = require("../../db/database");
const { TOKEN_TYPES, TOKEN_CATEGORIES, isTypeAllowedForCategory } = require("../../utils/tokenClassification");
const { untrustedText, isoOrNull } = require("./projections");
const { completeness, decodeCursor } = require("./readProjections");
const { inspectOutbound } = require("@tokentimer/mcp/src/outbound");
const { AUTO_SYNC_PROJECTION } = require("./inventoryPolicy");

const MAX_IMPORT_RECORDS = 100;
const FIELDS = `id, name, type, category, expiration, location, used_by, section, domains, description, source_provider, source_kind, ${AUTO_SYNC_PROJECTION}, last_used, imported_at`;
// Keep DATE columns typed for filtering, then return their calendar lexeme.
// The pg DATE parser otherwise creates local midnight, which can shift in UTC.
const RESULT_FIELDS = FIELDS.replace(" expiration,", " expiration::text AS expiration,") + ", public_provider, public_source_kind, public_location_truncated";
// Search/counts use the same public location as the DTO, so masked paths or
// URL credentials cannot be recovered by probing match counts.
const PUBLIC_LOCATION_SQL = String.raw`CASE WHEN location ~ '[[:cntrl:]]' THEN '(invalid location)'
  WHEN LEFT(BTRIM(location),1) IN ('/',CHR(92))
  OR (SUBSTR(BTRIM(location),1,1) ~* '^[a-z]$' AND SUBSTR(BTRIM(location),2,1)=':' AND SUBSTR(BTRIM(location),3,1) IN ('/',CHR(92)))
  OR LOWER(BTRIM(location)) LIKE 'file:%' THEN '(filesystem location)'
  WHEN location ~* 'https?:' AND (BTRIM(location) !~* '^https?://[^[:space:]/?#]+' OR STRPOS(location,CHR(92))>0 OR location ~ '[[:space:]]') THEN '(invalid URL location)'
  ELSE regexp_replace(split_part(split_part(BTRIM(location),'?',1),'#',1),'^(https?://)[^/]*@','\1','i') END`;
// 256 Unicode code points fit the shared 512 UTF-16-unit text cap even when
// every character is supplementary. PostgreSQL LEFT and this DTO agree.
const PUBLIC_FIELDS = FIELDS.replace(" location,", () => ` LEFT(${PUBLIC_LOCATION_SQL},256) AS location, LENGTH(${PUBLIC_LOCATION_SQL})>256 AS public_location_truncated,`);
function inventoryView() {
  const locations = `(SELECT ${PUBLIC_FIELDS} FROM tokens WHERE workspace_id=$1) public_locations`;
  const provider = "CASE WHEN LOWER(source_provider) ~ '^[a-z][a-z0-9_-]{0,63}$' THEN LOWER(source_provider) WHEN split_part(LOWER(location),':',1) ~ '^[a-z][a-z0-9_-]{0,63}$' THEN split_part(LOWER(location),':',1) ELSE NULL END";
  const providers = `(SELECT public_locations.*,${provider} AS public_provider FROM ${locations}) public_providers`;
  const kind = "CASE WHEN source_kind ~ '^[a-z][a-z0-9_-]{0,63}$' THEN source_kind WHEN public_provider='gitlab' AND STRPOS(location,'/deploy_tokens/')>0 THEN 'gitlab-deploy-token' ELSE NULL END";
  return `(SELECT public_providers.*,${kind} AS public_source_kind FROM ${providers}) public_inventory`;
}
const code = (value) => typeof value === "string" && /^[a-z][a-z0-9_-]{0,63}$/.test(value) ? value : null;
function invalid() { return Object.assign(new Error("Inventory metadata or filters are invalid"), { code: "OPERATOR_VALIDATION_ERROR" }); }
function assertSafe(value) {
  if (!inspectOutbound(value).clean) throw Object.assign(new Error("Inventory metadata must not contain credentials or secret values"), { code: "OPERATOR_UNSAFE_METADATA" });
  const visit = (item) => {
    if (typeof item === "string") {
      for (const match of item.matchAll(/\bhttps?:[^\s<>"']*/gi)) {
        const raw = match[0];
        if (!/^https?:\/\//i.test(raw) || raw.includes("\\")) throw Object.assign(new Error("HTTP inventory URLs must use their canonical form without credentials"), { code: "OPERATOR_UNSAFE_METADATA" });
        try { new URL(raw); } catch { throw Object.assign(new Error("Inventory URL is invalid"), { code: "OPERATOR_UNSAFE_METADATA" }); }
      }
      for (const match of item.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/[^\s<>"']+/gi)) {
        try {
          const url = new URL(match[0]);
          if (url.username || url.password || [...url.searchParams.keys()].some((key) => /token|secret|password|credential|api.?key|signature|authorization/i.test(key))) throw Object.assign(new Error("Credential URLs are not inventory metadata"), { code: "OPERATOR_UNSAFE_METADATA" });
        } catch (error) { if (error.code === "OPERATOR_UNSAFE_METADATA") throw error; }
      }
    } else if (Array.isArray(item)) item.forEach(visit);
    else if (item && typeof item === "object") Object.values(item).forEach(visit);
  };
  visit(value);
}
function publicLocation(value) {
  if (!value) return null;
  if (/[\u0000-\u001f\u007f]/.test(String(value))) return untrustedText("(invalid location)");
  const text = String(value).trim();
  if (/^(?:\/|\\|[a-z]:[\\/]|file:)/i.test(text)) return untrustedText("(filesystem location)");
  if (/https?:/i.test(text) && (!/^https?:\/\/[^\s/?#]+/i.test(text) || /[\\\s]/.test(text))) return untrustedText("(invalid URL location)");
  const points = Array.from(text.split(/[?#]/, 1)[0].replace(/^(https?:\/\/)[^/]*@/i, "$1"));
  const wrapped = untrustedText(points.slice(0, 256).join(""));
  if (wrapped) wrapped.truncated = points.length > 256;
  return wrapped;
}
function dateOnly(value) {
  // Date fallbacks from the pg DATE parser retain local calendar components.
  // Do not reinterpret a date-only value as a UTC instant.
  const date = value instanceof Date && Number.isFinite(value.getTime())
    ? [String(value.getFullYear()).padStart(4, "0"), String(value.getMonth() + 1).padStart(2, "0"), String(value.getDate()).padStart(2, "0")].join("-")
    : value;
  if (typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date) || date.startsWith("0000") || !Number.isFinite(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date) return null;
  return date === "2099-12-31" ? null : date;
}
function inferredProvider(row) {
  if (Object.hasOwn(row, "public_provider")) return code(row.public_provider);
  return code(row.source_provider?.toLowerCase()) || code(String(publicLocation(row.location)?.value || "").match(/^([a-z][a-z0-9_-]*):/i)?.[1]?.toLowerCase());
}
function inferredKind(row) {
  if (Object.hasOwn(row, "public_source_kind")) return code(row.public_source_kind);
  return code(row.source_kind) || (inferredProvider(row) === "gitlab" && /\/deploy_tokens\//.test(publicLocation(row.location)?.value || "") ? "gitlab-deploy-token" : null);
}
function projectToken(row) {
  const location = publicLocation(row.location);
  if (location && row.public_location_truncated === true) location.truncated = true;
  const record = {
    id: Number(row.id), name: untrustedText(row.name), type: row.type, category: row.category,
    expiresAt: dateOnly(row.expiration), location, usedBy: untrustedText(row.used_by),
    sections: (Array.isArray(row.section) ? row.section : []).slice(0, 50).map(untrustedText),
    domains: (Array.isArray(row.domains) ? row.domains : []).slice(0, 50).map(untrustedText),
    description: untrustedText(row.description), provider: inferredProvider(row), sourceKind: inferredKind(row),
    managedByAutoSync: row.auto_sync_managed === true, lastUsedAt: isoOrNull(row.last_used), importedAt: isoOrNull(row.imported_at),
  };
  assertSafe(record);
  return record;
}
function parseTokenQuery(query = {}) {
  const allowed = new Set(["provider", "sourceKind", "type", "category", "locationContains", "query", "expiresBefore", "limit", "cursor"]);
  const out = { limit: 25, offset: 0 };
  for (const [key, value] of Object.entries(query)) {
    if (!allowed.has(key) || typeof value !== "string") throw invalid();
    if (key === "limit") {
      if (!/^[1-9]\d?$/.test(value) || Number(value) > 50) throw invalid();
      out.limit = Number(value);
    } else if (key === "cursor") out.offset = decodeCursor(value);
    else if (key === "type" || key === "category") {
      if (!(key === "type" ? TOKEN_TYPES : TOKEN_CATEGORIES).includes(value)) throw invalid();
      out[key] = value;
    } else if (key === "provider" || key === "sourceKind") {
      if (!code(value)) throw invalid();
      out[key] = value;
    } else if (key === "expiresBefore") {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith("0000") || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0, 10) !== value) throw invalid();
      out[key] = value;
    } else {
      if (!value.trim() || value.length > 128) throw invalid();
      out[key] = value.trim();
    }
  }
  assertSafe(out);
  return out;
}
const like = (value) => "%" + value.replace(/[\\%_]/g, "\\$&") + "%";
async function listTokens({ workspaceId, query, client = pool }) {
  const parsed = parseTokenQuery(query), params = [workspaceId], where = ["TRUE"];
  const publicInventory = inventoryView();
  const add = (sql, value) => { params.push(value); where.push(sql.replace(/\?/g, "$" + params.length)); };
  if (parsed.provider) add("public_provider = ?", parsed.provider);
  if (parsed.sourceKind) add("public_source_kind = ?", parsed.sourceKind);
  for (const field of ["type", "category"]) if (parsed[field]) add(field + " = ?", parsed[field]);
  if (parsed.locationContains) add("location ILIKE ? ESCAPE '\\'", like(parsed.locationContains));
  if (parsed.query) add("(name ILIKE ? ESCAPE '\\' OR location ILIKE ? ESCAPE '\\')", like(parsed.query));
  if (parsed.expiresBefore) add("expiration < ?::date AND expiration <> '2099-12-31'::date", parsed.expiresBefore);
  const filter = where.join(" AND "), count = await client.query("SELECT COUNT(*)::int AS total FROM " + publicInventory + " WHERE " + filter, params);
  const result = await client.query(`SELECT ${RESULT_FIELDS} FROM ${publicInventory} WHERE ${filter} ORDER BY id ASC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, parsed.limit, parsed.offset]);
  const items = result.rows.map(projectToken);
  return { items, completeness: completeness({ offset: parsed.offset, returned: items.length, total: count.rows[0].total }) };
}
async function getToken({ workspaceId, tokenId, client = pool }) {
  if (!Number.isSafeInteger(Number(tokenId)) || Number(tokenId) > 2147483647 || !/^[1-9]\d{0,9}$/.test(String(tokenId))) return null;
  const result = await client.query(`SELECT ${RESULT_FIELDS} FROM ${inventoryView()} WHERE id=$2`, [workspaceId, Number(tokenId)]);
  return result.rows[0] ? { record: projectToken(result.rows[0]) } : null;
}
// Similarity means matching both the type and category of a known record.
// It never searches another workspace or infers similarity from secret fields.
async function similarTokens({ workspaceId, tokenId, query = {}, client = pool }) {
  if (Object.keys(query).some((key) => !["limit", "cursor"].includes(key))) throw invalid();
  const { limit, offset } = parseTokenQuery(query);
  const seed = await getToken({ workspaceId, tokenId, client });
  if (!seed) return null;
  const source = inventoryView();
  const where = "type=$2 AND category=$3 AND id<>$4";
  const args = [workspaceId, seed.record.type, seed.record.category, Number(tokenId)];
  const total = await client.query("SELECT COUNT(*)::int AS total FROM " + source + " WHERE " + where, args);
  const result = await client.query(`SELECT ${RESULT_FIELDS} FROM ${source} WHERE ${where} ORDER BY id ASC LIMIT $5 OFFSET $6`, [...args, limit, offset]);
  return { items: result.rows.map(projectToken), completeness: completeness({ offset, returned: result.rows.length, total: total.rows[0].total }) };
}
async function listSections({ workspaceId, query = {}, client = pool }) {
  if (Object.keys(query).some((key) => !["limit", "cursor"].includes(key))) throw invalid();
  const { limit, offset } = parseTokenQuery(query);
  const source = "(SELECT DISTINCT BTRIM(label) AS label FROM tokens CROSS JOIN LATERAL unnest(section) AS label WHERE workspace_id=$1 AND BTRIM(label) <> '') sections";
  const count = await client.query(`SELECT COUNT(*)::int AS total FROM ${source}`, [workspaceId]);
  const result = await client.query(`SELECT label FROM ${source} ORDER BY label ASC LIMIT $2 OFFSET $3`, [workspaceId, limit, offset]);
  const items = result.rows.map((row) => untrustedText(row.label));
  assertSafe(items);
  return { items, completeness: completeness({ offset, returned: items.length, total: count.rows[0].total }) };
}
function normalizeRecords(records) {
  if (!Array.isArray(records) || records.length < 1 || records.length > MAX_IMPORT_RECORDS || JSON.stringify(records).length > 200000) throw invalid();
  assertSafe(records);
  const allowed = new Set(["name", "type", "category", "expiresAt", "location", "usedBy", "sections", "domains", "description"]), identities = new Set();
  return records.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item) || Object.keys(item).some((key) => !allowed.has(key))) throw invalid();
    const text = (key, max, required = false) => {
      const value = item[key];
      if (value === undefined || value === null || value === "") { if (required) throw invalid(); return null; }
      if (typeof value !== "string" || !value.trim() || value.length > max || /[<>\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) throw invalid();
      return value.trim();
    };
    const name = text("name", 255, true), location = text("location", 512);
    if (!TOKEN_TYPES.includes(item.type) || !TOKEN_CATEGORIES.includes(item.category) || !isTypeAllowedForCategory(item.type, item.category)) throw invalid();
    let expiresAt = item.expiresAt ?? null;
    if (expiresAt !== null && (typeof expiresAt !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(expiresAt) || expiresAt.startsWith("0000") || !Number.isFinite(Date.parse(expiresAt)) || new Date(expiresAt).toISOString().slice(0, 10) !== expiresAt)) throw invalid();
    if (expiresAt === "2099-12-31") expiresAt = null;
    const identity = JSON.stringify([name, location]);
    if (identities.has(identity)) throw invalid();
    identities.add(identity);
    const list = (key) => {
      if (item[key] === undefined) return [];
      if (!Array.isArray(item[key]) || item[key].length > 50 || item[key].some((value) => typeof value !== "string" || !value.trim() || value.length > 120 || /[<>\r\n]/.test(value))) throw invalid();
      return [...new Set(item[key].map((value) => value.trim()))];
    };
    return { name, type: item.type, category: item.category, expiresAt, location, usedBy: text("usedBy", 255), sections: list("sections"), domains: list("domains"), description: text("description", 512) };
  });
}
module.exports = { MAX_IMPORT_RECORDS, assertSafe, invalid, publicLocation, projectToken, parseTokenQuery, listTokens, getToken, similarTokens, listSections, normalizeRecords };
