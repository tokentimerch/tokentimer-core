"use strict";

// A display-only reconciliation. The stored observations and security state
// are never changed; anything that cannot be matched unambiguously stays put.
const { isIP } = require("node:net");

function address(value) {
  if (typeof value !== "string" || value.includes("%")) return null;
  const bracket = /^\[([^\]]+)\]$/.exec(value);
  if ((value.includes("[") || value.includes("]")) && !bracket) return null;
  const raw = bracket ? bracket[1] : value;
  const family = isIP(raw);
  if (!family || (bracket && family !== 6)) return null;
  if (family === 4) return raw;
  try { return new URL(`http://[${raw}]/`).hostname.slice(1, -1); } catch { return null; }
}

function concrete(value) {
  const ip = address(value);
  return ip && ip !== "0.0.0.0" && ip !== "::" && !ip.startsWith("::ffff:") ? ip : null;
}

function httpAddress(reference, port) {
  if (typeof reference !== "string") return null;
  const match = /^http-sys:\/\/(\[[^\]]+\]|[^:]+):(\d+)$/.exec(reference);
  if (!match || Number(match[2]) !== port) return null;
  return concrete(match[1]);
}

function tuple(row) {
  const { target_agent_id: agent, target_hostname: host, target_port: port } = row;
  if (row.source !== "agent_windows" || typeof agent !== "string" || !agent ||
      typeof host !== "string" || !host || !Number.isInteger(port) || port < 1 || port > 65535 ||
      !row.target_id || row.target_sni) return null;
  const prefix = `${agent}/${host}/${row.location_kind}/`;
  if (typeof row.source_ref !== "string" || typeof row.deployment_reference !== "string" ||
      !row.source_ref.startsWith(prefix) || row.target_source_ref !== row.source_ref ||
      row.target_reference !== row.deployment_reference) return null;
  let ip;
  if (row.location_kind === "http_sys") {
    ip = httpAddress(row.deployment_reference, port);
    const slot = row.source_ref.slice(prefix.length), split = slot.lastIndexOf(":");
    if (!ip || split <= 0 || Number(slot.slice(split + 1)) !== port || concrete(slot.slice(0, split)) !== ip) return null;
  } else if (row.location_kind === "iis_binding") {
    ip = concrete(row.target_address);
    if (!ip || typeof row.target_site !== "string" || !row.target_site) return null;
    const sourcePrefix = `${prefix}${row.target_site}:${port}@`;
    const referencePrefix = `iis://${row.target_site}:${port}@`;
    if (!row.source_ref.startsWith(sourcePrefix) || !row.deployment_reference.startsWith(referencePrefix) ||
        concrete(row.source_ref.slice(sourcePrefix.length)) !== ip ||
        concrete(row.deployment_reference.slice(referencePrefix.length)) !== ip) return null;
  } else return null;
  return { agent, host: host.toLowerCase(), port, ip };
}

function key(t) { return JSON.stringify([t.agent, t.host, t.port, t.ip]); }

function targetAddress(target) {
  if (target.location_kind === "http_sys") return httpAddress(target.deployment_reference, target.windows_port);
  if (target.location_kind === "iis_binding") return address(target.bound_address);
  return null;
}

function mayOverlap(target, candidate) {
  const agent = target.agent_id;
  const host = String(target.hostname || "").toLowerCase();
  if (target.windows_port !== candidate.port) return false;
  if (!host) return !agent || agent === candidate.agent;
  if (host !== candidate.host) return false;
  // An unidentifiable agent on this host and port is ambiguous, not proof.
  if (!agent) return true;
  if (agent !== candidate.agent) return false;
  if (target.windows_sni_host) return true;
  const ip = targetAddress(target);
  if (!ip || ip === "::") return true;
  if (ip === "0.0.0.0") return isIP(candidate.ip) === 4;
  if (ip.startsWith("::ffff:")) return isIP(candidate.ip) === 4;
  return ip === candidate.ip;
}

function foldWindowsLocations(rows, targets) {
  const grouped = new Map();
  for (const row of rows) {
    const t = tuple(row);
    if (!t) continue;
    const k = key(t), group = grouped.get(k) || { tuple: t, http: [], iis: [] };
    group[row.location_kind === "http_sys" ? "http" : "iis"].push(row);
    grouped.set(k, group);
  }
  const hidden = new Set();
  for (const group of grouped.values()) {
    if (group.http.length !== 1 || group.iis.length !== 1) continue;
    const old = group.http[0], current = group.iis[0];
    const oldTime = new Date(old.captured_at).getTime();
    const currentTime = new Date(current.captured_at).getTime();
    if (!current.authoritative_instance || current.iis_attribution_verified !== true || !old.captured_at || !current.captured_at ||
        !Number.isFinite(oldTime) || !Number.isFinite(currentTime) || currentTime > Date.now() || oldTime >= currentTime) continue;
    const overlapping = targets.filter(target => mayOverlap(target, group.tuple));
    if (overlapping.length !== 2 || !overlapping.some(t => t.id === old.target_id) || !overlapping.some(t => t.id === current.target_id)) continue;
    const previous = {
      id: old.id, source: old.source, sourceRef: old.source_ref,
      targetHostname: old.target_hostname, locationKind: old.location_kind,
      deploymentReference: old.deployment_reference, evidenceKind: old.evidence_kind,
      presenceState: old.presence_state, capturedAt: old.captured_at,
      monitoringEnded: Boolean(old.monitoring_ended), observationReason: old.observation_reason,
    };
    current.previous_count = Number(current.previous_count || 0) + Number(old.previous_count || 0) + 1;
    current.previous_observations = [...(current.previous_observations || []), previous,
      ...(old.previous_observations || [])].sort((a, b) => new Date(b.capturedAt) - new Date(a.capturedAt)).slice(0, 20);
    hidden.add(old.id);
  }
  return rows.filter(row => !hidden.has(row.id));
}

module.exports = { foldWindowsLocations };
