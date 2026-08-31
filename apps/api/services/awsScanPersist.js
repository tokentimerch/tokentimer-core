"use strict";

const MAX_SWEEP_REGIONS = 40;

function normalizeAwsSweepRegions(regions) {
  if (!Array.isArray(regions)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of regions) {
    if (typeof raw !== "string") continue;
    const region = raw.trim();
    if (!region || region.length > 50) continue;
    if (!/^[a-z0-9-]+$/.test(region)) continue;
    if (seen.has(region)) continue;
    seen.add(region);
    out.push(region);
    if (out.length >= MAX_SWEEP_REGIONS) break;
  }
  return out;
}

function awsItemPersistDimensions(item, fallbackRegion) {
  if (!item || item.sourceKind === "aws-iam-key") return {};
  const region = item.region || fallbackRegion;
  return region ? { region } : {};
}

function awsScanSubScopeReason(summary) {
  if (summary?.error) return "error";
  if (summary?.truncated) return "truncated";
  if (summary?.failedCount > 0) return "describe_failures";
  return null;
}

/**
 * Build persistScan items/subScopes from an AWS scan result. IAM is global
 * (empty dimensions). Secrets and ACM are per-region. `service` is omitted
 * because sourceKind already distinguishes those kinds.
 */
function awsScanPersistRecords(items, summary, fallbackRegion) {
  return {
    items: (Array.isArray(items) ? items : []).map((item) => ({
      sourceKind: item.sourceKind,
      sourceObjectId: item.sourceObjectId,
      dimensions: awsItemPersistDimensions(item, fallbackRegion),
    })),
    subScopes: (Array.isArray(summary) ? summary : [])
      .filter((s) => s && s.sourceKind)
      .map((s) => ({
        sourceKind: s.sourceKind,
        dimensions: s.region ? { region: s.region } : {},
        complete: s.complete === true,
        reason: awsScanSubScopeReason(s),
      })),
  };
}

module.exports = {
  MAX_SWEEP_REGIONS,
  normalizeAwsSweepRegions,
  awsItemPersistDimensions,
  awsScanPersistRecords,
};
