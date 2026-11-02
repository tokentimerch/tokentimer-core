// Which assets the operator created through the asset step. operationRefs
// tokenIds also holds the certificates that website monitors create, so it
// cannot tell the two apart; operationRefs.assetTokenIds can.

// Sessions saved before assetTokenIds existed keep asset-step ids only in
// tokenIds. Trust that list only when no website monitor ever contributed to
// it, so old asset-only sessions stay done and website-then-asset ones do not.
function legacyIds(refs) {
  const monitorsInvolved =
    (refs.monitorIds || []).length > 0 || Boolean(refs.monitorUrl);
  return monitorsInvolved ? [] : refs.tokenIds || [];
}

/** Asset-step ids that still exist, from the verified summary references. */
export function existingAssetStepIds(refs = {}, references = {}) {
  if (Array.isArray(refs.assetTokenIds)) {
    return references.assetTokenIds?.existing || [];
  }
  const legacy = new Set(legacyIds(refs).map(String));
  return (references.tokenIds?.existing || []).filter(id =>
    legacy.has(String(id))
  );
}

/** assetTokenIds with one more asset-step id, migrating the legacy shape. */
export function withAssetTokenId(refs = {}, id) {
  const base = Array.isArray(refs.assetTokenIds)
    ? refs.assetTokenIds
    : legacyIds(refs);
  return Array.from(new Set([...base, id].filter(Boolean)));
}
