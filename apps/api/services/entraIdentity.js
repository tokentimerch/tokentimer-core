"use strict";

function legacyManagedIdentityLocation(item) {
  if (item?.servicePrincipalType !== "ManagedIdentity") return null;
  const kind = item.sourceKind || item.source;
  const match = /^azure-ad:managedIdentities\/([^/:]+)\/(certificates|secrets)\/([^/:]+)$/.exec(
    item.location || "",
  );
  if (!match) return null;
  const [, appId, category, keyId] = match;
  const expectedKind = category === "certificates"
    ? "azure-ad-sp-certificate" : "azure-ad-sp-secret";
  if (kind !== expectedKind) return null;
  if (item.sourceObjectId && item.sourceObjectId !== `${appId}:${keyId}`) return null;
  return `azure-ad:servicePrincipals/${appId}/${category}/${keyId}`;
}

module.exports = { legacyManagedIdentityLocation };
