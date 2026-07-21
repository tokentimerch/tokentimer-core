/**
 * Obsolete-token cleanup for integration imports and auto-sync.
 *
 * When a scan completes and cleanup is requested, previously imported tokens
 * that belong to the scanned provider AND fall inside the scanned scope
 * (source kinds actually included in this scan) but were NOT rediscovered
 * are hard-deleted with a TOKEN_DELETED audit event.
 *
 * Safety rules:
 *   - Only tokens in the same workspace.
 *   - Only tokens whose location starts with the provider prefix (e.g. "gitlab:").
 *   - Only tokens matching a location pattern of a source kind that was part
 *     of this scan (a PAT-less scan never deletes PAT entries).
 *   - Only tokens that were previously imported (imported_at IS NOT NULL).
 */

const { pool } = require("../db/database");
const { writeAudit } = require("./audit");
const { logger } = require("../utils/logger");

const PROVIDER_PREFIXES = {
  gitlab: "gitlab:",
  github: "github:",
  vault: "vault:",
  aws: "aws:",
  azure: "azure:",
  "azure-ad": "azure-ad:",
  gcp: "gcp:",
};

// Location shape per scan source kind. A stored token is only eligible for
// cleanup when its location matches the pattern of a source kind that was
// included in the current scan.
const SOURCE_LOCATION_PATTERNS = {
  "gitlab-pat": /^gitlab:(users\/[^/]+\/)?personal_access_tokens\//,
  "gitlab-project-token": /^gitlab:projects\/[^/]+\/access_tokens\//,
  "gitlab-group-token": /^gitlab:groups\/[^/]+\/access_tokens\//,
  "gitlab-deploy-token": /^gitlab:projects\/[^/]+\/deploy_tokens\//,
  "gitlab-trigger-token": /^gitlab:projects\/[^/]+\/triggers\//,
  "gitlab-ssh-key": /^gitlab:user\/keys\//,
  "github-ssh-key": /^github:user\/keys\//,
  "github-secret": /^github:repos\/.+\/actions\/secrets\//,
  "github-deploy-key": /^github:repos\/.+\/keys\//,
  "vault-kv": /^vault:/,
  "vault-pki": /^vault:/,
  "aws-secrets-manager": /^aws:secretsmanager:/,
  "aws-acm": /^aws:acm:/,
  "aws-iam-key": /^aws:iam:/,
  "azure-key-vault-secret": /^azure:.+\/secrets\//,
  "azure-key-vault-certificate": /^azure:.+\/certificates\//,
  "azure-key-vault-key": /^azure:.+\/keys\//,
  "azure-ad-client-secret": /^azure-ad:applications\/.+\/secrets\//,
  "azure-ad-certificate": /^azure-ad:applications\/.+\/certificates\//,
  "azure-ad-sp-secret": /^azure-ad:servicePrincipals\/.+\/secrets\//,
  "azure-ad-sp-certificate": /^azure-ad:servicePrincipals\/.+\/certificates\//,
  "gcp-secret-manager": /^gcp:.+\/secrets\//,
};

/**
 * Validates a cleanup payload. Returns null when valid, otherwise an error
 * string suitable for a 400 response.
 */
function validateCleanupRequest(cleanup) {
  if (cleanup === undefined || cleanup === null) return null;
  if (typeof cleanup !== "object" || Array.isArray(cleanup)) {
    return "cleanup must be an object";
  }
  if (cleanup.enabled !== true) return null;
  if (!PROVIDER_PREFIXES[cleanup.provider]) {
    return `cleanup.provider must be one of: ${Object.keys(PROVIDER_PREFIXES).join(", ")}`;
  }
  if (!Array.isArray(cleanup.scannedSources) || cleanup.scannedSources.length === 0) {
    return "cleanup.scannedSources must be a non-empty array of source kinds";
  }
  for (const s of cleanup.scannedSources) {
    if (!SOURCE_LOCATION_PATTERNS[s]) {
      return `cleanup.scannedSources contains unknown source kind: ${s}`;
    }
  }
  if (!Array.isArray(cleanup.scannedLocations)) {
    return "cleanup.scannedLocations must be an array of location strings";
  }
  if (cleanup.scannedLocations.length > 50000) {
    return "cleanup.scannedLocations is too large";
  }
  return null;
}

/**
 * Deletes workspace tokens that were previously imported from the given
 * provider, fall inside the scanned scope, and were not rediscovered.
 *
 * @returns {Promise<{deleted: Array<{id:number,name:string,location:string}>}>}
 */
async function cleanupObsoleteTokens({
  workspaceId,
  actorUserId,
  cleanup,
  reason = "import_cleanup",
}) {
  const deleted = [];
  if (!cleanup || cleanup.enabled !== true) return { deleted };

  const prefix = PROVIDER_PREFIXES[cleanup.provider];
  if (!prefix) return { deleted };

  const patterns = (cleanup.scannedSources || [])
    .map((s) => SOURCE_LOCATION_PATTERNS[s])
    .filter(Boolean);
  if (patterns.length === 0) return { deleted };

  const rediscovered = new Set(
    (cleanup.scannedLocations || [])
      .map((l) => String(l || "").trim())
      .filter(Boolean),
  );

  // Candidates: previously imported tokens from this provider in this workspace.
  const candidatesRes = await pool.query(
    `SELECT id, name, location FROM tokens
     WHERE workspace_id = $1
       AND imported_at IS NOT NULL
       AND location LIKE $2`,
    [workspaceId, `${prefix}%`],
  );

  for (const row of candidatesRes.rows) {
    const location = String(row.location || "");
    // Only delete inside the scanned scope.
    if (!patterns.some((p) => p.test(location))) continue;
    if (rediscovered.has(location)) continue;

    try {
      // Reuse the manual delete semantics: clear queue entries and linked
      // endpoint monitors so they don't become orphaned.
      await pool.query("DELETE FROM alert_queue WHERE token_id = $1", [row.id]);
      await pool.query("DELETE FROM domain_monitors WHERE token_id = $1", [
        row.id,
      ]);
      await pool.query("DELETE FROM tokens WHERE id = $1", [row.id]);
      deleted.push({ id: row.id, name: row.name, location });
      try {
        await writeAudit({
          actorUserId: actorUserId || null,
          subjectUserId: actorUserId || null,
          action: "TOKEN_DELETED",
          targetType: "token",
          targetId: row.id,
          channel: null,
          workspaceId,
          metadata: {
            name: row.name,
            location,
            reason,
            provider: cleanup.provider,
          },
        });
      } catch (auditErr) {
        logger.warn("Cleanup audit write failed", { error: auditErr.message });
      }
    } catch (delErr) {
      logger.warn("Obsolete token cleanup failed for token", {
        tokenId: row.id,
        error: delErr.message,
      });
    }
  }

  return { deleted };
}

module.exports = {
  PROVIDER_PREFIXES,
  SOURCE_LOCATION_PATTERNS,
  validateCleanupRequest,
  cleanupObsoleteTokens,
};
