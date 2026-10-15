import { tokenAPI } from '../../utils/apiClient.js';
import { retireCertificate } from './certopsApi.js';

const fingerprint = value =>
  String(value || '')
    .replace(/:/g, '')
    .trim()
    .toLowerCase();

/** Refresh every loaded token affected by retiring this fingerprint, including
 * rows beyond the first inventory page and tokens shared with live siblings. */
export async function retireCertificateAndRefreshAssets({
  workspaceId,
  certificate,
  status,
  reason,
  acknowledgeUncertainty,
  tokenId,
  managedByTokenId = new Map(),
  updateTokens,
  isCurrentWorkspace = () => true,
  refreshCertOps,
  retire = retireCertificate,
  getToken = tokenAPI.getToken,
}) {
  await retire(workspaceId, certificate.id, {
    status,
    reason,
    acknowledgeUncertainty,
    identityId: certificate.identityId,
    fingerprintSha256: certificate.fingerprintSha256,
  });
  refreshCertOps?.();
  const affectedIds = new Set(
    [tokenId, certificate.tokenId].filter(value => value != null).map(Number)
  );
  for (const [id, sources] of managedByTokenId) {
    if (
      sources.some(
        source =>
          (certificate.identityId &&
            source.identityId === certificate.identityId) ||
          (certificate.fingerprintSha256 &&
            fingerprint(source.fingerprintSha256) ===
              fingerprint(certificate.fingerprintSha256))
      )
    )
      affectedIds.add(Number(id));
  }
  const refreshed = await Promise.allSettled(
    [...affectedIds].map(async id => {
      const row = await getToken(id);
      const rowWorkspace = row?.workspaceId ?? row?.workspace_id;
      if (
        Number(row?.id) !== id ||
        (rowWorkspace != null && String(rowWorkspace) !== String(workspaceId))
      ) {
        throw new Error(
          'Asset refresh returned a different token or workspace'
        );
      }
      return row;
    })
  );
  if (!isCurrentWorkspace()) return { refreshFailed: false };
  const rows = new Map(
    refreshed
      .filter(result => result.status === 'fulfilled')
      .map(result => [Number(result.value.id), result.value])
  );
  if (rows.size)
    updateTokens?.(previous =>
      previous.map(token =>
        rows.has(Number(token.id))
          ? { ...token, ...rows.get(Number(token.id)) }
          : token
      )
    );
  return {
    refreshFailed: refreshed.some(result => result.status === 'rejected'),
  };
}
