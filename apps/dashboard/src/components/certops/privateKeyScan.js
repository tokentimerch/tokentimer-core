/**
 * Client-side private-key pre-scan for CertOps imports.
 *
 * This is a courtesy guard so the user gets an immediate, friendly refusal
 * before any request leaves the browser. It mirrors the conceptual boundary of
 * the server detector (apps/api/utils/secretMaterial.js) but is intentionally
 * conservative. The server remains the source of truth and rejects private key
 * material with HTTP 422 PRIVATE_KEY_MATERIAL_REJECTED regardless of this scan.
 */

const PRIVATE_KEY_PEM_PATTERN = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;
const BASE64_PATTERN = /^[A-Za-z0-9+/\s]+={0,2}$/;

function decodeBase64(value) {
  const compact = value.replace(/\s+/g, '');
  if (compact.length < 64 || !BASE64_PATTERN.test(value)) return null;
  try {
    if (typeof atob === 'function') return atob(compact);
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Returns true if the supplied text appears to contain private key material,
 * either as a raw PEM block or base64-wrapped PEM.
 * @param {string} value
 * @returns {boolean}
 */
export function containsPrivateKeyMaterial(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (PRIVATE_KEY_PEM_PATTERN.test(value)) return true;

  const decoded = decodeBase64(value);
  if (decoded && PRIVATE_KEY_PEM_PATTERN.test(decoded)) return true;

  return false;
}

export const PRIVATE_KEY_REFUSAL_MESSAGE =
  'This looks like it contains a private key. TokenTimer never stores private keys. Remove the private key block and paste only the public certificate (and chain).';
