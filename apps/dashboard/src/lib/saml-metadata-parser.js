/**
 * Client-side SAML IdP metadata parser (ESM). Dashboard-only; mirrors server policy.
 */

import { DOMParser as XmlParser } from '@xmldom/xmldom';

const REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const POST_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

const METADATA_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:metadata';
const SIGNATURE_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#';

function metadataChildren(element, ...names) {
  return Array.from(element.childNodes).filter(
    node =>
      node.namespaceURI === METADATA_NAMESPACE && names.includes(node.localName)
  );
}

function readSigningCertificates(descriptor) {
  const certificates = new Set();
  for (const key of metadataChildren(descriptor, 'KeyDescriptor')) {
    const use = key.getAttribute('use');
    if (use && use !== 'signing') continue;
    const candidates = key.getElementsByTagNameNS(
      SIGNATURE_NAMESPACE,
      'X509Certificate'
    );
    for (const candidate of Array.from(candidates)) {
      const raw = String(candidate.textContent || '').replace(/\s+/g, '');
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) continue;
      const lines = raw.match(/.{1,64}/g).join('\n');
      certificates.add(
        `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`
      );
      if (certificates.size === 2) return [...certificates];
    }
  }
  return [...certificates];
}

function pickSsoService(idpDescriptor) {
  const services = metadataChildren(
    idpDescriptor,
    'SingleLogoutService',
    'SingleSignOnService'
  );
  const signOnServices = services.filter(
    service => service.localName === 'SingleSignOnService'
  );
  if (!signOnServices.length) {
    return { error: 'No SingleSignOnService found in metadata' };
  }

  let redirect = null;
  let post = null;
  let fallback = null;
  for (const sso of signOnServices) {
    const binding = sso.getAttribute('Binding') || '';
    const location = sso.getAttribute('Location') || '';
    if (!location) continue;
    if (binding === REDIRECT_BINDING) redirect = { binding, location };
    else if (binding === POST_BINDING) post = { binding, location };
    else if (!fallback) fallback = { binding, location };
  }

  const picked = redirect || post || fallback;
  if (!picked) return { error: 'No SSO service Location in metadata' };
  const bindings = services
    .map(service => service.getAttribute('Binding'))
    .filter(Boolean);
  return { ...picked, bindings };
}

function findIdpDescriptor(entity) {
  if (entity.localName === 'EntityDescriptor') {
    const [idpDescriptor] = metadataChildren(entity, 'IDPSSODescriptor');
    return idpDescriptor ? { entity, idpDescriptor } : null;
  }
  for (const child of metadataChildren(
    entity,
    'EntityDescriptor',
    'EntitiesDescriptor'
  )) {
    const match = findIdpDescriptor(child);
    if (match) return match;
  }
  return null;
}

function bindingLabel(binding) {
  if (binding === REDIRECT_BINDING) return 'HTTP-Redirect';
  if (binding === POST_BINDING) return 'HTTP-POST';
  return binding || 'unknown';
}

/**
 * @param {string} xml
 * @returns {{ ok: true, entryPoint: string, cert: string, secondaryCert: string, idpEntityId: string, authnRequestBinding: string, bindings: string[] } | { ok: false, error: string }}
 */
export function parseSamlMetadataXml(xml) {
  const trimmed = String(xml || '').trim();
  if (!trimmed) {
    return { ok: false, error: 'Metadata XML is empty' };
  }
  let doc;
  try {
    if (/<!DOCTYPE\b/i.test(trimmed)) {
      return {
        ok: false,
        error: 'Metadata must not contain a document type declaration',
      };
    }
    let invalid = false;
    const parser = new XmlParser({
      errorHandler: () => {
        invalid = true;
      },
    });
    doc = parser.parseFromString(trimmed, 'application/xml');
    if (invalid || !doc?.documentElement) {
      return { ok: false, error: 'Invalid XML' };
    }
  } catch {
    return { ok: false, error: 'Invalid XML' };
  }

  const root = doc.documentElement;
  if (
    root.namespaceURI !== METADATA_NAMESPACE ||
    !['EntityDescriptor', 'EntitiesDescriptor'].includes(root.localName)
  ) {
    return { ok: false, error: 'Unsupported SAML metadata document' };
  }

  const match = findIdpDescriptor(root);
  if (!match) {
    return { ok: false, error: 'No IDPSSODescriptor in metadata' };
  }
  const { entity, idpDescriptor } = match;
  const picked = pickSsoService(idpDescriptor);
  if (picked.error) return { ok: false, error: picked.error };

  const [cert, secondaryCert = ''] = readSigningCertificates(idpDescriptor);
  if (!cert) {
    return { ok: false, error: 'No signing certificate found in metadata' };
  }

  return {
    ok: true,
    entryPoint: picked.location,
    cert,
    secondaryCert,
    idpEntityId: entity.getAttribute('entityID') || '',
    authnRequestBinding: bindingLabel(picked.binding),
    bindings: picked.bindings || [picked.binding],
  };
}

export { REDIRECT_BINDING, POST_BINDING, bindingLabel };

function isAllowedMetadataFetchUrl(url) {
  try {
    const parsed = new URL(String(url || '').trim());
    if (parsed.protocol === 'https:') return true;
    if (
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' ||
        parsed.hostname === '127.0.0.1' ||
        parsed.hostname === '::1')
    ) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Fetch metadata URL in browser (admin-only UI). HTTPS or localhost dev only.
 * Prefer fetchMetadataUrl (API proxy) when provided to avoid browser CORS blocks.
 *
 * @param {string} url
 * @param {{ fetchMetadataUrl?: (url: string) => Promise<string> }} [opts]
 * @returns {Promise<{ ok: true, ... } | { ok: false, error: string }>}
 */
export async function fetchAndParseSamlMetadataUrl(url, opts = {}) {
  const target = String(url || '').trim();
  if (!target) {
    return { ok: false, error: 'Metadata URL is required' };
  }
  if (typeof opts.fetchMetadataUrl === 'function') {
    try {
      const xml = await opts.fetchMetadataUrl(target);
      return parseSamlMetadataXml(xml);
    } catch (e) {
      const apiError = e?.response?.data?.error;
      return { ok: false, error: apiError || e.message || 'Fetch failed' };
    }
  }
  if (!isAllowedMetadataFetchUrl(target)) {
    return {
      ok: false,
      error:
        'Metadata URL must use https:// (or http://localhost for local dev)',
    };
  }
  try {
    const res = await fetch(target, {
      credentials: 'omit',
      redirect: 'follow',
    });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const xml = await res.text();
    return parseSamlMetadataXml(xml);
  } catch (e) {
    return { ok: false, error: e.message || 'Fetch failed' };
  }
}

/**
 * Resolve SAML metadata from wizard inputs. Pasted XML takes precedence over URL.
 *
 * @param {{ metadataUrl?: string, metadataXml?: string, fetchMetadataUrl?: (url: string) => Promise<string> }} input
 * @returns {Promise<{ ok: true, entryPoint: string, cert: string, secondaryCert: string, idpEntityId: string, authnRequestBinding: string, bindings: string[] } | { ok: false, error: string }>}
 */
export async function resolveSamlMetadataInput({
  metadataUrl,
  metadataXml,
  fetchMetadataUrl,
}) {
  const xml = String(metadataXml || '').trim();
  if (xml) {
    return parseSamlMetadataXml(xml);
  }
  const url = String(metadataUrl || '').trim();
  if (url) {
    return fetchAndParseSamlMetadataUrl(url, { fetchMetadataUrl });
  }
  return {
    ok: false,
    error: 'Paste IdP metadata XML or enter a metadata URL',
  };
}
