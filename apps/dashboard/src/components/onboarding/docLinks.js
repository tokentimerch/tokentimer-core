import registry from './docLinks.json';

// Enterprise has no pages for tokens, monitoring, alerts or agents; those
// topics live in the matching self-hosted docs.
function editionOf(baseUrl) {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  if (base.endsWith('/cloud')) return { edition: 'cloud', base };
  if (base.endsWith('/enterprise')) {
    return {
      edition: 'selfHosted',
      base: base.replace(/\/enterprise$/, '/self-hosted'),
    };
  }
  return { edition: 'selfHosted', base };
}

export function docKeys() {
  return Object.keys(registry).filter(key => !key.startsWith('_'));
}

/** Returns the absolute documentation URL, or null when the edition has no such page. */
export function docUrl(key, baseUrl) {
  const entry = registry[key];
  if (!entry || key.startsWith('_') || !baseUrl) return null;
  const { edition, base } = editionOf(baseUrl);
  const target = edition === 'cloud' && 'cloud' in entry ? entry.cloud : entry;
  if (!target) return null;
  return `${base}${target.path}${target.anchor ? `#${target.anchor}` : ''}`;
}
