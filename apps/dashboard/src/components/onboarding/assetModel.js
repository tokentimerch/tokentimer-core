// Builds an asset the way the main "Create New Token" form does: four
// categories with their own fields, an optional expiry, contact groups. Pure
// and shared with the real category table so the setup guide cannot drift from
// the product's own rules.

import { TOKEN_CATEGORIES } from '../../constants/tokenCategories.js';
import { NEVER_EXPIRES_DATE_VALUE } from '../../utils/dateUtils.js';
import { canonicalContactGroupFields } from '../../utils/contactGroupAssignment.js';

export { TOKEN_CATEGORIES };

const KEY_ALGO_TYPES = [
  'encryption_key',
  'ssh_key',
  'ssl_cert',
  'tls_cert',
  'code_signing',
  'client_cert',
];

export function categoryOf(value) {
  return TOKEN_CATEGORIES.find(c => c.value === value) || null;
}

/**
 * Assets are created one by one and each is checked on the way in, so a batch
 * stays small enough to review and to finish.
 */
export const MAX_STAGED_ASSETS = 25;

/**
 * What makes two drafts the same asset: the identity the wizard already uses
 * to recognise one it created earlier. Two drafts with the same key would be
 * collapsed into one, so the list refuses the second.
 */
export function assetKey(asset) {
  return [
    String(asset?.name || '')
      .trim()
      .toLowerCase(),
    asset?.category || '',
    asset?.type || '',
    asset?.neverExpires ? '' : String(asset?.expiresAt || ''),
  ].join('|');
}

/** One line for the list: the name, then kind and expiry in plain words. */
export function describeAsset(asset) {
  const cat = categoryOf(asset?.category);
  const type = cat?.types.find(x => x.value === asset?.type);
  const kind = [cat?.label, type?.label].filter(Boolean).join(', ');
  const expiry =
    asset?.neverExpires || !String(asset?.expiresAt || '').trim()
      ? 'no expiry date'
      : `expires ${asset.expiresAt}`;
  return {
    title: String(asset?.name || '').trim(),
    detail: [kind, expiry].filter(Boolean).join(', '),
  };
}

/** Fields a category shows, including type-specific ones. */
export function fieldsFor(category, type) {
  const cat = categoryOf(category);
  if (!cat) return [];
  return [...cat.fields, ...(cat.conditionalFields?.[type] || [])];
}

export const FIELD_LABELS = {
  domains: 'Domains (comma separated)',
  issuer: 'Issuer',
  serial_number: 'Serial number',
  subject: 'Subject',
  renewal_url: 'Renewal link',
  contacts: 'Contacts or owner',
  location: 'Where it is stored',
  used_by: 'Used by',
  description: 'Description',
  algorithm: 'Algorithm',
  key_size: 'Key size',
  vendor: 'Vendor',
  license_type: 'License type',
  cost: 'Cost',
  renewal_date: 'Renewal date',
};

export function emptyAsset() {
  return {
    category: 'key_secret',
    type: 'api_key',
    name: '',
    neverExpires: false,
    expiresAt: '',
    section: '',
    notes: '',
    contactGroupIds: [],
    fields: {},
  };
}

/** What the user typed, checked with the product's own limits. */
export function validateAsset(asset, now = new Date()) {
  const errors = {};
  const name = String(asset.name || '').trim();
  if (!name) errors.name = 'Name is required.';
  else if (name.length > 255) errors.name = 'Use 255 characters or fewer.';

  const cat = categoryOf(asset.category);
  if (!cat) errors.category = 'Choose a category.';
  else if (!cat.types.some(t => t.value === asset.type))
    errors.type = `Choose a type for ${cat.label}.`;

  if (!asset.neverExpires && asset.expiresAt) {
    const d = new Date(asset.expiresAt);
    if (Number.isNaN(d.getTime())) errors.expiresAt = 'Invalid date.';
    else if (d <= now)
      errors.expiresAt = 'The expiry date must be in the future.';
  }

  const f = asset.fields || {};
  if (cat?.value === 'cert' && f.domains) {
    const list = String(f.domains)
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    if (list.length === 0) errors.domains = 'Enter at least one domain.';
  }
  if (cat?.value === 'license' && String(f.cost || '').trim()) {
    const cost = Number.parseFloat(f.cost);
    if (Number.isNaN(cost) || cost < 0)
      errors.cost = 'Cost must be zero or more.';
    else if (cost > 999999999999.99)
      errors.cost = 'Cost must be less than one trillion.';
  }
  if (String(f.key_size || '').trim()) {
    const size = Number.parseInt(f.key_size, 10);
    if (!KEY_ALGO_TYPES.includes(asset.type))
      errors.key_size = 'Key size only applies to keys and certificates.';
    else if (Number.isNaN(size) || size <= 0)
      errors.key_size = 'Key size must be a positive whole number.';
  }
  if (String(f.algorithm || '').trim() && !KEY_ALGO_TYPES.includes(asset.type))
    errors.algorithm = 'Algorithm only applies to keys and certificates.';
  return { ok: Object.keys(errors).length === 0, errors };
}

const text = v => {
  const s = String(v ?? '').trim();
  return s || null;
};

const list = v => {
  const items = String(v ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return items.length ? items : null;
};

/**
 * The body for POST /api/tokens. An empty expiry becomes the product's
 * "never expires" date. Only fields that belong to the category are sent.
 */
export function buildAssetPayload(asset, workspaceId) {
  const allowed = new Set(fieldsFor(asset.category, asset.type));
  const f = asset.fields || {};
  const pick = key => (allowed.has(key) ? f[key] : undefined);
  const neverExpires =
    asset.neverExpires || !String(asset.expiresAt || '').trim();
  const cost = text(pick('cost'));
  const keySize = text(pick('key_size'));
  return {
    workspace_id: workspaceId,
    name: String(asset.name).trim(),
    category: asset.category,
    type: asset.type,
    expiresAt: neverExpires ? NEVER_EXPIRES_DATE_VALUE : asset.expiresAt,
    section: list(asset.section),
    domains: list(pick('domains')),
    location: text(pick('location')),
    used_by: text(pick('used_by')),
    issuer: text(pick('issuer')),
    serial_number: text(pick('serial_number')),
    subject: text(pick('subject')),
    key_size: keySize ? Number.parseInt(keySize, 10) : null,
    algorithm: text(pick('algorithm')),
    license_type: text(pick('license_type')),
    vendor: text(pick('vendor')),
    cost: cost ? Number.parseFloat(cost) : null,
    renewal_url: text(pick('renewal_url')),
    renewal_date: text(pick('renewal_date')),
    contacts: text(pick('contacts')),
    description: text(pick('description')),
    notes: text(asset.notes),
    ...canonicalContactGroupFields(asset.contactGroupIds || []),
  };
}
