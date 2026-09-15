export function createTokenEditData(token) {
  return {
    name: token?.name || '',
    section: Array.isArray(token?.section)
      ? token.section.join(', ')
      : token?.section || '',
    expiresAt: token?.expiresAt || '',
    domains: Array.isArray(token?.domains)
      ? token.domains.join(', ')
      : token?.domains || '',
    location: token?.location || '',
    used_by: token?.used_by || '',
    issuer: token?.issuer || '',
    serial_number: token?.serial_number || '',
    subject: token?.subject || '',
    key_size: token?.key_size || '',
    algorithm: token?.algorithm || '',
    license_type: token?.license_type || '',
    vendor: token?.vendor || '',
    cost: token?.cost || '',
    renewal_url: token?.renewal_url || '',
    renewal_date: token?.renewal_date || '',
    contacts: token?.contacts || '',
    description: token?.description || '',
    notes: token?.notes || '',
    privileges: token?.privileges || '',
    contact_group_id: token?.contact_group_id || '',
  };
}

/**
 * Normalizes the shared token-detail edit form into the update payload used by
 * every token details presentation. Keeping this in one place prevents the
 * compact CertOps certificate modal and the general asset modal from drifting
 * apart as editable fields evolve.
 */
export function createTokenUpdatePayload(editData, token) {
  const payload = { ...editData };

  if (typeof payload.section === 'string' && payload.section.trim()) {
    payload.section = payload.section
      .split(',')
      .map(section => section.trim())
      .filter(Boolean);
  } else if (payload.section === '') {
    payload.section = null;
  }

  if (typeof payload.domains === 'string' && payload.domains.trim()) {
    payload.domains = payload.domains
      .split(',')
      .map(domain => domain.trim())
      .filter(Boolean);
  } else if (payload.domains === '') {
    payload.domains = null;
  }

  const originalExpiresAt = token?.expiresAt ? String(token.expiresAt) : '';
  const nextExpiresAt =
    payload.expiresAt == null ? '' : String(payload.expiresAt).trim();
  if (nextExpiresAt === originalExpiresAt) {
    delete payload.expiresAt;
  }

  if (
    payload.key_size !== undefined &&
    String(payload.key_size).trim() !== ''
  ) {
    const keySize = parseInt(payload.key_size, 10);
    payload.key_size = Number.isFinite(keySize) ? keySize : null;
  } else {
    payload.key_size = null;
  }

  if (payload.cost !== undefined && String(payload.cost).trim() !== '') {
    const cost = parseFloat(payload.cost);
    payload.cost = Number.isFinite(cost) ? cost : null;
  } else {
    payload.cost = null;
  }

  [
    'section',
    'location',
    'used_by',
    'issuer',
    'serial_number',
    'subject',
    'algorithm',
    'license_type',
    'vendor',
    'renewal_url',
    'renewal_date',
    'contacts',
    'description',
    'notes',
    'privileges',
  ].forEach(key => {
    if (payload[key] !== undefined && String(payload[key]).trim() === '') {
      payload[key] = null;
    }
  });

  return payload;
}
