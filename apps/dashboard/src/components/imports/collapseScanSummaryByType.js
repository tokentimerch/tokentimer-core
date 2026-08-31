// Azure AD (and similar) scans emit one summary row per cleanup sourceKind,
// so the same Graph type appears twice. Collapse by `type` for display.
// Secrets/certs take the max across rows so duplicated kind counts from
// older API payloads are not added twice. FOUND is extracted credentials,
// not the number of Graph objects enumerated.
export function collapseScanSummaryByType(rows) {
  if (!Array.isArray(rows)) return [];
  const order = [];
  const byType = new Map();

  for (const s of rows) {
    if (!s || typeof s !== 'object') continue;
    const key = s.type || s.sourceKind;
    if (!key) continue;

    if (!byType.has(key)) {
      order.push(key);
      byType.set(key, {
        type: s.type || key,
        secrets: 0,
        certificates: 0,
        complete: true,
        truncated: false,
        error: null,
        sawSecrets: false,
        sawCerts: false,
        foundSum: 0,
      });
    }

    const acc = byType.get(key);
    if (s.error) acc.error = acc.error || s.error;
    if (s.complete === false) acc.complete = false;
    if (s.truncated) acc.truncated = true;
    acc.foundSum += Number(s.found) || 0;
    if (typeof s.secrets === 'number') {
      acc.sawSecrets = true;
      acc.secrets = Math.max(acc.secrets, s.secrets);
    }
    if (typeof s.certificates === 'number') {
      acc.sawCerts = true;
      acc.certificates = Math.max(acc.certificates, s.certificates);
    }
  }

  return order.map(k => {
    const acc = byType.get(k);
    return {
      type: acc.type,
      found:
        acc.sawSecrets || acc.sawCerts
          ? acc.secrets + acc.certificates
          : acc.foundSum,
      secrets: acc.secrets,
      certificates: acc.certificates,
      complete: acc.complete,
      truncated: acc.truncated,
      error: acc.error,
    };
  });
}
