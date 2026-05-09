import { Badge } from '@chakra-ui/react';

export function domainStatusColor(status) {
  switch (status) {
    case 'healthy':
      return 'green';
    case 'unhealthy':
      return 'orange';
    case 'error':
      return 'red';
    default:
      return 'gray';
  }
}

export function domainSslBadge(domain) {
  if (!domain.ssl_valid_to) return <Badge colorScheme='gray'>No SSL</Badge>;
  const daysLeft = Math.ceil(
    (new Date(domain.ssl_valid_to) - new Date()) / (1000 * 60 * 60 * 24)
  );
  if (daysLeft < 0) return <Badge colorScheme='red'>Expired</Badge>;
  if (daysLeft < 14)
    return <Badge colorScheme='orange'>{daysLeft}d left</Badge>;
  if (daysLeft < 30)
    return <Badge colorScheme='yellow'>{daysLeft}d left</Badge>;
  return <Badge colorScheme='green'>Valid ({daysLeft}d)</Badge>;
}

export function domainFormatUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname !== '/' ? u.pathname : '');
  } catch {
    return url;
  }
}

export function domainValueToUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  if (/^https?:\/\//i.test(raw)) return raw;
  return `https://${raw}`;
}
