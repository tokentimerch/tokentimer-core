import { Th, HStack, Text, Badge } from '@chakra-ui/react';

/**
 * Sortable Table Header Component
 */
export function SortableTh({
  children,
  sortKey,
  sortConfig,
  onSort,
  hoverBg,
  ...props
}) {
  const isActive = sortConfig.key === sortKey;
  const direction = isActive ? sortConfig.direction : 'asc';

  return (
    <Th
      {...props}
      cursor='pointer'
      userSelect='none'
      onClick={() => onSort(sortKey)}
      _hover={{ bg: hoverBg }}
      position='relative'
    >
      <HStack spacing={1} justify='space-between'>
        <Text>{children}</Text>
        <Text fontSize='xs' opacity={isActive ? 1 : 0.3}>
          {direction === 'asc' ? '↑' : '↓'}
        </Text>
      </HStack>
    </Th>
  );
}

/**
 * Endpoint (SSL) monitor helpers
 */
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
