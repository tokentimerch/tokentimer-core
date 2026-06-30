import { Badge, Tooltip } from '@chakra-ui/react';
import { keyModeLabel } from './certopsFormat';

/**
 * Shows where a certificate's private key is believed to live, without ever
 * implying TokenTimer holds it. CertOps records the key mode and an opaque,
 * non-secret reference only; the control plane never stores key material.
 */
export default function KeyLocalityBadge({ keyMode, keyReference }) {
  const fallbackLabel = keyModeLabel(keyMode);
  const label =
    keyMode === 'external-unknown' && keyReference
      ? keyReference.length > 48
        ? `${keyReference.slice(0, 45)}...`
        : keyReference
      : fallbackLabel;
  const tooltip = keyReference
    ? `${keyReference} (non-secret; the key never leaves its host)`
    : 'TokenTimer records where the key lives, never the key itself.';

  return (
    <Tooltip label={tooltip} hasArrow placement='top' openDelay={250}>
      <Badge
        colorScheme={keyMode ? 'purple' : 'gray'}
        variant='subtle'
        textTransform='none'
        fontWeight='medium'
      >
        {label}
      </Badge>
    </Tooltip>
  );
}
