import { Badge, Tooltip } from '@chakra-ui/react';
import { renewalDescriptor } from './certopsFormat';

/**
 * Shows whether a managed certificate is actually covered by automatic
 * renewal. An `active` certificate with a comfortable expiry date tells an
 * operator nothing about that: the renewal scheduler skips certificates
 * without a complete renewal profile, so without this badge a certificate that
 * will silently expire looks identical to one that renews itself.
 *
 * The explanation is duplicated onto the badge's aria-label because a Chakra
 * tooltip only mounts its text while hovered, and the reason a certificate
 * will never renew must not be reachable by mouse alone. Callers with room for
 * it should also render `renewalDescriptor(renewal).help` as visible helper
 * text (see the token detail panel).
 */
export default function RenewalBadge({ renewal, fontSize = 'xs' }) {
  const descriptor = renewalDescriptor(renewal);

  return (
    <Tooltip label={descriptor.help} hasArrow placement='top' openDelay={250}>
      <Badge
        colorScheme={descriptor.scheme}
        variant={descriptor.isWarning ? 'solid' : 'subtle'}
        textTransform='none'
        fontWeight='medium'
        fontSize={fontSize}
        aria-label={`${descriptor.label}. ${descriptor.help}`}
      >
        {descriptor.label}
      </Badge>
    </Tooltip>
  );
}
