import { Badge, Tooltip } from '@chakra-ui/react';
import { renewalPathDescriptor } from './certopsFormat';

/**
 * Renewal-path health: Healthy / Degraded / Renewal path unavailable /
 * Unknown. A SEPARATE axis from the certificate lifecycle status
 * (active/renewing/expired) and from `RenewalBadge` (is auto-renew
 * configured at all) - see certopsFormat.js#renewalPathDescriptor for why
 * these must never be merged into one badge.
 *
 * Renders nothing when the question does not apply to this certificate
 * (auto-renew disabled, no profile, not agent-deployable, retired), rather
 * than showing a misleading "unavailable" badge next to a certificate that
 * was never expected to auto-renew.
 */
export default function RenewalPathBadge({ certificate, fontSize = 'xs' }) {
  const descriptor = renewalPathDescriptor(certificate);
  if (!descriptor) return null;

  return (
    <Tooltip label={descriptor.help} hasArrow placement='top' openDelay={250}>
      <Badge
        colorScheme={descriptor.scheme}
        variant={descriptor.isWarning ? 'solid' : 'subtle'}
        textTransform='none'
        fontWeight='medium'
        fontSize={fontSize}
        aria-label={`Renewal path: ${descriptor.label}. ${descriptor.help}`}
      >
        {descriptor.label}
      </Badge>
    </Tooltip>
  );
}
