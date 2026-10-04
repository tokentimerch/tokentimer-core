import { Badge } from '@chakra-ui/react';
import { forwardRef } from 'react';
import { certificateLifecycleDescriptor } from './certopsFormat.js';
import {
  badgeColorScheme,
  dashboardBadgeBaseStyle,
} from '../../styles/badges.js';

/** Shared dashboard badge design for CertOps status and information. */
const CertOpsBadge = forwardRef(function CertOpsBadge(
  { colorScheme = 'gray', ...props },
  ref
) {
  return (
    <Badge
      ref={ref}
      colorScheme={badgeColorScheme(colorScheme)}
      variant='subtle'
      {...dashboardBadgeBaseStyle}
      {...props}
    />
  );
});

export default CertOpsBadge;

export const CertificateLifecycleBadge = forwardRef(
  function CertificateLifecycleBadge({ certificate, ...props }, ref) {
    const descriptor = certificateLifecycleDescriptor(certificate);
    return (
      <CertOpsBadge ref={ref} colorScheme={descriptor.scheme} {...props}>
        {descriptor.label}
      </CertOpsBadge>
    );
  }
);
