import { Badge } from '@chakra-ui/react';
import { forwardRef, useEffect, useState } from 'react';
import {
  certificateLifecycleDescriptor,
  observedRevocationDescriptor,
} from './certopsFormat.js';
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
    const result = certificate?.observedRevocation;
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
      const expiry = Date.parse(result?.validUntil);
      let timer;
      const update = () => {
        const current = Date.now();
        setNow(current);
        if (Number.isFinite(expiry) && expiry > current)
          timer = setTimeout(update, Math.min(expiry - current + 1, 2147483647));
      };
      update();
      return () => clearTimeout(timer);
    }, [result?.validUntil]);
    const observed = observedRevocationDescriptor(result, now);
    const revoked = ['Revoked', 'Revoked (stale)', 'CA revoked', 'CA revoked (stale)', 'Last known revoked', 'Last known CA revoked'].includes(observed.label);
    if (descriptor.status === 'active' && revoked) return null;
    return (
      <CertOpsBadge ref={ref} colorScheme={descriptor.scheme} {...props}>
        {descriptor.label}
      </CertOpsBadge>
    );
  }
);

export function ObservedRevocationBadge({ result, ...props }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const expiry = Date.parse(result?.validUntil);
    let timer;
    const update = () => {
      const current = Date.now();
      setNow(current);
      if (Number.isFinite(expiry) && expiry > current)
        timer = setTimeout(update, Math.min(expiry - current + 1, 2147483647));
    };
    update();
    return () => clearTimeout(timer);
  }, [result?.validUntil]);
  const descriptor = observedRevocationDescriptor(result, now);
  return (
    <CertOpsBadge
      colorScheme={descriptor.scheme}
      title={descriptor.help}
      {...props}
    >
      {descriptor.label}
    </CertOpsBadge>
  );
}

export function hasObservedRevocationContext(value) {
  return (
    Boolean(value?.observedRevocation || value?.revocationObservable) ||
    ['agent_filesystem', 'agent_windows', 'agent_issuance'].includes(
      value?.source
    )
  );
}
