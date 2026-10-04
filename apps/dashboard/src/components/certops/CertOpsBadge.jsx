import { Badge } from '@chakra-ui/react';
import { forwardRef } from 'react';
import { certificateLifecycleDescriptor } from './certopsFormat.js';

/** Consistent, theme-aware badges for certificate state and information. */
const CertOpsBadge = forwardRef(function CertOpsBadge(
  { colorScheme = 'gray', ...props },
  ref
) {
  return (
    <Badge
      ref={ref}
      colorScheme={colorScheme === 'yellow' ? 'orange' : colorScheme}
      variant='subtle'
      display='inline-flex'
      alignItems='center'
      px={2}
      py={0.5}
      minH='24px'
      borderRadius='md'
      fontSize='xs'
      fontWeight='semibold'
      lineHeight='short'
      textTransform='none'
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
