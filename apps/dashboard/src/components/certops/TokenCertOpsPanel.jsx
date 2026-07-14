import {
  Badge,
  Box,
  Code,
  Divider,
  GridItem,
  HStack,
  Text,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import CertificateInstances from './CertificateInstances.jsx';
import CertificateTimeline from './CertificateTimeline.jsx';
import KeyLocalityList from './KeyLocalityList.jsx';
import {
  expiryDescriptor,
  formatDate,
  isCertToken,
  statusScheme,
} from './certopsFormat';
import { useCertOpsForToken } from './useCertOps.js';

function Field({ label, children, colSpan = { base: 1, md: 1 } }) {
  const { muted, border } = useDashboardTheme();
  return (
    <GridItem colSpan={colSpan}>
      <Box
        bg='transparent'
        border='1px solid'
        borderColor={border}
        borderRadius='12px'
        p={{ base: 3.5, md: 4 }}
      >
        <Text fontSize='sm' fontWeight='semibold' color={muted} mb={2}>
          {label}
        </Text>
        <Box fontSize='sm'>{children || <Text color={muted}>--</Text>}</Box>
      </Box>
    </GridItem>
  );
}

/**
 * CertOps enrichment for an existing cert token in TokenDetailModal: key
 * locality, managed status, fingerprint, and deployment history.
 */
export default function TokenCertOpsPanel({ token, tokenId }) {
  // Cheap guard before any hooks: only certificate assets get this panel. The
  // hooks live in CertOpsPanelBody so they are never called conditionally.
  if (!isCertToken(token)) return null;
  return <CertOpsPanelBody tokenId={token?.id ?? tokenId} />;
}

function CertOpsPanelBody({ tokenId }) {
  const { muted } = useDashboardTheme();
  const {
    enabled,
    certificate,
    instances,
    instancesAvailable,
    loading,
    error,
  } = useCertOpsForToken(tokenId);

  if (enabled === false || enabled === null) return null;
  if (loading) {
    return (
      <GridItem colSpan={{ base: 1, md: 2 }}>
        <Text fontSize='sm' color={muted}>
          Loading certificate operations data...
        </Text>
      </GridItem>
    );
  }
  if (error) {
    return (
      <GridItem colSpan={{ base: 1, md: 2 }}>
        <DashboardErrorAlert>{error}</DashboardErrorAlert>
      </GridItem>
    );
  }
  if (!certificate) return null;

  const expiry = expiryDescriptor(certificate.notAfter);
  const sans = Array.isArray(certificate.subjectAltNames)
    ? certificate.subjectAltNames
    : [];
  const publicKeyLabel = [
    certificate.publicKeyAlgorithm,
    certificate.publicKeySize,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <>
      <GridItem colSpan={{ base: 1, md: 2 }}>
        <Divider my={2} />
        <HStack spacing={3} mb={3} flexWrap='wrap'>
          <Text
            fontSize={{ base: 'md', md: 'lg' }}
            fontWeight='bold'
            color={muted}
          >
            Certificate operations
          </Text>
          <Badge
            colorScheme={statusScheme(certificate.status)}
            variant='subtle'
            textTransform='none'
          >
            {certificate.status || 'unknown'}
          </Badge>
          <Badge colorScheme={expiry.scheme} variant='subtle'>
            {expiry.label}
          </Badge>
        </HStack>
      </GridItem>

      <Field label='Key locality'>
        <KeyLocalityList
          keyMode={certificate.keyMode}
          keyReference={certificate.keyReference}
        />
      </Field>

      <Field label='Registration source'>
        {[certificate.source, certificate.sourceRef]
          .filter(Boolean)
          .join(' / ')}
      </Field>

      {certificate.serialNumber ? (
        <Field label='Serial number (managed)'>
          <Code fontSize='xs'>{certificate.serialNumber}</Code>
        </Field>
      ) : null}

      {certificate.notBefore ? (
        <Field label='Valid from'>{formatDate(certificate.notBefore)}</Field>
      ) : null}

      {certificate.notAfter ? (
        <Field label='Valid to'>{formatDate(certificate.notAfter)}</Field>
      ) : null}

      {publicKeyLabel ? (
        <Field label='Public key'>{publicKeyLabel}</Field>
      ) : null}

      {certificate.signatureAlgorithm ? (
        <Field label='Signature algorithm'>
          {certificate.signatureAlgorithm}
        </Field>
      ) : null}

      {sans.length > 0 ? (
        <GridItem colSpan={{ base: 1, md: 2 }}>
          <Text fontSize='sm' fontWeight='semibold' color={muted} mb={2}>
            Subject alternative names (managed)
          </Text>
          <HStack flexWrap='wrap' spacing={2}>
            {sans.map(san => (
              <Badge key={san} variant='outline' textTransform='none'>
                {san}
              </Badge>
            ))}
          </HStack>
        </GridItem>
      ) : null}

      <Field label='SHA-256 fingerprint' colSpan={{ base: 1, md: 2 }}>
        <Code fontSize='xs' whiteSpace='pre-wrap' wordBreak='break-all'>
          {certificate.fingerprintSha256 || 'Not available'}
        </Code>
      </Field>

      <GridItem colSpan={{ base: 1, md: 2 }}>
        <Text fontSize='sm' fontWeight='semibold' color={muted} mb={2}>
          Deployments
        </Text>
        <CertificateInstances
          instances={instances}
          available={instancesAvailable}
        />
      </GridItem>

      <GridItem colSpan={{ base: 1, md: 2 }}>
        <Text fontSize='sm' fontWeight='semibold' color={muted} mb={2}>
          Job history
        </Text>
        <CertificateTimeline
          subjectType='managed_certificate'
          subjectId={certificate.id}
        />
      </GridItem>
    </>
  );
}
