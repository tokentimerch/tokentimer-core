import { useEffect, useState } from 'react';
import {
  Badge,
  Box,
  Code,
  Grid,
  GridItem,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Text,
  VStack,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import {
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import CertificateInstances from './CertificateInstances.jsx';
import CertificateTimeline from './CertificateTimeline.jsx';
import KeyLocalityList from './KeyLocalityList.jsx';
import RenewalBadge from './RenewalBadge.jsx';
import { getCertificateInstances } from './certopsApi.js';
import {
  expiryDescriptor,
  formatDate,
  renewalDescriptor,
  sourceLabel,
  statusLabel,
  statusScheme,
} from './certopsFormat';

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
 * Fetches observation history for a single certificate id, matching the
 * available/error contract CertificateInstances expects (see
 * useCertOpsForToken in useCertOps.js, which does the same thing keyed off
 * a token instead of a certificate id directly).
 */
function useCertificateInstancesFor(workspaceId, certificateId, isOpen) {
  const [instances, setInstances] = useState([]);
  const [available, setAvailable] = useState(true);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen || !workspaceId || !certificateId) {
      setInstances([]);
      setAvailable(true);
      setError('');
      setLoading(false);
      return undefined;
    }
    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    getCertificateInstances(workspaceId, certificateId, {
      signal: controller.signal,
    })
      .then(data => {
        if (cancelled) return;
        setInstances(Array.isArray(data?.items) ? data.items : []);
        setAvailable(true);
      })
      .catch(err => {
        if (cancelled) return;
        setInstances([]);
        // Only 404 means "history not recorded for this certificate yet".
        const notFound = err?.response?.status === 404;
        setAvailable(!notFound);
        setError(
          notFound
            ? ''
            : err?.response?.data?.error ||
                'Could not load certificate locations.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [isOpen, workspaceId, certificateId]);

  return { instances, available, error, loading };
}

/**
 * Certificate-native detail view: everything TokenCertOpsPanel shows (key
 * locality, fingerprint, SANs, observed locations, job history), minus the
 * assumption that a `tokenId` exists.
 *
 * Certificates observed by the M3 cert-manager controller (and any other
 * tokenless source) never get a linked token - see
 * apps/api/services/certops/controllerObservations.js, which does not call
 * ensureManagedCertificateToken the way agentObservations.js does - so
 * TokenDetailModal/TokenCertOpsPanel has nothing to open for them. This
 * reads straight off the managed_certificate row the Certificates list
 * already fetched instead.
 */
export default function CertificateDetailModal({
  isOpen,
  onClose,
  certificate,
}) {
  const { muted, dashboard } = useDashboardTheme();
  const { workspaceId } = useWorkspace();
  const { headerProps, bodyProps, closeButtonProps } =
    useDashboardModalProps();
  const { instances, available, error, loading } = useCertificateInstancesFor(
    workspaceId,
    certificate?.id,
    isOpen
  );

  if (!isOpen || !certificate) return null;

  const expiry = expiryDescriptor(certificate.notAfter);
  const renewal = renewalDescriptor(certificate.renewal);
  const sans = Array.isArray(certificate.subjectAltNames)
    ? certificate.subjectAltNames
    : [];
  const publicKeyLabel = [
    certificate.publicKeyAlgorithm,
    certificate.publicKeySize,
  ]
    .filter(Boolean)
    .join(' ');
  const fingerprintLabel =
    certificate.fingerprintSha256 ||
    (certificate.source === 'cert_manager'
      ? 'Not reported (status-only observation)'
      : 'Not available');

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      isCentered
      scrollBehavior='inside'
      motionPreset='none'
    >
      <ModalOverlay />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Certificate details</DashboardModalTitle>
          <HStack spacing={2} mt={2} flexWrap='wrap'>
            <Badge
              colorScheme={statusScheme(certificate.status)}
              variant='subtle'
              textTransform='none'
            >
              {statusLabel(certificate.status)}
            </Badge>
            <Badge colorScheme={expiry.scheme} variant='subtle'>
              {expiry.label}
            </Badge>
            <RenewalBadge renewal={certificate.renewal} fontSize='sm' />
          </HStack>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps} pb={6}>
          <Grid
            templateColumns={{ base: 'minmax(0, 1fr)', md: 'repeat(2, 1fr)' }}
            gap={{ base: 3, md: 4 }}
          >
            <Field label='Key locality'>
              <KeyLocalityList
                keyMode={certificate.keyMode}
                keyReference={certificate.keyReference}
              />
            </Field>

            <Field label='Automatic renewal'>
              <VStack align='start' spacing={2}>
                <RenewalBadge renewal={certificate.renewal} fontSize='sm' />
                <Text
                  fontSize='xs'
                  color={renewal.isWarning ? dashboard.state.warning : muted}
                >
                  {renewal.help}
                </Text>
              </VStack>
            </Field>

            <Field label='Registration source'>
              {[sourceLabel(certificate.source), certificate.sourceRef]
                .filter(Boolean)
                .join(' / ')}
            </Field>

            {certificate.serialNumber ? (
              <Field label='Serial number (managed)'>
                <Code fontSize='xs'>{certificate.serialNumber}</Code>
              </Field>
            ) : null}

            {certificate.notBefore ? (
              <Field label='Valid from'>
                {formatDate(certificate.notBefore)}
              </Field>
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
                  Subject alternative names
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
                {fingerprintLabel}
              </Code>
            </Field>

            <GridItem colSpan={{ base: 1, md: 2 }}>
              <Text fontSize='sm' fontWeight='semibold' color={muted} mb={2}>
                Observed locations
              </Text>
              {loading ? (
                <Text fontSize='sm' color={muted}>
                  Loading locations...
                </Text>
              ) : (
                <CertificateInstances
                  instances={instances}
                  available={available}
                  error={error}
                />
              )}
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
          </Grid>
        </ModalBody>
      </DashboardModalFrame>
    </Modal>
  );
}
