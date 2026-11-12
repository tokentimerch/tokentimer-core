import { useEffect, useState } from 'react';
import {
  Box,
  Button,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import apiClient from '../../utils/apiClient';
import { formatDateTime } from './certopsJobsFormat';
import CertOpsBadge from './CertOpsBadge.jsx';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';

const PAGE_SIZE = 10;
const VERDICTS = {
  good: 'Not revoked',
  revoked: 'Revoked',
  issuer_revoked: 'CA revoked',
  unknown: 'Revocation unknown',
  not_configured: 'Revocation not configured',
  disabled: 'Revocation disabled',
  invalid_observation: 'Invalid revocation observation',
};

export default function CertificateObservationHistory({
  workspaceId,
  certificateId,
  fingerprintSha256,
  enabled = true,
  onAvailabilityChange,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    closeButtonProps,
    outlineButtonProps,
  } = useDashboardModalProps();
  const [offset, setOffset] = useState(0);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [hasHistory, setHasHistory] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    setOffset(0);
    setHasHistory(false);
    setIsOpen(false);
  }, [workspaceId, certificateId, fingerprintSha256, enabled]);
  useEffect(() => {
    onAvailabilityChange?.(hasHistory);
  }, [hasHistory, onAvailabilityChange]);
  useEffect(() => {
    if (!enabled || !workspaceId || !certificateId || !fingerprintSha256)
      return undefined;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setItems([]);
    apiClient
      .get(
        `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/certificates/${encodeURIComponent(certificateId)}/observations`,
        {
          params: {
            limit: PAGE_SIZE,
            offset,
            ...(fingerprintSha256 ? { fingerprint: fingerprintSha256 } : {}),
          },
          signal: controller.signal,
        }
      )
      .then(({ data }) => {
        if (controller.signal.aborted) return;
        const nextItems = Array.isArray(data?.items) ? data.items : [];
        setItems(nextItems);
        if (offset === 0) setHasHistory(nextItems.length > 0);
      })
      .catch(err => {
        if (!controller.signal.aborted)
          setError(
            err?.response?.status === 409
              ? 'Certificate changed. Reload its details.'
              : 'Could not load observation history.'
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [workspaceId, certificateId, fingerprintSha256, offset, enabled, attempt]);

  if (!hasHistory) return null;
  return (
    <>
      <Button {...outlineButtonProps} size='xs' onClick={() => setIsOpen(true)}>
        Observation history
      </Button>
      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        size='xl'
        scrollBehavior='inside'
        isCentered
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame>
          <ModalHeader {...headerProps}>
            <DashboardModalTitle>Observation history</DashboardModalTitle>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps} pb={6}>
            <DashboardModalDescription mb={4}>
              Observations for this registration’s current fingerprint. Previous
              fingerprints are excluded.
            </DashboardModalDescription>
            {loading ? (
              <Spinner size='sm' aria-label='Loading observation history' />
            ) : error ? (
              <VStack align='start'>
                <Text role='alert'>{error}</Text>
                <Button
                  size='sm'
                  onClick={() => setAttempt(value => value + 1)}
                >
                  Retry
                </Button>
                {offset > 0 ? (
                  <Button
                    size='sm'
                    onClick={() =>
                      setOffset(value => Math.max(0, value - PAGE_SIZE))
                    }
                  >
                    Previous
                  </Button>
                ) : null}
              </VStack>
            ) : (
              <VStack align='stretch' spacing={3}>
                {!items.length ? <Text>No more observations.</Text> : null}
                {items.map(item => {
                  const m = item.metadata || {};
                  const verdict =
                    m.observedRevocationVerdict || m.observedRevocationState;
                  return (
                    <Box
                      key={item.id}
                      borderWidth='1px'
                      borderColor='dashboard.modal.border'
                      borderRadius='md'
                      p={3}
                    >
                      <CertOpsBadge
                        colorScheme={
                          ['revoked', 'issuer_revoked'].includes(verdict)
                            ? 'red'
                            : verdict === 'good'
                              ? 'green'
                              : 'gray'
                        }
                      >
                        {VERDICTS[verdict] || 'Revocation not reported'}
                      </CertOpsBadge>
                      <Text fontSize='sm'>
                        Observed:{' '}
                        {formatDateTime(item.observedAt || item.createdAt)}
                      </Text>
                      <Text fontSize='sm'>
                        Observer: {m.agentId || m.source || 'Unknown'}
                      </Text>
                      {m.targetHost ? (
                        <Text fontSize='sm'>Host: {m.targetHost}</Text>
                      ) : null}
                      {m.fingerprintSha256 ? (
                        <Text fontSize='sm' overflowWrap='anywhere'>
                          SHA-256: {m.fingerprintSha256}
                        </Text>
                      ) : null}
                      {m.locationSlot || m.filePath ? (
                        <Text fontSize='sm'>
                          Location: {m.locationSlot || m.filePath}
                        </Text>
                      ) : null}
                      {m.observedRevocationCheckedAt ? (
                        <Text fontSize='sm'>
                          Checked{' '}
                          {formatDateTime(m.observedRevocationCheckedAt)}
                        </Text>
                      ) : null}
                      {m.observedRevocationValidUntil ? (
                        <Text fontSize='sm'>
                          Evidence valid until{' '}
                          {formatDateTime(m.observedRevocationValidUntil)}
                        </Text>
                      ) : null}
                      {m.observedRevocationDetail ? (
                        <Text fontSize='sm'>{m.observedRevocationDetail}</Text>
                      ) : null}
                    </Box>
                  );
                })}
                <HStack>
                  <Button
                    size='sm'
                    isDisabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                  >
                    Previous
                  </Button>
                  <Button
                    size='sm'
                    isDisabled={items.length < PAGE_SIZE}
                    onClick={() => setOffset(offset + PAGE_SIZE)}
                  >
                    Next
                  </Button>
                </HStack>
              </VStack>
            )}
          </ModalBody>
        </DashboardModalFrame>
      </Modal>
    </>
  );
}
