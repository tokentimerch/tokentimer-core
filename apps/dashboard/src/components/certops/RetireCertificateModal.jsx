import CertOpsBadge from './CertOpsBadge.jsx';
import { useEffect, useId, useMemo, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  Checkbox,
  Flex,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { formatDate, sortCertificatesForToken } from './certopsFormat';

const RETIRE_OPTIONS = [
  {
    value: 'decommissioned',
    label: 'Decommission',
    hint: 'Record that, to your knowledge, this certificate is no longer in use.',
  },
  {
    value: 'revoked',
    label: 'Mark revoked',
    hint: 'Record revocation in TokenTimer. This does not contact the certificate authority.',
  },
];

/**
 * Retire (soft lifecycle transition) for a managed certificate. Most callers
 * link a token (the token inventory's retire action, where the token cannot
 * be hard-deleted while it is backed by a managed certificate; see App.jsx),
 * but the Certificates tab operates on certificate rows directly and often
 * has no linked token at all (e.g. `agent_issuance` before reconciliation),
 * so `token` is optional and the certificate's own name/status carries the
 * subject line when it is absent. The certificate row and its evidence are
 * preserved and the status is mirrored onto the linked token, if any, by the
 * backend.
 */
export default function RetireCertificateModal({
  isOpen,
  onClose,
  token,
  certificate,
  certificates,
  onRetire,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();

  const [status, setStatus] = useState('decommissioned');
  const [reason, setReason] = useState('');
  const [acknowledgeUncertainty, setAcknowledgeUncertainty] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [selectedCertificateId, setSelectedCertificateId] = useState('');
  const certificateSelectId = useId();
  const choices = useMemo(() => {
    const identities = new Map();
    for (const item of sortCertificatesForToken(
      certificate ? [certificate] : certificates
    )) {
      const fingerprint = String(item.fingerprintSha256 || '')
        .replace(/:/g, '')
        .trim()
        .toLowerCase();
      const key = /^[a-f0-9]{64}$/.test(fingerprint)
        ? fingerprint
        : `unidentified:${item.id}`;
      if (!identities.has(key)) identities.set(key, item);
    }
    return [...identities.values()];
  }, [certificate, certificates]);
  const selectedCertificate =
    choices.length === 1
      ? choices[0]
      : choices.find(item => String(item.id) === selectedCertificateId);

  useEffect(() => {
    if (isOpen) {
      setStatus('decommissioned');
      setReason('');
      setAcknowledgeUncertainty(false);
      setSubmitting(false);
      setError('');
      setSelectedCertificateId('');
    }
  }, [isOpen, certificate, certificates]);

  const handleConfirm = async () => {
    if (submitting) return;
    if (!selectedCertificate?.id) {
      setError('Choose the certificate to retire.');
      return;
    }
    const fingerprint = String(selectedCertificate.fingerprintSha256 || '')
      .replace(/:/g, '')
      .trim()
      .toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
      setError(
        'Retirement is unavailable until a certificate SHA-256 fingerprint is available. Refresh the inventory after issuance completes.'
      );
      return;
    }
    if (!reason.trim()) {
      setError('Enter a reason for this lifecycle change.');
      return;
    }
    if (status === 'decommissioned' && !acknowledgeUncertainty) {
      setError('Confirm that you understand visibility may be incomplete.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onRetire({
        certificate: selectedCertificate,
        status,
        reason: reason.trim(),
        acknowledgeUncertainty,
      });
    } catch (err) {
      const code = err?.response?.status;
      if (code === 404) {
        setError(
          'Retiring certificates is not available on this server yet. The backend retire endpoint is still being rolled out.'
        );
      } else {
        setError(
          err?.response?.data?.error ||
            'Could not retire this certificate. Please try again.'
        );
      }
      setSubmitting(false);
    }
  };

  const selected = RETIRE_OPTIONS.find(option => option.value === status);
  const subjectLabel =
    token?.name ||
    selectedCertificate?.commonName ||
    (Array.isArray(selectedCertificate?.subjectAltNames)
      ? selectedCertificate.subjectAltNames[0]
      : null) ||
    selectedCertificate?.id ||
    null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Retire certificate</DashboardModalTitle>
          <DashboardModalDescription>
            This asset is linked to certificate records, so it cannot be
            deleted. Record a lifecycle retirement instead; the record and its
            history are kept. This does not revoke the certificate at its
            certificate authority or remove it from a host.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <VStack spacing={4} align='stretch'>
            {subjectLabel ? (
              <Text fontSize='sm'>
                <Text as='span' fontWeight='semibold'>
                  {subjectLabel}
                </Text>
                {selectedCertificate?.status ? (
                  <CertOpsBadge ml={2} colorScheme='gray'>
                    {selectedCertificate.status}
                  </CertOpsBadge>
                ) : null}
              </Text>
            ) : null}

            {choices.length > 1 ? (
              <VStack align='stretch' spacing={2}>
                <Text
                  as='label'
                  htmlFor={certificateSelectId}
                  fontSize='sm'
                  fontWeight='semibold'
                >
                  Certificate to retire
                </Text>
                <Text fontSize='sm'>
                  This asset tracks several certificate identities. Choose the
                  certificate for this lifecycle change; the others keep their
                  status. Stopping management does not unlink these records.
                </Text>
                <Select
                  id={certificateSelectId}
                  value={selectedCertificateId}
                  isDisabled={submitting}
                  placeholder='Choose a certificate'
                  onChange={event => {
                    setSelectedCertificateId(event.target.value);
                    setError('');
                  }}
                >
                  {choices.map(item => (
                    <option key={item.id} value={item.id}>
                      {item.commonName || item.name || item.id} · Expires{' '}
                      {formatDate(item.notAfter)} ·{' '}
                      {item.fingerprintSha256?.replace(/:/g, '').slice(0, 12) ||
                        'Fingerprint unavailable'}
                    </option>
                  ))}
                </Select>
              </VStack>
            ) : null}
            {selectedCertificate?.fingerprintSha256 ? (
              <Text fontSize='xs' wordBreak='break-all'>
                SHA-256: {selectedCertificate.fingerprintSha256}
              </Text>
            ) : null}

            <RadioGroup value={status} onChange={setStatus}>
              <Stack spacing={3}>
                {RETIRE_OPTIONS.map(option => (
                  <Radio key={option.value} value={option.value}>
                    <Text fontSize='sm' fontWeight='medium'>
                      {option.label}
                    </Text>
                    <Text fontSize='xs' opacity={0.75}>
                      {option.hint}
                    </Text>
                  </Radio>
                ))}
              </Stack>
            </RadioGroup>

            <Alert status='warning' borderRadius='12px'>
              <AlertIcon />
              <AlertDescription fontSize='sm'>
                Renewal-failure alerts for this certificate will stop. Expiry
                alerts stop only when no other live certificate remains on this
                asset. Endpoint monitoring continues.
              </AlertDescription>
            </Alert>

            <Textarea
              value={reason}
              onChange={event => setReason(event.target.value)}
              placeholder='Reason (required, recorded in the audit trail)'
              size='sm'
              rows={2}
            />
            {status === 'decommissioned' ? (
              <Checkbox
                isChecked={acknowledgeUncertainty}
                onChange={event =>
                  setAcknowledgeUncertainty(event.target.checked)
                }
              >
                I understand TokenTimer may not see every location where this
                certificate is in use.
              </Checkbox>
            ) : null}

            {error ? (
              <Alert status='error' borderRadius='12px'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Flex
            w='100%'
            gap={3}
            justify={{ base: 'stretch', sm: 'flex-end' }}
            direction={{ base: 'column-reverse', sm: 'row' }}
          >
            <Button
              onClick={onClose}
              isDisabled={submitting}
              minW={{ base: '100%', sm: '104px' }}
              {...outlineButtonProps}
            >
              Cancel
            </Button>
            <Button
              onClick={handleConfirm}
              isLoading={submitting}
              minW={{ base: '100%', sm: '148px' }}
              {...dangerButtonProps}
            >
              {selected ? selected.label : 'Retire'}
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
